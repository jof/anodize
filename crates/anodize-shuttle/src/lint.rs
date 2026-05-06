use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Args;
use sha2::{Digest, Sha256};

#[derive(Args)]
pub struct LintArgs {
    /// Path to the mounted shuttle USB volume (e.g. /Volumes/ANODIZE or /mnt/usb).
    #[arg(long, short = 'p')]
    path: PathBuf,

    /// Show detailed file information (sizes, hashes).
    #[arg(long)]
    verbose: bool,
}

/// Files that are part of the shuttle specification.
const KNOWN_FILES: &[&str] = &[
    "profile.toml",
    "csr.der",
    "revoked.toml",
    "root.crt",
    "root.crl",
    "intermediate.crt",
    "audit.log",
];

/// Directory prefixes allowed on the shuttle.
const KNOWN_DIRS: &[&str] = &["softhsm2"];

/// Ceremony operations and the files they require or produce.
struct OperationSpec {
    name: &'static str,
    description: &'static str,
    required_inputs: &'static [&'static str],
    optional_inputs: &'static [&'static str],
    outputs: &'static [&'static str],
}

const OPERATIONS: &[OperationSpec] = &[
    OperationSpec {
        name: "generate-root-ca",
        description: "Generate root CA keypair and self-signed certificate",
        required_inputs: &["profile.toml"],
        optional_inputs: &[],
        outputs: &["root.crt", "root.crl", "audit.log"],
    },
    OperationSpec {
        name: "sign-csr",
        description: "Sign an intermediate CA CSR",
        required_inputs: &["profile.toml", "csr.der"],
        optional_inputs: &[],
        outputs: &["intermediate.crt", "audit.log"],
    },
    OperationSpec {
        name: "revoke-cert",
        description: "Revoke a certificate and issue updated CRL",
        required_inputs: &["profile.toml"],
        optional_inputs: &["revoked.toml"],
        outputs: &["revoked.toml", "root.crl", "audit.log"],
    },
    OperationSpec {
        name: "issue-crl",
        description: "Issue a CRL refresh (re-sign current revocation list)",
        required_inputs: &["profile.toml"],
        optional_inputs: &["revoked.toml"],
        outputs: &["root.crl", "audit.log"],
    },
];

pub fn run(args: LintArgs) -> Result<()> {
    let root = &args.path;
    if !root.exists() {
        anyhow::bail!("Path does not exist: {}", root.display());
    }
    if !root.is_dir() {
        anyhow::bail!("Path is not a directory: {}", root.display());
    }

    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut info: Vec<String> = Vec::new();

    // Enumerate all files on the shuttle
    let all_files = enumerate_files(root)?;
    let relative_files: BTreeSet<String> = all_files
        .iter()
        .filter_map(|p| p.strip_prefix(root).ok())
        .map(|p| p.to_string_lossy().to_string())
        .collect();

    // ── Check profile.toml ───────────────────────────────────────────────────

    let profile_path = root.join("profile.toml");
    let profile_ok = if !profile_path.exists() {
        errors.push("profile.toml: MISSING (required for all operations)".into());
        false
    } else {
        match anodize_config::load(&profile_path) {
            Ok(profile) => {
                info.push(format!(
                    "profile.toml: OK — CN={:?}, O={:?}, C={:?}, token={:?}",
                    profile.ca.common_name,
                    profile.ca.organization,
                    profile.ca.country,
                    profile.hsm.token_label,
                ));
                if profile.hsm.pin_source != anodize_config::PinSource::Prompt {
                    warnings.push(
                        "profile.toml: pin_source is not 'prompt' — unsuitable for ceremony"
                            .into(),
                    );
                }
                if profile.ca.cdp_url.is_none() {
                    warnings.push(
                        "profile.toml: cdp_url is not set — certificates will have no CRL distribution point".into(),
                    );
                }
                if profile.cert_profiles.is_empty() {
                    warnings.push(
                        "profile.toml: no [[cert_profiles]] defined — CSR signing will fail".into(),
                    );
                } else {
                    for (i, p) in profile.cert_profiles.iter().enumerate() {
                        info.push(format!(
                            "  cert_profile[{i}]: name={:?} validity={}d path_len={:?}",
                            p.name, p.validity_days, p.path_len,
                        ));
                    }
                }
                true
            }
            Err(e) => {
                errors.push(format!("profile.toml: PARSE ERROR — {e}"));
                false
            }
        }
    };

    // ── Check csr.der ────────────────────────────────────────────────────────

    let csr_path = root.join("csr.der");
    if csr_path.exists() {
        match validate_csr_der(&csr_path) {
            Ok(subject) => info.push(format!("csr.der: OK — subject={subject}")),
            Err(e) => errors.push(format!("csr.der: INVALID — {e}")),
        }
    }

    // ── Check root.crt ───────────────────────────────────────────────────────

    let root_crt_path = root.join("root.crt");
    if root_crt_path.exists() {
        match validate_cert_der(&root_crt_path, "root.crt") {
            Ok(desc) => info.push(format!("root.crt: OK — {desc}")),
            Err(e) => errors.push(format!("root.crt: INVALID — {e}")),
        }
    }

    // ── Check intermediate.crt ───────────────────────────────────────────────

    let int_crt_path = root.join("intermediate.crt");
    if int_crt_path.exists() {
        match validate_cert_der(&int_crt_path, "intermediate.crt") {
            Ok(desc) => info.push(format!("intermediate.crt: OK — {desc}")),
            Err(e) => errors.push(format!("intermediate.crt: INVALID — {e}")),
        }
    }

    // ── Check root.crl ───────────────────────────────────────────────────────

    let root_crl_path = root.join("root.crl");
    if root_crl_path.exists() {
        let meta = std::fs::metadata(&root_crl_path)?;
        info.push(format!("root.crl: present ({} bytes)", meta.len()));
    }

    // ── Check revoked.toml ───────────────────────────────────────────────────

    let revoked_path = root.join("revoked.toml");
    if revoked_path.exists() {
        match validate_revoked_toml(&revoked_path) {
            Ok(count) => info.push(format!("revoked.toml: OK — {count} entries")),
            Err(e) => errors.push(format!("revoked.toml: INVALID — {e}")),
        }
    }

    // ── Check audit.log ──────────────────────────────────────────────────────

    let audit_path = root.join("audit.log");
    if audit_path.exists() {
        match validate_audit_log(&audit_path) {
            Ok((count, chain_ok)) => {
                let chain_str = if chain_ok { "chain OK" } else { "CHAIN BROKEN" };
                let msg = format!("audit.log: {count} records, {chain_str}");
                if chain_ok {
                    info.push(msg);
                } else {
                    errors.push(msg);
                }
            }
            Err(e) => errors.push(format!("audit.log: INVALID — {e}")),
        }
    }

    // ── Check softhsm2 directory ─────────────────────────────────────────────

    let softhsm_dir = root.join("softhsm2");
    if softhsm_dir.exists() {
        let tokens_dir = softhsm_dir.join("tokens");
        if tokens_dir.exists() {
            let token_count = std::fs::read_dir(&tokens_dir)
                .map(|rd| rd.flatten().filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false)).count())
                .unwrap_or(0);
            info.push(format!("softhsm2/tokens/: {token_count} token slot(s)"));
        } else {
            warnings.push("softhsm2/ exists but softhsm2/tokens/ is missing".into());
        }
    }

    // ── Extraneous file check ────────────────────────────────────────────────

    for rel in &relative_files {
        let is_known = KNOWN_FILES.iter().any(|k| rel == *k)
            || KNOWN_DIRS.iter().any(|d| rel.starts_with(d));

        // macOS metadata files
        let is_system = rel.starts_with(".Spotlight-")
            || rel.starts_with(".fseventsd")
            || rel.starts_with(".Trashes")
            || rel.starts_with("._")
            || rel == ".DS_Store"
            || rel == "System Volume Information"
            || rel.starts_with("System Volume Information/");

        if !is_known && !is_system {
            warnings.push(format!("EXTRANEOUS: {rel}"));
        }
    }

    // ── Verbose file listing ─────────────────────────────────────────────────

    if args.verbose {
        eprintln!();
        eprintln!("── Files on shuttle ──");
        for rel in &relative_files {
            let full = root.join(rel);
            if let Ok(meta) = std::fs::metadata(&full) {
                let size = meta.len();
                let hash = if meta.is_file() && size < 10 * 1024 * 1024 {
                    file_sha256(&full).unwrap_or_else(|_| "?".into())
                } else {
                    "-".into()
                };
                eprintln!("  {rel:<30} {size:>10} bytes  sha256:{hash}");
            }
        }
    }

    // ── Operation readiness report ───────────────────────────────────────────

    eprintln!();
    eprintln!("── Shuttle Lint Report ──");
    eprintln!();

    if !info.is_empty() {
        for msg in &info {
            eprintln!("  \x1b[32m✓\x1b[0m {msg}");
        }
        eprintln!();
    }

    if !warnings.is_empty() {
        for msg in &warnings {
            eprintln!("  \x1b[33m⚠\x1b[0m {msg}");
        }
        eprintln!();
    }

    if !errors.is_empty() {
        for msg in &errors {
            eprintln!("  \x1b[31m✗\x1b[0m {msg}");
        }
        eprintln!();
    }

    // Readiness per operation
    eprintln!("── Operation Readiness ──");
    eprintln!();
    for op in OPERATIONS {
        let ready = profile_ok
            && op
                .required_inputs
                .iter()
                .all(|f| relative_files.contains(*f));

        let missing: Vec<&str> = op
            .required_inputs
            .iter()
            .filter(|f| !relative_files.contains(**f))
            .copied()
            .collect();

        let optional_present: Vec<&str> = op
            .optional_inputs
            .iter()
            .filter(|f| relative_files.contains(**f))
            .copied()
            .collect();

        let present_outputs: Vec<&str> = op
            .outputs
            .iter()
            .filter(|f| relative_files.contains(**f))
            .copied()
            .collect();

        let icon = if ready {
            "\x1b[32m✓\x1b[0m"
        } else {
            "\x1b[31m✗\x1b[0m"
        };

        eprintln!("  {icon} {:<20} {}", op.name, op.description);
        if !missing.is_empty() {
            eprintln!("    missing: {}", missing.join(", "));
        }
        if !optional_present.is_empty() {
            eprintln!(
                "    optional inputs present: {}",
                optional_present.join(", ")
            );
        }
        if !present_outputs.is_empty() {
            eprintln!(
                "    \x1b[33mnote\x1b[0m: output file(s) already present: {} \
                 (will be overwritten by ceremony)",
                present_outputs.join(", ")
            );
        }
    }
    eprintln!();

    // Summary
    let total_issues = errors.len() + warnings.len();
    if errors.is_empty() {
        if warnings.is_empty() {
            eprintln!("\x1b[32mShuttle is clean.\x1b[0m");
        } else {
            eprintln!(
                "\x1b[33mShuttle has {} warning(s) but no errors.\x1b[0m",
                warnings.len()
            );
        }
        Ok(())
    } else {
        eprintln!(
            "\x1b[31mShuttle has {} error(s) and {} warning(s).\x1b[0m",
            errors.len(),
            warnings.len()
        );
        anyhow::bail!("{} issue(s) found", total_issues);
    }
}

// ── Validation helpers ───────────────────────────────────────────────────────

fn enumerate_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut result = Vec::new();
    enumerate_files_recursive(root, root, &mut result)?;
    Ok(result)
}

fn enumerate_files_recursive(
    root: &Path,
    dir: &Path,
    out: &mut Vec<PathBuf>,
) -> Result<()> {
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("read_dir {}", dir.display()))?;

    for entry in entries.flatten() {
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_file() {
            out.push(path);
        } else if ft.is_dir() {
            enumerate_files_recursive(root, &path, out)?;
        }
    }
    Ok(())
}

fn validate_csr_der(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path)?;
    use der::Decode;
    let csr = x509_cert::request::CertReq::from_der(&bytes)
        .context("not a valid DER-encoded PKCS#10 CSR")?;
    Ok(csr.info.subject.to_string())
}

fn validate_cert_der(path: &Path, label: &str) -> Result<String> {
    let bytes = std::fs::read(path)?;
    use der::Decode;
    let cert = x509_cert::certificate::Certificate::from_der(&bytes)
        .with_context(|| format!("{label}: not a valid DER-encoded X.509 certificate"))?;
    let subject = cert.tbs_certificate.subject.to_string();
    let issuer = cert.tbs_certificate.issuer.to_string();
    let fp = sha256_fingerprint(&bytes);
    Ok(format!("subject={subject}, issuer={issuer}, sha256={fp}"))
}

fn validate_revoked_toml(path: &Path) -> Result<usize> {
    let data = std::fs::read(path)?;
    let entries = anodize_config::parse_revocation_list(&data)?;
    Ok(entries.len())
}

fn validate_audit_log(path: &Path) -> Result<(usize, bool)> {
    let data = std::fs::read(path)?;
    let mut count = 0usize;
    let mut prev_hash: Option<String> = None;
    let mut chain_ok = true;

    for line in data.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let record: serde_json::Value = serde_json::from_slice(line)
            .context("audit.log: line is not valid JSON")?;

        if let Some(expected) = &prev_hash {
            let actual = record
                .get("prev_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if actual != expected {
                chain_ok = false;
            }
        }
        prev_hash = record
            .get("entry_hash")
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned());
        count += 1;
    }

    Ok((count, chain_ok))
}

fn sha256_fingerprint(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    hash.iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn file_sha256(path: &Path) -> Result<String> {
    let data = std::fs::read(path)?;
    Ok(sha256_fingerprint(&data))
}
