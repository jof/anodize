//! Standalone disc validator binary.
//!
//! Reads a ceremony staging directory (containing session subdirectories with
//! AUDIT.LOG and STATE.JSON), runs offline validation checks, and prints a
//! human-readable report to stdout.
//!
//! Usage:
//!   anodize-validate [--staging /run/anodize/staging]
//!
//! Exit code 0 = PASS, 1 = WARN, 2 = ERROR.

use std::path::PathBuf;
use std::process;

use anyhow::{Context, Result};
use clap::Parser;

use anodize_audit::validate::{
    format_report, validate_audit_chain, validate_disc_status, validate_session_continuity,
    DiscStatus, Finding, SessionSnapshot, Severity, StateFields,
};
use anodize_config::state::SessionState;
use sha2::{Digest, Sha256};

#[derive(Parser)]
#[command(name = "anodize-validate", about = "Offline disc validation")]
struct Cli {
    /// Path to the ceremony staging directory (contains session subdirs).
    #[arg(long, default_value = "/run/anodize/staging")]
    staging: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let staging = &cli.staging;

    if !staging.is_dir() {
        eprintln!(
            "error: staging directory does not exist: {}",
            staging.display()
        );
        process::exit(2);
    }

    let mut findings: Vec<Finding> = Vec::new();

    // Discover session subdirectories (sorted by name = chronological).
    let mut session_dirs: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(staging).context("reading staging dir")? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            session_dirs.push(path);
        }
    }
    session_dirs.sort();

    // Build SessionSnapshot for each subdirectory.
    let mut snapshots: Vec<SessionSnapshot> = Vec::new();
    for (i, dir) in session_dirs.iter().enumerate() {
        let dir_name = dir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();

        // Collect file names and SHA-256 content hashes.
        let mut file_hashes: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for e in entries.flatten() {
                if let Some(name) = e.file_name().to_str() {
                    let upper = name.to_uppercase();
                    if let Ok(content) = std::fs::read(e.path()) {
                        let hash = format!("{:x}", Sha256::digest(&content));
                        file_hashes.insert(upper, hash);
                    } else {
                        file_hashes.insert(upper, String::new());
                    }
                }
            }
        }

        let has_migration = file_hashes.contains_key("MIGRATION.JSON");

        // Parse STATE.JSON if present.
        let state_path = dir.join("STATE.JSON");
        let state = if state_path.exists() {
            match std::fs::read_to_string(&state_path) {
                Ok(data) => match serde_json::from_str::<SessionState>(&data) {
                    Ok(s) => StateFields {
                        root_cert_sha256: s.root_cert_sha256,
                        crl_number: s.crl_number,
                        last_audit_hash: s.last_audit_hash,
                        last_hsm_log_seq: s.last_hsm_log_seq,
                        is_migration: has_migration,
                    },
                    Err(e) => {
                        findings.push(Finding {
                            severity: Severity::Error,
                            check: format!("session[{i}].state_json"),
                            message: format!("Failed to parse STATE.JSON in {dir_name}: {e}"),
                        });
                        StateFields {
                            root_cert_sha256: String::new(),
                            crl_number: 0,
                            last_audit_hash: String::new(),
                            last_hsm_log_seq: None,
                            is_migration: has_migration,
                        }
                    }
                },
                Err(e) => {
                    findings.push(Finding {
                        severity: Severity::Error,
                        check: format!("session[{i}].state_json"),
                        message: format!("Cannot read STATE.JSON in {dir_name}: {e}"),
                    });
                    StateFields {
                        root_cert_sha256: String::new(),
                        crl_number: 0,
                        last_audit_hash: String::new(),
                        last_hsm_log_seq: None,
                        is_migration: has_migration,
                    }
                }
            }
        } else {
            findings.push(Finding {
                severity: Severity::Warn,
                check: format!("session[{i}].state_json"),
                message: format!("No STATE.JSON in {dir_name}"),
            });
            StateFields {
                root_cert_sha256: String::new(),
                crl_number: 0,
                last_audit_hash: String::new(),
                last_hsm_log_seq: None,
                is_migration: has_migration,
            }
        };

        // Parse audit records from AUDIT.LOG if present.
        let audit_path = dir.join("AUDIT.LOG");
        let audit_records = if audit_path.exists() {
            std::fs::read_to_string(&audit_path)
                .unwrap_or_default()
                .lines()
                .filter_map(|line| serde_json::from_str::<anodize_audit::Record>(line).ok())
                .collect()
        } else {
            Vec::new()
        };

        snapshots.push(SessionSnapshot {
            index: i,
            file_hashes,
            audit_records,
            state,
        });
    }

    // Disc status — standalone validator cannot probe hardware, assume Incomplete.
    if snapshots.is_empty() {
        findings.extend(validate_disc_status(DiscStatus::Blank));
    } else {
        findings.extend(validate_disc_status(DiscStatus::Incomplete));
    }

    // Session continuity.
    findings.extend(validate_session_continuity(&snapshots));

    // Audit chain integrity.
    findings.extend(validate_audit_chain(&snapshots));

    // Combined audit log check (if there's a top-level audit.log).
    let combined_log = staging.join("audit.log");
    if combined_log.exists() {
        match anodize_audit::verify_log(&combined_log) {
            Ok(count) => {
                findings.push(Finding {
                    severity: Severity::Pass,
                    check: "audit.combined_chain".into(),
                    message: format!("Combined audit.log hash chain verified ({count} entries)"),
                });
            }
            Err(e) => {
                findings.push(Finding {
                    severity: Severity::Error,
                    check: "audit.combined_chain".into(),
                    message: format!("Combined audit.log hash chain FAILED: {e}"),
                });
            }
        }
    }

    // Print report.
    let report = format_report(&findings);
    print!("{report}");

    // Exit code based on worst severity.
    let worst = findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::Pass);

    match worst {
        Severity::Pass => process::exit(0),
        Severity::Warn => process::exit(1),
        Severity::Error => process::exit(2),
    }
}
