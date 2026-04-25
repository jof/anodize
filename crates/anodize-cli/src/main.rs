use std::path::PathBuf;
use std::time::SystemTime;

use anodize_audit::{genesis_hash, AuditLog};
use anodize_ca::{build_root_cert, issue_crl, sign_intermediate_csr, P384HsmSigner};
use anodize_config::{load as load_profile, PinSource};
use anodize_hsm::{Hsm, HsmActor, KeySpec, Pkcs11Hsm};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use der::{Decode, Encode};
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use tracing::info;
use x509_cert::certificate::Certificate;

#[derive(Parser)]
#[command(name = "anodize", about = "Root CA dev/CI tool (Phase 4)")]
struct Cli {
    /// Path to profile.toml
    #[arg(short, long, value_name = "FILE")]
    profile: PathBuf,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate root keypair and issue self-signed root certificate
    Init {
        /// Output path for root certificate (DER)
        #[arg(short, long, value_name = "FILE")]
        cert_out: PathBuf,
        /// Output path for audit log (JSONL)
        #[arg(short, long, value_name = "FILE")]
        log_out: PathBuf,
        /// Certificate validity in days
        #[arg(long, default_value_t = 7305)]
        validity_days: u32,
    },
    /// Sign an intermediate CA CSR
    SignCsr {
        /// CSR file (DER)
        #[arg(long, value_name = "FILE")]
        csr: PathBuf,
        /// Issuing root certificate (DER)
        #[arg(long, value_name = "FILE")]
        root_cert: PathBuf,
        /// Output path for intermediate certificate (DER)
        #[arg(short, long, value_name = "FILE")]
        cert_out: PathBuf,
        /// Audit log to append to
        #[arg(short, long, value_name = "FILE")]
        log: PathBuf,
        /// BasicConstraints pathLenConstraint (0 = no sub-CAs allowed)
        #[arg(long)]
        path_len: Option<u8>,
        /// Certificate validity in days
        #[arg(long, default_value_t = 1825)]
        validity_days: u32,
    },
    /// Issue a CRL (empty, for initial publication)
    IssueCrl {
        /// Issuing root certificate (DER)
        #[arg(long, value_name = "FILE")]
        root_cert: PathBuf,
        /// Output path for CRL (DER)
        #[arg(short, long, value_name = "FILE")]
        crl_out: PathBuf,
        /// Audit log to append to
        #[arg(short, long, value_name = "FILE")]
        log: PathBuf,
        /// Days until nextUpdate field
        #[arg(long, default_value_t = 30)]
        next_update_days: u64,
    },
    /// Verify the audit log hash chain
    VerifyLog {
        /// Audit log path
        #[arg(value_name = "FILE")]
        log: PathBuf,
    },
}

fn resolve_pin(source: &PinSource) -> Result<SecretString> {
    match source {
        PinSource::Prompt => {
            let s = rpassword::prompt_password("HSM PIN: ")
                .context("failed to read PIN from terminal")?;
            Ok(SecretString::new(s))
        }
        PinSource::Env(var) => {
            let val = std::env::var(var).with_context(|| format!("env var {var} not set"))?;
            Ok(SecretString::new(val))
        }
        PinSource::File(path) => {
            let val = std::fs::read_to_string(path)
                .with_context(|| format!("cannot read PIN from {}", path.display()))?;
            Ok(SecretString::new(val.trim_end_matches('\n').to_string()))
        }
    }
}

fn open_actor(profile: &anodize_config::Profile) -> Result<HsmActor> {
    let cfg = &profile.hsm;
    cfg.pin_source.warn_if_unsafe();
    let pin = resolve_pin(&cfg.pin_source)?;
    let hsm = Pkcs11Hsm::new(&cfg.module_path, &cfg.token_label)
        .with_context(|| format!("cannot open HSM token {:?}", cfg.token_label))?;
    let mut actor = HsmActor::spawn(hsm);
    actor.login(&pin).context("HSM login failed")?;
    Ok(actor)
}

fn cert_fingerprint(der: &[u8]) -> String {
    let hash = Sha256::digest(der);
    hash.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .chunks(2)
        .map(|c| c.join(""))
        .collect::<Vec<_>>()
        .join(":")
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let profile = load_profile(&cli.profile)
        .with_context(|| format!("cannot load profile {:?}", cli.profile))?;

    match cli.command {
        Cmd::Init {
            cert_out,
            log_out,
            validity_days,
        } => {
            let cfg = &profile.hsm;
            cfg.pin_source.warn_if_unsafe();
            let pin = resolve_pin(&cfg.pin_source)?;

            let hsm = Pkcs11Hsm::new(&cfg.module_path, &cfg.token_label)
                .with_context(|| format!("cannot open HSM token {:?}", cfg.token_label))?;
            let mut actor = HsmActor::spawn(hsm);
            actor.login(&pin).context("HSM login failed")?;

            let key = actor
                .generate_keypair(&cfg.key_label, KeySpec::EcdsaP384)
                .context("keypair generation failed")?;
            info!("generated P-384 keypair, label={:?}", cfg.key_label);

            let signer = P384HsmSigner::new(actor, key).context("build signer")?;
            let ca = &profile.ca;
            let cert = build_root_cert(
                &signer,
                &ca.common_name,
                &ca.organization,
                &ca.country,
                validity_days,
            )
            .context("build_root_cert failed")?;

            let cert_der = cert.to_der().context("encode cert DER")?;
            std::fs::write(&cert_out, &cert_der)
                .with_context(|| format!("write cert to {cert_out:?}"))?;

            let fp = cert_fingerprint(&cert_der);
            println!("Root CA fingerprint (SHA-256):");
            println!("  {fp}");
            info!("wrote root cert ({} bytes) → {cert_out:?}", cert_der.len());

            let genesis = genesis_hash(&cert_der);
            let mut log = AuditLog::create(&log_out, &genesis).context("create audit log")?;
            log.append(
                "cert.root.issue",
                serde_json::json!({
                    "subject": ca.common_name,
                    "fingerprint": fp,
                    "validity_days": validity_days,
                }),
            )
            .context("append audit record")?;
            info!("audit log initialized → {log_out:?}");
        }

        Cmd::SignCsr {
            csr,
            root_cert,
            cert_out,
            log,
            path_len,
            validity_days,
        } => {
            let actor = open_actor(&profile)?;
            let cfg = &profile.hsm;
            let key = actor
                .find_key(&cfg.key_label)
                .with_context(|| format!("key {:?} not found", cfg.key_label))?;
            let signer = P384HsmSigner::new(actor, key).context("build signer")?;

            let root_der = std::fs::read(&root_cert)
                .with_context(|| format!("read root cert {root_cert:?}"))?;
            let root_parsed = Certificate::from_der(&root_der).context("decode root cert DER")?;

            let csr_der = std::fs::read(&csr).with_context(|| format!("read CSR {csr:?}"))?;

            let int_cert = sign_intermediate_csr(
                &signer,
                &root_parsed,
                &csr_der,
                path_len,
                validity_days,
                profile.ca.cdp_url.as_deref(),
            )
            .context("sign_intermediate_csr failed")?;

            let int_der = int_cert.to_der().context("encode intermediate DER")?;
            std::fs::write(&cert_out, &int_der)
                .with_context(|| format!("write cert {cert_out:?}"))?;

            let fp = cert_fingerprint(&int_der);
            let subject = int_cert.tbs_certificate.subject.to_string();
            println!("Intermediate CA fingerprint (SHA-256):");
            println!("  {fp}");
            info!(
                "wrote intermediate cert ({} bytes) → {cert_out:?}",
                int_der.len()
            );

            let mut audit = AuditLog::open(&log).context("open audit log")?;
            audit
                .append(
                    "cert.intermediate.issue",
                    serde_json::json!({
                        "subject": subject,
                        "fingerprint": fp,
                        "validity_days": validity_days,
                    }),
                )
                .context("append audit record")?;
        }

        Cmd::IssueCrl {
            root_cert,
            crl_out,
            log,
            next_update_days,
        } => {
            let actor = open_actor(&profile)?;
            let cfg = &profile.hsm;
            let key = actor
                .find_key(&cfg.key_label)
                .with_context(|| format!("key {:?} not found", cfg.key_label))?;
            let signer = P384HsmSigner::new(actor, key).context("build signer")?;

            let root_der = std::fs::read(&root_cert)
                .with_context(|| format!("read root cert {root_cert:?}"))?;
            let root_parsed = Certificate::from_der(&root_der).context("decode root cert DER")?;

            let next_update =
                SystemTime::now() + std::time::Duration::from_secs(next_update_days * 86400);
            let crl_der =
                issue_crl(&signer, &root_parsed, &[], next_update).context("issue_crl failed")?;

            std::fs::write(&crl_out, &crl_der).with_context(|| format!("write CRL {crl_out:?}"))?;
            info!("wrote CRL ({} bytes) → {crl_out:?}", crl_der.len());

            let mut audit = AuditLog::open(&log).context("open audit log")?;
            audit
                .append(
                    "crl.issue",
                    serde_json::json!({
                        "revoked_count": 0,
                        "next_update_days": next_update_days,
                    }),
                )
                .context("append audit record")?;
        }

        Cmd::VerifyLog { log } => {
            let count =
                anodize_audit::verify_log(&log).with_context(|| format!("verify log {log:?}"))?;
            println!("Log OK: {count} records verified");
        }
    }

    Ok(())
}
