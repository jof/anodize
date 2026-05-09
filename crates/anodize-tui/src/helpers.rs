use std::time::SystemTime;

use anodize_ca::CaError;
use der::Decode;
use sha2::{Digest, Sha256};
use x509_cert::certificate::Certificate;

use crate::app::CertSummary;
use crate::media::SessionEntry;

// ── Noise PIN masking ─────────────────────────────────────────────────────────

pub fn noise_display_len() -> usize {
    use std::time::UNIX_EPOCH;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as usize;
    8 + (nanos % 13)
}

// ── Error helpers ─────────────────────────────────────────────────────────────

pub fn mechanism_error_msg(prefix: &str, e: &CaError) -> String {
    if e.is_mechanism_unsupported() {
        "HSM does not support CKM_ECDSA_SHA384. \
         Ubuntu SoftHSM2 is built without it — use 'make qemu-dev-curses' \
         (Nix SoftHSM2) or a YubiHSM 2."
            .to_string()
    } else {
        format!("{prefix}: {e}")
    }
}

// ── Fingerprint ───────────────────────────────────────────────────────────────

pub fn sha256_fingerprint(der: &[u8]) -> String {
    let hash = Sha256::digest(der);
    hash.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .chunks(2)
        .map(|c| c.join(""))
        .collect::<Vec<_>>()
        .join(":")
}

// ── Disc session helpers ──────────────────────────────────────────────────────

/// Load the most recent STATE.JSON from disc sessions (latest session first).
pub fn load_session_state_from_sessions(
    sessions: &[SessionEntry],
) -> Option<anodize_config::state::SessionState> {
    for session in sessions.iter().rev() {
        if let Some(file) = session
            .files
            .iter()
            .find(|f| f.name == anodize_config::state::STATE_FILENAME)
        {
            match anodize_config::state::SessionState::from_json(&file.data) {
                Ok(state) => return Some(state),
                Err(e) => {
                    tracing::warn!(
                        session = %session.dir_name,
                        error = %e,
                        "STATE.JSON parse/validation failed, trying older session"
                    );
                }
            }
        }
    }
    None
}

/// Load ROOT.CRT DER bytes from the first session on disc that contains it.
pub fn load_root_cert_der_from_sessions(sessions: &[SessionEntry]) -> Option<Vec<u8>> {
    sessions.iter().find_map(|s| {
        s.files
            .iter()
            .find(|f| f.name == "ROOT.CRT")
            .map(|f| f.data.clone())
    })
}

/// Load the most recent REVOKED.TOML from disc sessions.
pub fn load_revocation_from_sessions(
    sessions: &[SessionEntry],
) -> Vec<anodize_config::RevocationEntry> {
    for session in sessions.iter().rev() {
        if let Some(file) = session.files.iter().find(|f| f.name == "REVOKED.TOML") {
            if let Ok(entries) = anodize_config::parse_revocation_list(&file.data) {
                return entries;
            }
        }
    }
    Vec::new()
}

/// Determine the next CRL number by scanning audit logs in disc sessions.
/// Returns last issued crl_number + 1, or 2 if no prior CRL issue found
/// (1 is reserved for the initial CRL from root CA generation).
pub fn next_crl_number_from_sessions(sessions: &[SessionEntry]) -> u64 {
    let mut last = 0u64;
    for session in sessions.iter() {
        if let Some(file) = session.files.iter().find(|f| f.name == "AUDIT.LOG") {
            for line in file.data.split(|&b| b == b'\n') {
                if line.is_empty() {
                    continue;
                }
                if let Ok(record) = serde_json::from_slice::<serde_json::Value>(line) {
                    if record.get("event").and_then(|v| v.as_str()) == Some("crl.issue") {
                        if let Some(n) = record
                            .get("op_data")
                            .and_then(|d| d.get("crl_number"))
                            .and_then(|v| v.as_u64())
                        {
                            if n > last {
                                last = n;
                            }
                        }
                    }
                }
            }
        }
    }
    last + 1
}

/// Verify the audit hash chain within each disc session independently.
pub fn verify_audit_chain(sessions: &[SessionEntry]) -> bool {
    for session in sessions.iter() {
        if let Some(file) = session.files.iter().find(|f| f.name == "AUDIT.LOG") {
            let mut prev_hash: Option<String> = None;
            for line in file.data.split(|&b| b == b'\n') {
                if line.is_empty() {
                    continue;
                }
                if let Ok(record) = serde_json::from_slice::<serde_json::Value>(line) {
                    if let Some(ph) = prev_hash.as_deref() {
                        if record.get("prev_hash").and_then(|v| v.as_str()) != Some(ph) {
                            return false;
                        }
                    }
                    prev_hash = record
                        .get("entry_hash")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_owned());
                }
            }
        }
    }
    true
}

/// Parse an RFC 3339 timestamp string to SystemTime.
pub fn parse_rfc3339_to_system_time(s: &str) -> Option<SystemTime> {
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;
    let odt = OffsetDateTime::parse(s, &Rfc3339).ok()?;
    let unix_secs = odt.unix_timestamp();
    let unix_nanos = odt.unix_timestamp_nanos();
    let nanos = (unix_nanos - (unix_secs as i128) * 1_000_000_000) as u32;
    if unix_secs >= 0 {
        Some(SystemTime::UNIX_EPOCH + std::time::Duration::new(unix_secs as u64, nanos))
    } else {
        None
    }
}

/// Walk all disc sessions, parse .CRT files, and build a list of cert summaries
/// for the revocation picker. Cross-references against the revocation list to
/// mark already-revoked entries.
pub fn gather_cert_list_from_sessions(
    sessions: &[SessionEntry],
    revocation_list: &[anodize_config::RevocationEntry],
) -> Vec<CertSummary> {
    let revoked_serials: std::collections::HashSet<u64> =
        revocation_list.iter().map(|r| r.serial).collect();

    let mut certs = Vec::new();
    for session in sessions {
        for file in &session.files {
            if !file.name.ends_with(".CRT") {
                continue;
            }
            let is_root = file.name == "ROOT.CRT";
            match Certificate::from_der(&file.data) {
                Ok(cert) => {
                    let subject = cert.tbs_certificate.subject.to_string();
                    let not_after = format!("{}", cert.tbs_certificate.validity.not_after);
                    let serial = serial_to_u64(&cert.tbs_certificate.serial_number);
                    certs.push(CertSummary {
                        serial,
                        subject,
                        not_after,
                        session_dir: session.dir_name.clone(),
                        is_root,
                        already_revoked: revoked_serials.contains(&serial),
                    });
                }
                Err(e) => {
                    tracing::warn!(
                        file = %file.name,
                        session = %session.dir_name,
                        error = %e,
                        "Failed to parse certificate for revocation picker"
                    );
                }
            }
        }
    }
    certs
}

/// Convert an X.509 SerialNumber to u64. Returns 0 if it doesn't fit.
fn serial_to_u64(sn: &x509_cert::serial_number::SerialNumber) -> u64 {
    let bytes = sn.as_bytes();
    if bytes.len() > 8 {
        return 0;
    }
    let mut val = 0u64;
    for &b in bytes {
        val = (val << 8) | (b as u64);
    }
    val
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media::iso9660::IsoFile;

    fn make_session(name: &str, files: Vec<IsoFile>) -> SessionEntry {
        SessionEntry {
            dir_name: name.to_string(),
            timestamp: SystemTime::now(),
            files,
        }
    }

    #[test]
    fn serial_to_u64_single_byte() {
        let sn = x509_cert::serial_number::SerialNumber::new(&[0x2A]).unwrap();
        assert_eq!(serial_to_u64(&sn), 42);
    }

    #[test]
    fn serial_to_u64_multi_byte() {
        let sn = x509_cert::serial_number::SerialNumber::new(&[0x01, 0x00]).unwrap();
        assert_eq!(serial_to_u64(&sn), 256);
    }

    #[test]
    fn serial_to_u64_max_8_bytes() {
        let sn = x509_cert::serial_number::SerialNumber::new(&[0x01, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(serial_to_u64(&sn), 1u64 << 56);
    }

    #[test]
    fn serial_to_u64_overflow_returns_zero() {
        // 9 bytes won't fit in u64
        let sn = x509_cert::serial_number::SerialNumber::new(&[1, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(serial_to_u64(&sn), 0);
    }

    #[test]
    fn gather_empty_sessions() {
        let result = gather_cert_list_from_sessions(&[], &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn gather_skips_non_crt_files() {
        let sessions = vec![make_session(
            "20260508T120000-record",
            vec![IsoFile {
                name: "AUDIT.LOG".into(),
                data: b"not a cert".to_vec(),
            }],
        )];
        let result = gather_cert_list_from_sessions(&sessions, &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn gather_skips_invalid_crt() {
        let sessions = vec![make_session(
            "20260508T120000-record",
            vec![IsoFile {
                name: "ROOT.CRT".into(),
                data: b"not valid DER".to_vec(),
            }],
        )];
        let result = gather_cert_list_from_sessions(&sessions, &[]);
        assert!(result.is_empty());
    }
}

// ── SoftHSM2 shuttle backend (dev-softhsm-usb feature) ───────────────────────

#[cfg(feature = "dev-softhsm-usb")]
pub fn configure_softhsm_from_shuttle(shuttle_mount: &std::path::Path) -> anyhow::Result<()> {
    let token_dir = shuttle_mount.join("softhsm2/tokens");
    if !token_dir.exists() {
        return Ok(());
    }
    let conf_path = std::path::PathBuf::from("/tmp/anodize-softhsm2.conf");
    let conf = format!(
        "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n",
        token_dir.display()
    );
    std::fs::write(&conf_path, conf)?;
    unsafe { std::env::set_var("SOFTHSM2_CONF", &conf_path) };
    Ok(())
}
