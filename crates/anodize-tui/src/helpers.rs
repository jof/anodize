use std::time::SystemTime;

use anodize_ca::CaError;
use sha2::{Digest, Sha256};

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

/// Returns true if the wall clock is within 5 minutes of the operator-confirmed time.
pub fn clock_drift_ok(confirmed: SystemTime) -> bool {
    let now = SystemTime::now();
    let drift = if now >= confirmed {
        now.duration_since(confirmed)
    } else {
        confirmed.duration_since(now)
    };
    drift.map(|d| d.as_secs() <= 300).unwrap_or(false)
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
