use std::path::Path;
use std::time::SystemTime;

use anodize_ca::CaError;
use anodize_config::CertProfile;
use der::Decode;
use sha2::{Digest, Sha256};
use x509_cert::certificate::Certificate;
use x509_cert::request::CertReq;

use crate::disc::CertSummary;
use crate::media::SessionEntry;

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
        .join(":")
}

/// SHA-256 fingerprint of the SubjectPublicKeyInfo from a DER-encoded CSR.
/// Returns `None` if the CSR cannot be parsed or encoded.
pub fn csr_spki_fingerprint(csr_der: &[u8]) -> Option<String> {
    use der::Encode;
    let csr = CertReq::from_der(csr_der).ok()?;
    let spki_bytes = csr.info.public_key.to_der().ok()?;
    Some(sha256_fingerprint(&spki_bytes))
}

// ── Disc session helpers ──────────────────────────────────────────────────────

/// Load the most recent STATE.JSON from disc sessions (latest session first).
pub fn load_session_state_from_sessions(
    sessions: &[SessionEntry],
) -> Option<anodize_config::state::SessionState> {
    for session in sessions.iter().rev() {
        // dev-burn: a SEED.TXT marker means "treat disc as blank from here".
        #[cfg(feature = "dev-burn")]
        if session.files.iter().any(|f| f.name == "SEED.TXT") {
            tracing::info!(session = %session.dir_name, "SEED.TXT boundary — ignoring older sessions");
            return None;
        }
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

/// Load the most recent AUDIT.LOG bytes from disc sessions (latest session first).
/// Returns `None` on a blank disc or when no session contains an AUDIT.LOG.
pub fn load_audit_log_from_sessions(sessions: &[SessionEntry]) -> Option<Vec<u8>> {
    for session in sessions.iter().rev() {
        #[cfg(feature = "dev-burn")]
        if session.files.iter().any(|f| f.name == "SEED.TXT") {
            return None;
        }
        if let Some(file) = session.files.iter().find(|f| f.name == "AUDIT.LOG") {
            if !file.data.is_empty() {
                return Some(file.data.clone());
            }
        }
    }
    None
}

/// True if any session on the disc carries the Track 1 landing-pad marker,
/// identifying it as a known anodize audit disc. The superset invariant carries
/// the marker forward into every session, so any session having it suffices.
pub fn disc_has_landing_pad(sessions: &[SessionEntry]) -> bool {
    sessions.iter().any(|s| {
        s.files.iter().any(|f| {
            f.name
                .eq_ignore_ascii_case(anodize_audit::LANDING_PAD_MARKER)
        })
    })
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
            if anodize_audit::verify_log_bytes(&file.data).is_err() {
                return false;
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

/// Collect all certificate serial numbers from disc sessions for collision
/// checking during serial number generation.
pub fn collect_serial_numbers_from_sessions(
    sessions: &[SessionEntry],
) -> Vec<x509_cert::serial_number::SerialNumber> {
    let mut serials = Vec::new();
    for session in sessions {
        for file in &session.files {
            if !file.name.ends_with(".CRT") {
                continue;
            }
            if let Ok(cert) = Certificate::from_der(&file.data) {
                serials.push(cert.tbs_certificate.serial_number);
            }
        }
    }
    serials
}

/// Walk all disc sessions, parse .CRT files, and build a list of cert summaries
/// for the revocation picker. Cross-references against the revocation list to
/// mark already-revoked entries.
pub fn gather_cert_list_from_sessions(
    sessions: &[SessionEntry],
    revocation_list: &[anodize_config::RevocationEntry],
) -> Vec<CertSummary> {
    let revoked_serials: std::collections::HashSet<&str> =
        revocation_list.iter().map(|r| r.serial.as_str()).collect();

    // Use a set to deduplicate by serial — the same cert appears in every
    // session due to the superset invariant.
    let mut seen = std::collections::HashSet::new();
    let mut certs = Vec::new();
    // Iterate sessions in reverse so the newest (and most complete) session
    // is scanned first; duplicates from older sessions are then skipped.
    for session in sessions.iter().rev() {
        for file in &session.files {
            if !file.name.ends_with(".CRT") {
                continue;
            }
            let is_root = file.name == "ROOT.CRT";
            match Certificate::from_der(&file.data) {
                Ok(cert) => {
                    let serial = serial_to_hex(&cert.tbs_certificate.serial_number);
                    if !seen.insert(serial.clone()) {
                        continue; // already seen this serial
                    }
                    let subject = cert.tbs_certificate.subject.to_string();
                    certs.push(CertSummary {
                        already_revoked: revoked_serials.contains(serial.as_str()),
                        serial,
                        subject,
                        is_root,
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

/// Convert an X.509 SerialNumber to an uppercase hex string.
pub fn serial_to_hex(sn: &x509_cert::serial_number::SerialNumber) -> String {
    sn.as_bytes().iter().map(|b| format!("{b:02X}")).collect()
}

/// Decode an uppercase hex serial string back to raw bytes.
/// Returns `None` on invalid hex.
pub fn hex_serial_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

// ── Certificate field extraction ──────────────────────────────────────────────

/// Extract the subject DN string and approximate validity period in days from
/// a DER-encoded X.509 certificate. Returns `None` if the DER cannot be parsed.
pub fn cert_subject_and_validity_days(der: &[u8]) -> Option<(String, u32)> {
    let cert = Certificate::from_der(der).ok()?;
    let subject = cert.tbs_certificate.subject.to_string();
    let not_before = cert.tbs_certificate.validity.not_before;
    let not_after = cert.tbs_certificate.validity.not_after;
    // Convert x509_cert::time::Time → SystemTime for duration arithmetic.
    let before: SystemTime = not_before.to_system_time();
    let after: SystemTime = not_after.to_system_time();
    let days = after
        .duration_since(before)
        .map(|d| (d.as_secs() / 86400) as u32)
        .unwrap_or(0);
    Some((subject, days))
}

// ── Certificate preview (compiled CSR + profile) ─────────────────────────────

/// Build a human-readable preview of the certificate that will result from
/// signing the given CSR with the selected profile. This shows the *compiled*
/// certificate document — not the raw CSR inputs — so that custodians can
/// verify extensions, validity, issuer chain, and profile-injected fields
/// before authorizing the signature.
#[allow(clippy::too_many_arguments)]
pub fn build_cert_preview(
    csr_der: &[u8],
    profile: &CertProfile,
    issuer_cn: &str,
    issuer_org: &str,
    issuer_country: &str,
    issuer_state: Option<&str>,
    cdp_url: Option<&str>,
    root_cert_der: Option<&[u8]>,
) -> Vec<String> {
    let csr = match CertReq::from_der(csr_der) {
        Ok(c) => c,
        Err(e) => return vec![format!("  (CSR decode error: {e})")],
    };

    let subject = csr.info.subject.to_string();
    let issuer_dn = match issuer_state {
        Some(st) => format!("CN={issuer_cn}, O={issuer_org}, ST={st}, C={issuer_country}"),
        None => format!("CN={issuer_cn}, O={issuer_org}, C={issuer_country}"),
    };

    // Issuer from actual root cert on disc (authoritative) or config fallback
    let issuer_display = if let Some(der) = root_cert_der {
        match Certificate::from_der(der) {
            Ok(cert) => cert.tbs_certificate.subject.to_string(),
            Err(_) => issuer_dn,
        }
    } else {
        issuer_dn
    };

    // Validity period
    let now = time::OffsetDateTime::now_utc();
    let not_before = format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        now.year(),
        now.month() as u8,
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );
    let not_after_dt = now + time::Duration::days(i64::from(profile.validity_days));
    let not_after = format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        not_after_dt.year(),
        not_after_dt.month() as u8,
        not_after_dt.day(),
        not_after_dt.hour(),
        not_after_dt.minute(),
        not_after_dt.second()
    );

    // Public key algorithm from CSR SPKI
    let pub_key_alg = describe_spki_algorithm(&csr.info.public_key.algorithm.oid);

    let mut lines = Vec::new();
    lines.push(String::new());
    lines.push("  ── Compiled Certificate Document ──".into());
    lines.push(String::new());
    lines.push(format!("  Subject     : {subject}"));
    lines.push(format!("  Issuer      : {issuer_display}"));
    lines.push(format!("  Profile     : {}", profile.name));
    lines.push(String::new());
    lines.push(format!(
        "  Not Before  : ~{not_before}  (set at signing time)"
    ));
    lines.push(format!(
        "  Not After   : ~{not_after}  ({} days)",
        profile.validity_days
    ));
    lines.push("  Serial      : (random — assigned at signing time)".to_string());
    lines.push(String::new());
    lines.push(format!("  Public Key  : {pub_key_alg}"));
    let spki_fp = csr_spki_fingerprint(csr_der).unwrap_or_else(|| "(error)".into());
    lines.push(format!("  SPKI SHA-256: {spki_fp}"));
    lines.push("  ↑ Verify: openssl req -in csr.der -inform DER -noout -pubkey \\".into());
    lines.push(
        "      | openssl pkey -pubin -outform DER | openssl dgst -sha256 -c | tr 'a-f' 'A-F'"
            .into(),
    );
    lines.push("  Signature   : ecdsa-with-SHA384 (P-384)".into());
    lines.push(String::new());
    lines.push("  ── Extensions ──".into());
    lines.push(String::new());

    // BasicConstraints
    let path_str = match profile.path_len {
        Some(n) => format!("pathLenConstraint={n}"),
        None => "no pathLenConstraint".into(),
    };
    lines.push(format!(
        "  BasicConstraints    : critical, CA:TRUE, {path_str}"
    ));

    // KeyUsage — SubCA profile sets keyCertSign + cRLSign
    lines.push("  KeyUsage            : critical, keyCertSign, cRLSign".into());

    // SubjectKeyIdentifier — derived from CSR public key
    lines.push("  SubjectKeyIdentifier: (SHA-1 of subject public key)".into());

    // AuthorityKeyIdentifier — derived from issuer (root) cert
    lines.push("  AuthorityKeyIdent.  : (from issuer certificate)".into());

    // CRLDistributionPoints
    if let Some(url) = cdp_url {
        lines.push(format!("  CRLDistributionPts  : {url}"));
    } else {
        lines.push("  CRLDistributionPts  : (none — no cdp_url in profile.toml)".into());
    }

    lines.push(String::new());
    lines
}

/// Map an SPKI algorithm OID to a human-readable description.
fn describe_spki_algorithm(oid: &der::oid::ObjectIdentifier) -> &'static str {
    match oid.to_string().as_str() {
        // id-ecPublicKey
        "1.2.840.10045.2.1" => "EC Public Key",
        // Named curves are in the parameters, but the OID alone tells us EC.
        // For RSA:
        "1.2.840.113549.1.1.1" => "RSA",
        _ => "Unknown",
    }
}

// ── CSR discovery (shuttle file picker) ───────────────────────────────────────

/// Scan the shuttle mount root for CSR files (*.der, *.pem, *.csr, *.req).
/// Each file is read, optionally PEM-decoded, and validated as a DER-encoded
/// PKCS#10 CSR. Returns `(filename, der_bytes)` pairs sorted by filename.
pub fn discover_csr_files(shuttle_mount: &Path) -> Vec<(String, Vec<u8>)> {
    let entries = match std::fs::read_dir(shuttle_mount) {
        Ok(rd) => rd,
        Err(_) => return Vec::new(),
    };

    let mut candidates: Vec<(String, Vec<u8>)> = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
        if !matches!(ext.as_str(), "der" | "pem" | "csr" | "req") {
            continue;
        }

        let raw = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };

        let der_bytes = if looks_like_pem(&raw) {
            match decode_pem_csr(&raw) {
                Some(d) => d,
                None => continue,
            }
        } else {
            raw
        };

        if CertReq::from_der(&der_bytes).is_ok() {
            candidates.push((name, der_bytes));
        }
    }

    candidates.sort_by(|a, b| a.0.cmp(&b.0));
    candidates
}

/// Extract the subject DN string from a DER-encoded CSR.
pub fn csr_subject(csr_der: &[u8]) -> Option<String> {
    CertReq::from_der(csr_der)
        .ok()
        .map(|csr| csr.info.subject.to_string())
}

/// True if the raw bytes start with a PEM header.
fn looks_like_pem(raw: &[u8]) -> bool {
    raw.starts_with(b"-----BEGIN")
}

/// Decode a PEM-encoded CSR to DER bytes. Accepts `CERTIFICATE REQUEST` and
/// `NEW CERTIFICATE REQUEST` labels.
fn decode_pem_csr(raw: &[u8]) -> Option<Vec<u8>> {
    use base64::Engine;

    let text = std::str::from_utf8(raw).ok()?;
    let mut body = String::new();
    let mut in_block = false;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN") && trimmed.contains("CERTIFICATE REQUEST") {
            in_block = true;
            continue;
        }
        if trimmed.starts_with("-----END") && trimmed.contains("CERTIFICATE REQUEST") {
            break;
        }
        if in_block {
            body.push_str(trimmed);
        }
    }

    if body.is_empty() {
        return None;
    }

    base64::engine::general_purpose::STANDARD.decode(&body).ok()
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
    fn serial_to_hex_single_byte() {
        let sn = x509_cert::serial_number::SerialNumber::new(&[0x2A]).unwrap();
        assert_eq!(serial_to_hex(&sn), "2A");
    }

    #[test]
    fn serial_to_hex_multi_byte() {
        let sn = x509_cert::serial_number::SerialNumber::new(&[0x01, 0x00]).unwrap();
        assert_eq!(serial_to_hex(&sn), "0100");
    }

    #[test]
    fn serial_to_hex_16_bytes() {
        let sn = x509_cert::serial_number::SerialNumber::new(&[
            0x01, 0xAB, 0x23, 0xCD, 0x45, 0xEF, 0x67, 0x89, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0xCD, 0xEF,
        ])
        .unwrap();
        assert_eq!(serial_to_hex(&sn), "01AB23CD45EF67890123456789ABCDEF");
    }

    #[test]
    fn hex_serial_round_trip() {
        let sn = x509_cert::serial_number::SerialNumber::new(&[0x01, 0xAB, 0xFF]).unwrap();
        let hex = serial_to_hex(&sn);
        assert_eq!(hex, "01ABFF");
        let bytes = hex_serial_to_bytes(&hex).unwrap();
        assert_eq!(bytes, &[0x01, 0xAB, 0xFF]);
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

    #[test]
    fn disc_has_landing_pad_detects_marker() {
        let blank: Vec<SessionEntry> = vec![];
        assert!(!disc_has_landing_pad(&blank));

        let legacy = vec![make_session(
            "20260508T120000-record",
            vec![IsoFile {
                name: "ROOT.CRT".into(),
                data: b"cert".to_vec(),
            }],
        )];
        assert!(!disc_has_landing_pad(&legacy));

        let anodize = vec![make_session(
            "20260508T120000-landing",
            vec![IsoFile {
                name: anodize_audit::LANDING_PAD_MARKER.to_string(),
                data: b"ANODIZE-AUDIT-DISC\n".to_vec(),
            }],
        )];
        assert!(disc_has_landing_pad(&anodize));
    }

    // ── SPKI fingerprint tests ────────────────────────────────────────────

    #[test]
    fn csr_spki_fingerprint_returns_stable_value() {
        let csr_der = build_test_csr_der("CN=Test,O=Acme,C=US");
        let fp = csr_spki_fingerprint(&csr_der).expect("should parse CSR");
        // Colon-separated hex, 64 hex chars + 31 colons = 95 chars
        assert_eq!(fp.len(), 95, "unexpected fingerprint length: {fp}");
        // Same CSR → same fingerprint
        assert_eq!(fp, csr_spki_fingerprint(&csr_der).unwrap());
    }

    #[test]
    fn csr_spki_fingerprint_invalid_der() {
        assert!(csr_spki_fingerprint(b"not a CSR").is_none());
    }

    // ── Certificate preview tests ────────────────────────────────────────────

    /// Build a minimal P-256/SHA-256 CSR DER for testing.
    fn build_test_csr_der(subject_str: &str) -> Vec<u8> {
        use der::Encode;
        use p256::ecdsa::{DerSignature, SigningKey};
        use p256::pkcs8::EncodePublicKey;
        use spki::AlgorithmIdentifierOwned;
        use x509_cert::request::{CertReq, CertReqInfo, Version};

        let sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let vk = sk.verifying_key();
        let spki_der = vk.to_public_key_der().expect("encode SPKI");
        let spki =
            spki::SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes()).expect("parse SPKI");

        let subject = x509_cert::name::Name::from_str(subject_str).unwrap();
        let info = CertReqInfo {
            version: Version::V1,
            subject,
            public_key: spki,
            attributes: Default::default(),
        };
        let info_der = info.to_der().expect("encode CertReqInfo");

        use p256::ecdsa::signature::Signer;
        let sig: DerSignature = sk.sign(&info_der);
        let sig_bytes = sig.to_bytes();

        let alg = AlgorithmIdentifierOwned {
            oid: der::oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
            parameters: None,
        };

        let csr = CertReq {
            info,
            algorithm: alg,
            signature: der::asn1::BitString::from_bytes(&sig_bytes).expect("bitstring"),
        };
        csr.to_der().expect("encode CertReq")
    }

    use std::str::FromStr;

    fn test_profile(name: &str, validity_days: u32, path_len: Option<u8>) -> CertProfile {
        CertProfile {
            name: name.into(),
            validity_days,
            path_len,
        }
    }

    #[test]
    fn cert_preview_shows_compiled_structure() {
        let csr_der = build_test_csr_der("CN=Test Intermediate,O=Acme,C=US");
        let prof = test_profile("sub-ca", 1825, Some(0));
        let lines = build_cert_preview(
            &csr_der,
            &prof,
            "Root CA",
            "Acme",
            "US",
            None,
            Some("http://crl.example.com/root.crl"),
            None,
        );
        let text = lines.join("\n");

        assert!(text.contains("Compiled Certificate Document"));
        assert!(text.contains("CN=Test Intermediate"));
        assert!(text.contains("sub-ca"));
        assert!(text.contains("1825 days"));
        assert!(text.contains("EC Public Key"));
        assert!(text.contains("SPKI SHA-256:"));
        assert!(text.contains("ecdsa-with-SHA384"));
        assert!(text.contains("CA:TRUE"));
        assert!(text.contains("pathLenConstraint=0"));
        assert!(text.contains("keyCertSign, cRLSign"));
        assert!(text.contains("SubjectKeyIdentifier"));
        assert!(text.contains("AuthorityKeyIdent"));
        assert!(text.contains("http://crl.example.com/root.crl"));
    }

    #[test]
    fn cert_preview_no_cdp() {
        let csr_der = build_test_csr_der("CN=Test Sub,O=Org,C=US");
        let prof = test_profile("no-cdp", 365, None);
        let lines = build_cert_preview(&csr_der, &prof, "Root", "Org", "US", None, None, None);
        let text = lines.join("\n");

        assert!(text.contains("no pathLenConstraint"));
        assert!(text.contains("no cdp_url in profile.toml"));
        assert!(text.contains("365 days"));
    }

    #[test]
    fn cert_preview_invalid_csr() {
        let prof = test_profile("x", 365, None);
        let lines = build_cert_preview(b"not a csr", &prof, "R", "O", "US", None, None, None);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("CSR decode error"));
    }

    /// Build a minimal self-signed root certificate DER for testing.
    /// The signature is not valid — the preview only reads the subject DN.
    fn build_test_root_cert_der(subject_str: &str) -> Vec<u8> {
        use der::Encode;
        use p256::ecdsa::SigningKey;
        use p256::pkcs8::EncodePublicKey;
        use x509_cert::certificate::{Certificate, TbsCertificate, Version};
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::time::Validity;

        let sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let vk = sk.verifying_key();
        let spki_der = vk.to_public_key_der().expect("spki");
        let spki =
            spki::SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes()).expect("parse spki");

        let name = x509_cert::name::Name::from_str(subject_str).unwrap();
        let validity = Validity::from_now(std::time::Duration::from_secs(86400)).expect("validity");
        let serial = SerialNumber::new(&[0x01]).unwrap();

        let alg = spki::AlgorithmIdentifierOwned {
            oid: der::oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
            parameters: None,
        };

        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: serial,
            signature: alg.clone(),
            issuer: name.clone(),
            validity,
            subject: name,
            subject_public_key_info: spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: None,
        };

        let cert = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: alg,
            signature: der::asn1::BitString::from_bytes(&[0u8; 64]).expect("bitstring"),
        };
        cert.to_der().expect("encode cert")
    }

    #[test]
    fn cert_preview_with_root_cert_issuer() {
        let root_der = build_test_root_cert_der("CN=Disc Root CA,O=DiscOrg,C=DE");

        let csr_der = build_test_csr_der("CN=Sub CA,O=DiscOrg,C=DE");
        let prof = test_profile("sub-ca", 1825, Some(0));
        let lines = build_cert_preview(
            &csr_der,
            &prof,
            "Config Root",
            "ConfigOrg",
            "US",
            None,
            None,
            Some(&root_der),
        );
        let text = lines.join("\n");

        // Should use the issuer from the actual root cert, not the config fallback.
        assert!(text.contains("Disc Root CA"));
        assert!(text.contains("DiscOrg"));
        // Config values should NOT appear as issuer.
        assert!(!text.contains("Config Root"));
        assert!(!text.contains("ConfigOrg"));
    }

    #[test]
    fn cert_preview_invalid_root_cert_falls_back() {
        let csr_der = build_test_csr_der("CN=Sub,O=Org,C=US");
        let prof = test_profile("sub-ca", 365, None);
        let lines = build_cert_preview(
            &csr_der,
            &prof,
            "FallbackCN",
            "FallbackOrg",
            "US",
            None,
            None,
            Some(b"not valid DER"),
        );
        let text = lines.join("\n");

        // Should fall back to config-provided issuer DN.
        assert!(text.contains("FallbackCN"));
        assert!(text.contains("FallbackOrg"));
    }

    // ── cert_subject_and_validity_days tests ─────────────────────────────────

    #[test]
    fn cert_subject_and_validity_returns_correct_fields() {
        let der = build_test_root_cert_der("CN=Test Root,O=Acme,C=US");
        let (subject, days) = cert_subject_and_validity_days(&der).expect("should parse");
        assert!(subject.contains("Test Root"), "subject={subject}");
        assert!(subject.contains("Acme"), "subject={subject}");
        // build_test_root_cert_der uses 86400s = 1 day
        assert_eq!(days, 1);
    }

    #[test]
    fn cert_subject_and_validity_multi_year() {
        // Build a cert with ~5 years validity (1825 days).
        use der::Encode;
        use p256::ecdsa::SigningKey;
        use p256::pkcs8::EncodePublicKey;
        use x509_cert::certificate::{Certificate, TbsCertificate, Version};
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::time::Validity;

        let sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let vk = sk.verifying_key();
        let spki_der = vk.to_public_key_der().expect("spki");
        let spki =
            spki::SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes()).expect("parse spki");
        let name = x509_cert::name::Name::from_str("CN=Sub CA,O=Org,C=DE").unwrap();
        let validity =
            Validity::from_now(std::time::Duration::from_secs(1825 * 86400)).expect("validity");
        let serial = SerialNumber::new(&[0x02]).unwrap();
        let alg = spki::AlgorithmIdentifierOwned {
            oid: der::oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
            parameters: None,
        };
        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: serial,
            signature: alg.clone(),
            issuer: name.clone(),
            validity,
            subject: name,
            subject_public_key_info: spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: None,
        };
        let cert = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: alg,
            signature: der::asn1::BitString::from_bytes(&[0u8; 64]).expect("bitstring"),
        };
        let der = cert.to_der().expect("encode cert");

        let (subject, days) = cert_subject_and_validity_days(&der).expect("should parse");
        assert!(subject.contains("Sub CA"), "subject={subject}");
        // Allow ±1 day for rounding
        assert!((1824..=1825).contains(&days), "expected ~1825, got {days}");
    }

    #[test]
    fn cert_subject_and_validity_invalid_der() {
        assert!(cert_subject_and_validity_days(b"not valid DER").is_none());
    }

    #[test]
    fn describe_spki_algorithm_known_oids() {
        let ec_oid = der::oid::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
        assert_eq!(describe_spki_algorithm(&ec_oid), "EC Public Key");

        let rsa_oid = der::oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
        assert_eq!(describe_spki_algorithm(&rsa_oid), "RSA");

        let unknown_oid = der::oid::ObjectIdentifier::new_unwrap("1.2.3.4.5");
        assert_eq!(describe_spki_algorithm(&unknown_oid), "Unknown");
    }

    // ── PEM decode tests ────────────────────────────────────────────────

    #[test]
    fn decode_pem_csr_valid() {
        use base64::Engine;
        let csr_der = build_test_csr_der("CN=PEM Test,O=Acme,C=US");
        let b64 = base64::engine::general_purpose::STANDARD.encode(&csr_der);
        let pem = format!(
            "-----BEGIN CERTIFICATE REQUEST-----\n{b64}\n-----END CERTIFICATE REQUEST-----\n"
        );
        let decoded = decode_pem_csr(pem.as_bytes()).expect("should decode");
        assert_eq!(decoded, csr_der);
    }

    #[test]
    fn decode_pem_csr_new_label() {
        use base64::Engine;
        let csr_der = build_test_csr_der("CN=New Label,O=Org,C=US");
        let b64 = base64::engine::general_purpose::STANDARD.encode(&csr_der);
        let pem = format!(
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n{b64}\n-----END NEW CERTIFICATE REQUEST-----\n"
        );
        let decoded = decode_pem_csr(pem.as_bytes()).expect("should decode");
        assert_eq!(decoded, csr_der);
    }

    #[test]
    fn decode_pem_csr_invalid_base64() {
        let pem = b"-----BEGIN CERTIFICATE REQUEST-----\n!!!not-base64!!!\n-----END CERTIFICATE REQUEST-----\n";
        assert!(decode_pem_csr(pem).is_none());
    }

    #[test]
    fn decode_pem_csr_wrong_label() {
        let pem = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        assert!(decode_pem_csr(pem).is_none());
    }

    #[test]
    fn looks_like_pem_detects_header() {
        assert!(looks_like_pem(b"-----BEGIN CERTIFICATE REQUEST-----\n"));
        assert!(!looks_like_pem(b"\x30\x82"));
        assert!(!looks_like_pem(b""));
    }

    // ── CSR discovery tests ─────────────────────────────────────────────

    fn make_temp_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("anodize-test-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn discover_csr_files_finds_der_and_pem() {
        use base64::Engine;
        let dir = make_temp_dir("discover-csrs");
        let csr_der = build_test_csr_der("CN=Disc Test,O=Org,C=US");

        // Write a DER file
        std::fs::write(dir.join("my.csr"), &csr_der).unwrap();

        // Write a PEM file
        let b64 = base64::engine::general_purpose::STANDARD.encode(&csr_der);
        let pem = format!(
            "-----BEGIN CERTIFICATE REQUEST-----\n{b64}\n-----END CERTIFICATE REQUEST-----\n"
        );
        std::fs::write(dir.join("other.pem"), &pem).unwrap();

        // Write a .req file (DER-encoded)
        std::fs::write(dir.join("request.req"), &csr_der).unwrap();

        // Write a non-CSR file that should be skipped
        std::fs::write(dir.join("profile.toml"), b"not a csr").unwrap();

        // Write a .der file that isn't actually a valid CSR
        std::fs::write(dir.join("bad.der"), b"not valid").unwrap();

        let found = discover_csr_files(&dir);
        let names: Vec<&str> = found.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, &["my.csr", "other.pem", "request.req"]);
        // All should decode to the same DER
        assert_eq!(found[0].1, csr_der);
        assert_eq!(found[1].1, csr_der);
        assert_eq!(found[2].1, csr_der);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn discover_csr_files_empty_dir() {
        let dir = make_temp_dir("discover-empty");
        assert!(discover_csr_files(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn discover_csr_files_nonexistent_dir() {
        assert!(discover_csr_files(Path::new("/nonexistent/path")).is_empty());
    }

    #[test]
    fn csr_subject_extracts_dn() {
        let csr_der = build_test_csr_der("CN=Hello,O=World,C=US");
        let subject = csr_subject(&csr_der).expect("should parse");
        assert!(subject.contains("Hello"), "subject={subject}");
    }

    #[test]
    fn csr_subject_invalid_der() {
        assert!(csr_subject(b"garbage").is_none());
    }
}
