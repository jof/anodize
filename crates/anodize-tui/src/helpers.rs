use std::time::SystemTime;

use anodize_ca::CaError;
use anodize_config::CertProfile;
use der::Decode;
use sha2::{Digest, Sha256};
use x509_cert::certificate::Certificate;
use x509_cert::request::CertReq;

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

// ── Certificate preview (compiled CSR + profile) ─────────────────────────────

/// Build a human-readable preview of the certificate that will result from
/// signing the given CSR with the selected profile. This shows the *compiled*
/// certificate document — not the raw CSR inputs — so that custodians can
/// verify extensions, validity, issuer chain, and profile-injected fields
/// before authorizing the signature.
pub fn build_cert_preview(
    csr_der: &[u8],
    profile: &CertProfile,
    issuer_cn: &str,
    issuer_org: &str,
    issuer_country: &str,
    cdp_url: Option<&str>,
    root_cert_der: Option<&[u8]>,
) -> Vec<String> {
    let csr = match CertReq::from_der(csr_der) {
        Ok(c) => c,
        Err(e) => return vec![format!("  (CSR decode error: {e})")],
    };

    let subject = csr.info.subject.to_string();
    let issuer_dn = format!("CN={issuer_cn}, O={issuer_org}, C={issuer_country}");

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
    lines.push(format!(
        "  Serial      : (random — assigned at signing time)"
    ));
    lines.push(String::new());
    lines.push(format!("  Public Key  : {pub_key_alg}"));
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
            Some("http://crl.example.com/root.crl"),
            None,
        );
        let text = lines.join("\n");

        assert!(text.contains("Compiled Certificate Document"));
        assert!(text.contains("CN=Test Intermediate"));
        assert!(text.contains("sub-ca"));
        assert!(text.contains("1825 days"));
        assert!(text.contains("EC Public Key"));
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
        let lines = build_cert_preview(&csr_der, &prof, "Root", "Org", "US", None, None);
        let text = lines.join("\n");

        assert!(text.contains("no pathLenConstraint"));
        assert!(text.contains("no cdp_url in profile.toml"));
        assert!(text.contains("365 days"));
    }

    #[test]
    fn cert_preview_invalid_csr() {
        let prof = test_profile("x", 365, None);
        let lines = build_cert_preview(b"not a csr", &prof, "R", "O", "US", None, None);
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
            Some(b"not valid DER"),
        );
        let text = lines.join("\n");

        // Should fall back to config-provided issuer DN.
        assert!(text.contains("FallbackCN"));
        assert!(text.contains("FallbackOrg"));
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
