use std::{env, fs, path::PathBuf, process::Command, time::SystemTime};

use anodize_ca::{build_root_cert, issue_crl, sign_intermediate_csr, CaError, P384HsmSigner};
use anodize_hsm::{Hsm, HsmActor, KeySpec, Pkcs11Hsm};
use der::{Decode, Encode};
use x509_cert::serial_number::SerialNumber;

fn softhsm_env() -> Option<PathBuf> {
    let module = env::var("SOFTHSM2_MODULE").ok()?;
    Some(PathBuf::from(module))
}

fn init_test_token(label: &str) -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();

    let token_dir = workspace_root.join("target/test-softhsm/tokens");
    let conf_path = workspace_root.join("target/test-softhsm/softhsm2.conf");

    fs::create_dir_all(&token_dir).unwrap();

    let template =
        fs::read_to_string(workspace_root.join("tests/softhsm-fixtures/softhsm2.conf.template"))
            .unwrap();
    let conf_content = template.replace("$TOKEN_DIR", token_dir.to_str().unwrap());
    fs::write(&conf_path, conf_content).unwrap();

    let _ = fs::remove_dir_all(&token_dir);
    fs::create_dir_all(&token_dir).unwrap();

    let status = Command::new("softhsm2-util")
        .args([
            "--init-token",
            "--free",
            "--label",
            label,
            "--pin",
            "1234",
            "--so-pin",
            "12345678",
        ])
        .env("SOFTHSM2_CONF", &conf_path)
        .status()
        .expect("softhsm2-util not found — install softhsm2");
    assert!(status.success(), "softhsm2-util --init-token failed");

    // Tell libsofthsm2.so in THIS process where the token directory lives.
    env::set_var("SOFTHSM2_CONF", &conf_path);

    conf_path
}

#[test]
fn build_root_cert_roundtrip() {
    let module = match softhsm_env() {
        Some(m) => m,
        None => {
            eprintln!("SKIP: SOFTHSM2_MODULE not set");
            return;
        }
    };

    init_test_token("ca-root-test");
    let mut hsm = Pkcs11Hsm::new(&module, "ca-root-test").expect("open session");
    let pin = secrecy::SecretString::new("1234".to_string());
    hsm.login(&pin).expect("login");

    let key = hsm
        .generate_keypair("root-key", KeySpec::EcdsaP384)
        .expect("generate root keypair");

    let signer = P384HsmSigner::new(hsm, key).expect("create signer");
    let cert = match build_root_cert(&signer, "Test Root CA", "Test Org", "US", 7305) {
        Ok(c) => c,
        Err(e) => panic!("build root cert: {e}"),
    };

    let der = cert.to_der().expect("encode cert DER");
    let decoded = x509_cert::certificate::Certificate::from_der(&der).expect("decode cert DER");

    // BasicConstraints CA:TRUE must be present
    let bc_oid = der::asn1::ObjectIdentifier::new_unwrap("2.5.29.19");
    let exts = decoded.tbs_certificate.extensions.as_deref().unwrap_or(&[]);
    let bc_ext = exts
        .iter()
        .find(|e| e.extn_id == bc_oid)
        .expect("BasicConstraints missing");
    assert!(bc_ext.critical, "BasicConstraints should be critical");

    println!("build_root_cert_roundtrip: OK ({} bytes DER)", der.len());
}

#[test]
fn sign_csr_happy_path() {
    let module = match softhsm_env() {
        Some(m) => m,
        None => {
            eprintln!("SKIP: SOFTHSM2_MODULE not set");
            return;
        }
    };

    // One token, one session — generate both keypairs before splitting into two signers.
    // This avoids the SoftHSM2 stale-slot problem that occurs when a second init_test_token
    // call rm-rf's and recreates the token directory while the first session is still open.
    init_test_token("ca-sign-test");
    let hsm = Pkcs11Hsm::new(&module, "ca-sign-test").expect("open session");
    let mut actor = HsmActor::spawn(Box::new(hsm));
    let pin = secrecy::SecretString::new("1234".to_string());
    actor.login(&pin).expect("login");

    let root_key = actor
        .generate_keypair("root-key", KeySpec::EcdsaP384)
        .expect("generate root keypair");
    let int_key = actor
        .generate_keypair("int-key", KeySpec::EcdsaP384)
        .expect("generate int keypair");

    // Clone gives a second handle to the same session; both signers share it safely.
    let int_actor = actor.clone();
    let root_signer = P384HsmSigner::new(actor, root_key).expect("root signer");
    let int_signer = P384HsmSigner::new(int_actor, int_key).expect("int signer");

    let root_cert = match build_root_cert(&root_signer, "Test Root CA", "Test Org", "US", 7305) {
        Ok(c) => c,
        Err(e) => panic!("root cert: {e}"),
    };

    use x509_cert::builder::{Builder, RequestBuilder};
    let subject =
        x509_cert::name::Name::from_str("CN=Test Intermediate CA,O=Test Org,C=US").unwrap();
    let req_builder = RequestBuilder::new(subject, &int_signer).expect("request builder");
    let csr = req_builder
        .build::<p384::ecdsa::DerSignature>()
        .expect("build CSR");
    let csr_der = csr.to_der().expect("encode CSR DER");

    let int_cert = sign_intermediate_csr(
        &root_signer,
        &root_cert,
        &csr_der,
        Some(0),
        1825,
        Some("http://crl.example.com/root.crl"),
        &[],
    )
    .expect("sign intermediate CSR");

    let int_der = int_cert.to_der().expect("encode intermediate cert DER");
    let decoded =
        x509_cert::certificate::Certificate::from_der(&int_der).expect("decode intermediate DER");

    assert_eq!(
        decoded.tbs_certificate.issuer,
        root_cert.tbs_certificate.subject
    );

    println!(
        "sign_csr_happy_path: OK ({} bytes intermediate cert DER)",
        int_der.len()
    );
}

#[test]
fn csr_with_extra_extension_rejected() {
    let module = match softhsm_env() {
        Some(m) => m,
        None => {
            eprintln!("SKIP: SOFTHSM2_MODULE not set");
            return;
        }
    };

    init_test_token("ca-reject-test");
    let hsm = Pkcs11Hsm::new(&module, "ca-reject-test").expect("open session");
    let mut actor = HsmActor::spawn(Box::new(hsm));
    let pin = secrecy::SecretString::new("1234".to_string());
    actor.login(&pin).expect("login");

    let root_key = actor
        .generate_keypair("root-key", KeySpec::EcdsaP384)
        .expect("generate root keypair");
    let int_key = actor
        .generate_keypair("int-key", KeySpec::EcdsaP384)
        .expect("generate int keypair");

    let int_actor = actor.clone();
    let root_signer = P384HsmSigner::new(actor, root_key).expect("root signer");
    let int_signer = P384HsmSigner::new(int_actor, int_key).expect("int signer");

    let root_cert = match build_root_cert(&root_signer, "Test Root CA", "Test Org", "US", 7305) {
        Ok(c) => c,
        Err(e) => panic!("root cert: {e}"),
    };

    use x509_cert::builder::{Builder, RequestBuilder};
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::SubjectAltName;

    let subject = x509_cert::name::Name::from_str("CN=Rogue CA,O=Test Org,C=US").unwrap();
    let mut req_builder = RequestBuilder::new(subject, &int_signer).expect("request builder");
    let san = SubjectAltName(vec![GeneralName::DnsName(
        der::asn1::Ia5String::new("evil.example.com").unwrap(),
    )]);
    req_builder.add_extension(&san).expect("add SAN");
    let csr = req_builder
        .build::<p384::ecdsa::DerSignature>()
        .expect("build CSR");
    let csr_der = csr.to_der().expect("encode CSR DER");

    let result =
        sign_intermediate_csr(&root_signer, &root_cert, &csr_der, Some(0), 1825, None, &[]);
    assert!(
        matches!(result, Err(CaError::CsrExtensionRejected(_))),
        "expected CsrExtensionRejected, got: {:?}",
        result
    );

    println!("csr_with_extra_extension_rejected: OK");
}

#[test]
fn issue_crl_encodes_revoked_serials() {
    let module = match softhsm_env() {
        Some(m) => m,
        None => {
            eprintln!("SKIP: SOFTHSM2_MODULE not set");
            return;
        }
    };

    init_test_token("ca-crl-test");
    let mut hsm = Pkcs11Hsm::new(&module, "ca-crl-test").expect("open session");
    let pin = secrecy::SecretString::new("1234".to_string());
    hsm.login(&pin).expect("login");

    let root_key = hsm
        .generate_keypair("root-key", KeySpec::EcdsaP384)
        .expect("generate root keypair");
    let root_signer = P384HsmSigner::new(hsm, root_key).expect("root signer");
    let root_cert = match build_root_cert(&root_signer, "Test Root CA", "Test Org", "US", 7305) {
        Ok(c) => c,
        Err(e) => panic!("root cert: {e}"),
    };

    let now = SystemTime::now();
    let next_update = now + std::time::Duration::from_secs(30 * 24 * 3600);
    let revoked = vec![
        (SerialNumber::from(42u64), now, Some(anodize_ca::CrlReason::KeyCompromise)),
        (SerialNumber::from(99u64), now, None),
    ];

    let crl_der = issue_crl(&root_signer, &root_cert, &revoked, next_update, 1).expect("issue CRL");

    let cert_list = x509_cert::crl::CertificateList::from_der(&crl_der).expect("decode CRL");
    let revoked_certs = cert_list
        .tbs_cert_list
        .revoked_certificates
        .expect("no revoked certs in CRL");

    assert_eq!(revoked_certs.len(), 2);

    let serials: Vec<u64> = revoked_certs
        .iter()
        .filter_map(|rc| {
            let bytes = rc.serial_number.as_bytes();
            // Strip leading zero bytes, then interpret as u64
            let trimmed: Vec<u8> = bytes.iter().copied().skip_while(|&b| b == 0).collect();
            if trimmed.len() <= 8 {
                let mut arr = [0u8; 8];
                arr[8 - trimmed.len()..].copy_from_slice(&trimmed);
                Some(u64::from_be_bytes(arr))
            } else {
                None
            }
        })
        .collect();

    assert!(serials.contains(&42), "serial 42 not in CRL");
    assert!(serials.contains(&99), "serial 99 not in CRL");

    println!(
        "issue_crl_encodes_revoked_serials: OK ({} bytes CRL DER)",
        crl_der.len()
    );
}

#[test]
fn issue_crl_extensions_present() {
    let module = match softhsm_env() {
        Some(m) => m,
        None => {
            eprintln!("SKIP: SOFTHSM2_MODULE not set");
            return;
        }
    };

    init_test_token("ca-crl-ext-test");
    let mut hsm = Pkcs11Hsm::new(&module, "ca-crl-ext-test").expect("open session");
    let pin = secrecy::SecretString::new("1234".to_string());
    hsm.login(&pin).expect("login");

    let root_key = hsm
        .generate_keypair("root-key", KeySpec::EcdsaP384)
        .expect("generate root keypair");
    let root_signer = P384HsmSigner::new(hsm, root_key).expect("root signer");
    let root_cert = match build_root_cert(&root_signer, "Test Root CA", "Test Org", "US", 7305) {
        Ok(c) => c,
        Err(e) => panic!("root cert: {e}"),
    };

    let next_update = SystemTime::now() + std::time::Duration::from_secs(30 * 24 * 3600);
    let crl_der = issue_crl(&root_signer, &root_cert, &[], next_update, 1).expect("issue CRL");

    let cert_list = x509_cert::crl::CertificateList::from_der(&crl_der).expect("decode CRL");
    let exts = cert_list
        .tbs_cert_list
        .crl_extensions
        .as_deref()
        .expect("no CRL extensions");

    // CRL Number (OID 2.5.29.20) must be present and non-critical
    let crl_num_oid = der::asn1::ObjectIdentifier::new_unwrap("2.5.29.20");
    let crl_num_ext = exts
        .iter()
        .find(|e| e.extn_id == crl_num_oid)
        .expect("CRL Number extension missing");
    assert!(!crl_num_ext.critical, "CRL Number must be non-critical");

    // Authority Key Identifier (OID 2.5.29.35) must be present and non-critical
    let akid_oid = der::asn1::ObjectIdentifier::new_unwrap("2.5.29.35");
    let akid_ext = exts
        .iter()
        .find(|e| e.extn_id == akid_oid)
        .expect("Authority Key Identifier extension missing");
    assert!(!akid_ext.critical, "AKID must be non-critical");

    println!(
        "issue_crl_extensions_present: OK (CRL Number + AKID verified, {} bytes)",
        crl_der.len()
    );
}

/// A P-256/SHA-256 CSR should be accepted by sign_intermediate_csr.
#[test]
fn sign_csr_p256_sha256_accepted() {
    let module = match softhsm_env() {
        Some(m) => m,
        None => {
            eprintln!("SKIP: SOFTHSM2_MODULE not set");
            return;
        }
    };

    init_test_token("ca-p256-test");
    let hsm = Pkcs11Hsm::new(&module, "ca-p256-test").expect("open session");
    let mut actor = HsmActor::spawn(Box::new(hsm));
    let pin = secrecy::SecretString::new("1234".to_string());
    actor.login(&pin).expect("login");

    let root_key = actor
        .generate_keypair("root-key", KeySpec::EcdsaP384)
        .expect("generate root keypair");
    let root_signer = P384HsmSigner::new(actor, root_key).expect("root signer");
    let root_cert = match build_root_cert(&root_signer, "Test Root CA", "Test Org", "US", 7305) {
        Ok(c) => c,
        Err(e) => panic!("root cert: {e}"),
    };

    // Build a P-256/SHA-256 CSR using a software key.
    // x509-cert's RequestBuilder requires DynSignatureAlgorithmIdentifier which
    // p256::ecdsa::SigningKey doesn't implement, so we build the CSR at DER level.
    let csr_der = build_p256_csr_der("CN=P256 Intermediate,O=Test Org,C=US");

    let int_cert =
        sign_intermediate_csr(&root_signer, &root_cert, &csr_der, Some(0), 1825, None, &[])
            .expect("sign P-256 CSR");

    let int_der = int_cert.to_der().expect("encode intermediate cert DER");
    let decoded =
        x509_cert::certificate::Certificate::from_der(&int_der).expect("decode intermediate DER");
    assert_eq!(
        decoded.tbs_certificate.issuer,
        root_cert.tbs_certificate.subject
    );

    println!(
        "sign_csr_p256_sha256_accepted: OK ({} bytes intermediate cert DER)",
        int_der.len()
    );
}

/// Build a self-signed P-256/SHA-256 CSR DER for testing.
fn build_p256_csr_der(subject_str: &str) -> Vec<u8> {
    use der::{Decode, Encode};
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{DerSignature, SigningKey};
    use p256::pkcs8::EncodePublicKey;
    use spki::AlgorithmIdentifierOwned;
    use x509_cert::request::CertReqInfo;

    let sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let vk = sk.verifying_key();
    let spki_der = vk.to_public_key_der().expect("encode SPKI");
    let spki = spki::SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes()).expect("parse SPKI");

    let subject = x509_cert::name::Name::from_str(subject_str).unwrap();
    let info = CertReqInfo {
        version: x509_cert::request::Version::V1,
        subject,
        public_key: spki,
        attributes: Default::default(),
    };
    let info_der = info.to_der().expect("encode CertReqInfo");
    let sig: DerSignature = sk.sign(&info_der);
    let sig_bytes = sig.to_bytes();

    let ecdsa_sha256_oid = der::oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
    let alg = AlgorithmIdentifierOwned {
        oid: ecdsa_sha256_oid,
        parameters: None,
    };

    let csr = x509_cert::request::CertReq {
        info,
        algorithm: alg,
        signature: der::asn1::BitString::from_bytes(&sig_bytes).expect("bitstring from sig"),
    };
    csr.to_der().expect("encode CertReq")
}

/// A P-384 key signed with SHA-256 (the combination OpenSSL produces by default
/// for `ecparam -name secp384r1`) should be accepted.
#[test]
fn sign_csr_p384_sha256_accepted() {
    let module = match softhsm_env() {
        Some(m) => m,
        None => {
            eprintln!("SKIP: SOFTHSM2_MODULE not set");
            return;
        }
    };

    init_test_token("ca-p384sha256-test");
    let hsm = Pkcs11Hsm::new(&module, "ca-p384sha256-test").expect("open session");
    let mut actor = HsmActor::spawn(Box::new(hsm));
    let pin = secrecy::SecretString::new("1234".to_string());
    actor.login(&pin).expect("login");

    let root_key = actor
        .generate_keypair("root-key", KeySpec::EcdsaP384)
        .expect("generate root keypair");
    let root_signer = P384HsmSigner::new(actor, root_key).expect("root signer");
    let root_cert = match build_root_cert(&root_signer, "Test Root CA", "Test Org", "US", 7305) {
        Ok(c) => c,
        Err(e) => panic!("root cert: {e}"),
    };

    let csr_der = build_p384_sha256_csr_der("CN=P384-SHA256 Intermediate,O=Test Org,C=US");

    let int_cert =
        sign_intermediate_csr(&root_signer, &root_cert, &csr_der, Some(0), 1825, None, &[])
            .expect("sign P-384/SHA-256 CSR");

    let int_der = int_cert.to_der().expect("encode intermediate cert DER");
    let decoded =
        x509_cert::certificate::Certificate::from_der(&int_der).expect("decode intermediate DER");
    assert_eq!(
        decoded.tbs_certificate.issuer,
        root_cert.tbs_certificate.subject
    );

    println!(
        "sign_csr_p384_sha256_accepted: OK ({} bytes intermediate cert DER)",
        int_der.len()
    );
}

/// Build a P-384 key / ecdsa-with-SHA256 CSR DER for testing.
fn build_p384_sha256_csr_der(subject_str: &str) -> Vec<u8> {
    use der::{Decode, Encode};
    use p384::ecdsa::signature::hazmat::PrehashSigner;
    use p384::ecdsa::SigningKey;
    use p384::pkcs8::EncodePublicKey;
    use sha2::Digest;
    use spki::AlgorithmIdentifierOwned;
    use x509_cert::request::CertReqInfo;

    let sk = SigningKey::random(&mut p384::elliptic_curve::rand_core::OsRng);
    let vk = sk.verifying_key();
    let spki_der = vk.to_public_key_der().expect("encode SPKI");
    let spki = spki::SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes()).expect("parse SPKI");

    let subject = x509_cert::name::Name::from_str(subject_str).unwrap();
    let info = CertReqInfo {
        version: x509_cert::request::Version::V1,
        subject,
        public_key: spki,
        attributes: Default::default(),
    };
    let info_der = info.to_der().expect("encode CertReqInfo");

    let digest = sha2::Sha256::digest(&info_der);
    let sig: p384::ecdsa::Signature = sk.sign_prehash(&digest).expect("prehash sign");
    let sig_bytes = sig.to_der();

    let ecdsa_sha256_oid = der::oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
    let alg = AlgorithmIdentifierOwned {
        oid: ecdsa_sha256_oid,
        parameters: None,
    };

    let csr = x509_cert::request::CertReq {
        info,
        algorithm: alg,
        signature: der::asn1::BitString::from_bytes(sig_bytes.as_bytes()).expect("bitstring"),
    };
    csr.to_der().expect("encode CertReq")
}

/// A P-256 key signed with SHA-384 should be accepted.
#[test]
fn sign_csr_p256_sha384_accepted() {
    let module = match softhsm_env() {
        Some(m) => m,
        None => {
            eprintln!("SKIP: SOFTHSM2_MODULE not set");
            return;
        }
    };

    init_test_token("ca-p256sha384-test");
    let hsm = Pkcs11Hsm::new(&module, "ca-p256sha384-test").expect("open session");
    let mut actor = HsmActor::spawn(Box::new(hsm));
    let pin = secrecy::SecretString::new("1234".to_string());
    actor.login(&pin).expect("login");

    let root_key = actor
        .generate_keypair("root-key", KeySpec::EcdsaP384)
        .expect("generate root keypair");
    let root_signer = P384HsmSigner::new(actor, root_key).expect("root signer");
    let root_cert = match build_root_cert(&root_signer, "Test Root CA", "Test Org", "US", 7305) {
        Ok(c) => c,
        Err(e) => panic!("root cert: {e}"),
    };

    let csr_der = build_p256_sha384_csr_der("CN=P256-SHA384 Intermediate,O=Test Org,C=US");

    let int_cert =
        sign_intermediate_csr(&root_signer, &root_cert, &csr_der, Some(0), 1825, None, &[])
            .expect("sign P-256/SHA-384 CSR");

    let int_der = int_cert.to_der().expect("encode intermediate cert DER");
    let decoded =
        x509_cert::certificate::Certificate::from_der(&int_der).expect("decode intermediate DER");
    assert_eq!(
        decoded.tbs_certificate.issuer,
        root_cert.tbs_certificate.subject
    );

    println!(
        "sign_csr_p256_sha384_accepted: OK ({} bytes)",
        int_der.len()
    );
}

/// A P-384 key signed with SHA-512 should be accepted.
#[test]
fn sign_csr_p384_sha512_accepted() {
    let module = match softhsm_env() {
        Some(m) => m,
        None => {
            eprintln!("SKIP: SOFTHSM2_MODULE not set");
            return;
        }
    };

    init_test_token("ca-p384sha512-test");
    let hsm = Pkcs11Hsm::new(&module, "ca-p384sha512-test").expect("open session");
    let mut actor = HsmActor::spawn(Box::new(hsm));
    let pin = secrecy::SecretString::new("1234".to_string());
    actor.login(&pin).expect("login");

    let root_key = actor
        .generate_keypair("root-key", KeySpec::EcdsaP384)
        .expect("generate root keypair");
    let root_signer = P384HsmSigner::new(actor, root_key).expect("root signer");
    let root_cert = match build_root_cert(&root_signer, "Test Root CA", "Test Org", "US", 7305) {
        Ok(c) => c,
        Err(e) => panic!("root cert: {e}"),
    };

    let csr_der = build_p384_sha512_csr_der("CN=P384-SHA512 Intermediate,O=Test Org,C=US");

    let int_cert =
        sign_intermediate_csr(&root_signer, &root_cert, &csr_der, Some(0), 1825, None, &[])
            .expect("sign P-384/SHA-512 CSR");

    let int_der = int_cert.to_der().expect("encode intermediate cert DER");
    let decoded =
        x509_cert::certificate::Certificate::from_der(&int_der).expect("decode intermediate DER");
    assert_eq!(
        decoded.tbs_certificate.issuer,
        root_cert.tbs_certificate.subject
    );

    println!(
        "sign_csr_p384_sha512_accepted: OK ({} bytes)",
        int_der.len()
    );
}

/// A CSR with an unsupported signature algorithm OID should be rejected.
#[test]
fn sign_csr_unsupported_algorithm_rejected() {
    let module = match softhsm_env() {
        Some(m) => m,
        None => {
            eprintln!("SKIP: SOFTHSM2_MODULE not set");
            return;
        }
    };

    init_test_token("ca-unsup-alg-test");
    let hsm = Pkcs11Hsm::new(&module, "ca-unsup-alg-test").expect("open session");
    let mut actor = HsmActor::spawn(Box::new(hsm));
    let pin = secrecy::SecretString::new("1234".to_string());
    actor.login(&pin).expect("login");

    let root_key = actor
        .generate_keypair("root-key", KeySpec::EcdsaP384)
        .expect("generate root keypair");
    let root_signer = P384HsmSigner::new(actor, root_key).expect("root signer");
    let root_cert = match build_root_cert(&root_signer, "Test Root CA", "Test Org", "US", 7305) {
        Ok(c) => c,
        Err(e) => panic!("root cert: {e}"),
    };

    let csr_der = build_csr_with_bogus_alg("CN=Bogus,O=Test Org,C=US");

    let result =
        sign_intermediate_csr(&root_signer, &root_cert, &csr_der, Some(0), 1825, None, &[]);
    assert!(
        matches!(result, Err(CaError::CsrAlgorithmUnsupported(_))),
        "expected CsrAlgorithmUnsupported, got: {:?}",
        result
    );

    println!("sign_csr_unsupported_algorithm_rejected: OK");
}

/// Build a P-256 key / ecdsa-with-SHA384 CSR DER for testing.
fn build_p256_sha384_csr_der(subject_str: &str) -> Vec<u8> {
    use der::{Decode, Encode};
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::EncodePublicKey;
    use sha2::Digest;
    use spki::AlgorithmIdentifierOwned;
    use x509_cert::request::CertReqInfo;

    let sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let vk = sk.verifying_key();
    let spki_der = vk.to_public_key_der().expect("encode SPKI");
    let spki = spki::SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes()).expect("parse SPKI");

    let subject = x509_cert::name::Name::from_str(subject_str).unwrap();
    let info = CertReqInfo {
        version: x509_cert::request::Version::V1,
        subject,
        public_key: spki,
        attributes: Default::default(),
    };
    let info_der = info.to_der().expect("encode CertReqInfo");

    let digest = sha2::Sha384::digest(&info_der);
    let sig: p256::ecdsa::Signature = sk.sign_prehash(&digest).expect("prehash sign");
    let sig_bytes = sig.to_der();

    let ecdsa_sha384_oid = der::oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
    let alg = AlgorithmIdentifierOwned {
        oid: ecdsa_sha384_oid,
        parameters: None,
    };

    let csr = x509_cert::request::CertReq {
        info,
        algorithm: alg,
        signature: der::asn1::BitString::from_bytes(sig_bytes.as_bytes()).expect("bitstring"),
    };
    csr.to_der().expect("encode CertReq")
}

/// Build a P-384 key / ecdsa-with-SHA512 CSR DER for testing.
fn build_p384_sha512_csr_der(subject_str: &str) -> Vec<u8> {
    use der::{Decode, Encode};
    use p384::ecdsa::signature::hazmat::PrehashSigner;
    use p384::ecdsa::SigningKey;
    use p384::pkcs8::EncodePublicKey;
    use sha2::Digest;
    use spki::AlgorithmIdentifierOwned;
    use x509_cert::request::CertReqInfo;

    let sk = SigningKey::random(&mut p384::elliptic_curve::rand_core::OsRng);
    let vk = sk.verifying_key();
    let spki_der = vk.to_public_key_der().expect("encode SPKI");
    let spki = spki::SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes()).expect("parse SPKI");

    let subject = x509_cert::name::Name::from_str(subject_str).unwrap();
    let info = CertReqInfo {
        version: x509_cert::request::Version::V1,
        subject,
        public_key: spki,
        attributes: Default::default(),
    };
    let info_der = info.to_der().expect("encode CertReqInfo");

    let digest = sha2::Sha512::digest(&info_der);
    let sig: p384::ecdsa::Signature = sk.sign_prehash(&digest).expect("prehash sign");
    let sig_bytes = sig.to_der();

    let ecdsa_sha512_oid = der::oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");
    let alg = AlgorithmIdentifierOwned {
        oid: ecdsa_sha512_oid,
        parameters: None,
    };

    let csr = x509_cert::request::CertReq {
        info,
        algorithm: alg,
        signature: der::asn1::BitString::from_bytes(sig_bytes.as_bytes()).expect("bitstring"),
    };
    csr.to_der().expect("encode CertReq")
}

/// Build a CSR with a valid P-256 signature but a bogus algorithm OID.
fn build_csr_with_bogus_alg(subject_str: &str) -> Vec<u8> {
    use der::{Decode, Encode};
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{DerSignature, SigningKey};
    use p256::pkcs8::EncodePublicKey;
    use spki::AlgorithmIdentifierOwned;
    use x509_cert::request::CertReqInfo;

    let sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let vk = sk.verifying_key();
    let spki_der = vk.to_public_key_der().expect("encode SPKI");
    let spki = spki::SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes()).expect("parse SPKI");

    let subject = x509_cert::name::Name::from_str(subject_str).unwrap();
    let info = CertReqInfo {
        version: x509_cert::request::Version::V1,
        subject,
        public_key: spki,
        attributes: Default::default(),
    };
    let info_der = info.to_der().expect("encode CertReqInfo");
    let sig: DerSignature = sk.sign(&info_der);
    let sig_bytes = sig.to_bytes();

    // Ed25519 OID — not supported
    let bogus_oid = der::oid::ObjectIdentifier::new_unwrap("1.3.101.112");
    let alg = AlgorithmIdentifierOwned {
        oid: bogus_oid,
        parameters: None,
    };

    let csr = x509_cert::request::CertReq {
        info,
        algorithm: alg,
        signature: der::asn1::BitString::from_bytes(&sig_bytes).expect("bitstring"),
    };
    csr.to_der().expect("encode CertReq")
}

/// An RSA-2048 key signed with SHA-256 should be accepted.
#[test]
fn sign_csr_rsa_sha256_accepted() {
    let module = match softhsm_env() {
        Some(m) => m,
        None => {
            eprintln!("SKIP: SOFTHSM2_MODULE not set");
            return;
        }
    };

    init_test_token("ca-rsa256-test");
    let hsm = Pkcs11Hsm::new(&module, "ca-rsa256-test").expect("open session");
    let mut actor = HsmActor::spawn(Box::new(hsm));
    let pin = secrecy::SecretString::new("1234".to_string());
    actor.login(&pin).expect("login");

    let root_key = actor
        .generate_keypair("root-key", KeySpec::EcdsaP384)
        .expect("generate root keypair");
    let root_signer = P384HsmSigner::new(actor, root_key).expect("root signer");
    let root_cert = match build_root_cert(&root_signer, "Test Root CA", "Test Org", "US", 7305) {
        Ok(c) => c,
        Err(e) => panic!("root cert: {e}"),
    };

    let csr_der = build_rsa_sha256_csr_der("CN=RSA-SHA256 Intermediate,O=Test Org,C=US");

    let int_cert =
        sign_intermediate_csr(&root_signer, &root_cert, &csr_der, Some(0), 1825, None, &[])
            .expect("sign RSA/SHA-256 CSR");

    let int_der = int_cert.to_der().expect("encode intermediate cert DER");
    let decoded =
        x509_cert::certificate::Certificate::from_der(&int_der).expect("decode intermediate DER");
    assert_eq!(
        decoded.tbs_certificate.issuer,
        root_cert.tbs_certificate.subject
    );

    println!("sign_csr_rsa_sha256_accepted: OK ({} bytes)", int_der.len());
}

/// An RSA-2048 key signed with SHA-384 should be accepted.
#[test]
fn sign_csr_rsa_sha384_accepted() {
    let module = match softhsm_env() {
        Some(m) => m,
        None => {
            eprintln!("SKIP: SOFTHSM2_MODULE not set");
            return;
        }
    };

    init_test_token("ca-rsa384-test");
    let hsm = Pkcs11Hsm::new(&module, "ca-rsa384-test").expect("open session");
    let mut actor = HsmActor::spawn(Box::new(hsm));
    let pin = secrecy::SecretString::new("1234".to_string());
    actor.login(&pin).expect("login");

    let root_key = actor
        .generate_keypair("root-key", KeySpec::EcdsaP384)
        .expect("generate root keypair");
    let root_signer = P384HsmSigner::new(actor, root_key).expect("root signer");
    let root_cert = match build_root_cert(&root_signer, "Test Root CA", "Test Org", "US", 7305) {
        Ok(c) => c,
        Err(e) => panic!("root cert: {e}"),
    };

    let csr_der = build_rsa_sha384_csr_der("CN=RSA-SHA384 Intermediate,O=Test Org,C=US");

    let int_cert =
        sign_intermediate_csr(&root_signer, &root_cert, &csr_der, Some(0), 1825, None, &[])
            .expect("sign RSA/SHA-384 CSR");

    let int_der = int_cert.to_der().expect("encode intermediate cert DER");
    let decoded =
        x509_cert::certificate::Certificate::from_der(&int_der).expect("decode intermediate DER");
    assert_eq!(
        decoded.tbs_certificate.issuer,
        root_cert.tbs_certificate.subject
    );

    println!("sign_csr_rsa_sha384_accepted: OK ({} bytes)", int_der.len());
}

/// An RSA-2048 key signed with SHA-512 should be accepted.
#[test]
fn sign_csr_rsa_sha512_accepted() {
    let module = match softhsm_env() {
        Some(m) => m,
        None => {
            eprintln!("SKIP: SOFTHSM2_MODULE not set");
            return;
        }
    };

    init_test_token("ca-rsa512-test");
    let hsm = Pkcs11Hsm::new(&module, "ca-rsa512-test").expect("open session");
    let mut actor = HsmActor::spawn(Box::new(hsm));
    let pin = secrecy::SecretString::new("1234".to_string());
    actor.login(&pin).expect("login");

    let root_key = actor
        .generate_keypair("root-key", KeySpec::EcdsaP384)
        .expect("generate root keypair");
    let root_signer = P384HsmSigner::new(actor, root_key).expect("root signer");
    let root_cert = match build_root_cert(&root_signer, "Test Root CA", "Test Org", "US", 7305) {
        Ok(c) => c,
        Err(e) => panic!("root cert: {e}"),
    };

    let csr_der = build_rsa_sha512_csr_der("CN=RSA-SHA512 Intermediate,O=Test Org,C=US");

    let int_cert =
        sign_intermediate_csr(&root_signer, &root_cert, &csr_der, Some(0), 1825, None, &[])
            .expect("sign RSA/SHA-512 CSR");

    let int_der = int_cert.to_der().expect("encode intermediate cert DER");
    let decoded =
        x509_cert::certificate::Certificate::from_der(&int_der).expect("decode intermediate DER");
    assert_eq!(
        decoded.tbs_certificate.issuer,
        root_cert.tbs_certificate.subject
    );

    println!("sign_csr_rsa_sha512_accepted: OK ({} bytes)", int_der.len());
}

/// An Ed25519 key should be accepted.
#[test]
fn sign_csr_ed25519_accepted() {
    let module = match softhsm_env() {
        Some(m) => m,
        None => {
            eprintln!("SKIP: SOFTHSM2_MODULE not set");
            return;
        }
    };

    init_test_token("ca-ed25519-test");
    let hsm = Pkcs11Hsm::new(&module, "ca-ed25519-test").expect("open session");
    let mut actor = HsmActor::spawn(Box::new(hsm));
    let pin = secrecy::SecretString::new("1234".to_string());
    actor.login(&pin).expect("login");

    let root_key = actor
        .generate_keypair("root-key", KeySpec::EcdsaP384)
        .expect("generate root keypair");
    let root_signer = P384HsmSigner::new(actor, root_key).expect("root signer");
    let root_cert = match build_root_cert(&root_signer, "Test Root CA", "Test Org", "US", 7305) {
        Ok(c) => c,
        Err(e) => panic!("root cert: {e}"),
    };

    let csr_der = build_ed25519_csr_der("CN=Ed25519 Intermediate,O=Test Org,C=US");

    let int_cert =
        sign_intermediate_csr(&root_signer, &root_cert, &csr_der, Some(0), 1825, None, &[])
            .expect("sign Ed25519 CSR");

    let int_der = int_cert.to_der().expect("encode intermediate cert DER");
    let decoded =
        x509_cert::certificate::Certificate::from_der(&int_der).expect("decode intermediate DER");
    assert_eq!(
        decoded.tbs_certificate.issuer,
        root_cert.tbs_certificate.subject
    );

    println!("sign_csr_ed25519_accepted: OK ({} bytes)", int_der.len());
}

/// Build an RSA-2048 key / sha256WithRSAEncryption CSR DER for testing.
fn build_rsa_sha256_csr_der(subject_str: &str) -> Vec<u8> {
    use der::{Decode, Encode};
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::signature::Signer;
    use spki::AlgorithmIdentifierOwned;
    use x509_cert::request::CertReqInfo;

    let mut rng = rsa::rand_core::OsRng;
    let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA key");
    let pub_key = private_key.to_public_key();
    let spki_der = pub_key.to_public_key_der().expect("encode SPKI");
    let spki = spki::SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes()).expect("parse SPKI");

    let subject = x509_cert::name::Name::from_str(subject_str).unwrap();
    let info = CertReqInfo {
        version: x509_cert::request::Version::V1,
        subject,
        public_key: spki,
        attributes: Default::default(),
    };
    let info_der = info.to_der().expect("encode CertReqInfo");

    let signing_key = SigningKey::<sha2::Sha256>::new(private_key);
    let sig = signing_key.sign(&info_der);
    let sig_bytes = <rsa::pkcs1v15::Signature as rsa::signature::SignatureEncoding>::to_bytes(&sig);
    let sig_bytes: &[u8] = &sig_bytes;

    let sha256_with_rsa_oid = der::oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
    let alg = AlgorithmIdentifierOwned {
        oid: sha256_with_rsa_oid,
        parameters: Some(der::asn1::Any::null()),
    };

    let csr = x509_cert::request::CertReq {
        info,
        algorithm: alg,
        signature: der::asn1::BitString::from_bytes(sig_bytes).expect("bitstring"),
    };
    csr.to_der().expect("encode CertReq")
}

/// Build an RSA-2048 key / sha384WithRSAEncryption CSR DER for testing.
fn build_rsa_sha384_csr_der(subject_str: &str) -> Vec<u8> {
    use der::{Decode, Encode};
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::signature::Signer;
    use spki::AlgorithmIdentifierOwned;
    use x509_cert::request::CertReqInfo;

    let mut rng = rsa::rand_core::OsRng;
    let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA key");
    let pub_key = private_key.to_public_key();
    let spki_der = pub_key.to_public_key_der().expect("encode SPKI");
    let spki = spki::SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes()).expect("parse SPKI");

    let subject = x509_cert::name::Name::from_str(subject_str).unwrap();
    let info = CertReqInfo {
        version: x509_cert::request::Version::V1,
        subject,
        public_key: spki,
        attributes: Default::default(),
    };
    let info_der = info.to_der().expect("encode CertReqInfo");

    let signing_key = SigningKey::<sha2::Sha384>::new(private_key);
    let sig = signing_key.sign(&info_der);
    let sig_bytes = <rsa::pkcs1v15::Signature as rsa::signature::SignatureEncoding>::to_bytes(&sig);
    let sig_bytes: &[u8] = &sig_bytes;

    let sha384_with_rsa_oid = der::oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
    let alg = AlgorithmIdentifierOwned {
        oid: sha384_with_rsa_oid,
        parameters: Some(der::asn1::Any::null()),
    };

    let csr = x509_cert::request::CertReq {
        info,
        algorithm: alg,
        signature: der::asn1::BitString::from_bytes(sig_bytes).expect("bitstring"),
    };
    csr.to_der().expect("encode CertReq")
}

/// Build an RSA-2048 key / sha512WithRSAEncryption CSR DER for testing.
fn build_rsa_sha512_csr_der(subject_str: &str) -> Vec<u8> {
    use der::{Decode, Encode};
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::signature::Signer;
    use spki::AlgorithmIdentifierOwned;
    use x509_cert::request::CertReqInfo;

    let mut rng = rsa::rand_core::OsRng;
    let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA key");
    let pub_key = private_key.to_public_key();
    let spki_der = pub_key.to_public_key_der().expect("encode SPKI");
    let spki = spki::SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes()).expect("parse SPKI");

    let subject = x509_cert::name::Name::from_str(subject_str).unwrap();
    let info = CertReqInfo {
        version: x509_cert::request::Version::V1,
        subject,
        public_key: spki,
        attributes: Default::default(),
    };
    let info_der = info.to_der().expect("encode CertReqInfo");

    let signing_key = SigningKey::<sha2::Sha512>::new(private_key);
    let sig = signing_key.sign(&info_der);
    let sig_bytes = <rsa::pkcs1v15::Signature as rsa::signature::SignatureEncoding>::to_bytes(&sig);
    let sig_bytes: &[u8] = &sig_bytes;

    let sha512_with_rsa_oid = der::oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
    let alg = AlgorithmIdentifierOwned {
        oid: sha512_with_rsa_oid,
        parameters: Some(der::asn1::Any::null()),
    };

    let csr = x509_cert::request::CertReq {
        info,
        algorithm: alg,
        signature: der::asn1::BitString::from_bytes(sig_bytes).expect("bitstring"),
    };
    csr.to_der().expect("encode CertReq")
}

/// Build an Ed25519 CSR DER for testing.
fn build_ed25519_csr_der(subject_str: &str) -> Vec<u8> {
    use der::Encode;
    use ed25519_dalek::{Signer, SigningKey};
    use spki::AlgorithmIdentifierOwned;
    use x509_cert::request::CertReqInfo;

    let mut secret = [0u8; 32];
    getrandom::getrandom(&mut secret).expect("rng");
    let sk = SigningKey::from_bytes(&secret);

    let vk = sk.verifying_key();
    let vk_bytes = vk.as_bytes();

    // Ed25519 SPKI: algorithm OID 1.3.101.112, no parameters, 32-byte key
    let ed25519_oid = der::oid::ObjectIdentifier::new_unwrap("1.3.101.112");
    let spki = spki::SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: ed25519_oid,
            parameters: None,
        },
        subject_public_key: der::asn1::BitString::from_bytes(vk_bytes).expect("bitstring"),
    };

    let subject = x509_cert::name::Name::from_str(subject_str).unwrap();
    let info = CertReqInfo {
        version: x509_cert::request::Version::V1,
        subject,
        public_key: spki,
        attributes: Default::default(),
    };
    let info_der = info.to_der().expect("encode CertReqInfo");

    let sig = sk.sign(&info_der);
    let sig_bytes = sig.to_bytes();

    let alg = AlgorithmIdentifierOwned {
        oid: ed25519_oid,
        parameters: None,
    };

    let csr = x509_cert::request::CertReq {
        info,
        algorithm: alg,
        signature: der::asn1::BitString::from_bytes(&sig_bytes).expect("bitstring"),
    };
    csr.to_der().expect("encode CertReq")
}

// Required for Name::from_str in tests
use std::str::FromStr;
