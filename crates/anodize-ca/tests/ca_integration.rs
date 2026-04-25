use std::{env, fs, path::PathBuf, process::Command, time::SystemTime};

use anodize_ca::{build_root_cert, issue_crl, sign_intermediate_csr, CaError, P384HsmSigner};
use anodize_hsm::{Hsm, HsmActor, KeySpec, Pkcs11Hsm};
use der::{Decode, Encode};

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
    let cert =
        build_root_cert(&signer, "Test Root CA", "Test Org", "US", 7305).expect("build root cert");

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
    let mut actor = HsmActor::spawn(hsm);
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

    let root_cert =
        build_root_cert(&root_signer, "Test Root CA", "Test Org", "US", 7305).expect("root cert");

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
    let mut actor = HsmActor::spawn(hsm);
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

    let root_cert =
        build_root_cert(&root_signer, "Test Root CA", "Test Org", "US", 7305).expect("root cert");

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

    let result = sign_intermediate_csr(&root_signer, &root_cert, &csr_der, Some(0), 1825, None);
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
    let root_cert =
        build_root_cert(&root_signer, "Test Root CA", "Test Org", "US", 7305).expect("root cert");

    let now = SystemTime::now();
    let next_update = now + std::time::Duration::from_secs(30 * 24 * 3600);
    let revoked = vec![(42u64, now), (99u64, now)];

    let crl_der = issue_crl(&root_signer, &root_cert, &revoked, next_update).expect("issue CRL");

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

// Required for Name::from_str in tests
use std::str::FromStr;
