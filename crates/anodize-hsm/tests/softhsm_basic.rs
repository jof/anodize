use std::{env, fs, path::PathBuf, process::Command};

use anodize_hsm::{Hsm, HsmActor, KeySpec, Pkcs11Hsm, SignMech};

/// Returns (module_path, conf_path) or skips the test if the env vars aren't set.
fn softhsm_env() -> Option<(PathBuf, PathBuf)> {
    let module = env::var("SOFTHSM2_MODULE").ok()?;
    let conf = env::var("SOFTHSM2_CONF").ok()?;
    Some((PathBuf::from(module), PathBuf::from(conf)))
}

/// Initialise a fresh SoftHSM token for testing.
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

    // Delete and recreate the token dir to ensure a clean slate.
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

    conf_path
}

#[test]
fn list_slots_returns_at_least_one() {
    let (module, _conf) = match softhsm_env() {
        Some(v) => v,
        None => {
            eprintln!("SKIP: SOFTHSM2_MODULE or SOFTHSM2_CONF not set");
            return;
        }
    };

    init_test_token("anodize-test");

    let hsm = Pkcs11Hsm::new(&module, "anodize-test").expect("open session");
    let slots = hsm.list_slots().expect("list_slots failed");

    assert!(!slots.is_empty(), "expected at least one slot with a token");
    println!("Found {} slot(s) with token", slots.len());
}

#[test]
fn open_session_by_token_label() {
    let (module, _conf) = match softhsm_env() {
        Some(v) => v,
        None => {
            eprintln!("SKIP: SOFTHSM2_MODULE or SOFTHSM2_CONF not set");
            return;
        }
    };

    init_test_token("anodize-test");

    let hsm =
        Pkcs11Hsm::new(&module, "anodize-test").expect("failed to open session by token label");
    drop(hsm);
}

/// End-to-end: generate a P-384 keypair, sign a message, verify the signature.
#[test]
fn p384_keygen_sign_verify() {
    let (module, _conf) = match softhsm_env() {
        Some(v) => v,
        None => {
            eprintln!("SKIP: SOFTHSM2_MODULE or SOFTHSM2_CONF not set");
            return;
        }
    };

    init_test_token("anodize-p384");

    let mut hsm = Pkcs11Hsm::new(&module, "anodize-p384").expect("open session");

    let pin = secrecy::SecretString::new("1234".to_string());
    hsm.login(&pin).expect("login");

    let key = hsm
        .generate_keypair("test-root-key", KeySpec::EcdsaP384)
        .expect("generate_keypair");

    let message = b"anodize root CA ceremony -- test vector";
    let sig_bytes = hsm.sign(key, SignMech::EcdsaSha384, message).expect("sign");

    // P1363 signature for P-384 is 96 bytes (48 bytes r || 48 bytes s).
    assert_eq!(
        sig_bytes.len(),
        96,
        "expected 96-byte P1363 signature for P-384, got {}",
        sig_bytes.len()
    );

    let spki_der = hsm.public_key_der(key).expect("public_key_der");
    assert!(!spki_der.is_empty(), "SPKI DER must not be empty");

    // Verify using the p384 crate (hash-then-verify, matching CKM_ECDSA_SHA384).
    use p384::{
        ecdsa::{signature::Verifier, Signature, VerifyingKey},
        pkcs8::DecodePublicKey,
    };

    let vk = VerifyingKey::from_public_key_der(&spki_der)
        .expect("failed to decode SPKI DER into P-384 VerifyingKey");

    let sig = Signature::try_from(sig_bytes.as_slice()).expect("failed to parse P1363 signature");

    vk.verify(message, &sig)
        .expect("signature verification failed");
    println!(
        "P-384 keygen+sign+verify: OK (SPKI {} bytes)",
        spki_der.len()
    );
}

/// Verify that HsmActor is Send + Sync (compile-time check).
#[test]
fn hsm_actor_is_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<HsmActor>();
    assert_sync::<HsmActor>();
}

/// End-to-end through the HsmActor thread boundary.
#[test]
fn p384_via_actor() {
    let (module, _conf) = match softhsm_env() {
        Some(v) => v,
        None => {
            eprintln!("SKIP: SOFTHSM2_MODULE or SOFTHSM2_CONF not set");
            return;
        }
    };

    init_test_token("anodize-actor");

    let hsm = Pkcs11Hsm::new(&module, "anodize-actor").expect("open session");
    let mut actor = HsmActor::spawn(Box::new(hsm));

    let pin = secrecy::SecretString::new("1234".to_string());
    actor.login(&pin).expect("actor login");

    let key = actor
        .generate_keypair("actor-key", KeySpec::EcdsaP384)
        .expect("actor generate_keypair");

    let message = b"actor test message";
    let sig_bytes = actor
        .sign(key, SignMech::EcdsaSha384, message)
        .expect("actor sign");

    let spki_der = actor.public_key_der(key).expect("actor public_key_der");

    use p384::{
        ecdsa::{signature::Verifier, Signature, VerifyingKey},
        pkcs8::DecodePublicKey,
    };

    let vk = VerifyingKey::from_public_key_der(&spki_der).expect("decode SPKI DER");
    let sig = Signature::try_from(sig_bytes.as_slice()).expect("parse P1363 signature");
    vk.verify(message, &sig).expect("verify");

    println!("HsmActor P-384 keygen+sign+verify: OK");
}

// ── change_pin tests ─────────────────────────────────────────────────────────

/// Change PIN on a SoftHSM token, then verify the new PIN works.
#[test]
fn change_pin_softhsm() {
    let (module, _conf) = match softhsm_env() {
        Some(v) => v,
        None => {
            eprintln!("SKIP: SOFTHSM2_MODULE or SOFTHSM2_CONF not set");
            return;
        }
    };

    init_test_token("anodize-chpin");

    let mut hsm = Pkcs11Hsm::new(&module, "anodize-chpin").expect("open session");

    let old_pin = secrecy::SecretString::new("1234".to_string());
    let new_pin = secrecy::SecretString::new("5678".to_string());

    hsm.login(&old_pin).expect("login with old pin");
    hsm.change_pin(&old_pin, &new_pin)
        .expect("change_pin failed");
    hsm.logout().expect("logout");

    // Re-login with the new PIN must succeed.
    hsm.login(&new_pin).expect("login with new pin");
    hsm.logout().expect("logout after new pin");

    println!("change_pin (SoftHSM): OK");
}

/// Change PIN through the HsmActor boundary.
#[test]
fn change_pin_via_actor() {
    let (module, _conf) = match softhsm_env() {
        Some(v) => v,
        None => {
            eprintln!("SKIP: SOFTHSM2_MODULE or SOFTHSM2_CONF not set");
            return;
        }
    };

    init_test_token("anodize-chpin-actor");

    let hsm = Pkcs11Hsm::new(&module, "anodize-chpin-actor").expect("open session");
    let mut actor = HsmActor::spawn(Box::new(hsm));

    let old_pin = secrecy::SecretString::new("1234".to_string());
    let new_pin = secrecy::SecretString::new("5678".to_string());

    actor.login(&old_pin).expect("actor login");
    actor
        .change_pin(&old_pin, &new_pin)
        .expect("actor change_pin");
    actor.logout().expect("actor logout");

    actor.login(&new_pin).expect("actor login with new pin");
    actor.logout().expect("actor logout after new pin");

    println!("change_pin via HsmActor: OK");
}

// ── HsmInventory tests ───────────────────────────────────────────────────────

/// Compile-time check: HsmInventory is object-safe and Send.
#[test]
fn hsm_inventory_is_object_safe_and_send() {
    fn assert_send<T: Send>() {}
    assert_send::<Box<dyn anodize_hsm::HsmInventory>>();
}

/// SoftHSM inventory returns the initialized token with correct fields.
#[test]
fn softhsm_inventory_enumerate() {
    let (_module, _conf) = match softhsm_env() {
        Some(v) => v,
        None => {
            eprintln!("SKIP: SOFTHSM2_MODULE or SOFTHSM2_CONF not set");
            return;
        }
    };

    init_test_token("anodize-inv");

    let module = PathBuf::from(env::var("SOFTHSM2_MODULE").unwrap());
    let backend =
        anodize_hsm::SoftHsmBackend::with_module(module).expect("SoftHsmBackend::with_module");

    use anodize_hsm::HsmInventory;
    let devices = backend.enumerate_devices().expect("enumerate_devices");

    assert!(!devices.is_empty(), "expected at least one device");

    let dev = &devices[0];
    assert!(!dev.serial.is_empty(), "serial should not be empty");
    assert!(!dev.model.is_empty(), "model should not be empty");
    assert_eq!(
        dev.auth_state, "initialized",
        "token was initialized with a PIN"
    );
    // SoftHSM has no audit log
    assert!(dev.log_used.is_none());
    assert!(dev.log_total.is_none());
    // No signing key on a fresh token
    assert_eq!(dev.has_signing_key, Some(false));
    // Wrap keys invisible without login
    assert!(dev.has_wrap_key.is_none());

    println!(
        "SoftHSM inventory: {} device(s), first = {} / {} / {}",
        devices.len(),
        dev.model,
        dev.serial,
        dev.auth_state
    );
}

/// Change PIN on a specific device via HsmBackup::change_pin_on_device.
#[test]
fn change_pin_on_device_via_backup() {
    let (module, _conf) = match softhsm_env() {
        Some(v) => v,
        None => {
            eprintln!("SKIP: SOFTHSM2_MODULE or SOFTHSM2_CONF not set");
            return;
        }
    };

    init_test_token("anodize-chpin-backup");

    let backup = anodize_hsm::Pkcs11BackupImpl::new().expect("Pkcs11BackupImpl::new");

    let old_pin = secrecy::SecretString::new("1234".to_string());
    let new_pin = secrecy::SecretString::new("9999".to_string());

    use anodize_hsm::HsmBackup;
    backup
        .change_pin_on_device("anodize-chpin-backup", &old_pin, &new_pin)
        .expect("change_pin_on_device failed");

    // Verify new PIN works.
    let mut hsm = Pkcs11Hsm::new(&module, "anodize-chpin-backup").expect("open session");
    hsm.login(&new_pin)
        .expect("login with new pin after change_pin_on_device");
    hsm.logout().expect("logout");

    // Verify old PIN is rejected.
    let mut hsm2 = Pkcs11Hsm::new(&module, "anodize-chpin-backup").expect("open session");
    assert!(
        hsm2.login(&old_pin).is_err(),
        "old PIN should be rejected after change_pin_on_device"
    );

    println!("change_pin_on_device (Pkcs11BackupImpl): OK");
}

/// change_pin_on_device works through dyn HsmBackup (object safety).
#[test]
fn change_pin_on_device_dyn_dispatch() {
    let (_module, _conf) = match softhsm_env() {
        Some(v) => v,
        None => {
            eprintln!("SKIP: SOFTHSM2_MODULE or SOFTHSM2_CONF not set");
            return;
        }
    };

    init_test_token("anodize-chpin-dyn");

    let backup: Box<dyn anodize_hsm::HsmBackup> =
        anodize_hsm::create_backup(anodize_config::HsmBackendKind::Softhsm).expect("create_backup");

    let old_pin = secrecy::SecretString::new("1234".to_string());
    let new_pin = secrecy::SecretString::new("abcd".to_string());

    backup
        .change_pin_on_device("anodize-chpin-dyn", &old_pin, &new_pin)
        .expect("change_pin_on_device via dyn dispatch");

    println!("change_pin_on_device (dyn HsmBackup): OK");
}
