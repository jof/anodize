//! YubiHSM2 native backend using the `yubihsm` crate over USB.
//!
//! Bypasses the PKCS#11 bridge entirely — connects directly to the device
//! via USB HID, eliminating the yubihsm-connector daemon dependency and
//! sidestepping PKCS#11 operations that YubiHSM2 doesn't support
//! (C_InitToken, C_SetPIN).

use secrecy::{ExposeSecret, SecretString};
use sha2::Digest as _;

use crate::{
    BackupResult, BackupTarget, Hsm, HsmBackend, HsmBackup, HsmError, KeyHandle, KeySpec, Result,
    SignMech, SlotTokenInfo,
};

// Default auth key slot on factory-fresh YubiHSM2 devices.
const DEFAULT_AUTH_KEY_ID: yubihsm::object::Id = 1;
const DEFAULT_AUTH_PASSWORD: &str = "password";

// Object ID we use for the ceremony signing key (arbitrary, avoid 0).
const SIGNING_KEY_ID: yubihsm::object::Id = 0x0100;
// Object ID for the anodize-managed auth key that replaces the default.
const ANODIZE_AUTH_KEY_ID: yubihsm::object::Id = 2;

// Object ID for the shared wrap key used in backup operations.
const WRAP_KEY_ID: yubihsm::object::Id = 0x0200;

// ── YubiHsmBackend ───────────────────────────────────────────────────────────

/// Native YubiHSM2 backend connected via USB HID.
pub struct YubiHsmBackend;

impl YubiHsmBackend {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }
}

impl HsmBackend for YubiHsmBackend {
    fn list_tokens(&self) -> Result<Vec<SlotTokenInfo>> {
        // Enumerate connected YubiHSM2 devices by USB serial (no auth needed).
        let serials = yubihsm::connector::usb::Devices::serial_numbers()
            .map_err(|e| HsmError::BackendError(format!("USB enumerate: {e}")))?;

        if serials.is_empty() {
            return Ok(vec![]);
        }

        let mut tokens = Vec::new();
        for (i, serial) in serials.iter().enumerate() {
            let serial_str = format!("{serial}");
            // Try connecting to get firmware version.
            // First try factory default auth, then a dummy connect just for device_info.
            let connector = yubihsm::Connector::usb(&yubihsm::UsbConfig {
                serial: Some(*serial),
                ..Default::default()
            });
            let creds = yubihsm::Credentials::from_password(
                DEFAULT_AUTH_KEY_ID,
                DEFAULT_AUTH_PASSWORD.as_bytes(),
            );

            let (model, needs_bootstrap) = match yubihsm::Client::open(connector, creds, true) {
                Ok(client) => {
                    let info = client.device_info().ok();
                    let fw = info
                        .map(|i| {
                            format!(
                                "YubiHSM2 (fw {}.{}.{})",
                                i.major_version, i.minor_version, i.build_version
                            )
                        })
                        .unwrap_or_else(|| "YubiHSM2".to_string());
                    (fw, true) // factory default auth works → not yet bootstrapped
                }
                Err(_) => {
                    // Factory auth failed — device already bootstrapped with anodize key.
                    ("YubiHSM2 (bootstrapped)".to_string(), false)
                }
            };

            tokens.push(SlotTokenInfo {
                slot_id: i as u64,
                token_label: "YubiHSM2".to_string(),
                model,
                serial_number: serial_str,
                login_required: true,
                user_pin_initialized: !needs_bootstrap,
                user_pin_locked: false,
                min_pin_len: 0,
                max_pin_len: 0,
                token_initialized: true,
            });
        }

        Ok(tokens)
    }

    fn probe_token(&self, _label: &str) -> Result<bool> {
        // YubiHSM2 doesn't have per-token labels.  We probe by connecting.
        let connector = yubihsm::Connector::usb(&yubihsm::UsbConfig::default());
        let creds = yubihsm::Credentials::from_password(
            DEFAULT_AUTH_KEY_ID,
            DEFAULT_AUTH_PASSWORD.as_bytes(),
        );
        Ok(yubihsm::Client::open(connector, creds, true).is_ok())
    }

    fn open_session(&self, _label: &str, pin: &SecretString) -> Result<Box<dyn Hsm>> {
        // Derive credentials from the SSS-reconstructed PIN.
        // Auth key ID 2 is the anodize-managed key created during bootstrap.
        let connector = yubihsm::Connector::usb(&yubihsm::UsbConfig::default());
        let creds = yubihsm::Credentials::from_password(
            ANODIZE_AUTH_KEY_ID,
            pin.expose_secret().as_bytes(),
        );

        let client = yubihsm::Client::open(connector, creds, true)
            .map_err(|e| HsmError::BackendError(format!("YubiHSM open_session: {e}")))?;

        Ok(Box::new(YubiHsmSession { client }))
    }

    fn bootstrap(
        &self,
        _slot_id: u64,
        _so_pin: &SecretString,
        user_pin: &SecretString,
        _label: &str,
    ) -> Result<Box<dyn Hsm>> {
        // 1. Connect with factory-default credentials.
        let connector = yubihsm::Connector::usb(&yubihsm::UsbConfig::default());
        let creds = yubihsm::Credentials::from_password(
            DEFAULT_AUTH_KEY_ID,
            DEFAULT_AUTH_PASSWORD.as_bytes(),
        );

        let client = yubihsm::Client::open(connector, creds, true)
            .map_err(|e| HsmError::BackendError(format!("YubiHSM bootstrap connect: {e}")))?;

        // 2. Create a new auth key (ID 2) derived from the SSS user_pin.
        //    This replaces the factory default for future sessions.
        let auth_key =
            yubihsm::authentication::Key::derive_from_password(user_pin.expose_secret().as_bytes());
        client
            .put_authentication_key(
                ANODIZE_AUTH_KEY_ID,
                yubihsm::object::Label::from_bytes(b"anodize-auth")
                    .map_err(|e| HsmError::BackendError(format!("label: {e}")))?,
                yubihsm::Domain::all(),
                yubihsm::Capability::all(),
                yubihsm::Capability::all(), // delegated
                yubihsm::authentication::Algorithm::default(),
                auth_key,
            )
            .map_err(|e| HsmError::BackendError(format!("put_authentication_key: {e}")))?;

        tracing::info!("YubiHSM bootstrap: created auth key {ANODIZE_AUTH_KEY_ID}");

        // 3. Delete the factory default auth key to lock down the device.
        client
            .delete_object(
                DEFAULT_AUTH_KEY_ID,
                yubihsm::object::Type::AuthenticationKey,
            )
            .map_err(|e| HsmError::BackendError(format!("delete default auth key: {e}")))?;

        tracing::info!("YubiHSM bootstrap: deleted factory auth key {DEFAULT_AUTH_KEY_ID}");

        // 4. Reconnect with the new credentials.
        let connector2 = yubihsm::Connector::usb(&yubihsm::UsbConfig::default());
        let new_creds = yubihsm::Credentials::from_password(
            ANODIZE_AUTH_KEY_ID,
            user_pin.expose_secret().as_bytes(),
        );
        let client2 = yubihsm::Client::open(connector2, new_creds, true)
            .map_err(|e| HsmError::BackendError(format!("YubiHSM reconnect: {e}")))?;

        Ok(Box::new(YubiHsmSession { client: client2 }))
    }
}

// ── YubiHsmSession ───────────────────────────────────────────────────────────

/// An authenticated native session to a YubiHSM2 device.
pub(crate) struct YubiHsmSession {
    client: yubihsm::Client,
}

impl Hsm for YubiHsmSession {
    fn login(&mut self, _pin: &SecretString) -> Result<()> {
        // No-op: authentication happens at Client::open() time.
        Ok(())
    }

    fn logout(&mut self) -> Result<()> {
        // No-op: session closed on Drop.
        Ok(())
    }

    fn find_key(&self, _label: &str) -> Result<KeyHandle> {
        // YubiHSM uses numeric object IDs, not string labels.
        // We use a well-known ID for the signing key.
        self.client
            .get_object_info(SIGNING_KEY_ID, yubihsm::object::Type::AsymmetricKey)
            .map_err(|e| HsmError::KeyNotFound(format!("key {SIGNING_KEY_ID:#06x}: {e}")))?;

        Ok(KeyHandle {
            priv_id: SIGNING_KEY_ID as u64,
            pub_id: Some(SIGNING_KEY_ID as u64), // same object for YubiHSM
        })
    }

    fn generate_keypair(&mut self, label: &str, spec: KeySpec) -> Result<KeyHandle> {
        let algorithm = match spec {
            KeySpec::EcdsaP384 => yubihsm::asymmetric::Algorithm::EcP384,
            KeySpec::EcdsaP256 => yubihsm::asymmetric::Algorithm::EcP256,
            _ => return Err(HsmError::UnsupportedKeySpec),
        };

        let obj_label =
            yubihsm::object::Label::from_bytes(&label.as_bytes()[..label.len().min(40)])
                .map_err(|e| HsmError::BackendError(format!("label: {e}")))?;

        self.client
            .generate_asymmetric_key(
                SIGNING_KEY_ID,
                obj_label,
                yubihsm::Domain::all(),
                yubihsm::Capability::SIGN_ECDSA | yubihsm::Capability::EXPORTABLE_UNDER_WRAP,
                algorithm,
            )
            .map_err(|e| HsmError::BackendError(format!("generate_asymmetric_key: {e}")))?;

        tracing::info!(id = SIGNING_KEY_ID, %label, "YubiHSM: generated EC keypair");

        Ok(KeyHandle {
            priv_id: SIGNING_KEY_ID as u64,
            pub_id: Some(SIGNING_KEY_ID as u64),
        })
    }

    fn sign(&self, key: KeyHandle, mech: SignMech, data: &[u8]) -> Result<Vec<u8>> {
        let key_id = key.priv_id as yubihsm::object::Id;

        // YubiHSM sign_ecdsa_prehash_raw expects a pre-hashed digest.
        let digest = match mech {
            SignMech::EcdsaSha384 => sha2::Sha384::digest(data).to_vec(),
            SignMech::EcdsaSha256 => sha2::Sha256::digest(data).to_vec(),
            _ => return Err(HsmError::UnsupportedKeySpec),
        };

        let sig = self
            .client
            .sign_ecdsa_prehash_raw(key_id, digest)
            .map_err(|e| HsmError::BackendError(format!("sign_ecdsa: {e}")))?;

        Ok(sig)
    }

    fn public_key_der(&self, key: KeyHandle) -> Result<Vec<u8>> {
        let key_id = key.priv_id as yubihsm::object::Id;
        let pubkey = self
            .client
            .get_public_key(key_id)
            .map_err(|e| HsmError::BackendError(format!("get_public_key: {e}")))?;

        // Build DER SubjectPublicKeyInfo from the raw uncompressed point.
        let raw_point = pubkey.as_ref();

        // Determine the EC params OID from the algorithm.
        let algo = pubkey.algorithm;
        let ec_params: &[u8] = if algo == yubihsm::asymmetric::Algorithm::EcP384 {
            // secp384r1 OID
            &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]
        } else if algo == yubihsm::asymmetric::Algorithm::EcP256 {
            // prime256v1 OID
            &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]
        } else {
            return Err(HsmError::UnsupportedKeySpec);
        };

        // The raw point from YubiHSM is the uncompressed coordinates (x || y)
        // without the 0x04 prefix.  Prepend it.
        let mut point = vec![0x04u8];
        point.extend_from_slice(raw_point);

        Ok(crate::softhsm::ec_spki_from_params_and_point(
            ec_params, &point,
        ))
    }

    fn list_slot_details(&self) -> Result<Vec<SlotTokenInfo>> {
        // Provide a single synthetic slot for the YubiHSM device.
        match self.client.device_info() {
            Ok(info) => Ok(vec![SlotTokenInfo {
                slot_id: 0,
                token_label: "YubiHSM2".to_string(),
                model: format!(
                    "YubiHSM2 (fw {}.{}.{})",
                    info.major_version, info.minor_version, info.build_version
                ),
                serial_number: format!("{}", info.serial_number),
                login_required: false,
                user_pin_initialized: true,
                user_pin_locked: false,
                min_pin_len: 0,
                max_pin_len: 0,
                token_initialized: true,
            }]),
            Err(e) => Err(HsmError::BackendError(format!("device_info: {e}"))),
        }
    }
}

// ── YubiHsmBackupImpl ──────────────────────────────────────────────────────────

/// YubiHSM backup implementation using native SDK wrap/unwrap over USB.
pub struct YubiHsmBackupImpl;

impl YubiHsmBackupImpl {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }

    /// Open a client to a specific device by serial string.
    /// Tries anodize auth key (2) with `pin` first, falls back to factory default.
    fn open_client(serial_str: &str, pin: &SecretString) -> Result<yubihsm::Client> {
        let serial: yubihsm::device::SerialNumber = serial_str
            .parse()
            .map_err(|e| HsmError::BackendError(format!("invalid serial '{serial_str}': {e}")))?;

        let cfg = yubihsm::UsbConfig {
            serial: Some(serial),
            ..Default::default()
        };

        // Try anodize auth (key 2) first.
        let connector = yubihsm::Connector::usb(&cfg);
        let creds = yubihsm::Credentials::from_password(
            ANODIZE_AUTH_KEY_ID,
            pin.expose_secret().as_bytes(),
        );
        if let Ok(client) = yubihsm::Client::open(connector, creds, true) {
            return Ok(client);
        }

        // Fall back to factory default auth (key 1).
        let connector2 = yubihsm::Connector::usb(&cfg);
        let default_creds = yubihsm::Credentials::from_password(
            DEFAULT_AUTH_KEY_ID,
            DEFAULT_AUTH_PASSWORD.as_bytes(),
        );
        yubihsm::Client::open(connector2, default_creds, true)
            .map_err(|e| HsmError::BackendError(format!("connect to {serial_str}: {e}")))
    }

    fn has_object(
        client: &yubihsm::Client,
        id: yubihsm::object::Id,
        obj_type: yubihsm::object::Type,
    ) -> bool {
        client.get_object_info(id, obj_type).is_ok()
    }
}

impl HsmBackup for YubiHsmBackupImpl {
    fn enumerate_backup_targets(&self) -> Result<Vec<BackupTarget>> {
        let serials = yubihsm::connector::usb::Devices::serial_numbers()
            .map_err(|e| HsmError::BackendError(format!("USB enumeration: {e}")))?;

        let mut targets = Vec::with_capacity(serials.len());
        for serial in serials {
            let serial_str = format!("{serial}");

            let cfg = yubihsm::UsbConfig {
                serial: Some(serial),
                ..Default::default()
            };

            // Try factory-default auth to probe the device.
            let connector = yubihsm::Connector::usb(&cfg);
            let default_creds = yubihsm::Credentials::from_password(
                DEFAULT_AUTH_KEY_ID,
                DEFAULT_AUTH_PASSWORD.as_bytes(),
            );

            let (description, needs_bootstrap, has_wrap, has_signing) =
                match yubihsm::Client::open(connector, default_creds, false) {
                    Ok(client) => {
                        let fw = match client.device_info() {
                            Ok(info) => format!(
                                "YubiHSM2 fw {}.{}.{}",
                                info.major_version, info.minor_version, info.build_version
                            ),
                            Err(_) => "YubiHSM2".to_string(),
                        };
                        let has_wrap =
                            Self::has_object(&client, WRAP_KEY_ID, yubihsm::object::Type::WrapKey);
                        let has_signing = Self::has_object(
                            &client,
                            SIGNING_KEY_ID,
                            yubihsm::object::Type::AsymmetricKey,
                        );
                        (fw, true, has_wrap, has_signing)
                    }
                    Err(_) => {
                        // Can't open with default — device is bootstrapped.
                        ("YubiHSM2 (bootstrapped)".to_string(), false, false, false)
                    }
                };

            targets.push(BackupTarget {
                identifier: serial_str,
                description,
                needs_bootstrap,
                has_wrap_key: has_wrap,
                has_signing_key: has_signing,
            });
        }

        Ok(targets)
    }

    fn pair_devices(&self, src: &str, dst: &str, pin: &SecretString) -> Result<String> {
        let client_a = Self::open_client(src, pin)?;
        let client_b = Self::open_client(dst, pin)?;

        // Generate a fresh AES-256-CCM wrap key.
        let mut key_bytes = [0u8; 32];
        getrandom::getrandom(&mut key_bytes)
            .map_err(|e| HsmError::BackendError(format!("getrandom: {e}")))?;

        let label_a = yubihsm::object::Label::from_bytes(b"anodize-wrap")
            .map_err(|e| HsmError::BackendError(format!("label: {e}")))?;
        let label_b = yubihsm::object::Label::from_bytes(b"anodize-wrap")
            .map_err(|e| HsmError::BackendError(format!("label: {e}")))?;

        let wrap_caps = yubihsm::Capability::EXPORT_WRAPPED
            | yubihsm::Capability::IMPORT_WRAPPED
            | yubihsm::Capability::WRAP_DATA
            | yubihsm::Capability::UNWRAP_DATA;

        // Remove any existing wrap key first.
        let _ = client_a.delete_object(WRAP_KEY_ID, yubihsm::object::Type::WrapKey);
        let _ = client_b.delete_object(WRAP_KEY_ID, yubihsm::object::Type::WrapKey);

        client_a
            .put_wrap_key(
                WRAP_KEY_ID,
                label_a,
                yubihsm::Domain::all(),
                wrap_caps,
                yubihsm::Capability::all(),
                yubihsm::wrap::Algorithm::Aes256Ccm,
                key_bytes.to_vec(),
            )
            .map_err(|e| HsmError::BackendError(format!("put_wrap_key on {src}: {e}")))?;

        client_b
            .put_wrap_key(
                WRAP_KEY_ID,
                label_b,
                yubihsm::Domain::all(),
                wrap_caps,
                yubihsm::Capability::all(),
                yubihsm::wrap::Algorithm::Aes256Ccm,
                key_bytes.to_vec(),
            )
            .map_err(|e| HsmError::BackendError(format!("put_wrap_key on {dst}: {e}")))?;

        // Zeroize the raw key material.
        key_bytes.fill(0);

        tracing::info!(
            src,
            dst,
            wrap_key_id = WRAP_KEY_ID,
            "YubiHSM backup: devices paired"
        );
        Ok(format!("0x{WRAP_KEY_ID:04X}"))
    }

    fn backup_key(
        &self,
        src: &str,
        dst: &str,
        pin: &SecretString,
        _key_id: &str,
    ) -> Result<BackupResult> {
        let client_src = Self::open_client(src, pin)?;
        let client_dst = Self::open_client(dst, pin)?;

        // 1. Get public key from source before export.
        let pubkey_src = client_src
            .get_public_key(SIGNING_KEY_ID)
            .map_err(|e| HsmError::BackendError(format!("get_public_key on {src}: {e}")))?;

        // 2. Export-wrapped from source.
        let wrapped = client_src
            .export_wrapped(
                WRAP_KEY_ID,
                yubihsm::object::Type::AsymmetricKey,
                SIGNING_KEY_ID,
            )
            .map_err(|e| HsmError::BackendError(format!("export_wrapped on {src}: {e}")))?;

        // 3. Clear any existing key at the target slot on dest.
        let _ = client_dst.delete_object(SIGNING_KEY_ID, yubihsm::object::Type::AsymmetricKey);

        // 4. Import-wrapped into dest.
        client_dst
            .import_wrapped(WRAP_KEY_ID, wrapped)
            .map_err(|e| HsmError::BackendError(format!("import_wrapped on {dst}: {e}")))?;

        // 5. Verify public keys match.
        let pubkey_dst = client_dst
            .get_public_key(SIGNING_KEY_ID)
            .map_err(|e| HsmError::BackendError(format!("get_public_key on {dst}: {e}")))?;

        let keys_match = pubkey_src.as_ref() == pubkey_dst.as_ref();

        tracing::info!(
            src,
            dst,
            keys_match,
            key_id = format!("0x{SIGNING_KEY_ID:04X}"),
            "YubiHSM backup: key transferred"
        );

        Ok(BackupResult {
            source_id: src.to_string(),
            dest_id: dst.to_string(),
            key_id: format!("0x{SIGNING_KEY_ID:04X}"),
            public_keys_match: keys_match,
        })
    }
}
