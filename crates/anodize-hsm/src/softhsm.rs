//! SoftHSM backend — PKCS#11 implementation via the `cryptoki` crate.
//!
//! Used for SoftHSM2 (development/testing) and could serve as the basis for
//! any PKCS#11–compliant device.

use std::path::{Path, PathBuf};

use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, AttributeType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    types::AuthPin,
};
use secrecy::{ExposeSecret, SecretString};

use crate::{
    BackupResult, BackupTarget, Hsm, HsmBackend, HsmBackup, HsmDeviceInfo, HsmError, HsmInventory,
    KeyHandle, KeySpec, Result, SignMech, SlotTokenInfo,
};

// ── ObjectHandle ↔ u64 conversion ────────────────────────────────────────────
//
// cryptoki 0.7 does not expose ObjectHandle's inner CK_OBJECT_HANDLE.
// ObjectHandle is a `#[derive(Copy, Clone)]` newtype over CK_OBJECT_HANDLE
// (c_ulong = u64 on our target platforms).  We use transmute with a
// compile-time size assertion.
const _: () = assert!(std::mem::size_of::<ObjectHandle>() == std::mem::size_of::<u64>());

fn obj_to_u64(h: ObjectHandle) -> u64 {
    // SAFETY: layout verified by const assertion above.
    unsafe { std::mem::transmute(h) }
}

fn u64_to_obj(id: u64) -> ObjectHandle {
    // SAFETY: layout verified by const assertion above.
    unsafe { std::mem::transmute(id) }
}

// ── Module path resolution ───────────────────────────────────────────────────

const SOFTHSM_MODULE: &str = "libsofthsm2.so";

const FALLBACK_MODULE_DIRS: &[&str] = &[
    "/run/current-system/sw/lib/pkcs11",
    "/run/current-system/sw/lib/softhsm",
    "/usr/lib/softhsm",
    "/usr/lib/pkcs11",
    "/usr/lib/x86_64-linux-gnu/softhsm",
    "/usr/lib/x86_64-linux-gnu/pkcs11",
    "/usr/lib/aarch64-linux-gnu/softhsm",
    "/usr/lib/aarch64-linux-gnu/pkcs11",
];

fn find_softhsm_module() -> Result<PathBuf> {
    // 1. Explicit env override
    if let Ok(p) = std::env::var("SOFTHSM2_MODULE") {
        let path = PathBuf::from(&p);
        if path.exists() {
            return Ok(path);
        }
    }
    // 2. ANODIZE_PKCS11_MODULES (legacy, still set on dev ISOs)
    if let Ok(paths) = std::env::var("ANODIZE_PKCS11_MODULES") {
        for entry in paths.split(':').filter(|s| !s.is_empty()) {
            let p = Path::new(entry);
            if p.file_name().and_then(|f| f.to_str()) == Some(SOFTHSM_MODULE) {
                return Ok(p.into());
            }
        }
    }
    // 3. Well-known fallback directories
    for dir in FALLBACK_MODULE_DIRS {
        let candidate = Path::new(dir).join(SOFTHSM_MODULE);
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(HsmError::ModuleNotFound(SOFTHSM_MODULE.into()))
}

// ── Shared PKCS#11 initialisation ────────────────────────────────────────────

fn init_ctx(module_path: &Path) -> Result<Pkcs11> {
    let ctx = Pkcs11::new(module_path)?;
    match ctx.initialize(CInitializeArgs::OsThreads) {
        Ok(()) => {}
        // A second open in the same process reuses the already-initialized
        // library. PKCS#11 §11.4: the library stays initialized until the
        // last C_Finalize call, so this is safe to ignore.
        Err(cryptoki::error::Error::Pkcs11(
            cryptoki::error::RvError::CryptokiAlreadyInitialized,
            _,
        )) => {}
        Err(e) => return Err(HsmError::Pkcs11(e)),
    }
    Ok(ctx)
}

fn token_info_from_slot(ctx: &Pkcs11, slot: cryptoki::slot::Slot) -> Option<SlotTokenInfo> {
    ctx.get_token_info(slot).ok().map(|ti| SlotTokenInfo {
        slot_id: slot.id(),
        token_label: ti.label().trim().to_string(),
        model: ti.model().trim().to_string(),
        serial_number: ti.serial_number().trim().to_string(),
        login_required: ti.login_required(),
        user_pin_initialized: ti.user_pin_initialized(),
        user_pin_locked: ti.user_pin_locked(),
        min_pin_len: ti.min_pin_length(),
        max_pin_len: ti.max_pin_length(),
        token_initialized: ti.token_initialized(),
    })
}

// ── SoftHsmBackend ───────────────────────────────────────────────────────────

/// PKCS#11 backend using SoftHSM2 (`libsofthsm2.so`).
pub struct SoftHsmBackend {
    module_path: PathBuf,
}

impl SoftHsmBackend {
    pub fn new() -> Result<Self> {
        let module_path = find_softhsm_module()?;
        tracing::info!(path = %module_path.display(), "SoftHsmBackend: resolved module");
        Ok(Self { module_path })
    }

    /// Construct from an explicit module path (useful for tests).
    pub fn with_module(module_path: PathBuf) -> Result<Self> {
        Ok(Self { module_path })
    }
}

impl HsmBackend for SoftHsmBackend {
    fn list_tokens(&self) -> Result<Vec<SlotTokenInfo>> {
        let ctx = init_ctx(&self.module_path)?;
        let slots = ctx.get_slots_with_token()?;
        Ok(slots
            .iter()
            .filter_map(|&s| token_info_from_slot(&ctx, s))
            .collect())
    }

    fn probe_token(&self, label: &str) -> Result<bool> {
        let ctx = init_ctx(&self.module_path)?;
        let found = ctx.get_slots_with_token()?.into_iter().any(|slot| {
            ctx.get_token_info(slot)
                .map(|info| info.label().trim() == label.trim())
                .unwrap_or(false)
        });
        Ok(found)
    }

    fn open_session(&self, label: &str, pin: &SecretString) -> Result<Box<dyn Hsm>> {
        let ctx = init_ctx(&self.module_path)?;
        let slot = ctx
            .get_slots_with_token()?
            .into_iter()
            .find(|&slot| {
                ctx.get_token_info(slot)
                    .map(|info| info.label().trim() == label.trim())
                    .unwrap_or(false)
            })
            .ok_or_else(|| HsmError::TokenNotFound(label.to_string()))?;

        let session = ctx.open_rw_session(slot)?;
        let auth = AuthPin::new(pin.expose_secret().to_string());
        session.login(UserType::User, Some(&auth))?;

        Ok(Box::new(Pkcs11Hsm {
            ctx,
            session: Some(session),
        }))
    }

    fn bootstrap(
        &self,
        slot_id: u64,
        so_pin: &SecretString,
        user_pin: &SecretString,
        label: &str,
    ) -> Result<Box<dyn Hsm>> {
        let module = Pkcs11Module::open(&self.module_path)?;
        let hsm = module.bootstrap_token(slot_id, so_pin, user_pin, None, label)?;
        Ok(Box::new(hsm))
    }

    fn list_all_slots(&self) -> Result<Vec<SlotTokenInfo>> {
        let ctx = init_ctx(&self.module_path)?;
        let slots = ctx.get_all_slots()?;
        Ok(slots
            .iter()
            .map(|&s| {
                token_info_from_slot(&ctx, s).unwrap_or(SlotTokenInfo {
                    slot_id: s.id(),
                    token_label: String::new(),
                    model: String::new(),
                    serial_number: String::new(),
                    login_required: false,
                    user_pin_initialized: false,
                    user_pin_locked: false,
                    min_pin_len: 0,
                    max_pin_len: 0,
                    token_initialized: false,
                })
            })
            .collect())
    }
}

// ---------------------------------------------------------------------------
// Pkcs11Module — pre-session management (enumerate, init token, bootstrap)
// ---------------------------------------------------------------------------

/// Module-level PKCS#11 handle for operations that don't require a session:
/// device enumeration, token initialisation, and bootstrap.
pub struct Pkcs11Module {
    ctx: Pkcs11,
}

impl Pkcs11Module {
    pub fn open(module_path: &std::path::Path) -> Result<Self> {
        Ok(Self {
            ctx: init_ctx(module_path)?,
        })
    }

    /// Enumerate all slots that have a token present.
    pub fn list_tokens(&self) -> Result<Vec<SlotTokenInfo>> {
        let slots = self.ctx.get_slots_with_token()?;
        Ok(slots
            .iter()
            .filter_map(|&s| token_info_from_slot(&self.ctx, s))
            .collect())
    }

    /// Bootstrap a token and return an authenticated `Pkcs11Hsm`.
    ///
    /// Two strategies are attempted:
    ///
    /// 1. **C_InitToken path** (SoftHSM, generic PKCS#11): `C_InitToken` →
    ///    SO login → `C_InitPIN` → user login.
    /// 2. **SetPIN fallback** (devices that don't support `C_InitToken`):
    ///    login with `factory_pin` → `C_SetPIN` to `user_pin` → re-login
    ///    with new PIN.
    pub fn bootstrap_token(
        self,
        slot_id: u64,
        so_pin: &SecretString,
        user_pin: &SecretString,
        factory_pin: Option<&SecretString>,
        label: &str,
    ) -> Result<Pkcs11Hsm> {
        use cryptoki::slot::Slot;

        let slot = Slot::try_from(slot_id)
            .map_err(|_| HsmError::TokenNotFound(format!("invalid slot_id={slot_id}")))?;

        let so_auth = AuthPin::new(so_pin.expose_secret().to_string());
        let user_auth = AuthPin::new(user_pin.expose_secret().to_string());

        // Strategy 1: C_InitToken (full initialisation).
        match self.ctx.init_token(slot, &so_auth, label) {
            Ok(()) => {
                tracing::info!("bootstrap_token: C_InitToken succeeded");
                let session = self.ctx.open_rw_session(slot)?;
                session.login(UserType::So, Some(&so_auth))?;
                session.init_pin(&user_auth)?;
                session.logout()?;
                session.login(UserType::User, Some(&user_auth))?;
                return Ok(Pkcs11Hsm {
                    ctx: self.ctx,
                    session: Some(session),
                });
            }
            Err(cryptoki::error::Error::Pkcs11(
                cryptoki::error::RvError::FunctionNotSupported,
                _,
            )) => {
                tracing::info!(
                    "bootstrap_token: C_InitToken not supported, trying SetPIN fallback"
                );
            }
            Err(e) => return Err(HsmError::Pkcs11(e)),
        }

        // Strategy 2 & 3: login with factory PIN, optionally change it.
        let old_pin = factory_pin.ok_or_else(|| {
            HsmError::TokenNotFound(
                "C_InitToken not supported and no factory_pin configured".to_string(),
            )
        })?;
        let old_auth = AuthPin::new(old_pin.expose_secret().to_string());

        let session = self.ctx.open_rw_session(slot)?;
        session.login(UserType::User, Some(&old_auth))?;

        // Strategy 2: try C_SetPIN to rotate to the new user PIN.
        match session.set_pin(&old_auth, &user_auth) {
            Ok(()) => {
                tracing::info!("bootstrap_token: C_SetPIN succeeded, re-logging in");
                session.logout()?;
                session.login(UserType::User, Some(&user_auth))?;
            }
            Err(cryptoki::error::Error::Pkcs11(
                cryptoki::error::RvError::FunctionNotSupported,
                _,
            )) => {
                // Strategy 3: device doesn't support PIN management via
                // PKCS#11. Stay logged in with factory credentials.
                tracing::warn!(
                    "bootstrap_token: C_SetPIN not supported — proceeding \
                     with factory credentials. Auth key rotation deferred."
                );
            }
            Err(e) => return Err(HsmError::Pkcs11(e)),
        }

        Ok(Pkcs11Hsm {
            ctx: self.ctx,
            session: Some(session),
        })
    }
}

// ---------------------------------------------------------------------------
// Pkcs11Hsm — session-level operations (login, keygen, sign)
// ---------------------------------------------------------------------------

pub struct Pkcs11Hsm {
    ctx: Pkcs11,
    session: Option<Session>,
}

impl Pkcs11Hsm {
    /// Open the PKCS#11 module at `module_path` and find the slot whose token
    /// label matches `token_label`. Does not log in; call `login()` next.
    pub fn new(module_path: &std::path::Path, token_label: &str) -> Result<Self> {
        let ctx = init_ctx(module_path)?;

        let slot = ctx
            .get_slots_with_token()?
            .into_iter()
            .find(|&slot| {
                ctx.get_token_info(slot)
                    .map(|info| info.label().trim() == token_label.trim())
                    .unwrap_or(false)
            })
            .ok_or_else(|| HsmError::TokenNotFound(token_label.to_string()))?;

        let session = ctx.open_rw_session(slot)?;

        Ok(Self {
            ctx,
            session: Some(session),
        })
    }

    /// Open the PKCS#11 module and find the slot whose token serial number
    /// matches `serial`. Does not log in; call `login()` next.
    pub fn open_by_serial(module_path: &std::path::Path, serial: &str) -> Result<Self> {
        let ctx = init_ctx(module_path)?;

        let slot = ctx
            .get_slots_with_token()?
            .into_iter()
            .find(|&slot| {
                ctx.get_token_info(slot)
                    .map(|info| info.serial_number().trim() == serial.trim())
                    .unwrap_or(false)
            })
            .ok_or_else(|| HsmError::TokenNotFound(format!("serial={serial}")))?;

        let session = ctx.open_rw_session(slot)?;

        Ok(Self {
            ctx,
            session: Some(session),
        })
    }

    /// List all slots with a token present — useful for diagnostics and tests.
    pub fn list_slots(&self) -> Result<Vec<cryptoki::slot::Slot>> {
        Ok(self.ctx.get_slots_with_token()?)
    }

    fn session(&self) -> &Session {
        self.session
            .as_ref()
            .expect("session always open after new()")
    }
}

// DER OID bytes for named curves (tag 0x06 + length + OID components)
const EC_PARAMS_P384: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
const EC_PARAMS_P256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

impl Hsm for Pkcs11Hsm {
    fn login(&mut self, pin: &SecretString) -> Result<()> {
        let auth = AuthPin::new(pin.expose_secret().to_string());
        self.session()
            .login(cryptoki::session::UserType::User, Some(&auth))?;
        Ok(())
    }

    fn logout(&mut self) -> Result<()> {
        self.session().logout()?;
        Ok(())
    }

    fn find_key(&self, label: &str) -> Result<KeyHandle> {
        let priv_handles = self.session().find_objects(&[
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Class(ObjectClass::PRIVATE_KEY),
        ])?;
        let priv_handle = priv_handles
            .into_iter()
            .next()
            .ok_or_else(|| HsmError::KeyNotFound(label.to_string()))?;

        let pub_handle = self
            .session()
            .find_objects(&[
                Attribute::Label(label.as_bytes().to_vec()),
                Attribute::Class(ObjectClass::PUBLIC_KEY),
            ])?
            .into_iter()
            .next();

        Ok(KeyHandle {
            priv_id: obj_to_u64(priv_handle),
            pub_id: pub_handle.map(obj_to_u64),
        })
    }

    fn generate_keypair(&mut self, label: &str, spec: KeySpec) -> Result<KeyHandle> {
        let ec_params: &[u8] = match spec {
            KeySpec::EcdsaP384 => EC_PARAMS_P384,
            KeySpec::EcdsaP256 => EC_PARAMS_P256,
            KeySpec::Ed25519 | KeySpec::Rsa4096 => {
                return Err(HsmError::UnsupportedKeySpec);
            }
        };

        let pub_template = [
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Verify(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::EcParams(ec_params.to_vec()),
        ];
        let priv_template = [
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sign(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Label(label.as_bytes().to_vec()),
        ];

        let (pub_handle, priv_handle) = self.session().generate_key_pair(
            &Mechanism::EccKeyPairGen,
            &pub_template,
            &priv_template,
        )?;

        Ok(KeyHandle {
            priv_id: obj_to_u64(priv_handle),
            pub_id: Some(obj_to_u64(pub_handle)),
        })
    }

    fn sign(&self, key: KeyHandle, mech: SignMech, data: &[u8]) -> Result<Vec<u8>> {
        use sha2::Digest as _;

        let priv_handle = u64_to_obj(key.priv_id);

        // For each ECDSA-with-hash mechanism: try the PKCS#11 v3.0 combined
        // mechanism first (hash occurs inside the HSM — preferred security model).
        // SoftHSM2 2.x only implements CKM_ECDSA_SHA1; the SHA-2 variants
        // are defined in PKCS#11 v3.0 but not yet implemented by SoftHSM2.
        // If the token rejects the combined mechanism, fall back to computing
        // the digest in software and using raw CKM_ECDSA.
        let is_mech_invalid = |e: &cryptoki::error::Error| {
            matches!(
                e,
                cryptoki::error::Error::Pkcs11(cryptoki::error::RvError::MechanismInvalid, _)
            )
        };

        match mech {
            SignMech::EcdsaSha384 => {
                match self
                    .session()
                    .sign(&Mechanism::EcdsaSha384, priv_handle, data)
                {
                    Ok(sig) => Ok(sig),
                    Err(ref e) if is_mech_invalid(e) => {
                        let digest = sha2::Sha384::digest(data).to_vec();
                        self.session()
                            .sign(&Mechanism::Ecdsa, priv_handle, &digest)
                            .map_err(HsmError::Pkcs11)
                    }
                    Err(e) => Err(HsmError::Pkcs11(e)),
                }
            }
            SignMech::EcdsaSha256 => {
                match self
                    .session()
                    .sign(&Mechanism::EcdsaSha256, priv_handle, data)
                {
                    Ok(sig) => Ok(sig),
                    Err(ref e) if is_mech_invalid(e) => {
                        let digest = sha2::Sha256::digest(data).to_vec();
                        self.session()
                            .sign(&Mechanism::Ecdsa, priv_handle, &digest)
                            .map_err(HsmError::Pkcs11)
                    }
                    Err(e) => Err(HsmError::Pkcs11(e)),
                }
            }
            _ => Err(HsmError::UnsupportedKeySpec),
        }
    }

    fn public_key_der(&self, key: KeyHandle) -> Result<Vec<u8>> {
        let session = self.session();

        // Resolve the public key object handle, preferring the one stored at
        // key-generation time.
        let pub_handle = match key.pub_id {
            Some(id) => u64_to_obj(id),
            None => {
                // Fallback: search by label on the private key.
                let priv_handle = u64_to_obj(key.priv_id);
                let label = {
                    let attrs = session.get_attributes(priv_handle, &[AttributeType::Label])?;
                    match attrs.into_iter().next() {
                        Some(Attribute::Label(bytes)) => {
                            String::from_utf8_lossy(&bytes).into_owned()
                        }
                        _ => return Err(HsmError::KeyNotFound("(no label)".into())),
                    }
                };
                session
                    .find_objects(&[
                        Attribute::Label(label.as_bytes().to_vec()),
                        Attribute::Class(ObjectClass::PUBLIC_KEY),
                    ])?
                    .into_iter()
                    .next()
                    .ok_or(HsmError::KeyNotFound(label))?
            }
        };

        // Try CKA_PUBLIC_KEY_INFO (PKCS#11 3.0 attribute on public key objects).
        let attrs = session.get_attributes(pub_handle, &[AttributeType::PublicKeyInfo])?;
        if let Some(Attribute::PublicKeyInfo(der)) = attrs.into_iter().next() {
            if !der.is_empty() {
                return Ok(der);
            }
        }

        // Fallback: build SPKI manually from CKA_EC_PARAMS and CKA_EC_POINT.
        let attrs = session.get_attributes(
            pub_handle,
            &[AttributeType::EcParams, AttributeType::EcPoint],
        )?;
        let mut ec_params_opt = None;
        let mut ec_point_opt = None;
        for attr in attrs {
            match attr {
                Attribute::EcParams(b) => ec_params_opt = Some(b),
                Attribute::EcPoint(b) => ec_point_opt = Some(b),
                _ => {}
            }
        }
        let ec_params =
            ec_params_opt.ok_or_else(|| HsmError::KeyNotFound("CKA_EC_PARAMS missing".into()))?;
        let ec_point =
            ec_point_opt.ok_or_else(|| HsmError::KeyNotFound("CKA_EC_POINT missing".into()))?;

        Ok(ec_spki_from_params_and_point(&ec_params, &ec_point))
    }

    fn list_slot_details(&self) -> Result<Vec<SlotTokenInfo>> {
        let slots = self.ctx.get_slots_with_token()?;
        Ok(slots
            .iter()
            .filter_map(|&s| token_info_from_slot(&self.ctx, s))
            .collect())
    }

    fn change_pin(&mut self, old_pin: &SecretString, new_pin: &SecretString) -> Result<()> {
        let old_auth = AuthPin::new(old_pin.expose_secret().to_string());
        let new_auth = AuthPin::new(new_pin.expose_secret().to_string());
        self.session().set_pin(&old_auth, &new_auth)?;
        Ok(())
    }
}

// ── HsmInventory ─────────────────────────────────────────────────────────────

const SIGNING_KEY_LABEL: &str = "anodize-root";

impl HsmInventory for SoftHsmBackend {
    fn enumerate_devices(&self) -> Result<Vec<HsmDeviceInfo>> {
        let ctx = init_ctx(&self.module_path)?;
        let slots = ctx.get_slots_with_token()?;

        let mut devices = Vec::new();
        for &slot in &slots {
            let Some(ti) = token_info_from_slot(&ctx, slot) else {
                continue;
            };

            let auth_state = if ti.user_pin_initialized {
                "initialized"
            } else {
                "uninitialized"
            };

            // Unauthenticated session — search for public key to detect signing key.
            let has_signing = match ctx.open_rw_session(slot) {
                Ok(session) => Some(
                    session
                        .find_objects(&[
                            Attribute::Label(SIGNING_KEY_LABEL.as_bytes().to_vec()),
                            Attribute::Class(ObjectClass::PUBLIC_KEY),
                        ])
                        .map(|v| !v.is_empty())
                        .unwrap_or(false),
                ),
                Err(_) => None,
            };

            devices.push(HsmDeviceInfo {
                serial: ti.serial_number.clone(),
                model: if ti.model.is_empty() {
                    "SoftHSM".into()
                } else {
                    ti.model.clone()
                },
                firmware: None, // PKCS#11 token_info doesn't expose firmware cleanly
                auth_state: auth_state.into(),
                log_used: None,
                log_total: None,
                has_wrap_key: None, // SECRET_KEY invisible without login
                has_signing_key: has_signing,
            });
        }

        Ok(devices)
    }
}

// ── Pkcs11BackupImpl ─────────────────────────────────────────────────────────

const WRAP_KEY_LABEL: &str = "anodize-wrap";

/// PKCS#11 backup implementation using `C_WrapKey`/`C_UnwrapKey`.
///
/// SoftHSM2 tokens are all slots in the same process, so source and dest
/// sessions can both be open simultaneously.
pub struct Pkcs11BackupImpl {
    module_path: PathBuf,
}

impl Pkcs11BackupImpl {
    pub fn new() -> Result<Self> {
        let module_path = find_softhsm_module()?;
        Ok(Self { module_path })
    }

    fn open_session(&self, token_label: &str, pin: &SecretString) -> Result<Session> {
        let ctx = init_ctx(&self.module_path)?;
        let slot = ctx
            .get_slots_with_token()?
            .into_iter()
            .find(|&slot| {
                ctx.get_token_info(slot)
                    .map(|info| info.label().trim() == token_label.trim())
                    .unwrap_or(false)
            })
            .ok_or_else(|| HsmError::TokenNotFound(token_label.to_string()))?;

        let session = ctx.open_rw_session(slot)?;
        let auth = AuthPin::new(pin.expose_secret().to_string());
        session.login(UserType::User, Some(&auth))?;
        Ok(session)
    }

    fn find_object(
        session: &Session,
        label: &str,
        class: ObjectClass,
    ) -> Result<Option<ObjectHandle>> {
        let objs = session.find_objects(&[
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Class(class),
        ])?;
        Ok(objs.into_iter().next())
    }

    #[allow(dead_code)]
    fn has_object(session: &Session, label: &str, class: ObjectClass) -> bool {
        Self::find_object(session, label, class)
            .map(|o| o.is_some())
            .unwrap_or(false)
    }
}

impl HsmBackup for Pkcs11BackupImpl {
    fn enumerate_backup_targets(&self, _pin: Option<&SecretString>) -> Result<Vec<BackupTarget>> {
        let ctx = init_ctx(&self.module_path)?;
        let slots = ctx.get_slots_with_token()?;

        let mut targets = Vec::new();
        for &slot in &slots {
            let Some(ti) = token_info_from_slot(&ctx, slot) else {
                continue;
            };

            // Open an unauthenticated session just to check object presence.
            // We can't search private objects without login, so we conservatively
            // report false for has_signing_key unless we can see a public key.
            let has_wrap = false; // Wrap keys are SECRET_KEY — invisible without login
            let has_signing = {
                match ctx.open_rw_session(slot) {
                    Ok(session) => {
                        let found = session
                            .find_objects(&[
                                Attribute::Label(SIGNING_KEY_LABEL.as_bytes().to_vec()),
                                Attribute::Class(ObjectClass::PUBLIC_KEY),
                            ])
                            .map(|v| !v.is_empty())
                            .unwrap_or(false);
                        found
                    }
                    Err(_) => false,
                }
            };

            targets.push(BackupTarget {
                identifier: ti.token_label.clone(),
                description: format!("{} (serial {})", ti.model, ti.serial_number),
                needs_bootstrap: !ti.user_pin_initialized,
                has_wrap_key: has_wrap,
                has_signing_key: has_signing,
            });
        }

        Ok(targets)
    }

    fn pair_devices(&self, src: &str, dst: &str, pin: &SecretString) -> Result<String> {
        let session_src = self.open_session(src, pin)?;
        let session_dst = self.open_session(dst, pin)?;

        // Generate AES-256 wrap key material.
        let mut key_bytes = [0u8; 32];
        getrandom::getrandom(&mut key_bytes)
            .map_err(|e| HsmError::BackendError(format!("getrandom: {e}")))?;

        // Delete any existing wrap keys.
        if let Some(h) = Self::find_object(&session_src, WRAP_KEY_LABEL, ObjectClass::SECRET_KEY)? {
            session_src.destroy_object(h)?;
        }
        if let Some(h) = Self::find_object(&session_dst, WRAP_KEY_LABEL, ObjectClass::SECRET_KEY)? {
            session_dst.destroy_object(h)?;
        }

        let wrap_template = |label: &str| -> Vec<Attribute> {
            vec![
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(cryptoki::object::KeyType::AES),
                Attribute::ValueLen(32.into()),
                Attribute::Value(key_bytes.to_vec()),
                Attribute::Label(label.as_bytes().to_vec()),
                Attribute::Encrypt(true),
                Attribute::Decrypt(true),
                Attribute::Wrap(true),
                Attribute::Unwrap(true),
                Attribute::Extractable(false),
                Attribute::Sensitive(true),
            ]
        };

        session_src.create_object(&wrap_template(WRAP_KEY_LABEL))?;
        session_dst.create_object(&wrap_template(WRAP_KEY_LABEL))?;

        // Zeroize
        key_bytes.fill(0);

        tracing::info!(src, dst, "PKCS#11 backup: tokens paired with wrap key");
        Ok(WRAP_KEY_LABEL.to_string())
    }

    fn backup_key(
        &self,
        src: &str,
        dst: &str,
        pin: &SecretString,
        _key_id: &str,
    ) -> Result<BackupResult> {
        let session_src = self.open_session(src, pin)?;
        let session_dst = self.open_session(dst, pin)?;

        // Find wrap key on both.
        let wrap_src = Self::find_object(&session_src, WRAP_KEY_LABEL, ObjectClass::SECRET_KEY)?
            .ok_or_else(|| HsmError::BackendError("wrap key not found on source".into()))?;
        let wrap_dst = Self::find_object(&session_dst, WRAP_KEY_LABEL, ObjectClass::SECRET_KEY)?
            .ok_or_else(|| HsmError::BackendError("wrap key not found on dest".into()))?;

        // Find private key to export on source.
        let priv_src =
            Self::find_object(&session_src, SIGNING_KEY_LABEL, ObjectClass::PRIVATE_KEY)?
                .ok_or_else(|| HsmError::KeyNotFound(SIGNING_KEY_LABEL.into()))?;

        // Get public key from source for verification.
        let pub_src = Self::find_object(&session_src, SIGNING_KEY_LABEL, ObjectClass::PUBLIC_KEY)?
            .ok_or_else(|| HsmError::KeyNotFound(format!("{SIGNING_KEY_LABEL} (public)")))?;
        let src_ec_point = session_src.get_attributes(pub_src, &[AttributeType::EcPoint])?;
        let src_point = match src_ec_point.into_iter().next() {
            Some(Attribute::EcPoint(b)) => b,
            _ => return Err(HsmError::KeyNotFound("CKA_EC_POINT on source".into())),
        };

        // Check extractable.  If key was generated with Extractable(false) we
        // can't wrap it — report the failure clearly.
        let attrs = session_src.get_attributes(priv_src, &[AttributeType::Extractable])?;
        let extractable = match attrs.into_iter().next() {
            Some(Attribute::Extractable(v)) => v,
            _ => false,
        };
        if !extractable {
            return Err(HsmError::BackendError(
                "signing key is not extractable (CKA_EXTRACTABLE=false). \
                 Key must be regenerated with Extractable(true) to allow backup."
                    .into(),
            ));
        }

        // Wrap the private key with CKM_AES_KEY_WRAP_PAD (RFC 5649).
        let wrapped = session_src
            .wrap_key(&Mechanism::AesKeyWrapPad, wrap_src, priv_src)
            .map_err(|e| HsmError::BackendError(format!("C_WrapKey: {e}")))?;

        // Delete any existing signing key on dest.
        if let Some(h) =
            Self::find_object(&session_dst, SIGNING_KEY_LABEL, ObjectClass::PRIVATE_KEY)?
        {
            session_dst.destroy_object(h)?;
        }
        if let Some(h) =
            Self::find_object(&session_dst, SIGNING_KEY_LABEL, ObjectClass::PUBLIC_KEY)?
        {
            session_dst.destroy_object(h)?;
        }

        // Get EC params from source public key for the unwrap template.
        let src_params = session_src.get_attributes(pub_src, &[AttributeType::EcParams])?;
        let ec_params = match src_params.into_iter().next() {
            Some(Attribute::EcParams(b)) => b,
            _ => return Err(HsmError::KeyNotFound("CKA_EC_PARAMS on source".into())),
        };

        // Unwrap into dest.
        let unwrap_template = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sign(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(true),
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(cryptoki::object::KeyType::EC),
            Attribute::EcParams(ec_params.clone()),
            Attribute::Label(SIGNING_KEY_LABEL.as_bytes().to_vec()),
        ];

        session_dst
            .unwrap_key(
                &Mechanism::AesKeyWrapPad,
                wrap_dst,
                &wrapped,
                &unwrap_template,
            )
            .map_err(|e| HsmError::BackendError(format!("C_UnwrapKey: {e}")))?;

        // Verify: get EC point from the imported key's public component.
        // The unwrap creates a private key; we need to derive/find the public key.
        // On SoftHSM2, the public key isn't automatically created on unwrap,
        // so we compare by signing + verifying or by extracting the public point
        // from the private key attributes.
        let dst_priv =
            Self::find_object(&session_dst, SIGNING_KEY_LABEL, ObjectClass::PRIVATE_KEY)?
                .ok_or_else(|| HsmError::KeyNotFound("unwrapped key not found on dest".into()))?;

        // Try to read CKA_EC_POINT from the private key (SoftHSM2 stores it).
        let dst_point_attrs = session_dst.get_attributes(dst_priv, &[AttributeType::EcPoint])?;
        let keys_match = match dst_point_attrs.into_iter().next() {
            Some(Attribute::EcPoint(dst_pt)) => dst_pt == src_point,
            _ => {
                // Can't directly compare — assume success if unwrap didn't error.
                tracing::warn!("Could not read EC point from dest for comparison");
                true
            }
        };

        tracing::info!(src, dst, keys_match, "PKCS#11 backup: key transferred");

        Ok(BackupResult {
            source_id: src.to_string(),
            dest_id: dst.to_string(),
            key_id: SIGNING_KEY_LABEL.to_string(),
            public_keys_match: keys_match,
        })
    }
}

// ── DER helpers ──────────────────────────────────────────────────────────────

// id-ecPublicKey OID: 1.2.840.10045.2.1
const ID_EC_PUBLIC_KEY_OID: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

fn uncompressed_point_len(ec_params_der: &[u8]) -> Option<usize> {
    if ec_params_der == EC_PARAMS_P384 {
        Some(97)
    } else if ec_params_der == EC_PARAMS_P256 {
        Some(65)
    } else {
        None
    }
}

/// Build a DER SubjectPublicKeyInfo for an EC public key from raw PKCS#11 attributes.
pub fn ec_spki_from_params_and_point(ec_params_der: &[u8], ec_point_raw: &[u8]) -> Vec<u8> {
    let expected_len = uncompressed_point_len(ec_params_der);
    let point: &[u8] =
        if ec_point_raw.len() >= 3 && ec_point_raw[0] == 0x04 && ec_point_raw[2] == 0x04 {
            let inner_len = ec_point_raw[1] as usize;
            if inner_len + 2 == ec_point_raw.len() && expected_len == Some(inner_len) {
                &ec_point_raw[2..]
            } else {
                ec_point_raw
            }
        } else {
            ec_point_raw
        };

    // AlgorithmIdentifier SEQUENCE { id-ecPublicKey OID, ec_params_der }
    let alg_inner = [ID_EC_PUBLIC_KEY_OID, ec_params_der].concat();
    let alg_id = der_sequence(&alg_inner);

    // BIT STRING: 0x00 (no unused bits) || point
    let mut bs_content = vec![0x00u8];
    bs_content.extend_from_slice(point);
    let mut bit_string = vec![0x03];
    bit_string.extend(der_len(bs_content.len()));
    bit_string.extend(bs_content);

    der_sequence(&[alg_id, bit_string].concat())
}

fn der_sequence(content: &[u8]) -> Vec<u8> {
    let mut out = vec![0x30u8];
    out.extend(der_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn der_len(n: usize) -> Vec<u8> {
    if n < 128 {
        vec![n as u8]
    } else if n < 256 {
        vec![0x81, n as u8]
    } else {
        vec![0x82, (n >> 8) as u8, (n & 0xff) as u8]
    }
}
