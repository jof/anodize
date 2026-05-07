use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, AttributeType, ObjectClass},
    session::{Session, UserType},
    types::AuthPin,
};
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HsmError {
    #[error("PKCS#11 error: {0}")]
    Pkcs11(#[from] cryptoki::error::Error),
    #[error("key not found: label={0}")]
    KeyNotFound(String),
    #[error("token not found: label={0}")]
    TokenNotFound(String),
    #[error("operation not supported for this key spec")]
    UnsupportedKeySpec,
    /// The HSM does not support the requested signing mechanism (e.g.
    /// CKM_ECDSA_SHA384 on an older SoftHSM2 build). Production hardware
    /// (YubiHSM 2) and Nix-packaged SoftHSM2 both support it.
    #[error("HSM does not support mechanism: {0}")]
    MechanismUnsupported(String),
    #[error("HSM actor thread died unexpectedly")]
    ActorDead,
}

pub type Result<T> = std::result::Result<T, HsmError>;

/// Diagnostic info for a single PKCS#11 slot + token pair.
#[derive(Debug, Clone)]
pub struct SlotTokenInfo {
    pub slot_id: u64,
    pub token_label: String,
    pub model: String,
    pub serial_number: String,
    pub login_required: bool,
    pub user_pin_initialized: bool,
    pub user_pin_locked: bool,
    pub min_pin_len: usize,
    pub max_pin_len: usize,
    pub token_initialized: bool,
}

/// Opaque handle to a key pair on the HSM.
///
/// Stores the private key handle (always present) and, when the pair was
/// generated in this session, the matching public key handle. Having the
/// public handle lets `public_key_der` read `CKA_PUBLIC_KEY_INFO` directly
/// rather than searching for the public object by label (which can fail on
/// some SoftHSM2 builds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyHandle {
    pub(crate) priv_handle: cryptoki::object::ObjectHandle,
    pub(crate) pub_handle: Option<cryptoki::object::ObjectHandle>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySpec {
    EcdsaP384,
    EcdsaP256,
    Ed25519,
    Rsa4096,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignMech {
    EcdsaSha384,
    EcdsaSha256,
    EdDsa,
    RsaPkcs1Sha256,
    RsaPssSha256,
}

/// Abstraction over a hardware or software HSM.
///
/// All signing operations happen inside the HSM; private key material never
/// crosses this boundary into the calling process.
pub trait Hsm: Send {
    fn login(&mut self, pin: &SecretString) -> Result<()>;
    fn logout(&mut self) -> Result<()>;

    fn find_key(&self, label: &str) -> Result<KeyHandle>;
    fn generate_keypair(&mut self, label: &str, spec: KeySpec) -> Result<KeyHandle>;

    /// Sign `data` with the given key. For ECDSA/RSA, `data` is the raw bytes
    /// to be hashed-then-signed by the HSM. For EdDSA, `data` is the message.
    fn sign(&self, key: KeyHandle, mech: SignMech, data: &[u8]) -> Result<Vec<u8>>;

    /// Return the DER-encoded SubjectPublicKeyInfo for the given key handle.
    fn public_key_der(&self, key: KeyHandle) -> Result<Vec<u8>>;
}

// ---------------------------------------------------------------------------
// Shared initialisation helper
// ---------------------------------------------------------------------------

fn init_ctx(module_path: &std::path::Path) -> Result<Pkcs11> {
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
        Ok(Self { ctx: init_ctx(module_path)? })
    }

    /// Enumerate all slots that have a token present.
    pub fn list_tokens(&self) -> Result<Vec<SlotTokenInfo>> {
        let slots = self.ctx.get_slots_with_token()?;
        let mut result = Vec::new();
        for slot in slots {
            if let Ok(ti) = self.ctx.get_token_info(slot) {
                result.push(SlotTokenInfo {
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
                });
            }
        }
        Ok(result)
    }

    /// Bootstrap a token and return an authenticated `Pkcs11Hsm`.
    ///
    /// Two strategies are attempted:
    ///
    /// 1. **C_InitToken path** (SoftHSM, generic PKCS#11): `C_InitToken` →
    ///    SO login → `C_InitPIN` → user login.
    /// 2. **SetPIN fallback** (YubiHSM2 and devices that don't support
    ///    `C_InitToken`): login with `factory_pin` → `C_SetPIN` to
    ///    `user_pin` → re-login with new PIN.
    ///
    /// `slot_id`     — target slot (from `list_tokens`).
    /// `so_pin`      — Security Officer PIN (used as SO PIN if C_InitToken
    ///                  succeeds).
    /// `user_pin`    — User PIN to set (the SSS-reconstructed secret).
    /// `factory_pin` — optional factory-default PIN for fallback path
    ///                  (e.g. "0001password" for YubiHSM2).
    /// `label`       — desired token label (e.g. "anodize-root-2026").
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

        // Strategy 2: login with factory PIN, then C_SetPIN.
        let old_pin = factory_pin.ok_or_else(|| {
            HsmError::TokenNotFound(
                "C_InitToken not supported and no factory_pin configured".to_string(),
            )
        })?;
        let old_auth = AuthPin::new(old_pin.expose_secret().to_string());

        let session = self.ctx.open_rw_session(slot)?;
        session.login(UserType::User, Some(&old_auth))?;
        session.set_pin(&old_auth, &user_auth)?;
        session.logout()?;

        // Re-login with new PIN.
        session.login(UserType::User, Some(&user_auth))?;
        tracing::info!("bootstrap_token: SetPIN fallback succeeded");

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

    /// Return detailed slot + token info for every populated slot.
    pub fn list_slot_details(&self) -> Result<Vec<SlotTokenInfo>> {
        let slots = self.ctx.get_slots_with_token()?;
        let mut result = Vec::new();
        for slot in slots {
            if let Ok(ti) = self.ctx.get_token_info(slot) {
                result.push(SlotTokenInfo {
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
                });
            }
        }
        Ok(result)
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
            priv_handle,
            pub_handle,
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
            priv_handle,
            pub_handle: Some(pub_handle),
        })
    }

    fn sign(&self, key: KeyHandle, mech: SignMech, data: &[u8]) -> Result<Vec<u8>> {
        use sha2::Digest as _;

        // For each ECDSA-with-hash mechanism: try the PKCS#11 v3.0 combined
        // mechanism first (hash occurs inside the HSM — preferred security model).
        // SoftHSM2 2.x only implements CKM_ECDSA_SHA1; the SHA-2 variants
        // (CKM_ECDSA_SHA256, CKM_ECDSA_SHA384, …) are defined in PKCS#11 v3.0
        // but not yet implemented by SoftHSM2. If the token rejects the
        // combined mechanism, fall back to computing the digest in software
        // and using raw CKM_ECDSA. YubiHSM 2 (production hardware) supports
        // the combined mechanisms and never hits the fallback.
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
                    .sign(&Mechanism::EcdsaSha384, key.priv_handle, data)
                {
                    Ok(sig) => Ok(sig),
                    Err(ref e) if is_mech_invalid(e) => {
                        let digest = sha2::Sha384::digest(data).to_vec();
                        self.session()
                            .sign(&Mechanism::Ecdsa, key.priv_handle, &digest)
                            .map_err(HsmError::Pkcs11)
                    }
                    Err(e) => Err(HsmError::Pkcs11(e)),
                }
            }
            SignMech::EcdsaSha256 => {
                match self
                    .session()
                    .sign(&Mechanism::EcdsaSha256, key.priv_handle, data)
                {
                    Ok(sig) => Ok(sig),
                    Err(ref e) if is_mech_invalid(e) => {
                        let digest = sha2::Sha256::digest(data).to_vec();
                        self.session()
                            .sign(&Mechanism::Ecdsa, key.priv_handle, &digest)
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
        // key-generation time (avoids a label-based search that can fail on some
        // SoftHSM2 builds when CKA_LABEL matching behaves unexpectedly).
        let pub_handle = match key.pub_handle {
            Some(h) => h,
            None => {
                // Fallback: search by label on the private key.
                let label = {
                    let attrs = session.get_attributes(key.priv_handle, &[AttributeType::Label])?;
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
        // SoftHSM2 2.6.x on Ubuntu returns this as empty for EC keys; fall through if so.
        let attrs = session.get_attributes(pub_handle, &[AttributeType::PublicKeyInfo])?;
        if let Some(Attribute::PublicKeyInfo(der)) = attrs.into_iter().next() {
            if !der.is_empty() {
                return Ok(der);
            }
        }

        // Fallback: build SPKI manually from CKA_EC_PARAMS and CKA_EC_POINT.
        // Needed for SoftHSM2 2.6.x builds that do not populate CKA_PUBLIC_KEY_INFO.
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
}

// id-ecPublicKey OID: 1.2.840.10045.2.1
const ID_EC_PUBLIC_KEY_OID: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

/// Return the expected byte length of an uncompressed EC point for a known
/// curve's DER params, or `None` for an unrecognised curve.
///
/// Uncompressed point: 0x04 || X(coord_bytes) || Y(coord_bytes)
/// P-256: 1 + 32 + 32 = 65 bytes
/// P-384: 1 + 48 + 48 = 97 bytes
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
///
/// `ec_params_der` is the DER-encoded curve OID (from CKA_EC_PARAMS).
/// `ec_point_raw` is the EC point from CKA_EC_POINT; some implementations wrap
/// it in a DER OCTET STRING — we unwrap if needed.
fn ec_spki_from_params_and_point(ec_params_der: &[u8], ec_point_raw: &[u8]) -> Vec<u8> {
    // Some PKCS#11 implementations return CKA_EC_POINT wrapped in a DER OCTET STRING
    // (tag 0x04 + length byte + inner point). Strip the wrapper only when:
    //   [0] == 0x04  (DER OCTET STRING tag)
    //   [1]          inner length byte
    //   [2] == 0x04  inner: uncompressed point marker
    //   inner_len + 2 == total length     (length byte is consistent)
    //   inner_len == expected point size  (matches the known curve)
    //
    // The last check eliminates the 1-in-65536 false-positive where a raw
    // P-384 point has X[0]==95 and X[1]==0x04, which would otherwise satisfy
    // the earlier structural conditions.
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

// ---------------------------------------------------------------------------
// HsmActor — serialises all PKCS#11 calls onto a dedicated thread.
//
// PKCS#11's C_Initialize is process-global and cryptoki's Session contains
// a raw pointer (*mut u32), making Pkcs11Hsm !Sync. The actor pattern solves
// this structurally: Pkcs11Hsm never leaves its thread, and callers
// communicate through a channel.  HsmActor is Send + Sync and can be shared
// freely across threads.
// ---------------------------------------------------------------------------

enum HsmRequest {
    Login {
        pin: SecretString,
        tx: std::sync::mpsc::SyncSender<Result<()>>,
    },
    Logout {
        tx: std::sync::mpsc::SyncSender<Result<()>>,
    },
    FindKey {
        label: String,
        tx: std::sync::mpsc::SyncSender<Result<KeyHandle>>,
    },
    GenerateKeypair {
        label: String,
        spec: KeySpec,
        tx: std::sync::mpsc::SyncSender<Result<KeyHandle>>,
    },
    Sign {
        key: KeyHandle,
        mech: SignMech,
        data: Vec<u8>,
        tx: std::sync::mpsc::SyncSender<Result<Vec<u8>>>,
    },
    PublicKeyDer {
        key: KeyHandle,
        tx: std::sync::mpsc::SyncSender<Result<Vec<u8>>>,
    },
    ListSlotDetails {
        tx: std::sync::mpsc::SyncSender<Result<Vec<SlotTokenInfo>>>,
    },
}

fn actor_loop(mut hsm: Pkcs11Hsm, rx: std::sync::mpsc::Receiver<HsmRequest>) {
    for req in rx {
        match req {
            HsmRequest::Login { pin, tx } => {
                let _ = tx.send(hsm.login(&pin));
            }
            HsmRequest::Logout { tx } => {
                let _ = tx.send(hsm.logout());
            }
            HsmRequest::FindKey { label, tx } => {
                let _ = tx.send(hsm.find_key(&label));
            }
            HsmRequest::GenerateKeypair { label, spec, tx } => {
                let _ = tx.send(hsm.generate_keypair(&label, spec));
            }
            HsmRequest::Sign {
                key,
                mech,
                data,
                tx,
            } => {
                let _ = tx.send(hsm.sign(key, mech, &data));
            }
            HsmRequest::PublicKeyDer { key, tx } => {
                let _ = tx.send(hsm.public_key_der(key));
            }
            HsmRequest::ListSlotDetails { tx } => {
                let _ = tx.send(hsm.list_slot_details());
            }
        }
    }
}

/// `Send + Sync` wrapper around `Pkcs11Hsm` that serialises all PKCS#11 calls
/// onto a single dedicated thread via a rendezvous channel.
///
/// `Clone` gives a second handle to the same underlying session; callers share
/// the session safely because all requests are serialised on the actor thread.
#[derive(Clone)]
pub struct HsmActor {
    tx: std::sync::mpsc::SyncSender<HsmRequest>,
}

impl HsmActor {
    /// Spawn the actor thread and return a handle. The underlying `Pkcs11Hsm`
    /// is owned exclusively by the actor thread for its lifetime.
    pub fn spawn(hsm: Pkcs11Hsm) -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel(8);
        std::thread::Builder::new()
            .name("hsm-actor".into())
            .spawn(move || actor_loop(hsm, rx))
            .expect("failed to spawn HSM actor thread");
        Self { tx }
    }

    /// Return detailed slot + token info for every populated slot,
    /// routed through the actor thread.
    pub fn list_slot_details(&self) -> Result<Vec<SlotTokenInfo>> {
        self.call(|tx| HsmRequest::ListSlotDetails { tx })
    }

    fn call<T: Send + 'static>(
        &self,
        make_req: impl FnOnce(std::sync::mpsc::SyncSender<Result<T>>) -> HsmRequest,
    ) -> Result<T> {
        let (reply_tx, reply_rx) = std::sync::mpsc::sync_channel(1);
        self.tx
            .send(make_req(reply_tx))
            .map_err(|_| HsmError::ActorDead)?;
        reply_rx.recv().map_err(|_| HsmError::ActorDead)?
    }
}

impl Hsm for HsmActor {
    fn login(&mut self, pin: &SecretString) -> Result<()> {
        self.call(|tx| HsmRequest::Login {
            pin: pin.clone(),
            tx,
        })
    }

    fn logout(&mut self) -> Result<()> {
        self.call(|tx| HsmRequest::Logout { tx })
    }

    fn find_key(&self, label: &str) -> Result<KeyHandle> {
        self.call(|tx| HsmRequest::FindKey {
            label: label.to_string(),
            tx,
        })
    }

    fn generate_keypair(&mut self, label: &str, spec: KeySpec) -> Result<KeyHandle> {
        self.call(|tx| HsmRequest::GenerateKeypair {
            label: label.to_string(),
            spec,
            tx,
        })
    }

    fn sign(&self, key: KeyHandle, mech: SignMech, data: &[u8]) -> Result<Vec<u8>> {
        self.call(|tx| HsmRequest::Sign {
            key,
            mech,
            data: data.to_vec(),
            tx,
        })
    }

    fn public_key_der(&self, key: KeyHandle) -> Result<Vec<u8>> {
        self.call(|tx| HsmRequest::PublicKeyDer { key, tx })
    }
}
