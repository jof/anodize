use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, AttributeType, ObjectClass},
    session::Session,
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
    #[error("HSM actor thread died unexpectedly")]
    ActorDead,
}

pub type Result<T> = std::result::Result<T, HsmError>;

/// Opaque handle to a key object on the HSM (stores the private key handle).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyHandle(pub(crate) cryptoki::object::ObjectHandle);

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
// PKCS#11 backend
// ---------------------------------------------------------------------------

pub struct Pkcs11Hsm {
    #[allow(dead_code)]
    ctx: Pkcs11,
    session: Option<Session>,
}

impl Pkcs11Hsm {
    /// Open the PKCS#11 module at `module_path` and find the slot whose token
    /// label matches `token_label`. Does not log in; call `login()` next.
    pub fn new(module_path: &std::path::Path, token_label: &str) -> Result<Self> {
        let ctx = Pkcs11::new(module_path)?;
        ctx.initialize(CInitializeArgs::OsThreads)?;

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

    /// List all slots with a token present — useful for diagnostics and tests.
    pub fn list_slots(module_path: &std::path::Path) -> Result<Vec<cryptoki::slot::Slot>> {
        let ctx = Pkcs11::new(module_path)?;
        ctx.initialize(CInitializeArgs::OsThreads)?;
        Ok(ctx.get_slots_with_token()?)
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
        let handles = self.session().find_objects(&[
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Class(ObjectClass::PRIVATE_KEY),
        ])?;
        handles
            .into_iter()
            .next()
            .map(KeyHandle)
            .ok_or_else(|| HsmError::KeyNotFound(label.to_string()))
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

        let (_, priv_handle) = self.session().generate_key_pair(
            &Mechanism::EccKeyPairGen,
            &pub_template,
            &priv_template,
        )?;

        Ok(KeyHandle(priv_handle))
    }

    fn sign(&self, key: KeyHandle, mech: SignMech, data: &[u8]) -> Result<Vec<u8>> {
        let mechanism = match mech {
            SignMech::EcdsaSha384 => Mechanism::EcdsaSha384,
            SignMech::EcdsaSha256 => Mechanism::EcdsaSha256,
            _ => return Err(HsmError::UnsupportedKeySpec),
        };
        Ok(self.session().sign(&mechanism, key.0, data)?)
    }

    fn public_key_der(&self, key: KeyHandle) -> Result<Vec<u8>> {
        let session = self.session();

        // Try CKA_PUBLIC_KEY_INFO on the private key handle (PKCS#11 3.0).
        // SoftHSM2 2.6+ and YubiHSM 2 both support this.
        let attrs = session.get_attributes(key.0, &[AttributeType::PublicKeyInfo])?;
        if let Some(Attribute::PublicKeyInfo(der)) = attrs.into_iter().next() {
            if !der.is_empty() {
                return Ok(der);
            }
        }

        // Fallback: find the corresponding public key object by label and
        // read CKA_PUBLIC_KEY_INFO from that object.
        let label = {
            let attrs = session.get_attributes(key.0, &[AttributeType::Label])?;
            match attrs.into_iter().next() {
                Some(Attribute::Label(bytes)) => String::from_utf8_lossy(&bytes).into_owned(),
                _ => return Err(HsmError::KeyNotFound("(no label)".into())),
            }
        };

        let pub_handles = session.find_objects(&[
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Class(ObjectClass::PUBLIC_KEY),
        ])?;
        let pub_handle = pub_handles
            .into_iter()
            .next()
            .ok_or_else(|| HsmError::KeyNotFound(label.clone()))?;

        let attrs = session.get_attributes(pub_handle, &[AttributeType::PublicKeyInfo])?;
        match attrs.into_iter().next() {
            Some(Attribute::PublicKeyInfo(der)) if !der.is_empty() => Ok(der),
            _ => Err(HsmError::KeyNotFound(label)),
        }
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
            HsmRequest::Sign { key, mech, data, tx } => {
                let _ = tx.send(hsm.sign(key, mech, &data));
            }
            HsmRequest::PublicKeyDer { key, tx } => {
                let _ = tx.send(hsm.public_key_der(key));
            }
        }
    }
}

/// `Send + Sync` wrapper around `Pkcs11Hsm` that serialises all PKCS#11 calls
/// onto a single dedicated thread via a rendezvous channel.
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
