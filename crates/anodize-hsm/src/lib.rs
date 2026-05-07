pub mod softhsm;
pub mod yubihsm_backend;

pub use softhsm::{Pkcs11Hsm, Pkcs11Module, SoftHsmBackend};
pub use yubihsm_backend::YubiHsmBackend;

use anodize_config::HsmBackendKind;
use secrecy::SecretString;
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
    #[error("PKCS#11 module {0:?} not found in search paths")]
    ModuleNotFound(String),
    #[error("HSM backend error: {0}")]
    BackendError(String),
}

pub type Result<T> = std::result::Result<T, HsmError>;

/// Diagnostic info for a single slot + token pair.
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
/// Stores backend-specific numeric IDs. For PKCS#11 these are transmuted
/// `ObjectHandle` values; for YubiHSM they are native object IDs widened
/// to u64.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyHandle {
    pub(crate) priv_id: u64,
    pub(crate) pub_id: Option<u64>,
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

/// Abstraction over a hardware or software HSM session.
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

    /// List all populated slots/tokens visible to this session (optional).
    fn list_slot_details(&self) -> Result<Vec<SlotTokenInfo>> {
        Ok(Vec::new())
    }
}

/// Pluggable HSM backend — covers the full lifecycle: discover devices,
/// bootstrap a fresh token, and open an authenticated session.
pub trait HsmBackend: Send {
    /// Enumerate all visible tokens/devices.
    fn list_tokens(&self) -> Result<Vec<SlotTokenInfo>>;

    /// Check whether a token with the given label exists.
    fn probe_token(&self, label: &str) -> Result<bool>;

    /// Open an existing token by label and authenticate with `pin`.
    /// Returns a ready-to-use `Hsm` session.
    fn open_session(&self, label: &str, pin: &SecretString) -> Result<Box<dyn Hsm>>;

    /// Bootstrap a fresh token: initialise, set PIN, return authenticated
    /// session. Used during InitRoot.
    fn bootstrap(
        &self,
        slot_id: u64,
        so_pin: &SecretString,
        user_pin: &SecretString,
        label: &str,
    ) -> Result<Box<dyn Hsm>>;
}

/// Instantiate the appropriate backend for the given model.
pub fn create_backend(kind: HsmBackendKind) -> Result<Box<dyn HsmBackend>> {
    match kind {
        HsmBackendKind::Softhsm => Ok(Box::new(SoftHsmBackend::new()?)),
        HsmBackendKind::Yubihsm => Ok(Box::new(YubiHsmBackend::new()?)),
    }
}

// ---------------------------------------------------------------------------
// HsmActor — serialises all HSM calls onto a dedicated thread.
//
// PKCS#11's C_Initialize is process-global and cryptoki's Session contains
// a raw pointer (*mut u32), making Pkcs11Hsm !Sync. The actor pattern solves
// this structurally: the Hsm impl never leaves its thread, and callers
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

fn actor_loop(mut hsm: Box<dyn Hsm>, rx: std::sync::mpsc::Receiver<HsmRequest>) {
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

/// `Send + Sync` wrapper around any `Hsm` implementation that serialises all
/// calls onto a single dedicated thread via a rendezvous channel.
///
/// `Clone` gives a second handle to the same underlying session; callers share
/// the session safely because all requests are serialised on the actor thread.
#[derive(Clone)]
pub struct HsmActor {
    tx: std::sync::mpsc::SyncSender<HsmRequest>,
}

impl HsmActor {
    /// Spawn the actor thread and return a handle. The underlying `Hsm`
    /// is owned exclusively by the actor thread for its lifetime.
    pub fn spawn(hsm: Box<dyn Hsm>) -> Self {
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
