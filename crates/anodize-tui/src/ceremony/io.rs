//! The ceremony effect vocabulary.
//!
//! A ceremony script is a straight-line function written against the three
//! traits in this module — [`Operator`] (the human), [`Vault`] (the HSM), and
//! [`Archive`] (optical disc + shuttle USB). In production these are backed by
//! the real TUI/HSM/media adapters; in tests they are backed by scripted fakes.
//!
//! The script never knows whether it is talking to a terminal or a test
//! harness, which is the whole point: the same `fn` is exercised by the
//! transcript test and by the live ceremony.
//!
//! Irreversible ordering is enforced two ways:
//! 1. **Source order** — the script runs top to bottom; an early `?` on
//!    [`Abort`] short-circuits before any later effect can run.
//! 2. **Typestate** — [`IntentCommitted`] / [`RecordCommitted`] are tokens with
//!    private fields that only an [`Archive`] impl can mint. You cannot commit a
//!    record without proving the intent was committed, nor export to shuttle
//!    without proving the record was committed (the disc-before-shuttle
//!    invariant, by type).

use anodize_config::state::SssMetadata;
use anodize_config::RevocationEntry;
use secrecy::SecretString;

// ── shared value types ──────────────────────────────────────────────────────

/// The operator aborted the ceremony (quit, cancel, or a failed quorum).
///
/// Propagated via `?`; unwinding the script runs every RAII guard on the way
/// out (HSM logout, PIN zeroization).
#[derive(Debug, Clone)]
pub struct Abort(pub String);

impl Abort {
    pub fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }
}

impl std::fmt::Display for Abort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A reconstructed HSM PIN (hex string). Zeroized on drop by `SecretString`.
pub type Pin = SecretString;

/// A confirmed signing timestamp.
pub type Timestamp = std::time::SystemTime;

/// One selectable option in a [`Operator::choose`] prompt.
#[derive(Debug, Clone)]
pub struct Choice {
    pub key: char,
    pub label: String,
}

/// The result of a completed ceremony, rendered on the done screen.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub headline: String,
    pub detail: Vec<String>,
}

// ── operation context (read-only inputs gathered before the script runs) ──────

/// Everything an `IssueCrl` ceremony needs to know up front.
#[derive(Debug, Clone)]
pub struct CrlPlan {
    pub crl_number: u64,
    pub revocation_list: Vec<RevocationEntry>,
    pub root_cert_der: Vec<u8>,
}

/// A revocation: pick a certificate (or enter a serial), then re-sign the CRL.
#[derive(Debug, Clone)]
pub struct RevokePlan {
    pub cert_list: Vec<crate::disc::CertSummary>,
    pub revocation_list: Vec<RevocationEntry>,
    pub crl_number: u64,
    pub root_cert_der: Vec<u8>,
}

/// One selectable certificate profile, pre-rendered by the App (the script
/// stays free of `Profile`/preview-building concerns).
#[derive(Debug, Clone)]
pub struct CsrProfileChoice {
    pub name: String,
    pub label: String,
    pub validity_days: u32,
    pub path_len: Option<u8>,
    pub preview: Vec<String>,
}

/// Sign an intermediate CSR (loaded from the shuttle) under a chosen profile.
#[derive(Debug, Clone)]
pub struct SignCsrPlan {
    pub csr_der: Vec<u8>,
    pub root_cert_der: Vec<u8>,
    pub cdp_url: Option<String>,
    pub profiles: Vec<CsrProfileChoice>,
    pub existing_serials: Vec<x509_cert::serial_number::SerialNumber>,
}

/// Read-only environment handed to a script, generic over the operation's plan.
/// Built from disc/profile state before the ceremony thread is spawned.
#[derive(Debug, Clone)]
pub struct Env<P> {
    pub sss: SssMetadata,
    pub plan: P,
}

// ── artifacts ─────────────────────────────────────────────────────────────

/// A signed CRL produced by the HSM.
#[derive(Debug, Clone)]
pub struct SignedCrl {
    der: Vec<u8>,
}

impl SignedCrl {
    pub fn new(der: Vec<u8>) -> Self {
        Self { der }
    }
    pub fn der(&self) -> &[u8] {
        &self.der
    }
}

/// A signed intermediate certificate produced by the HSM.
#[derive(Debug, Clone)]
pub struct SignedCert {
    der: Vec<u8>,
}

impl SignedCert {
    pub fn new(der: Vec<u8>) -> Self {
        Self { der }
    }
    pub fn der(&self) -> &[u8] {
        &self.der
    }
}

/// Inputs the HSM needs to sign an intermediate certificate from a CSR.
#[derive(Debug, Clone)]
pub struct IntermediateReq {
    pub csr_der: Vec<u8>,
    pub root_cert_der: Vec<u8>,
    pub path_len: Option<u8>,
    pub validity_days: u32,
    pub cdp_url: Option<String>,
    pub existing_serials: Vec<x509_cert::serial_number::SerialNumber>,
}

/// The intent WAL event the script declares before any irreversible step.
#[derive(Debug, Clone)]
pub struct IntentEvent {
    pub name: String,
    pub data: serde_json::Value,
}

/// A single named file destined for the optical disc.
#[derive(Debug, Clone)]
pub struct Artifact {
    pub name: String,
    pub bytes: Vec<u8>,
}

/// The record session the script asks the archive to burn: an audit event to
/// append to the WAL plus the artifact files. STATE.JSON assembly is the
/// archive's responsibility (it owns the disc/session context).
#[derive(Debug, Clone)]
pub struct RecordSession {
    /// One or more audit events to append (in order) before bundling artifacts.
    pub audit_events: Vec<(String, serde_json::Value)>,
    pub artifacts: Vec<Artifact>,
    /// Optional STATE.JSON update to fold into this record session. The archive
    /// applies it to the base session state plus the post-append audit hash.
    pub state: Option<StateDelta>,
}

/// A semantic update to STATE.JSON the script requests. The archive applies it
/// to the base `SessionState` it holds, filling in the new audit-chain head
/// (`last_audit_hash`) computed from the just-appended record event.
#[derive(Debug, Clone, Default)]
pub struct StateDelta {
    pub crl_number: Option<u64>,
    pub revocation_list: Vec<RevocationEntry>,
    pub hsm_log_seq: Option<u64>,
}

// ── typestate tokens ──────────────────────────────────────────────────────

/// Proof that the intent WAL session was committed to disc.
///
/// The private field makes this unconstructible by struct literal outside this
/// module; only an [`Archive`] impl mints one via [`IntentCommitted::new`].
/// [`Archive::commit_record`] consumes it, so a record can never be written
/// before its intent.
#[derive(Debug)]
pub struct IntentCommitted {
    dir_name: String,
    _seal: (),
}

impl IntentCommitted {
    pub(crate) fn new(dir_name: impl Into<String>) -> Self {
        Self {
            dir_name: dir_name.into(),
            _seal: (),
        }
    }
    pub fn dir_name(&self) -> &str {
        &self.dir_name
    }
}

/// Proof that the record session was committed to disc.
///
/// Required by [`Archive::export_shuttle`]; this is the disc-before-shuttle
/// invariant expressed as a type, not a runtime phase check.
#[derive(Debug)]
pub struct RecordCommitted {
    dir_name: String,
    _seal: (),
}

impl RecordCommitted {
    pub(crate) fn new(dir_name: impl Into<String>) -> Self {
        Self {
            dir_name: dir_name.into(),
            _seal: (),
        }
    }
    pub fn dir_name(&self) -> &str {
        &self.dir_name
    }
}

// ── effect traits ──────────────────────────────────────────────────────────

/// The human in the loop. Every method may return [`Abort`] if the operator
/// quits or cancels.
pub trait Operator {
    /// Present a numbered menu and return the chosen index.
    fn choose(&mut self, title: &str, body: &[String], options: &[Choice]) -> Result<usize, Abort>;

    /// Two-key confirmation gate.
    fn confirm(&mut self, title: &str, body: &[String]) -> Result<(), Abort>;

    /// Collect threshold SSS shares, reconstruct + verify the PIN, return it.
    fn collect_quorum(&mut self, sss: &SssMetadata) -> Result<Pin, Abort>;

    /// Re-confirm the system clock immediately before a signing operation.
    fn reconfirm_clock(&mut self) -> Result<Timestamp, Abort>;

    /// Collect a line of free text (e.g. a serial number or revocation reason).
    /// The returned string may be empty (the script decides if that is valid).
    fn prompt_text(&mut self, title: &str, label: &str) -> Result<String, Abort>;

    /// Emit an informational status line (no input expected).
    fn note(&mut self, msg: &str);
}

/// The HSM. [`Vault::login`] yields an authenticated [`Session`] guard.
pub trait Vault {
    fn login<'a>(&'a mut self, pin: Pin) -> Result<Box<dyn Session + 'a>, Abort>;
}

/// An authenticated HSM session. Implementations log out and zeroize on drop —
/// including when the script unwinds through an early `?`.
pub trait Session {
    /// Sign a CRL over the given plan. Defaulted so a session used only for
    /// signing certs need not implement it.
    fn issue_crl(&mut self, _plan: &CrlPlan, _when: Timestamp) -> Result<SignedCrl, Abort> {
        Err(Abort::new("issue_crl not supported by this session"))
    }

    /// Sign an intermediate certificate from a CSR.
    fn sign_intermediate(
        &mut self,
        _req: &IntermediateReq,
        _when: Timestamp,
    ) -> Result<SignedCert, Abort> {
        Err(Abort::new(
            "sign_intermediate not supported by this session",
        ))
    }

    /// Return the HSM's latest internal audit-log sequence number and drain the
    /// log up to it, so STATE.JSON can record the reconciliation point. Returns
    /// `None` for backends without an internal audit log (e.g. SoftHSM).
    fn record_audit_seq(&mut self) -> Option<u64> {
        None
    }
}

/// The append-only archive: write-once optical disc plus the shuttle USB.
pub trait Archive {
    /// Burn the intent WAL session. Crash-safe commit point.
    fn commit_intent(&mut self, event: IntentEvent) -> Result<IntentCommitted, Abort>;

    /// Burn the record session. Requires proof the intent was committed.
    fn commit_record(
        &mut self,
        intent: IntentCommitted,
        session: RecordSession,
    ) -> Result<RecordCommitted, Abort>;

    /// Copy artifacts to the shuttle USB. Requires proof the record was burned
    /// to disc first.
    fn export_shuttle(
        &mut self,
        record: &RecordCommitted,
        files: &[(&str, &[u8])],
    ) -> Result<(), Abort>;
}
