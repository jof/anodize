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

use anodize_config::state::{SessionState, SssMetadata};
use anodize_config::{HsmBackendKind, RevocationEntry};
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

/// Operator's custodian-setup result: names and threshold.
#[derive(Debug, Clone)]
pub struct CustodianResult {
    pub names: Vec<String>,
    pub threshold: u8,
}

/// Root CA certificate parameters.
#[derive(Debug, Clone)]
pub struct RootCertParams {
    pub common_name: String,
    pub organization: String,
    pub country: String,
    pub state: Option<String>,
    pub validity_days: u32,
}

/// Device identity returned after HSM bootstrap.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub device_id: String,
    pub model: String,
    pub backend: HsmBackendKind,
}

/// Plan for InitRoot: generate a root CA keypair + self-signed certificate.
#[derive(Debug, Clone)]
pub struct InitRootPlan {
    pub ca: RootCertParams,
}

/// Re-key shares: rotate the HSM PIN and redistribute SSS shares.
/// No plan data beyond `env.sss` (the current SSS metadata).
#[derive(Debug, Clone)]
pub struct RekeyPlan;

/// Plan for KeyBackup: pair or backup HSM keys between two devices.
/// Discovery happens at runtime after the quorum reconstructs the PIN.
#[derive(Debug, Clone)]
pub struct KeyBackupPlan {
    /// Backend kind for fleet enrollment metadata.
    pub backend: anodize_config::HsmBackendKind,
    /// Current fleet state, used to determine whether the destination device
    /// needs to be enrolled.
    pub base_fleet: anodize_config::state::HsmFleet,
}

/// A device or token available for key backup operations.
#[derive(Debug, Clone)]
pub struct BackupTarget {
    pub identifier: String,
    pub description: String,
    pub has_wrap_key: bool,
    pub has_signing_key: bool,
    pub needs_bootstrap: bool,
}

/// Result of a backup key operation.
#[derive(Debug, Clone)]
pub struct BackupResult {
    pub source_id: String,
    pub dest_id: String,
    pub public_keys_match: bool,
}

/// A single file from a disc session, used for migration.
#[derive(Debug, Clone)]
pub struct MigrationFile {
    pub name: String,
    pub data: Vec<u8>,
}

/// Plan for MigrateDisc: copy the latest session from a source disc to a new
/// blank disc. The plan is assembled from source-disc state before the script
/// thread is spawned.
#[derive(Debug, Clone)]
pub struct MigrateDiscPlan {
    pub session_count: usize,
    pub chain_ok: bool,
    pub source_fingerprint: Option<String>,
    pub total_bytes: u64,
    /// Files from the latest source session to write to the target disc.
    pub files: Vec<MigrationFile>,
}

/// Plan for ValidateDisc: read-only audit and integrity check.
/// The initial report is pre-computed from disc state before the script spawns.
#[derive(Debug, Clone)]
pub struct ValidateDiscPlan {
    /// Pre-formatted initial validation report.
    pub initial_report: String,
    /// Whether an HSM device is available for audit-log cross-check.
    pub has_hsm: bool,
    /// Raw AUDIT.LOG bytes from staging, for HSM cross-check parsing.
    pub staging_audit_bytes: Option<Vec<u8>>,
    /// Last reconciled HSM log sequence from STATE.JSON.
    pub last_hsm_log_seq: Option<u64>,
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

/// Plan for RefreshDisc (dev-burn only): write a seed session to disc.
#[cfg(feature = "dev-burn")]
#[derive(Debug, Clone)]
pub struct RefreshDiscPlan {
    pub dir_name: String,
}

/// Plan for LandingPad: initialize a blank disc as a known anodize audit disc
/// by writing a self-describing Track 1 session (marker + README + helper
/// script + bundled source). Assembled before the script thread is spawned so
/// the bundled source/provenance (read from `/etc/anodize`) is resolved on the
/// main thread; absent bundles degrade gracefully.
#[derive(Debug, Clone)]
pub struct LandingPadPlan {
    /// Session directory name (without the `-landing` suffix the adapter adds).
    pub dir_name: String,
    /// Bytes of the bundled source archive (`/etc/anodize/source.tar.gz`), if present.
    pub source_archive: Option<Vec<u8>>,
    /// Provenance text (`/etc/anodize/build-info.txt`), if present.
    pub build_info: Option<String>,
}

/// Read-only environment handed to a script, generic over the operation's plan.
/// Built from disc/profile state before the ceremony thread is spawned.
#[derive(Debug, Clone)]
pub struct Env<P> {
    pub sss: SssMetadata,
    pub plan: P,
}

// ── HSM audit log types ───────────────────────────────────────────────────

/// A single entry from the HSM's internal audit log.
/// Mirrors `anodize_hsm::audit_log::HsmAuditEntry` without coupling io.rs to
/// that crate.
#[derive(Debug, Clone)]
pub struct HsmAuditEntry {
    pub item: u16,
    pub command: u8,
    pub session_key: u16,
    pub target_key: u16,
    pub second_key: u16,
    pub result: u8,
    pub tick: u32,
    pub digest: [u8; 16],
}

/// Snapshot of the HSM's internal audit log.
#[derive(Debug, Clone)]
pub struct HsmAuditLog {
    pub unlogged_boot_events: u16,
    pub unlogged_auth_events: u16,
    pub entries: Vec<HsmAuditEntry>,
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

impl RecordSession {
    /// Helper: build a record with a single audit event.
    pub fn single(
        event_name: impl Into<String>,
        event_data: serde_json::Value,
        artifacts: Vec<Artifact>,
        state: Option<StateDelta>,
    ) -> Self {
        Self {
            audit_events: vec![(event_name.into(), event_data)],
            artifacts,
            state,
        }
    }
}

/// A semantic update to STATE.JSON the script requests. The archive applies it
/// to the base `SessionState` it holds, filling in the new audit-chain head
/// (`last_audit_hash`) computed from the just-appended record event.
#[derive(Debug, Clone, Default)]
pub struct StateDelta {
    pub crl_number: Option<u64>,
    pub revocation_list: Vec<RevocationEntry>,
    pub hsm_log_seq: Option<u64>,
    /// A fresh initial state for ceremonies that create state from scratch
    /// (e.g., InitRoot). The archive fills in `last_audit_hash`.
    pub fresh_state: Option<SessionState>,
    /// Updated SSS metadata (e.g., after RekeyShares).
    pub sss: Option<SssMetadata>,
    /// Updated fleet (e.g., after KeyBackup enrolls a new device).
    pub fleet: Option<anodize_config::state::HsmFleet>,
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

    /// Configure custodians: collect names and a k-of-n threshold.
    fn setup_custodians(&mut self, _title: &str) -> Result<CustodianResult, Abort> {
        Err(Abort::new("setup_custodians not supported"))
    }

    /// Display each SSS share to its custodian one-at-a-time.
    fn reveal_shares(
        &mut self,
        _shares: &[anodize_sss::Share],
        _names: &[String],
        _generation: u64,
    ) -> Result<(), Abort> {
        Err(Abort::new("reveal_shares not supported"))
    }

    /// Verify all shares (each custodian re-enters theirs).
    fn verify_shares(&mut self, _sss: &SssMetadata) -> Result<(), Abort> {
        Err(Abort::new("verify_shares not supported"))
    }

    /// Wait for the operator to physically swap the optical disc (eject source,
    /// insert blank target). The adapter blocks until the hardware is ready and
    /// the operator confirms. `session_count` is informational.
    fn wait_for_disc_swap(&mut self, _session_count: usize) -> Result<(), Abort> {
        Err(Abort::new("wait_for_disc_swap not supported"))
    }

    /// Show a scrollable read-only review screen. The operator dismisses it
    /// with any key (Esc, Q, Enter) — there is no abort path.
    fn review(&mut self, _title: &str, _body: &[String]) {}

    /// Emit an informational status line (no input expected).
    fn note(&mut self, msg: &str);
}

/// The HSM. [`Vault::login`] yields an authenticated [`Session`] guard.
pub trait Vault {
    fn login<'a>(&'a mut self, pin: Pin) -> Result<Box<dyn Session + 'a>, Abort>;

    /// Initialize a fresh HSM token and return an authenticated session.
    fn bootstrap<'a>(&'a mut self, _pin: Pin) -> Result<Box<dyn Session + 'a>, Abort> {
        Err(Abort::new("bootstrap not supported by this vault"))
    }

    /// Change the PIN on all backup/fleet HSMs (excluding the primary, which
    /// the session already changed). On failure, rolls back all already-changed
    /// devices and the primary back to `old_pin`. Returns device IDs changed.
    fn change_pin_fleet(
        &self,
        _old_pin: &Pin,
        _new_pin: &Pin,
        _primary_device_id: &str,
    ) -> Result<Vec<String>, Abort> {
        // Default: no fleet, nothing to do.
        Ok(Vec::new())
    }

    /// Verify that `old_pin` is rejected on every active fleet device.
    fn verify_pin_rejected(&self, _old_pin: &Pin) -> Result<(), Abort> {
        Ok(())
    }

    /// Discover devices/tokens available for backup operations.
    fn discover_backup_targets(&self, _pin: &Pin) -> Result<Vec<BackupTarget>, Abort> {
        Err(Abort::new("discover_backup_targets not supported"))
    }

    /// Install a shared wrap key on both source and destination devices.
    /// Returns a description of the wrap key (e.g. "0x0200").
    fn pair_devices(&self, _src: &str, _dst: &str, _pin: &Pin) -> Result<String, Abort> {
        Err(Abort::new("pair_devices not supported"))
    }

    /// Export the signing key from source, import into destination, verify
    /// public keys match.
    fn backup_key(&self, _src: &str, _dst: &str, _pin: &Pin) -> Result<BackupResult, Abort> {
        Err(Abort::new("backup_key not supported"))
    }
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

    /// Generate a root P-384 keypair on the HSM.
    fn generate_root_key(&mut self) -> Result<(), Abort> {
        Err(Abort::new(
            "generate_root_key not supported by this session",
        ))
    }

    /// Build a self-signed root CA certificate.
    fn build_root_cert(
        &mut self,
        _params: &RootCertParams,
        _when: Timestamp,
    ) -> Result<SignedCert, Abort> {
        Err(Abort::new("build_root_cert not supported by this session"))
    }

    /// Return device identity info (populated after bootstrap).
    fn device_info(&self) -> Option<DeviceInfo> {
        None
    }

    /// Return the HSM's latest internal audit-log sequence number and drain the
    /// log up to it, so STATE.JSON can record the reconciliation point. Returns
    /// `None` for backends without an internal audit log (e.g. SoftHSM).
    fn record_audit_seq(&mut self) -> Option<u64> {
        None
    }

    /// Change the PIN on this session's HSM device.
    fn change_pin(&mut self, _old_pin: &Pin, _new_pin: &Pin) -> Result<(), Abort> {
        Err(Abort::new("change_pin not supported by this session"))
    }

    /// Fetch the HSM's internal audit log. Returns `Err` for backends without
    /// an internal audit log (e.g. SoftHSM/PKCS#11).
    fn get_hsm_audit_log(&mut self) -> Result<HsmAuditLog, Abort> {
        Err(Abort::new(
            "get_hsm_audit_log not supported by this session",
        ))
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

    /// Write migrated session files to a new blank disc. Used by the
    /// MigrateDisc ceremony, which bypasses intent/record typestate because it
    /// is a disc copy, not a state mutation.
    fn write_migration(&mut self, _files: &[MigrationFile]) -> Result<(), Abort> {
        Err(Abort::new("write_migration not supported"))
    }

    /// Write the Track 1 "landing pad" session to a blank disc. Like
    /// [`Self::write_migration`] it bypasses intent/record typestate (it is a
    /// self-describing seed, not a state mutation), but uses a distinct
    /// `-landing` session-directory suffix.
    fn write_landing_pad(&mut self, _files: &[MigrationFile]) -> Result<(), Abort> {
        Err(Abort::new("write_landing_pad not supported"))
    }

    /// Write files directly to the shuttle USB without requiring a disc commit.
    /// Used by read-only ceremonies (e.g. ValidateDisc) that produce a report
    /// but do not mutate disc state.
    fn write_shuttle_direct(&mut self, _files: &[(&str, &[u8])]) -> Result<(), Abort> {
        Err(Abort::new("write_shuttle_direct not supported"))
    }
}
