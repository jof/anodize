//! Per-operation context types and shared traits for ceremony operations.
//!
//! Each ceremony operation (InitRoot, SignCsr, etc.) gets its own context
//! struct that owns all operation-specific state plus a typed phase enum.
//! The `ActiveOperation` enum wraps them all.

pub mod init_root;
pub mod issue_crl;
pub mod key_backup;
pub mod migrate_disc;
pub mod rekey_shares;
pub mod revoke_cert;
pub mod sign_csr;
pub mod validate_disc;

use std::path::Path;
use std::time::SystemTime;

use anodize_hsm::Hsm as _;
use crossterm::event::KeyEvent;
use ratatui::layout::Rect;
use ratatui::Frame;

use crate::app::DiscContext;
use crate::hardware::HardwareManager;
use anodize_config::Profile;

// ── ActiveOperation ─────────────────────────────────────────────────────────

/// Top-level enum owning the active ceremony operation's context.
pub enum ActiveOperation {
    InitRoot(init_root::InitRootCtx),
    SignCsr(sign_csr::SignCsrCtx),
    RevokeCert(revoke_cert::RevokeCertCtx),
    IssueCrl(issue_crl::IssueCrlCtx),
    RekeyShares(rekey_shares::RekeyCtx),
    KeyBackup(key_backup::BackupCtx),
    MigrateDisc(migrate_disc::MigrateCtx),
    ValidateDisc(validate_disc::ValidateCtx),
    #[cfg(feature = "dev-burn")]
    RefreshDisc(RefreshCtx),
}

#[cfg(feature = "dev-burn")]
pub struct RefreshCtx;

// ── OpAction ────────────────────────────────────────────────────────────────

/// Return type from `OpContext::handle_key`, replacing most `Action` variants.
#[derive(Debug)]
pub enum OpAction {
    /// No-op — event consumed, no side effects.
    Noop,
    /// Update the status bar.
    SetStatus(String),
    /// Show a two-key confirmation dialog.
    ShowConfirm {
        title: String,
        body: Vec<String>,
        on_confirm: ConfirmTarget,
    },
    /// Write intent WAL to disc.
    WriteIntent,
    /// Start the record burn.
    StartRecordBurn,
    /// Execute the pending crypto operation (sign CSR, sign CRL, etc.).
    /// The App dispatches based on `current_op`.
    ExecuteOp,
    /// Operation complete — return to operation select.
    Done,
    /// Abort — return to operation select.
    Abort,
}

/// What action a confirmation dialog should trigger on confirm.
#[derive(Debug, Clone)]
pub enum ConfirmTarget {
    WriteIntent,
    StartRecordBurn,
    Abort,
}

// ── OpContext trait ──────────────────────────────────────────────────────────

/// Shared interface implemented by every per-operation context struct.
pub trait OpContext {
    /// Phase index for the phase bar (0=Select, 1=Plan, 2=Commit, 3=Quorum, 4=Execute, 5=Export).
    fn phase_index(&self) -> usize;

    /// Title string for the content area border.
    fn title(&self) -> &str;

    /// Build the body lines for the content area.
    ///
    /// The context should contain all data needed for rendering.
    fn build_body(&self) -> Vec<String>;

    /// Handle a key event. Returns an `OpAction` describing what the app should do.
    fn handle_key(&mut self, key: KeyEvent, shared: &mut AppShared<'_>) -> OpAction;

    /// Whether this phase holds ephemeral/unrecoverable state (blocks quit).
    fn holds_ephemeral_state(&self) -> bool;

    /// Whether aborting from this phase requires a confirmation dialog.
    fn needs_abort_confirmation(&self) -> bool;

    /// Whether the user is entering text (disables 'q' quit / 'L' log toggle).
    fn in_text_entry(&self) -> bool;

    /// Render any overlay components (ShareReveal, ShareInput, CustodianSetup)
    /// on top of the content area.
    fn render_overlay(&self, _frame: &mut Frame, _area: Rect) {}

    /// Called by `tick_intent_burn` when the intent session is written successfully.
    /// The context should advance its phase (e.g. to Quorum).
    fn advance_after_intent_burn(&mut self, _shared: &mut AppShared<'_>) {}

    /// Execute the HSM crypto operation after clock reconfirm.
    /// Default: starts the record burn directly (no crypto needed).
    fn execute(&mut self, _shared: &mut AppShared<'_>) -> OpAction {
        OpAction::StartRecordBurn
    }

    /// Build the intent audit event (event_name, json_data) for this operation.
    fn build_intent_audit_event(
        &self,
        _genesis_hex: &str,
        _shared: &AppShared<'_>,
    ) -> Option<(String, serde_json::Value)> {
        None
    }

    /// Build the record session for disc burn.
    fn build_record_session(
        &mut self,
        _dir_name: String,
        _ts: SystemTime,
        _staging: &Path,
        _shared: &mut AppShared<'_>,
    ) -> Option<crate::media::SessionEntry> {
        None
    }

    /// Returns `true` if this operation produces shuttle USB artifacts.
    fn has_shuttle_artifacts(&self) -> bool {
        false
    }

    /// Write artifacts to shuttle USB.
    /// Returns `true` if artifacts were written, `false` if no artifacts needed.
    fn write_shuttle_artifacts(&self, _shuttle: &Path) -> Result<bool, String> {
        Ok(false)
    }
}

// ── AppShared ───────────────────────────────────────────────────────────────

/// Borrow-split view of `App` fields that operation contexts may need.
///
/// Passed by reference to `OpContext` methods so that the operation context
/// (borrowed mutably from `App.active_op`) can still access sibling fields.
pub struct AppShared<'a> {
    pub hw: &'a mut HardwareManager,
    pub disc: &'a mut DiscContext,
    pub profile: Option<&'a Profile>,
    pub shuttle_mount: &'a Path,
    pub skip_disc: bool,
    pub confirmed_time: &'a mut Option<SystemTime>,
    pub pin_buf: &'a mut String,
    pub status: &'a mut String,
    pub log_lines: &'a mut Vec<String>,
    pub content_scroll: &'a mut u16,
}

// ── ActiveOperation delegation ──────────────────────────────────────────────

macro_rules! delegate_op {
    ($self:expr, $method:ident $(, $arg:expr)*) => {
        match $self {
            ActiveOperation::InitRoot(ctx) => ctx.$method($($arg),*),
            ActiveOperation::SignCsr(ctx) => ctx.$method($($arg),*),
            ActiveOperation::RevokeCert(ctx) => ctx.$method($($arg),*),
            ActiveOperation::IssueCrl(ctx) => ctx.$method($($arg),*),
            ActiveOperation::RekeyShares(ctx) => ctx.$method($($arg),*),
            ActiveOperation::KeyBackup(ctx) => ctx.$method($($arg),*),
            ActiveOperation::MigrateDisc(ctx) => ctx.$method($($arg),*),
            ActiveOperation::ValidateDisc(ctx) => ctx.$method($($arg),*),
            #[cfg(feature = "dev-burn")]
            ActiveOperation::RefreshDisc(_) => unimplemented!("RefreshDisc"),
        }
    };
}

impl OpContext for ActiveOperation {
    fn phase_index(&self) -> usize {
        delegate_op!(self, phase_index)
    }
    fn title(&self) -> &str {
        delegate_op!(self, title)
    }
    fn build_body(&self) -> Vec<String> {
        delegate_op!(self, build_body)
    }
    fn handle_key(&mut self, key: KeyEvent, shared: &mut AppShared<'_>) -> OpAction {
        delegate_op!(self, handle_key, key, shared)
    }
    fn holds_ephemeral_state(&self) -> bool {
        delegate_op!(self, holds_ephemeral_state)
    }
    fn needs_abort_confirmation(&self) -> bool {
        delegate_op!(self, needs_abort_confirmation)
    }
    fn in_text_entry(&self) -> bool {
        delegate_op!(self, in_text_entry)
    }
    fn render_overlay(&self, frame: &mut Frame, area: Rect) {
        delegate_op!(self, render_overlay, frame, area)
    }
    fn advance_after_intent_burn(&mut self, shared: &mut AppShared<'_>) {
        delegate_op!(self, advance_after_intent_burn, shared)
    }
    fn execute(&mut self, shared: &mut AppShared<'_>) -> OpAction {
        delegate_op!(self, execute, shared)
    }
    fn build_intent_audit_event(
        &self,
        genesis_hex: &str,
        shared: &AppShared<'_>,
    ) -> Option<(String, serde_json::Value)> {
        delegate_op!(self, build_intent_audit_event, genesis_hex, shared)
    }
    fn build_record_session(
        &mut self,
        dir_name: String,
        ts: SystemTime,
        staging: &Path,
        shared: &mut AppShared<'_>,
    ) -> Option<crate::media::SessionEntry> {
        delegate_op!(self, build_record_session, dir_name, ts, staging, shared)
    }
    fn has_shuttle_artifacts(&self) -> bool {
        delegate_op!(self, has_shuttle_artifacts)
    }
    fn write_shuttle_artifacts(&self, shuttle: &Path) -> Result<bool, String> {
        delegate_op!(self, write_shuttle_artifacts, shuttle)
    }
}

impl AppShared<'_> {
    pub fn set_status(&mut self, msg: impl Into<String>) {
        let s: String = msg.into();
        if self.log_lines.last().map(|l| l.as_str()) != Some(s.as_str()) {
            self.log_lines.push(s.clone());
        }
        *self.status = s;
        *self.content_scroll = 0;
    }

    /// Reconstruct PIN from collected shares, verify hash, and login to the HSM.
    ///
    /// On success stores the hex PIN in `self.pin_buf` and populates
    /// `self.hw.actor`.  Returns `Err(msg)` on any failure.
    pub fn quorum_complete(&mut self, shares: &[anodize_sss::Share]) -> Result<(), String> {
        use anodize_hsm::{create_backend, HsmActor};
        use secrecy::SecretString;

        let threshold = self
            .disc
            .session_state
            .as_ref()
            .map(|s| s.sss.threshold)
            .unwrap_or(2);
        let pin_bytes = anodize_sss::reconstruct(shares, threshold)
            .map_err(|e| format!("PIN reconstruction failed: {e}"))?;

        let expected = self
            .disc
            .session_state
            .as_ref()
            .map(|s| s.sss.pin_verify_hash.as_str())
            .unwrap_or("");
        if !anodize_sss::verify_pin_hash(&pin_bytes, expected) {
            return Err("PIN verify hash mismatch — shares may be corrupted.".into());
        }

        let pin_hex = hex::encode(&pin_bytes);
        let pin = SecretString::new(pin_hex.clone());

        let cfg = self
            .profile
            .as_ref()
            .map(|p| &p.hsm)
            .ok_or_else(|| "No profile loaded".to_string())?;

        let backend = create_backend(cfg.backend).map_err(|e| format!("HSM backend error: {e}"))?;

        let fleet_ids: Vec<String> = self
            .disc
            .session_state
            .as_ref()
            .map(|s| {
                s.fleet
                    .active_device_ids()
                    .into_iter()
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();

        let (device_id, hsm) = if fleet_ids.is_empty() {
            let hsm = backend
                .open_session(&cfg.token_label, &pin)
                .map_err(|e| format!("HSM open/login failed: {e}"))?;
            (None, hsm)
        } else {
            let inventory = anodize_hsm::create_inventory(cfg.backend)
                .map_err(|e| format!("HSM inventory error: {e}"))?;
            let id_refs: Vec<&str> = fleet_ids.iter().map(|s| s.as_str()).collect();
            let (did, hsm) =
                anodize_hsm::open_session_any_recognized(&*backend, &*inventory, &id_refs, &pin)
                    .map_err(|e| format!("Fleet login failed: {e}"))?;
            tracing::info!(device_id = %did, "Fleet login: authenticated to known device");
            (Some(did), hsm)
        };

        if let Some(ref did) = device_id {
            if let Some(ref mut state) = self.disc.session_state {
                let now = {
                    let d = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default();
                    format!("{}Z", d.as_secs())
                };
                for dev in &mut state.fleet.devices {
                    if dev.device_id == *did {
                        dev.last_seen_at = now.clone();
                    }
                }
            }
        }

        let actor = HsmActor::spawn(hsm);
        self.hw.actor = Some(actor);
        self.hw.device_id = device_id;
        self.hw.hsm_state =
            crate::components::status_bar::HwState::Ready("authenticated via SSS quorum".into());
        *self.pin_buf = pin_hex;
        Ok(())
    }

    /// Update `session_state` to reflect the outcome of the current operation.
    /// Must be called before `build_state_json_file` in record session builders.
    pub fn update_session_state_for_record(
        &mut self,
        audit_bytes: &[u8],
        crl_number: Option<u64>,
        revocation_list: &[anodize_config::RevocationEntry],
    ) {
        let last_hash = audit_bytes
            .split(|&b| b == b'\n')
            .rev()
            .find(|line| !line.is_empty())
            .and_then(|line| serde_json::from_slice::<serde_json::Value>(line).ok())
            .and_then(|v| {
                v.get("entry_hash")
                    .and_then(|h| h.as_str().map(String::from))
            })
            .unwrap_or_default();

        if let Some(ref mut state) = self.disc.session_state {
            state.last_audit_hash = last_hash;
            if let Some(n) = crl_number {
                state.crl_number = n;
            }
            if !revocation_list.is_empty() {
                state.revocation_list = revocation_list.to_vec();
            }
            if let Some(ref actor) = self.hw.actor {
                match actor.get_audit_log() {
                    Ok(snapshot) => {
                        if let Some(last) = snapshot.entries.last() {
                            state.last_hsm_log_seq = Some(last.item as u64);
                            tracing::info!(seq = last.item, "recorded last_hsm_log_seq");
                            if let Err(e) = actor.drain_audit_log(last.item) {
                                tracing::warn!(seq = last.item, "drain_audit_log failed: {e}");
                            }
                        }
                    }
                    Err(e) => tracing::warn!("could not read HSM audit log: {e}"),
                }
            }
        }
    }

    /// Build a STATE.JSON IsoFile from the current session_state.
    pub fn build_state_json_file(&self) -> Option<crate::media::IsoFile> {
        self.disc
            .session_state
            .as_ref()
            .map(|state| crate::media::IsoFile {
                name: anodize_config::state::STATE_FILENAME.into(),
                data: state.to_json(),
            })
    }

    /// Returns `true` if the operator's clock confirmation is recent enough.
    pub fn clock_is_fresh(&self) -> bool {
        self.confirmed_time
            .as_ref()
            .map(|t| {
                t.elapsed().unwrap_or(std::time::Duration::ZERO) < crate::app::CLOCK_DRIFT_THRESHOLD
            })
            .unwrap_or(false)
    }
}
