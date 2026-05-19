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

use crossterm::event::KeyEvent;
use ratatui::layout::Rect;
use ratatui::Frame;

use crate::app::DiscContext;
use crate::hardware::HardwareManager;
use crate::media::SessionEntry;
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

// ── DiscTransaction ─────────────────────────────────────────────────────────

/// Typed state machine for the intent → record disc-write lifecycle.
///
/// Transitions are consuming methods that enforce the correct ordering
/// at the type level.
#[derive(Debug)]
pub enum DiscTransaction {
    /// Intent session built in memory, not yet written to disc.
    Pending { session: SessionEntry },
    /// Intent session burned to disc; crypto operation may proceed.
    IntentBurned { intent_dir_name: String },
    /// Record session built and ready to burn.
    RecordReady { session: SessionEntry },
    /// Record session burned to disc.
    RecordBurned,
}

// ── OpAction ────────────────────────────────────────────────────────────────

/// Return type from `OpContext::handle_key`, replacing most `Action` variants.
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
    /// Copy artifacts to shuttle USB.
    WriteShuttle,
    /// Operation complete — return to operation select.
    Done,
    /// Abort — return to operation select.
    Abort,
    /// Quit the application.
    Quit,
}

/// What action a confirmation dialog should trigger on confirm.
#[derive(Debug, Clone)]
pub enum ConfirmTarget {
    WriteIntent,
    StartRecordBurn,
    Abort,
    Quit,
}

// ── OpContext trait ──────────────────────────────────────────────────────────

/// Shared interface implemented by every per-operation context struct.
pub trait OpContext {
    /// Phase index for the phase bar (0=Select, 1=Plan, 2=Commit, 3=Quorum, 4=Execute, 5=Export).
    fn phase_index(&self) -> usize;

    /// Title string for the content area border.
    fn title(&self) -> &str;

    /// Build the body lines for the content area.
    fn build_body(&self, shared: &AppShared<'_>) -> Vec<String>;

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
    pub profile_toml_bytes: Option<&'a [u8]>,
    pub shuttle_mount: &'a Path,
    pub skip_disc: bool,
    pub confirmed_time: &'a mut Option<SystemTime>,
    pub pin_buf: &'a mut String,
    pub status: &'a mut String,
    pub log_lines: &'a mut Vec<String>,
    pub content_scroll: &'a mut u16,
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
}
