//! MigrateDisc operation context.
//!
//! Copies all sessions from the current disc to a new blank disc.
//! Flow: Confirm → WaitTarget → (burn handled by App) → Done.

use crossterm::event::{KeyCode, KeyEvent};

use crate::helpers::verify_audit_chain;
use crate::media::SessionEntry;

use super::{OpAction, OpContext, OpEnv};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigratePhase {
    /// Show source disc summary, chain verification. [1] to proceed.
    Confirm,
    /// Old disc ejected, waiting for blank target disc insertion.
    WaitTarget,
}

pub struct MigrateCtx {
    pub phase: MigratePhase,
    pub chain_ok: bool,
    pub source_fingerprint: Option<String>,
    pub total_bytes: u64,
    pub session_count: usize,
    /// Sessions to copy to the new disc (populated on Confirm → WaitTarget).
    pub sessions: Vec<SessionEntry>,
}

impl MigrateCtx {
    /// Build the context from the current disc state.
    pub fn run(shared: &OpEnv<'_>) -> Self {
        let prior = &shared.disc.prior_sessions;

        let total_bytes: u64 = prior
            .last()
            .map(|s| s.files.iter().map(|f| f.data.len() as u64).sum())
            .unwrap_or(0);

        let source_fingerprint = prior
            .last()
            .and_then(|s| s.files.iter().find(|f| f.name == "AUDIT.LOG"))
            .and_then(|f| {
                f.data
                    .split(|&b| b == b'\n')
                    .rev()
                    .find(|line| !line.is_empty())
                    .and_then(|line| serde_json::from_slice::<serde_json::Value>(line).ok())
                    .and_then(|v| v.get("entry_hash")?.as_str().map(String::from))
            });

        let chain_ok = verify_audit_chain(prior);
        let session_count = prior.len();

        Self {
            phase: MigratePhase::Confirm,
            chain_ok,
            source_fingerprint,
            total_bytes,
            session_count,
            sessions: Vec::new(),
        }
    }
}

impl OpContext for MigrateCtx {
    fn phase_index(&self) -> usize {
        1 // Planning
    }

    fn title(&self) -> &str {
        match self.phase {
            MigratePhase::Confirm => "Disc Migration \u{2014} Verify Chain",
            MigratePhase::WaitTarget => "Insert Blank Target Disc",
        }
    }

    fn build_body(&self) -> Vec<String> {
        match self.phase {
            MigratePhase::Confirm => {
                let chain_str = if self.chain_ok {
                    "OK \u{2714}"
                } else {
                    "FAIL \u{2718}"
                };
                let fp_str = self.source_fingerprint.as_deref().unwrap_or("(none)");
                let mb = self.total_bytes / (1024 * 1024);
                vec![
                    String::new(),
                    format!("  Sessions  : {}", self.session_count),
                    format!("  Audit chain: {chain_str}"),
                    format!("  Source hash: {fp_str}"),
                    format!("  Last session: {mb} MiB ({} bytes)", self.total_bytes),
                    String::new(),
                    "  Verify chain is OK before proceeding.".into(),
                    String::new(),
                    "  [1]  Eject old disc, insert blank new disc".into(),
                    "  [Esc]  Abort".into(),
                ]
            }
            MigratePhase::WaitTarget => {
                vec![
                    String::new(),
                    format!(
                        "  Ready to copy {} session(s) to new disc.",
                        self.sessions.len()
                    ),
                    String::new(),
                    "  Insert a blank write-once disc and press [1] when ready.".into(),
                    String::new(),
                    "  [1]  Write all sessions to new disc".into(),
                    "  [Esc]  Abort".into(),
                ]
            }
        }
    }

    fn handle_key(&mut self, key: KeyEvent, shared: &mut OpEnv<'_>) -> OpAction {
        match self.phase {
            MigratePhase::Confirm => match key.code {
                KeyCode::Char('1') => {
                    // Move sessions from disc into context, clear disc state.
                    self.sessions = shared.disc.prior_sessions.clone();
                    shared.disc.prior_sessions.clear();
                    shared.disc.optical_dev = None;
                    shared.disc.sessions_remaining = None;
                    self.phase = MigratePhase::WaitTarget;
                    OpAction::SetStatus("Eject old disc. Insert blank new disc.".into())
                }
                KeyCode::Esc => OpAction::Abort,
                _ => OpAction::Noop,
            },
            MigratePhase::WaitTarget => match key.code {
                KeyCode::Char('1') => {
                    // Check disc readiness
                    let ready = shared.skip_disc
                        || (shared.disc.optical_dev.is_some()
                            && shared
                                .disc
                                .sessions_remaining
                                .map(|r| r >= 50)
                                .unwrap_or(false));
                    if ready {
                        OpAction::StartRecordBurn
                    } else {
                        OpAction::Noop
                    }
                }
                KeyCode::Esc => OpAction::Abort,
                _ => OpAction::Noop,
            },
        }
    }

    fn build_record_session(
        &mut self,
        dir_name: String,
        ts: std::time::SystemTime,
        _staging: &std::path::Path,
        shared: &mut OpEnv<'_>,
    ) -> Option<SessionEntry> {
        let source_files = match self.sessions.last() {
            Some(s) => s.files.clone(),
            None => {
                shared.set_status("No sessions on source disc to migrate");
                return None;
            }
        };

        Some(SessionEntry {
            dir_name,
            timestamp: ts,
            files: source_files,
        })
    }

    fn wants_disc_scan(&self) -> bool {
        matches!(self.phase, MigratePhase::WaitTarget)
    }

    fn holds_ephemeral_state(&self) -> bool {
        // Once sessions are moved to WaitTarget, we're holding data.
        matches!(self.phase, MigratePhase::WaitTarget)
    }

    fn needs_abort_confirmation(&self) -> bool {
        // WaitTarget holds moved sessions, needs confirmation.
        matches!(self.phase, MigratePhase::WaitTarget)
    }

    fn in_text_entry(&self) -> bool {
        false
    }
}
