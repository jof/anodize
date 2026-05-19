//! MigrateDisc operation context.

use crossterm::event::KeyEvent;

use super::{AppShared, OpAction, OpContext};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigratePhase {
    Confirm,
    WaitTarget,
    BurningDisc,
    DiscDone,
    Done,
}

pub struct MigrateCtx {
    pub phase: MigratePhase,
    pub migrate_chain_ok: bool,
    pub migrate_source_fingerprint: Option<String>,
    pub migrate_total_bytes: u64,
    pub migrate_sessions: Vec<crate::media::SessionEntry>,
    pub fingerprint: Option<String>,
}

impl MigrateCtx {
    pub fn new() -> Self {
        Self {
            phase: MigratePhase::Confirm,
            migrate_chain_ok: false,
            migrate_source_fingerprint: None,
            migrate_total_bytes: 0,
            migrate_sessions: Vec::new(),
            fingerprint: None,
        }
    }
}

impl OpContext for MigrateCtx {
    fn phase_index(&self) -> usize {
        match self.phase {
            MigratePhase::Confirm | MigratePhase::WaitTarget => 1,
            MigratePhase::BurningDisc | MigratePhase::DiscDone | MigratePhase::Done => 5,
        }
    }

    fn title(&self) -> &str {
        match self.phase {
            MigratePhase::Confirm => "Disc Migration \u{2014} Verify Chain",
            MigratePhase::WaitTarget => "Insert Blank Target Disc",
            MigratePhase::BurningDisc => "Writing Session\u{2026}",
            MigratePhase::DiscDone => "Disc Migration Written",
            MigratePhase::Done => "Ceremony Complete",
        }
    }

    fn build_body(&self, _shared: &AppShared<'_>) -> Vec<String> {
        vec![String::new(), "  (MigrateDisc — not yet wired)".into()]
    }

    fn handle_key(&mut self, _key: KeyEvent, _shared: &mut AppShared<'_>) -> OpAction {
        OpAction::Noop
    }

    fn holds_ephemeral_state(&self) -> bool {
        !matches!(self.phase, MigratePhase::DiscDone | MigratePhase::Done)
    }

    fn needs_abort_confirmation(&self) -> bool {
        !matches!(
            self.phase,
            MigratePhase::DiscDone | MigratePhase::Done | MigratePhase::BurningDisc
        )
    }

    fn in_text_entry(&self) -> bool {
        false
    }
}
