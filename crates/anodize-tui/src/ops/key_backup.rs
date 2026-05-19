//! KeyBackup operation context.

use crossterm::event::KeyEvent;

use super::{AppShared, OpAction, OpContext};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackupPhase {
    Quorum,
    DeviceSelection,
    BurningDisc,
    DiscDone,
    Done,
}

pub struct BackupCtx {
    pub phase: BackupPhase,
    pub share_input: Option<crate::components::share_input::ShareInput>,
    pub fingerprint: Option<String>,
}

impl BackupCtx {
    pub fn new() -> Self {
        Self {
            phase: BackupPhase::Quorum,
            share_input: None,
            fingerprint: None,
        }
    }
}

impl OpContext for BackupCtx {
    fn phase_index(&self) -> usize {
        match self.phase {
            BackupPhase::Quorum => 3,
            BackupPhase::DeviceSelection => 1,
            BackupPhase::BurningDisc | BackupPhase::DiscDone | BackupPhase::Done => 5,
        }
    }

    fn title(&self) -> &str {
        match self.phase {
            BackupPhase::Quorum => "Key Backup \u{2014} Reconstruct PIN",
            BackupPhase::DeviceSelection => "Key Backup \u{2014} Device Selection",
            BackupPhase::BurningDisc => "Writing Session\u{2026}",
            BackupPhase::DiscDone => "Key Backup Written",
            BackupPhase::Done => "Ceremony Complete",
        }
    }

    fn build_body(&self) -> Vec<String> {
        vec![String::new(), "  (KeyBackup — not yet wired)".into()]
    }

    fn handle_key(&mut self, _key: KeyEvent, _shared: &mut AppShared<'_>) -> OpAction {
        OpAction::Noop
    }

    fn holds_ephemeral_state(&self) -> bool {
        !matches!(self.phase, BackupPhase::DiscDone | BackupPhase::Done)
    }

    fn needs_abort_confirmation(&self) -> bool {
        !matches!(
            self.phase,
            BackupPhase::DiscDone | BackupPhase::Done | BackupPhase::BurningDisc
        )
    }

    fn in_text_entry(&self) -> bool {
        matches!(self.phase, BackupPhase::Quorum)
    }
}
