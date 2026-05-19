//! IssueCrl operation context.

use crossterm::event::KeyEvent;

use super::{AppShared, OpAction, OpContext};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssueCrlPhase {
    CrlPreview,
    Commit,
    PostCommitError,
    Quorum,
    ClockReconfirm,
    Execute,
    BurningDisc,
    DiscDone,
    Done,
}

pub struct IssueCrlCtx {
    pub phase: IssueCrlPhase,
    pub revocation_list: Vec<anodize_config::RevocationEntry>,
    pub crl_number: Option<u64>,
    pub crl_der: Option<Vec<u8>>,
    pub fingerprint: Option<String>,
}

impl IssueCrlCtx {
    pub fn new() -> Self {
        Self {
            phase: IssueCrlPhase::CrlPreview,
            revocation_list: Vec::new(),
            crl_number: None,
            crl_der: None,
            fingerprint: None,
        }
    }
}

impl OpContext for IssueCrlCtx {
    fn phase_index(&self) -> usize {
        match self.phase {
            IssueCrlPhase::CrlPreview => 1,
            IssueCrlPhase::Commit | IssueCrlPhase::PostCommitError => 2,
            IssueCrlPhase::Quorum | IssueCrlPhase::ClockReconfirm => 3,
            IssueCrlPhase::Execute => 4,
            IssueCrlPhase::BurningDisc | IssueCrlPhase::DiscDone | IssueCrlPhase::Done => 5,
        }
    }

    fn title(&self) -> &str {
        match self.phase {
            IssueCrlPhase::CrlPreview => "CRL Issuance Preview",
            IssueCrlPhase::Commit => "Committing Intent to Disc\u{2026}",
            IssueCrlPhase::PostCommitError => "Post-Commit Error",
            IssueCrlPhase::Quorum => "Quorum \u{2014} Reconstruct PIN",
            IssueCrlPhase::ClockReconfirm => "Clock Re-confirm \u{2014} Verify Before Signing",
            IssueCrlPhase::Execute => "Certificate Preview \u{2014} VERIFY FINGERPRINT",
            IssueCrlPhase::BurningDisc => "Writing Session\u{2026}",
            IssueCrlPhase::DiscDone => "CRL Refresh Written",
            IssueCrlPhase::Done => "Ceremony Complete",
        }
    }

    fn build_body(&self, _shared: &AppShared<'_>) -> Vec<String> {
        vec![String::new(), "  (IssueCrl — not yet wired)".into()]
    }

    fn handle_key(&mut self, _key: KeyEvent, _shared: &mut AppShared<'_>) -> OpAction {
        OpAction::Noop
    }

    fn holds_ephemeral_state(&self) -> bool {
        !matches!(self.phase, IssueCrlPhase::DiscDone | IssueCrlPhase::Done)
    }

    fn needs_abort_confirmation(&self) -> bool {
        !matches!(
            self.phase,
            IssueCrlPhase::DiscDone
                | IssueCrlPhase::Done
                | IssueCrlPhase::Commit
                | IssueCrlPhase::BurningDisc
        )
    }

    fn in_text_entry(&self) -> bool {
        matches!(self.phase, IssueCrlPhase::Quorum)
    }
}
