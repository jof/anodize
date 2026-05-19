//! SignCsr operation context.

use crossterm::event::KeyEvent;

use super::{AppShared, OpAction, OpContext};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignCsrPhase {
    LoadCsr,
    CsrPreview,
    Commit,
    PostCommitError,
    Quorum,
    ClockReconfirm,
    Execute,
    BurningDisc,
    DiscDone,
    Done,
}

pub struct SignCsrCtx {
    pub phase: SignCsrPhase,
    pub csr_der: Option<Vec<u8>>,
    pub csr_subject_display: Option<String>,
    pub selected_profile_idx: Option<usize>,
    pub cert_der: Option<Vec<u8>>,
    pub root_cert_der: Option<Vec<u8>>,
    pub fingerprint: Option<String>,
    pub cert_preview_lines: Vec<String>,
}

impl SignCsrCtx {
    pub fn new() -> Self {
        Self {
            phase: SignCsrPhase::LoadCsr,
            csr_der: None,
            csr_subject_display: None,
            selected_profile_idx: None,
            cert_der: None,
            root_cert_der: None,
            fingerprint: None,
            cert_preview_lines: Vec::new(),
        }
    }
}

impl OpContext for SignCsrCtx {
    fn phase_index(&self) -> usize {
        match self.phase {
            SignCsrPhase::LoadCsr | SignCsrPhase::CsrPreview => 1,
            SignCsrPhase::Commit | SignCsrPhase::PostCommitError => 2,
            SignCsrPhase::Quorum | SignCsrPhase::ClockReconfirm => 3,
            SignCsrPhase::Execute => 4,
            SignCsrPhase::BurningDisc | SignCsrPhase::DiscDone | SignCsrPhase::Done => 5,
        }
    }

    fn title(&self) -> &str {
        match self.phase {
            SignCsrPhase::LoadCsr => "Select Certificate Profile",
            SignCsrPhase::CsrPreview => "Certificate Review \u{2014} VERIFY BEFORE SIGNING",
            SignCsrPhase::Commit => "Committing Intent to Disc\u{2026}",
            SignCsrPhase::PostCommitError => "Post-Commit Error",
            SignCsrPhase::Quorum => "Quorum \u{2014} Reconstruct PIN",
            SignCsrPhase::ClockReconfirm => "Clock Re-confirm \u{2014} Verify Before Signing",
            SignCsrPhase::Execute => "Certificate Preview \u{2014} VERIFY FINGERPRINT",
            SignCsrPhase::BurningDisc => "Writing Session\u{2026}",
            SignCsrPhase::DiscDone => "Certificate Written",
            SignCsrPhase::Done => "Ceremony Complete",
        }
    }

    fn build_body(&self, _shared: &AppShared<'_>) -> Vec<String> {
        vec![String::new(), "  (SignCsr — not yet wired)".into()]
    }

    fn handle_key(&mut self, _key: KeyEvent, _shared: &mut AppShared<'_>) -> OpAction {
        OpAction::Noop
    }

    fn holds_ephemeral_state(&self) -> bool {
        !matches!(self.phase, SignCsrPhase::DiscDone | SignCsrPhase::Done)
    }

    fn needs_abort_confirmation(&self) -> bool {
        !matches!(
            self.phase,
            SignCsrPhase::DiscDone
                | SignCsrPhase::Done
                | SignCsrPhase::Commit
                | SignCsrPhase::BurningDisc
        )
    }

    fn in_text_entry(&self) -> bool {
        matches!(self.phase, SignCsrPhase::Quorum)
    }
}
