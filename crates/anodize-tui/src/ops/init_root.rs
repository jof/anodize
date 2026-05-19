//! InitRoot operation context.

use crossterm::event::KeyEvent;

use super::{AppShared, OpAction, OpContext};

/// Phase FSM for the InitRoot ceremony.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitRootPhase {
    CustodianSetup,
    ShareReveal,
    ShareVerify,
    Commit,
    PostCommitError,
    Quorum,
    ClockReconfirm,
    Execute,
    BurningDisc,
    DiscDone,
    Done,
}

/// Operation context for InitRoot.
pub struct InitRootCtx {
    pub phase: InitRootPhase,
    pub custodian_setup: Option<crate::components::custodian_setup::CustodianSetup>,
    pub share_reveal: Option<crate::components::share_reveal::ShareReveal>,
    pub share_input: Option<crate::components::share_input::ShareInput>,
    pub shares: Option<Vec<anodize_sss::Share>>,
    pub custodian_names: Vec<String>,
    pub cert_der: Option<Vec<u8>>,
    pub crl_der: Option<Vec<u8>>,
    pub root_cert_der: Option<Vec<u8>>,
    pub fingerprint: Option<String>,
}

impl InitRootCtx {
    pub fn new() -> Self {
        Self {
            phase: InitRootPhase::CustodianSetup,
            custodian_setup: None,
            share_reveal: None,
            share_input: None,
            shares: None,
            custodian_names: Vec::new(),
            cert_der: None,
            crl_der: None,
            root_cert_der: None,
            fingerprint: None,
        }
    }
}

impl OpContext for InitRootCtx {
    fn phase_index(&self) -> usize {
        match self.phase {
            InitRootPhase::CustodianSetup
            | InitRootPhase::ShareReveal
            | InitRootPhase::ShareVerify => 1,
            InitRootPhase::Commit | InitRootPhase::PostCommitError => 2,
            InitRootPhase::Quorum | InitRootPhase::ClockReconfirm => 3,
            InitRootPhase::Execute => 4,
            InitRootPhase::BurningDisc | InitRootPhase::DiscDone | InitRootPhase::Done => 5,
        }
    }

    fn title(&self) -> &str {
        match self.phase {
            InitRootPhase::CustodianSetup => "Root Init \u{2014} Custodian Setup",
            InitRootPhase::ShareReveal => "Root Init \u{2014} Distribute Shares",
            InitRootPhase::ShareVerify => "Root Init \u{2014} Verify Shares",
            InitRootPhase::Commit => "Committing Intent to Disc\u{2026}",
            InitRootPhase::PostCommitError => "Post-Commit Error",
            InitRootPhase::Quorum => "Quorum \u{2014} Reconstruct PIN",
            InitRootPhase::ClockReconfirm => "Clock Re-confirm \u{2014} Verify Before Signing",
            InitRootPhase::Execute => "Certificate Preview \u{2014} RECORD FINGERPRINT",
            InitRootPhase::BurningDisc => "Writing Session\u{2026}",
            InitRootPhase::DiscDone => "Root Init Written",
            InitRootPhase::Done => "Ceremony Complete",
        }
    }

    fn build_body(&self, _shared: &AppShared<'_>) -> Vec<String> {
        // TODO: migrate from CeremonyMode::build_body
        vec![String::new(), "  (InitRoot — not yet wired)".into()]
    }

    fn handle_key(&mut self, _key: KeyEvent, _shared: &mut AppShared<'_>) -> OpAction {
        // TODO: migrate from app.rs handle_key_event
        OpAction::Noop
    }

    fn holds_ephemeral_state(&self) -> bool {
        !matches!(self.phase, InitRootPhase::DiscDone | InitRootPhase::Done)
    }

    fn needs_abort_confirmation(&self) -> bool {
        !matches!(
            self.phase,
            InitRootPhase::DiscDone
                | InitRootPhase::Done
                | InitRootPhase::Commit
                | InitRootPhase::BurningDisc
        )
    }

    fn in_text_entry(&self) -> bool {
        matches!(
            self.phase,
            InitRootPhase::CustodianSetup | InitRootPhase::ShareVerify | InitRootPhase::Quorum
        )
    }
}
