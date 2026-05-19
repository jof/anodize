//! RekeyShares operation context.

use crossterm::event::KeyEvent;

use super::{AppShared, OpAction, OpContext};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RekeyPhase {
    Quorum,
    CustodianSetup,
    ShareReveal,
    ShareVerify,
    BurningDisc,
    DiscDone,
    Done,
}

pub struct RekeyCtx {
    pub phase: RekeyPhase,
    pub custodian_setup: Option<crate::components::custodian_setup::CustodianSetup>,
    pub share_reveal: Option<crate::components::share_reveal::ShareReveal>,
    pub share_input: Option<crate::components::share_input::ShareInput>,
    pub shares: Option<Vec<anodize_sss::Share>>,
    pub custodian_names: Vec<String>,
    pub rekey_old_pin_hex: Option<String>,
    pub rekey_changed_backup_ids: Vec<String>,
    pub fingerprint: Option<String>,
}

impl RekeyCtx {
    pub fn new() -> Self {
        Self {
            phase: RekeyPhase::Quorum,
            custodian_setup: None,
            share_reveal: None,
            share_input: None,
            shares: None,
            custodian_names: Vec::new(),
            rekey_old_pin_hex: None,
            rekey_changed_backup_ids: Vec::new(),
            fingerprint: None,
        }
    }
}

impl OpContext for RekeyCtx {
    fn phase_index(&self) -> usize {
        match self.phase {
            RekeyPhase::Quorum => 3,
            RekeyPhase::CustodianSetup | RekeyPhase::ShareReveal | RekeyPhase::ShareVerify => 1,
            RekeyPhase::BurningDisc | RekeyPhase::DiscDone | RekeyPhase::Done => 5,
        }
    }

    fn title(&self) -> &str {
        match self.phase {
            RekeyPhase::Quorum => "Re-key Shares \u{2014} Quorum",
            RekeyPhase::CustodianSetup => "Re-key Shares \u{2014} New Custodians",
            RekeyPhase::ShareReveal => "Re-key Shares \u{2014} Distribute New Shares",
            RekeyPhase::ShareVerify => "Re-key Shares \u{2014} Verify New Shares",
            RekeyPhase::BurningDisc => "Writing Session\u{2026}",
            RekeyPhase::DiscDone => "Re-key Shares Written",
            RekeyPhase::Done => "Ceremony Complete",
        }
    }

    fn build_body(&self) -> Vec<String> {
        vec![String::new(), "  (RekeyShares — not yet wired)".into()]
    }

    fn handle_key(&mut self, _key: KeyEvent, _shared: &mut AppShared<'_>) -> OpAction {
        OpAction::Noop
    }

    fn holds_ephemeral_state(&self) -> bool {
        !matches!(self.phase, RekeyPhase::DiscDone | RekeyPhase::Done)
    }

    fn needs_abort_confirmation(&self) -> bool {
        !matches!(
            self.phase,
            RekeyPhase::DiscDone | RekeyPhase::Done | RekeyPhase::BurningDisc
        )
    }

    fn in_text_entry(&self) -> bool {
        matches!(
            self.phase,
            RekeyPhase::CustodianSetup | RekeyPhase::ShareVerify | RekeyPhase::Quorum
        )
    }
}
