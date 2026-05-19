//! RevokeCert operation context.

use crossterm::event::KeyEvent;

use super::{AppShared, OpAction, OpContext};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokeCertPhase {
    RevokeSelect,
    RevokeInput,
    RevokePreview,
    Commit,
    PostCommitError,
    Quorum,
    ClockReconfirm,
    Execute,
    BurningDisc,
    DiscDone,
    Done,
}

pub struct RevokeCertCtx {
    pub phase: RevokeCertPhase,
    pub cert_list: Vec<crate::app::CertSummary>,
    pub cert_list_cursor: usize,
    pub revoke_serial_buf: String,
    pub revoke_reason_buf: String,
    pub revoke_phase: u8,
    pub revocation_list: Vec<anodize_config::RevocationEntry>,
    pub crl_number: Option<u64>,
    pub crl_der: Option<Vec<u8>>,
    pub fingerprint: Option<String>,
}

impl RevokeCertCtx {
    pub fn new() -> Self {
        Self {
            phase: RevokeCertPhase::RevokeSelect,
            cert_list: Vec::new(),
            cert_list_cursor: 0,
            revoke_serial_buf: String::new(),
            revoke_reason_buf: String::new(),
            revoke_phase: 0,
            revocation_list: Vec::new(),
            crl_number: None,
            crl_der: None,
            fingerprint: None,
        }
    }
}

impl OpContext for RevokeCertCtx {
    fn phase_index(&self) -> usize {
        match self.phase {
            RevokeCertPhase::RevokeSelect
            | RevokeCertPhase::RevokeInput
            | RevokeCertPhase::RevokePreview => 1,
            RevokeCertPhase::Commit | RevokeCertPhase::PostCommitError => 2,
            RevokeCertPhase::Quorum | RevokeCertPhase::ClockReconfirm => 3,
            RevokeCertPhase::Execute => 4,
            RevokeCertPhase::BurningDisc | RevokeCertPhase::DiscDone | RevokeCertPhase::Done => 5,
        }
    }

    fn title(&self) -> &str {
        match self.phase {
            RevokeCertPhase::RevokeSelect => "Revoke Certificate \u{2014} Select Certificate",
            RevokeCertPhase::RevokeInput => "Revoke Certificate",
            RevokeCertPhase::RevokePreview => {
                "Revocation Preview \u{2014} VERIFY BEFORE COMMITTING"
            }
            RevokeCertPhase::Commit => "Committing Intent to Disc\u{2026}",
            RevokeCertPhase::PostCommitError => "Post-Commit Error",
            RevokeCertPhase::Quorum => "Quorum \u{2014} Reconstruct PIN",
            RevokeCertPhase::ClockReconfirm => "Clock Re-confirm \u{2014} Verify Before Signing",
            RevokeCertPhase::Execute => "Certificate Preview \u{2014} VERIFY FINGERPRINT",
            RevokeCertPhase::BurningDisc => "Writing Session\u{2026}",
            RevokeCertPhase::DiscDone => "Revocation Record Written",
            RevokeCertPhase::Done => "Ceremony Complete",
        }
    }

    fn build_body(&self) -> Vec<String> {
        vec![String::new(), "  (RevokeCert — not yet wired)".into()]
    }

    fn handle_key(&mut self, _key: KeyEvent, _shared: &mut AppShared<'_>) -> OpAction {
        OpAction::Noop
    }

    fn holds_ephemeral_state(&self) -> bool {
        !matches!(
            self.phase,
            RevokeCertPhase::DiscDone | RevokeCertPhase::Done
        )
    }

    fn needs_abort_confirmation(&self) -> bool {
        !matches!(
            self.phase,
            RevokeCertPhase::DiscDone
                | RevokeCertPhase::Done
                | RevokeCertPhase::Commit
                | RevokeCertPhase::BurningDisc
        )
    }

    fn in_text_entry(&self) -> bool {
        matches!(
            self.phase,
            RevokeCertPhase::RevokeInput | RevokeCertPhase::Quorum
        )
    }
}
