//! ValidateDisc operation context.

use crossterm::event::KeyEvent;

use super::{AppShared, OpAction, OpContext};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidatePhase {
    Report,
    HsmResult,
}

pub struct ValidateCtx {
    pub phase: ValidatePhase,
    pub report_lines: Vec<String>,
    pub has_hsm: bool,
    pub findings: Vec<anodize_audit::validate::Finding>,
}

impl ValidateCtx {
    pub fn new() -> Self {
        Self {
            phase: ValidatePhase::Report,
            report_lines: Vec::new(),
            has_hsm: false,
            findings: Vec::new(),
        }
    }
}

impl OpContext for ValidateCtx {
    fn phase_index(&self) -> usize {
        // Validate is always in the "Plan" phase bar position
        1
    }

    fn title(&self) -> &str {
        match self.phase {
            ValidatePhase::Report => "Disc Validation Report",
            ValidatePhase::HsmResult => "HSM Audit Log Cross-Check",
        }
    }

    fn build_body(&self, _shared: &AppShared<'_>) -> Vec<String> {
        vec![String::new(), "  (ValidateDisc — not yet wired)".into()]
    }

    fn handle_key(&mut self, _key: KeyEvent, _shared: &mut AppShared<'_>) -> OpAction {
        OpAction::Noop
    }

    fn holds_ephemeral_state(&self) -> bool {
        false
    }

    fn needs_abort_confirmation(&self) -> bool {
        false
    }

    fn in_text_entry(&self) -> bool {
        false
    }
}
