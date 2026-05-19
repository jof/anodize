use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::Rect,
    text::{Line, Text},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

use crate::action::{Action, Operation};
use crate::components::Component;

/// Pipeline phase for the ceremony state machine.
///
/// Phases: Select → Plan → Commit → Execute → Export → Done
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CeremonyPhase {
    /// Pre-pipeline: choose an operation.
    OperationSelect,
    /// Phase 3: write intent WAL to disc.
    Commit,
    /// Phase 4: re-confirm clock before signing.
    ClockReconfirm,
    /// Delegation: the active operation context owns state + rendering.
    ActiveOp,
    /// Phase 5: HSM crypto operation complete, verify result.
    Execute,
    /// Post-commit error: HSM/keygen/cert-build failed after intent write.
    /// Operator can [1] retry or [Esc] abort.
    PostCommitError,
    /// Phase 6a: writing record session to disc.
    BurningDisc,
    /// Phase 6b: disc written, shuttle copy pending.
    DiscDone,
    /// Terminal.
    Done,
}

pub struct CeremonyMode {
    pub state: CeremonyPhase,
}

impl CeremonyMode {
    pub fn new() -> Self {
        Self {
            state: CeremonyPhase::OperationSelect,
        }
    }

    /// Whether the user is entering text (affects 'q' quit and 'L' log toggle).
    ///
    /// Always false for the top-level ceremony phases; each `OpContext`
    /// reports its own `in_text_entry()` status during `ActiveOp`.
    pub fn in_text_entry(&self) -> bool {
        false
    }

    pub fn is_writing_intent(&self) -> bool {
        self.state == CeremonyPhase::Commit
    }

    pub fn is_burning_disc(&self) -> bool {
        self.state == CeremonyPhase::BurningDisc
    }

    /// Whether the current phase holds ephemeral/unrecoverable state in RAM.
    /// Quit is blocked entirely during these phases.
    pub fn holds_ephemeral_state(&self) -> bool {
        !matches!(
            self.state,
            CeremonyPhase::OperationSelect | CeremonyPhase::Done | CeremonyPhase::DiscDone
        )
    }

    /// Whether aborting from the current phase requires a two-key confirmation
    /// dialog.  Returns `false` for phases that are safe to leave freely
    /// (menu, completion screens, auto-advance, read-only reports).
    pub fn needs_abort_confirmation(&self) -> bool {
        !matches!(
            self.state,
            CeremonyPhase::OperationSelect
                | CeremonyPhase::Done
                | CeremonyPhase::DiscDone
                | CeremonyPhase::Commit
                | CeremonyPhase::BurningDisc
        )
    }

    /// Phase index for the phase bar.
    ///
    /// Maps to: 0=Select, 1=Plan, 2=Commit, 3=Quorum, 4=Execute, 5=Export
    pub fn phase_index(&self) -> usize {
        match self.state {
            // 0 — Select
            CeremonyPhase::OperationSelect => 0,
            // 2 — Commit (write intent WAL to disc)
            CeremonyPhase::Commit | CeremonyPhase::PostCommitError => 2,
            // 3 — Clock re-confirm before signing
            CeremonyPhase::ClockReconfirm => 3,
            // 4 — Execute (HSM crypto operation, cert preview/verify)
            CeremonyPhase::Execute => 4,
            // 5 — Export (write record to disc + shuttle copy)
            CeremonyPhase::BurningDisc | CeremonyPhase::DiscDone | CeremonyPhase::Done => 5,
            // Delegated — ask the active operation context
            CeremonyPhase::ActiveOp => 1,
        }
    }

    /// Phase-bar title for the Execute phase, context-sensitive to operation.
    pub fn execute_phase_title(op: Option<Operation>) -> &'static str {
        match op {
            Some(Operation::InitRoot) => "Certificate Preview \u{2014} RECORD FINGERPRINT",
            _ => "Certificate Preview \u{2014} VERIFY FINGERPRINT",
        }
    }

    /// Instruction text shown below the fingerprint on the Execute screen.
    pub fn fingerprint_instruction(op: Option<Operation>) -> &'static str {
        match op {
            Some(Operation::InitRoot) => "  Record this fingerprint on your paper checklist.",
            _ => "  Compare this fingerprint against your paper checklist.",
        }
    }

    /// Render with access to parent App state.
    pub fn render_with_app(&self, frame: &mut Frame, area: Rect, app: &crate::app::App) {
        let title = match self.state {
            CeremonyPhase::OperationSelect => "Select Operation",
            CeremonyPhase::Commit => "Committing Intent to Disc\u{2026}",
            CeremonyPhase::PostCommitError => "Post-Commit Error",
            CeremonyPhase::Execute => Self::execute_phase_title(app.current_op),
            CeremonyPhase::BurningDisc => "Writing Session\u{2026}",
            CeremonyPhase::DiscDone => match app.current_op {
                Some(Operation::InitRoot) => "Root Init Written",
                Some(Operation::SignCsr) => "Certificate Written",
                Some(Operation::RevokeCert) => "Revocation Record Written",
                Some(Operation::IssueCrl) => "CRL Refresh Written",
                Some(Operation::RekeyShares) => "Re-key Shares Written",
                Some(Operation::MigrateDisc) => "Disc Migration Written",
                Some(Operation::KeyBackup) => "Key Backup Written",
                Some(Operation::ValidateDisc) => "Disc Validation Written",
                #[cfg(feature = "dev-burn")]
                Some(Operation::RefreshDisc) => "Disc Refreshed",
                None => "Disc Session Written",
            },
            CeremonyPhase::ActiveOp => {
                // Title comes from the active operation context; rendered in render_with_app.
                "Operation"
            }
            CeremonyPhase::ClockReconfirm => "Clock Re-confirm \u{2014} Verify Before Signing",
            CeremonyPhase::Done => "Ceremony Complete",
        };

        let content = self.build_body(app);

        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .style(crate::theme::BLOCK)
            .border_style(crate::theme::BORDER)
            .title_style(crate::theme::TITLE);
        let lines: Vec<Line> = content
            .into_iter()
            .map(|s| {
                #[cfg(feature = "dev-burn")]
                if s.contains("[9]") {
                    return Line::from(ratatui::text::Span::styled(
                        s,
                        ratatui::style::Style::default().fg(ratatui::style::Color::Red),
                    ));
                }
                Line::from(s)
            })
            .collect();
        let para = Paragraph::new(Text::from(lines))
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((app.content_scroll, 0));
        frame.render_widget(para, area);
    }

    fn build_body(&self, app: &crate::app::App) -> Vec<String> {
        match &self.state {
            CeremonyPhase::OperationSelect => {
                let n_sessions = app.disc.prior_sessions.len();
                let disc_label = if n_sessions == 0 {
                    "  Blank disc \u{2014} no prior sessions.".into()
                } else {
                    format!("  Disc: {n_sessions} prior session(s).")
                };
                let state_label = if let Some(ref state) = app.disc.session_state {
                    let names: Vec<&str> = state
                        .sss
                        .custodians
                        .iter()
                        .map(|c| c.name.as_str())
                        .collect();
                    format!(
                        "  STATE.JSON: v{}, {}/{} SSS, custodians: {}",
                        state.version,
                        state.sss.threshold,
                        state.sss.total,
                        names.join(", ")
                    )
                } else if n_sessions > 0 {
                    "  STATE.JSON: not found (legacy disc)".into()
                } else {
                    "  STATE.JSON: (blank disc)".into()
                };
                vec![
                    String::new(),
                    disc_label,
                    state_label,
                    String::new(),
                    "  [1]  Init root CA           (SSS PIN split + key generation)".into(),
                    "  [2]  Sign intermediate CSR  (requires csr.der on shuttle)".into(),
                    "  [3]  Revoke a certificate   (adds entry + issues new CRL)".into(),
                    "  [4]  Issue CRL refresh      (re-signs current revocation list)".into(),
                    "  [5]  Re-key shares          (new custodians + new HSM PIN)".into(),
                    "  [6]  Migrate disc           (copy all sessions to new disc)".into(),
                    "  [7]  Key backup             (pair HSMs + backup signing key)".into(),
                    "  [8]  Validate disc           (verify integrity + HSM audit)".into(),
                    #[cfg(feature = "dev-burn")]
                    "  [9]  Refresh disc            (seed session → fresh start)".into(),
                ]
            }

            CeremonyPhase::Commit => {
                let elapsed = app
                    .disc
                    .burn_started
                    .map(|t| t.elapsed().as_secs())
                    .unwrap_or(0);
                let spin = app
                    .disc
                    .burn_started
                    .map(crate::helpers::spinner_frame)
                    .unwrap_or(' ');
                let mut lines = vec![
                    String::new(),
                    "  Writing intent session to disc.".into(),
                    "  HSM signing will begin after disc commit completes.".into(),
                    "  Do not remove the disc or power off.".into(),
                    String::new(),
                ];
                for entry in &app.disc.burn_log {
                    lines.push(format!("    {entry}"));
                }
                lines.push(format!("  {spin} [{elapsed:>3}s]"));
                lines
            }

            CeremonyPhase::PostCommitError => {
                vec![
                    String::new(),
                    "  The intent session was written to disc, but the post-commit".into(),
                    "  operation (HSM bootstrap / key generation / cert build) failed.".into(),
                    String::new(),
                    format!("  Error: {}", app.status),
                    String::new(),
                    "  The disc is safe — only the intent WAL was written.".into(),
                    "  You may retry without re-burning the intent session.".into(),
                    String::new(),
                    "  [1]   Retry HSM + key operation".into(),
                    "  [Esc] Abort to operation select".into(),
                ]
            }

            CeremonyPhase::Execute => {
                let fp = app.data.fingerprint.as_deref().unwrap_or("(none)");
                // Parse actual cert for subject/validity when available; fall
                // back to root CA profile only when cert_der is absent.
                let (subject, validity_label) = app
                    .data
                    .cert_der
                    .as_deref()
                    .and_then(crate::helpers::cert_subject_and_validity_days)
                    .map(|(subj, days)| (subj, format!("{days} days")))
                    .unwrap_or_else(|| {
                        let ca = app.profile.as_ref().map(|p| &p.ca);
                        let (cn, org, country) = ca
                            .map(|c| {
                                (
                                    c.common_name.as_str(),
                                    c.organization.as_str(),
                                    c.country.as_str(),
                                )
                            })
                            .unwrap_or(("?", "?", "?"));
                        (
                            format!("CN={cn}, O={org}, C={country}"),
                            "7305 days (20 years)".into(),
                        )
                    });
                let has_crl = app.data.crl_der.is_some();
                let mut lines = vec![
                    String::new(),
                    format!("  Subject  : {subject}"),
                    format!("  Validity : {validity_label}"),
                    String::new(),
                    "  SHA-256 Fingerprint:".into(),
                    format!("  {fp}"),
                ];
                if has_crl {
                    lines.push(String::new());
                    lines.push("  Initial CRL #1 (empty) will be included in this session.".into());
                }
                lines.push(String::new());
                lines.push(Self::fingerprint_instruction(app.current_op).into());
                lines.push(String::new());
                lines.push("  [1]  Proceed to disc write".into());
                lines.push("  [Esc]  Abort".into());
                lines
            }

            CeremonyPhase::BurningDisc => {
                let elapsed = app
                    .disc
                    .burn_started
                    .map(|t| t.elapsed().as_secs())
                    .unwrap_or(0);
                let spin = app
                    .disc
                    .burn_started
                    .map(crate::helpers::spinner_frame)
                    .unwrap_or(' ');
                let mut lines = vec![
                    String::new(),
                    "  Writing ISO 9660 session to optical disc\u{2026}".into(),
                    "  Please wait. Do not remove the disc or USB.".into(),
                    String::new(),
                ];
                for entry in &app.disc.burn_log {
                    lines.push(format!("    {entry}"));
                }
                lines.push(format!("  {spin} [{elapsed:>3}s]"));
                lines
            }

            CeremonyPhase::DiscDone => {
                let op_label = match app.current_op {
                    Some(Operation::InitRoot) => "Root init",
                    Some(Operation::SignCsr) => "Intermediate certificate",
                    Some(Operation::RevokeCert) => "Revocation record + CRL",
                    Some(Operation::IssueCrl) => "CRL refresh",
                    Some(Operation::RekeyShares) => "Re-key shares",
                    Some(Operation::MigrateDisc) => "Disc migration",
                    Some(Operation::KeyBackup) => "Key backup",
                    Some(Operation::ValidateDisc) => "Disc validation",
                    #[cfg(feature = "dev-burn")]
                    Some(Operation::RefreshDisc) => "Disc refresh",
                    None => "Session",
                };
                let fp = app.data.fingerprint.as_deref().unwrap_or("(none)");
                let mut lines = vec![
                    String::new(),
                    format!("  {op_label} written to disc successfully."),
                ];
                if app.data.fingerprint.is_some() {
                    lines.push(String::new());
                    lines.push(format!("  Fingerprint: {fp}"));
                }
                lines.push(String::new());
                match app.current_op {
                    Some(Operation::MigrateDisc) => {
                        lines.push("  [Q]  Quit (migration complete; no USB export)".into());
                    }
                    #[cfg(feature = "dev-burn")]
                    Some(Operation::RefreshDisc) => {
                        lines.push("  [1]  Continue (disc refreshed; no shuttle artifacts)".into());
                    }
                    _ => {
                        lines.push("  [1]  Copy artifacts to shuttle".into());
                        lines.push(
                            "  [Q]  Quit without shuttle copy (disc is the primary record)".into(),
                        );
                    }
                }
                lines
            }

            CeremonyPhase::ClockReconfirm => {
                let now = time::OffsetDateTime::now_utc()
                    .replace_nanosecond(0)
                    .expect("0ns is always valid");
                let time_str = now
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_else(|_| "unknown".into());
                vec![
                    String::new(),
                    "  HSM unlocked. Before signing, confirm the system clock is correct.".into(),
                    String::new(),
                    format!("  Current time:  {time_str}"),
                    String::new(),
                    "  Certificates will be timestamped with this time.".into(),
                    "  If the clock is wrong, quit and correct it before proceeding.".into(),
                    String::new(),
                    "  [1]  Clock is correct \u{2014} proceed with signing".into(),
                    "  [Esc]  Abort".into(),
                ]
            }

            CeremonyPhase::ActiveOp => {
                // Body is rendered by App via OpContext; this shouldn't be reached.
                vec![String::new(), "  (delegated to active operation)".into()]
            }

            CeremonyPhase::Done => {
                vec![
                    String::new(),
                    "  Ceremony complete.".into(),
                    String::new(),
                    match app.current_op {
                        Some(Operation::MigrateDisc) => {
                            "  Disc migration finished. Store new disc and archive old disc.".into()
                        }
                        _ => format!("  Shuttle : {}  \u{2713}", app.shuttle_mount.display()),
                    },
                    String::new(),
                    "  Remove and store both disc and USB separately.".into(),
                    "  The HSM holds the private key; no key material was written to disk.".into(),
                    String::new(),
                    "  [Q]  Quit".into(),
                ]
            }
        }
    }
}

impl Component for CeremonyMode {
    fn handle_key_event(&mut self, key: KeyEvent) -> Action {
        match &self.state {
            CeremonyPhase::OperationSelect => match key.code {
                KeyCode::Char('1') => Action::SelectOperation(Operation::InitRoot),
                KeyCode::Char('2') => Action::SelectOperation(Operation::SignCsr),
                KeyCode::Char('3') => Action::SelectOperation(Operation::RevokeCert),
                KeyCode::Char('4') => Action::SelectOperation(Operation::IssueCrl),
                KeyCode::Char('5') => Action::SelectOperation(Operation::RekeyShares),
                KeyCode::Char('6') => Action::SelectOperation(Operation::MigrateDisc),
                KeyCode::Char('7') => Action::SelectOperation(Operation::KeyBackup),
                KeyCode::Char('8') => Action::SelectOperation(Operation::ValidateDisc),
                #[cfg(feature = "dev-burn")]
                KeyCode::Char('9') => Action::SelectOperation(Operation::RefreshDisc),
                _ => Action::Noop,
            },

            CeremonyPhase::Commit => Action::Noop, // auto-advance on burn

            CeremonyPhase::PostCommitError => match key.code {
                KeyCode::Char('1') => Action::RetryPostCommit,
                KeyCode::Esc => Action::InitRootAbort,
                _ => Action::Noop,
            },

            CeremonyPhase::Execute => match key.code {
                KeyCode::Char('1') => Action::ConfirmCertBurn,
                KeyCode::Esc => Action::CeremonyCancel,
                _ => Action::Noop,
            },

            CeremonyPhase::BurningDisc => Action::Noop, // auto-advance on burn

            CeremonyPhase::DiscDone => match key.code {
                KeyCode::Char('1') => Action::DoWriteShuttle,
                KeyCode::Char('q') | KeyCode::Char('Q') => Action::Quit,
                _ => Action::Noop,
            },

            CeremonyPhase::ActiveOp => Action::Noop, // handled by App via OpContext

            CeremonyPhase::ClockReconfirm => match key.code {
                KeyCode::Char('1') => Action::ReconfirmClock,
                KeyCode::Esc => Action::CeremonyCancel,
                _ => Action::Noop,
            },

            CeremonyPhase::Done => match key.code {
                KeyCode::Char('q') | KeyCode::Char('Q') => Action::Quit,
                _ => Action::Noop,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_title_init_root_says_record() {
        let title = CeremonyMode::execute_phase_title(Some(Operation::InitRoot));
        assert!(
            title.contains("RECORD"),
            "InitRoot should say RECORD, got: {title}"
        );
        assert!(
            !title.contains("VERIFY"),
            "InitRoot should not say VERIFY, got: {title}"
        );
    }

    #[test]
    fn execute_title_other_ops_says_verify() {
        for op in [
            Some(Operation::SignCsr),
            Some(Operation::RevokeCert),
            Some(Operation::IssueCrl),
            None,
        ] {
            let title = CeremonyMode::execute_phase_title(op);
            assert!(
                title.contains("VERIFY"),
                "Op {op:?} should say VERIFY, got: {title}"
            );
        }
    }

    #[test]
    fn fingerprint_instruction_init_root_says_record() {
        let text = CeremonyMode::fingerprint_instruction(Some(Operation::InitRoot));
        assert!(
            text.contains("Record"),
            "InitRoot instruction should say Record, got: {text}"
        );
    }

    #[test]
    fn fingerprint_instruction_other_ops_says_compare() {
        for op in [Some(Operation::SignCsr), Some(Operation::RevokeCert), None] {
            let text = CeremonyMode::fingerprint_instruction(op);
            assert!(
                text.contains("Compare"),
                "Op {op:?} should say Compare, got: {text}"
            );
        }
    }
}
