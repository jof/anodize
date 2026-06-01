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
/// All ceremony operations now run through the script engine; only
/// `OperationSelect` is used by the top-level ceremony mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CeremonyPhase {
    /// Choose an operation.
    OperationSelect,
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
    pub fn in_text_entry(&self) -> bool {
        false
    }

    /// Render with access to parent App state.
    pub fn render_with_app(&self, frame: &mut Frame, area: Rect, app: &crate::app::App) {
        let title = "Select Operation";
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
            "  [9]  Refresh disc            (seed session \u{2192} fresh start)".into(),
        ]
    }
}

impl Component for CeremonyMode {
    fn handle_key_event(&mut self, key: KeyEvent) -> Action {
        match key.code {
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
        }
    }
}
