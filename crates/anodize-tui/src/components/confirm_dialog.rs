//! Two-key confirmation dialog overlay.
//!
//! Critical ceremony actions (disc burn, cert signing) require pressing
//! two keys in sequence to prevent accidental activation.
//! Renders as a centered modal over the existing content.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Flex, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};

use crate::action::Action;

/// State of the two-key confirmation sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Stage {
    /// Waiting for the first key.
    First,
    /// First key accepted; waiting for the second key.
    Second,
}

/// A modal dialog that requires two sequential keypresses to confirm.
pub struct ConfirmDialog {
    /// Title shown in the dialog border.
    pub title: String,
    /// Body text explaining what will happen.
    pub body: Vec<String>,
    /// The Action to emit on successful two-key confirm.
    pub confirm_action: Action,
    /// Internal stage tracker.
    stage: Stage,
}

impl ConfirmDialog {
    pub fn new(title: impl Into<String>, body: Vec<String>, confirm_action: Action) -> Self {
        Self {
            title: title.into(),
            body,
            confirm_action,
            stage: Stage::First,
        }
    }

    /// Handle a key event. Returns Some(action) if the dialog should close.
    /// - `Some(confirm_action)` on successful two-key confirm
    /// - `Some(Action::Noop)` on cancel (Esc)
    /// - `None` if the dialog should stay open
    pub fn handle_key(&mut self, key: KeyEvent) -> Option<Action> {
        match key.code {
            KeyCode::Esc => {
                // Cancel at any stage
                Some(Action::Noop)
            }
            KeyCode::Char('1') if self.stage == Stage::First => {
                self.stage = Stage::Second;
                None // Stay open, show second prompt
            }
            KeyCode::Enter if self.stage == Stage::Second => {
                // Both keys pressed — confirm
                Some(std::mem::replace(&mut self.confirm_action, Action::Noop))
            }
            _ => {
                // Wrong key — reset to first stage
                if self.stage == Stage::Second {
                    self.stage = Stage::First;
                }
                None
            }
        }
    }

    /// Render as a centered modal overlay.
    pub fn render(&self, frame: &mut Frame, area: Rect) {
        // Size the dialog: 60 wide, body lines + 6 for chrome/instructions
        let width = 60u16.min(area.width.saturating_sub(4));
        let height = (self.body.len() as u16 + 8).min(area.height.saturating_sub(2));

        let dialog_area = centered_rect(width, height, area);

        // Clear the background
        frame.render_widget(Clear, dialog_area);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow))
            .title(self.title.as_str())
            .title_style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            );

        let inner = block.inner(dialog_area);
        frame.render_widget(block, dialog_area);

        let mut lines: Vec<Line> = Vec::new();
        lines.push(Line::from(""));
        for line in &self.body {
            lines.push(Line::from(format!("  {line}")));
        }
        lines.push(Line::from(""));

        match self.stage {
            Stage::First => {
                lines.push(Line::from(vec![
                    Span::styled("  Press ", Style::default().fg(Color::White)),
                    Span::styled(
                        "[1]",
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(" to begin confirmation", Style::default().fg(Color::White)),
                ]));
            }
            Stage::Second => {
                lines.push(Line::from(vec![
                    Span::styled("  Step 1 ", Style::default().fg(Color::Green)),
                    Span::styled("\u{2714}", Style::default().fg(Color::Green)),
                    Span::styled("  Now press ", Style::default().fg(Color::White)),
                    Span::styled(
                        "[Enter]",
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(" to confirm", Style::default().fg(Color::White)),
                ]));
            }
        }
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("  ", Style::default()),
            Span::styled("[Esc]", Style::default().fg(Color::DarkGray)),
            Span::styled(" Cancel", Style::default().fg(Color::DarkGray)),
        ]));

        let para = Paragraph::new(lines).wrap(Wrap { trim: false });
        frame.render_widget(para, inner);
    }
}

/// Center a rect of given size within an outer area.
fn centered_rect(width: u16, height: u16, outer: Rect) -> Rect {
    let [area] = Layout::horizontal([Constraint::Length(width)])
        .flex(Flex::Center)
        .areas(outer);
    let [area] = Layout::vertical([Constraint::Length(height)])
        .flex(Flex::Center)
        .areas(area);
    area
}
