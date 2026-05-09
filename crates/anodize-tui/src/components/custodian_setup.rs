//! Structured custodian setup component for SSS configuration.
//!
//! Two-phase flow:
//!   1. Add custodians one-by-one (Enter to add, minimum 2).
//!   2. Pick threshold with ↑/↓ (default: majority, minimum: 2).
//!
//! Used by both InitRoot and RekeyShares.

use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

/// Internal phase of the custodian setup widget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Entering custodian names one-by-one.
    Names,
    /// Choosing the SSS threshold (k-of-n).
    Threshold,
}

/// Interactive component for configuring SSS custodians and threshold.
pub struct CustodianSetup {
    phase: Phase,
    /// Names entered so far.
    pub names: Vec<String>,
    /// Current text input buffer for the name being entered.
    pub name_buf: String,
    /// Selected threshold (k in k-of-n).
    pub threshold: u8,
    /// Whether the user has confirmed the final configuration.
    pub confirmed: bool,
    /// Whether the user aborted.
    pub aborted: bool,
    /// Title prefix for the block (e.g. "Root Init" or "Re-key Shares").
    title_prefix: String,
}

impl CustodianSetup {
    pub fn new(title_prefix: impl Into<String>) -> Self {
        Self {
            phase: Phase::Names,
            names: Vec::new(),
            name_buf: String::new(),
            threshold: 2,
            confirmed: false,
            aborted: false,
            title_prefix: title_prefix.into(),
        }
    }

    /// Pre-populate with existing names (for re-key).
    pub fn with_names(mut self, names: Vec<String>) -> Self {
        self.names = names;
        self.threshold = default_threshold(self.names.len());
        self
    }

    /// Handle a key event. Returns true if the component consumed the event.
    pub fn handle_key(&mut self, key: crossterm::event::KeyEvent) -> bool {
        use crossterm::event::KeyCode;
        match self.phase {
            Phase::Names => match key.code {
                KeyCode::Char(c) => {
                    self.name_buf.push(c);
                    true
                }
                KeyCode::Backspace => {
                    self.name_buf.pop();
                    true
                }
                KeyCode::Enter => {
                    let trimmed = self.name_buf.trim().to_string();
                    if !trimmed.is_empty() {
                        self.names.push(trimmed);
                        self.name_buf.clear();
                        self.threshold = default_threshold(self.names.len());
                    }
                    true
                }
                KeyCode::Tab => {
                    // Switch to threshold phase if we have enough names
                    if self.names.len() >= 2 {
                        self.phase = Phase::Threshold;
                        self.threshold = default_threshold(self.names.len());
                    }
                    true
                }
                KeyCode::Delete => {
                    // Remove the last custodian from the list
                    if self.name_buf.is_empty() {
                        self.names.pop();
                        self.threshold = default_threshold(self.names.len());
                    }
                    true
                }
                KeyCode::Esc => {
                    self.aborted = true;
                    true
                }
                _ => false,
            },
            Phase::Threshold => match key.code {
                KeyCode::Up => {
                    let max = self.names.len() as u8;
                    if self.threshold < max {
                        self.threshold += 1;
                    }
                    true
                }
                KeyCode::Down => {
                    if self.threshold > 2 {
                        self.threshold -= 1;
                    }
                    true
                }
                KeyCode::Enter => {
                    self.confirmed = true;
                    true
                }
                KeyCode::Backspace | KeyCode::Tab => {
                    // Go back to name entry
                    self.phase = Phase::Names;
                    true
                }
                KeyCode::Esc => {
                    self.aborted = true;
                    true
                }
                _ => false,
            },
        }
    }

    pub fn render(&self, frame: &mut Frame, area: Rect) {
        let title = format!("{} — Custodian Setup", self.title_prefix);

        let bold = Style::default().add_modifier(Modifier::BOLD);
        let dim = Style::default().fg(Color::DarkGray);
        let highlight = Style::default().fg(Color::Cyan);
        let green = Style::default().fg(Color::Green);

        let mut lines: Vec<Line> = Vec::new();

        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("  Shamir Secret Sharing — ", bold),
            Span::styled(
                format!("{} custodian(s) entered", self.names.len()),
                highlight,
            ),
        ]));
        lines.push(Line::from(""));

        // Show entered custodians
        if self.names.is_empty() {
            lines.push(Line::from(Span::styled("  (no custodians yet)", dim)));
        } else {
            for (i, name) in self.names.iter().enumerate() {
                lines.push(Line::from(vec![
                    Span::styled(format!("  {}. ", i + 1), dim),
                    Span::styled(name.as_str(), green),
                ]));
            }
        }
        lines.push(Line::from(""));

        match self.phase {
            Phase::Names => {
                lines.push(Line::from(vec![
                    Span::raw("  Name: "),
                    Span::styled(format!("{}█", self.name_buf), highlight),
                ]));
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "  [Enter] Add name   [Tab] Set threshold   [Del] Remove last   [Esc] Abort",
                    dim,
                )));
                if self.names.len() < 2 {
                    lines.push(Line::from(Span::styled(
                        "  (need at least 2 custodians)",
                        Style::default().fg(Color::Yellow),
                    )));
                }
            }
            Phase::Threshold => {
                let n = self.names.len() as u8;
                lines.push(Line::from(vec![
                    Span::styled("  Threshold: ", bold),
                    Span::styled(
                        format!("{}-of-{}", self.threshold, n),
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]));
                lines.push(Line::from(""));

                // Visual bar
                let bar: String = (1..=n)
                    .map(|i| if i <= self.threshold { '■' } else { '□' })
                    .collect();
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(bar, highlight),
                ]));
                lines.push(Line::from(""));

                lines.push(Line::from(Span::styled(
                    "  [↑/↓] Adjust threshold   [Enter] Confirm   [Tab/BS] Back   [Esc] Abort",
                    dim,
                )));
            }
        }

        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .style(crate::theme::BLOCK)
            .border_style(crate::theme::BORDER)
            .title_style(crate::theme::TITLE);
        let para = Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false });
        frame.render_widget(para, area);
    }
}

/// Default threshold: majority rule, minimum 2.
fn default_threshold(n: usize) -> u8 {
    if n < 2 {
        2
    } else {
        ((n / 2) + 1).min(n) as u8
    }
}
