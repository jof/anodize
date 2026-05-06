//! Share reveal component for InitRoot and RekeyShares ceremonies.
//!
//! Displays one share at a time as a wordlist string for custodian
//! transcription. The operator advances through shares one by one,
//! confirming each custodian has copied their share before proceeding.

use anodize_sss::Share;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

/// A share paired with its custodian name for display.
pub struct NamedShare {
    pub custodian_name: String,
    pub index: u8,
    pub words: String,
}

/// Interactive share reveal widget — shows one share at a time.
pub struct ShareReveal {
    /// All shares to reveal, in custodian order.
    pub shares: Vec<NamedShare>,
    /// Index into `shares` of the currently displayed share (or past the end if done).
    pub current: usize,
    /// Whether the current share's words are visible (toggled by operator).
    pub visible: bool,
}

impl ShareReveal {
    pub fn new(shares: Vec<Share>, custodian_names: &[String]) -> Self {
        let named: Vec<NamedShare> = shares
            .iter()
            .zip(custodian_names.iter())
            .map(|(share, name)| NamedShare {
                custodian_name: name.clone(),
                index: share.index,
                words: share.to_words(),
            })
            .collect();
        Self {
            shares: named,
            current: 0,
            visible: false,
        }
    }

    /// True when all shares have been revealed and confirmed.
    pub fn all_revealed(&self) -> bool {
        self.current >= self.shares.len()
    }

    /// Handle a key event. Returns true when all shares are done.
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        if self.all_revealed() {
            return true;
        }
        match key.code {
            KeyCode::Char('s') | KeyCode::Char('S') => {
                // Toggle visibility
                self.visible = !self.visible;
                false
            }
            KeyCode::Enter if self.visible => {
                // Confirm this share was transcribed, advance
                self.visible = false;
                self.current += 1;
                self.all_revealed()
            }
            _ => false,
        }
    }

    /// Render the share reveal UI.
    pub fn render(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(format!(
                "Share Distribution ({}/{})",
                self.current.min(self.shares.len()),
                self.shares.len()
            ))
            .border_style(Style::default().fg(Color::Magenta));

        let inner = block.inner(area);
        frame.render_widget(block, area);

        let mut lines: Vec<Line> = Vec::new();

        // Already-revealed shares
        for (i, ns) in self.shares.iter().enumerate() {
            if i < self.current {
                lines.push(Line::from(vec![
                    Span::styled("  \u{2714} ", Style::default().fg(Color::Green)),
                    Span::styled(
                        format!("#{} {}", ns.index, ns.custodian_name),
                        Style::default().fg(Color::Green),
                    ),
                    Span::styled(" — transcribed", Style::default().fg(Color::DarkGray)),
                ]));
            }
        }

        if self.all_revealed() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "  All shares distributed. Press Enter to continue.",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )));
        } else {
            let ns = &self.shares[self.current];
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!("  Hand device to: #{} {}", ns.index, ns.custodian_name),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(""));

            if self.visible {
                // Show the wordlist string — split into groups for readability
                for chunk in ns.words.split(" / ") {
                    lines.push(Line::from(Span::styled(
                        format!("    {chunk}"),
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD),
                    )));
                }
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "  Transcribe this share, then press [Enter] to confirm.",
                    Style::default().fg(Color::Cyan),
                )));
                lines.push(Line::from(Span::styled(
                    "  [S] Hide share",
                    Style::default().fg(Color::DarkGray),
                )));
            } else {
                lines.push(Line::from(Span::styled(
                    "  Share hidden. Press [S] to reveal.",
                    Style::default().fg(Color::DarkGray),
                )));
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "  Only the custodian should see this screen.",
                    Style::default().fg(Color::Yellow),
                )));
            }
        }

        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  [Esc] Abort ceremony",
            Style::default().fg(Color::DarkGray),
        )));

        let para = Paragraph::new(lines).wrap(Wrap { trim: false });
        frame.render_widget(para, inner);
    }
}
