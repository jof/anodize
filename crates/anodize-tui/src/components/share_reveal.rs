//! Share reveal component for InitRoot and RekeyShares ceremonies.
//!
//! Displays one share at a time as a numbered word grid for custodian
//! transcription. Screen-clear protocol: the share is hidden by default
//! and only shown on explicit toggle, ensuring only the intended custodian
//! sees the sensitive data.

use anodize_sss::Share;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

/// A share paired with its custodian name for display.
pub struct NamedShare {
    pub custodian_name: String,
    pub index: u8,
    /// Word groups (each is a dash-separated group of 4 words).
    pub word_groups: Vec<String>,
}

/// Interactive share reveal widget — shows one share at a time.
pub struct ShareReveal {
    /// All shares to reveal, in custodian order.
    pub shares: Vec<NamedShare>,
    /// Index into `shares` of the currently displayed share (or past the end if done).
    pub current: usize,
    /// Whether the current share's words are visible (toggled by operator).
    pub visible: bool,
    /// Vertical scroll offset for the content area.
    pub scroll_offset: u16,
}

impl ShareReveal {
    pub fn new(shares: Vec<Share>, custodian_names: &[String]) -> Self {
        let named: Vec<NamedShare> = shares
            .iter()
            .zip(custodian_names.iter())
            .map(|(share, name)| {
                let words = share.to_words();
                let groups: Vec<String> = words.split(" / ").map(String::from).collect();
                NamedShare {
                    custodian_name: name.clone(),
                    index: share.index,
                    word_groups: groups,
                }
            })
            .collect();
        Self {
            shares: named,
            current: 0,
            visible: false,
            scroll_offset: 0,
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
                self.visible = !self.visible;
                self.scroll_offset = 0;
                false
            }
            KeyCode::Enter if self.visible => {
                // Confirm transcription, hide and advance
                self.visible = false;
                self.scroll_offset = 0;
                self.current += 1;
                self.all_revealed()
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.scroll_offset = self.scroll_offset.saturating_add(1);
                false
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.scroll_offset = self.scroll_offset.saturating_sub(1);
                false
            }
            _ => false,
        }
    }

    /// Render the share reveal UI.
    pub fn render(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(format!(
                "Share Distribution — {}/{}",
                (self.current + 1).min(self.shares.len()),
                self.shares.len()
            ))
            .border_style(Style::default().fg(Color::Magenta));

        let inner = block.inner(area);
        frame.render_widget(block, area);

        // Reserve 2 lines at the bottom for fixed key-hint footer.
        let footer_height = 2u16;
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(footer_height)])
            .split(inner);
        let content_area = chunks[0];
        let footer_area = chunks[1];

        let bold = Style::default().add_modifier(Modifier::BOLD);
        let dim = Style::default().fg(Color::DarkGray);
        let green = Style::default().fg(Color::Green);

        let mut lines: Vec<Line> = Vec::new();
        lines.push(Line::from(""));

        // Progress: already-distributed shares
        for (i, ns) in self.shares.iter().enumerate() {
            if i < self.current {
                lines.push(Line::from(vec![
                    Span::styled("  ✓ ", green),
                    Span::styled(
                        format!("Share #{} — {}", ns.index, ns.custodian_name),
                        green,
                    ),
                ]));
            } else if i == self.current && !self.all_revealed() {
                lines.push(Line::from(vec![
                    Span::styled("  ▸ ", Style::default().fg(Color::Yellow)),
                    Span::styled(
                        format!("Share #{} — {}", ns.index, ns.custodian_name),
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]));
            } else {
                lines.push(Line::from(vec![
                    Span::styled("  ○ ", dim),
                    Span::styled(format!("Share #{} — {}", ns.index, ns.custodian_name), dim),
                ]));
            }
        }

        lines.push(Line::from(""));

        if self.all_revealed() {
            lines.push(Line::from(Span::styled(
                "  All shares distributed successfully.",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "  Press [Enter] to continue to verification.",
                Style::default().fg(Color::Cyan),
            )));
        } else {
            let ns = &self.shares[self.current];

            if self.visible {
                // ── Numbered word grid ──
                lines.push(Line::from(Span::styled(
                    format!("  Share #{} for: {}", ns.index, ns.custodian_name),
                    bold,
                )));
                lines.push(Line::from(""));

                for group in ns.word_groups.iter() {
                    lines.push(Line::from(Span::styled(
                        format!("  {group}"),
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD),
                    )));
                }

                lines.push(Line::from(""));
                lines.push(Line::from(vec![
                    Span::styled("  Total: ", dim),
                    Span::styled(
                        format!(
                            "{} groups, {} words",
                            ns.word_groups.len(),
                            ns.word_groups.len() * 4
                        ),
                        Style::default().fg(Color::Cyan),
                    ),
                ]));
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "  Transcribe all words carefully.",
                    Style::default().fg(Color::Cyan),
                )));
            } else {
                // ── Screen-clear state ──
                lines.push(Line::from(Span::styled(
                    format!("  HAND DEVICE TO: #{} {}", ns.index, ns.custodian_name),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )));
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "  The share is hidden. Only the custodian should see this screen.",
                    Style::default().fg(Color::Yellow),
                )));
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "  When ready, the custodian presses [S] to reveal their share.",
                    dim,
                )));
            }
        }

        // Clamp scroll offset so we can't scroll past content.
        let content_lines = lines.len() as u16;
        let max_scroll = content_lines.saturating_sub(content_area.height);
        let clamped_scroll = self.scroll_offset.min(max_scroll);

        let para = Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((clamped_scroll, 0));
        frame.render_widget(para, content_area);

        // Fixed footer: context-dependent hints + abort.
        let hint = if self.all_revealed() {
            "  [Enter] Continue"
        } else if self.visible {
            "  [Enter] Confirm transcription   [S] Hide share   [j/k] Scroll"
        } else {
            "  [S] Reveal share"
        };
        let footer_lines = vec![
            Line::from(Span::styled(hint, dim)),
            Line::from(Span::styled("  [Esc] Abort ceremony", dim)),
        ];
        let footer = Paragraph::new(footer_lines);
        frame.render_widget(footer, footer_area);
    }
}
