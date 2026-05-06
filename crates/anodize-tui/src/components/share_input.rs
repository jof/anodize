//! Share input component for the Quorum phase.
//!
//! Accepts wordlist-encoded share input from a custodian. On submission,
//! decodes the wordlist string into a `Share`, auto-identifies the custodian
//! via the embedded index byte, and verifies the share against its commitment
//! stored in `STATE.JSON`.

use anodize_config::state::SssMetadata;
use anodize_sss::Share;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

/// Result of validating a submitted share.
#[derive(Debug, Clone)]
pub enum ShareVerifyResult {
    /// Share decoded and commitment verified.
    Accepted {
        custodian_name: String,
        index: u8,
    },
    /// Share decoded but commitment mismatch.
    CommitmentFailed {
        custodian_name: String,
        index: u8,
    },
    /// Index not found in custodian roster.
    UnknownIndex(u8),
    /// Wordlist/checksum decode error.
    DecodeError(String),
}

/// A collected share that passed verification.
#[derive(Debug, Clone)]
pub struct CollectedShare {
    pub custodian_name: String,
    pub index: u8,
    pub share: Share,
}

/// Interactive share input widget.
pub struct ShareInput {
    /// Current text buffer (words typed so far).
    pub buf: String,
    /// Number of shares required (threshold k).
    pub threshold: u8,
    /// Shares collected so far.
    pub collected: Vec<CollectedShare>,
    /// Expected share byte length (1 + secret_len + 1, from split params).
    pub secret_len: usize,
    /// Last verification result for display feedback.
    pub last_result: Option<ShareVerifyResult>,
    /// SSS metadata from STATE.JSON (custodian roster + commitments).
    pub sss_meta: SssMetadata,
}

impl ShareInput {
    pub fn new(sss_meta: SssMetadata, secret_len: usize) -> Self {
        let threshold = sss_meta.threshold;
        Self {
            buf: String::new(),
            threshold,
            collected: Vec::new(),
            secret_len,
            last_result: None,
            sss_meta,
        }
    }

    /// True when enough shares have been collected.
    pub fn quorum_reached(&self) -> bool {
        self.collected.len() >= self.threshold as usize
    }

    /// Handle a key event. Returns true if the share was submitted (Enter).
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char(c) => {
                // Accept letters, spaces, dashes, slashes for wordlist input
                if c.is_ascii_alphabetic() || c == ' ' || c == '-' || c == '/' {
                    self.buf.push(if c.is_ascii_uppercase() {
                        c.to_ascii_lowercase()
                    } else {
                        c
                    });
                }
                false
            }
            KeyCode::Backspace => {
                self.buf.pop();
                self.last_result = None;
                false
            }
            KeyCode::Enter => {
                if self.buf.trim().is_empty() {
                    return false;
                }
                self.submit();
                true
            }
            _ => false,
        }
    }

    /// Submit the current buffer: decode, identify custodian, verify commitment.
    fn submit(&mut self) {
        let input = self.buf.trim().to_string();
        self.buf.clear();

        // Decode wordlist → Share
        let share = match Share::from_words(&input, self.secret_len) {
            Ok(s) => s,
            Err(e) => {
                self.last_result = Some(ShareVerifyResult::DecodeError(e.to_string()));
                return;
            }
        };

        // Look up custodian by index
        let custodian = self
            .sss_meta
            .custodians
            .iter()
            .find(|c| c.index == share.index);

        let custodian = match custodian {
            Some(c) => c,
            None => {
                self.last_result = Some(ShareVerifyResult::UnknownIndex(share.index));
                return;
            }
        };

        // Check for duplicate
        if self.collected.iter().any(|c| c.index == share.index) {
            self.last_result = Some(ShareVerifyResult::DecodeError(format!(
                "Share #{} ({}) already collected",
                share.index, custodian.name
            )));
            return;
        }

        // Verify commitment
        let commitment = share.commitment(&custodian.name);
        let commitment_hex = hex::encode(commitment);
        let expected = self
            .sss_meta
            .share_commitments
            .get(
                self.sss_meta
                    .custodians
                    .iter()
                    .position(|c| c.index == share.index)
                    .unwrap_or(0),
            )
            .cloned()
            .unwrap_or_default();

        if commitment_hex != expected {
            self.last_result = Some(ShareVerifyResult::CommitmentFailed {
                custodian_name: custodian.name.clone(),
                index: share.index,
            });
            return;
        }

        // Accepted
        let name = custodian.name.clone();
        let idx = share.index;
        self.collected.push(CollectedShare {
            custodian_name: name.clone(),
            index: idx,
            share,
        });
        self.last_result = Some(ShareVerifyResult::Accepted {
            custodian_name: name,
            index: idx,
        });
    }

    /// Render the share input UI.
    pub fn render(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(format!(
                "Share Input ({}/{})",
                self.collected.len(),
                self.threshold
            ))
            .border_style(Style::default().fg(Color::Cyan));

        let inner = block.inner(area);
        frame.render_widget(block, area);

        let mut lines: Vec<Line> = Vec::new();

        // Collected shares summary
        if !self.collected.is_empty() {
            for cs in &self.collected {
                lines.push(Line::from(vec![
                    Span::styled("  \u{2714} ", Style::default().fg(Color::Green)),
                    Span::styled(
                        format!("#{} {}", cs.index, cs.custodian_name),
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]));
            }
            lines.push(Line::from(""));
        }

        // Remaining needed
        let remaining = self.threshold as usize - self.collected.len();
        if remaining > 0 {
            lines.push(Line::from(format!(
                "  Enter share ({remaining} more needed):"
            )));
            lines.push(Line::from(""));

            // Input buffer with cursor
            let display = if self.buf.is_empty() {
                Span::styled(
                    "  (type wordlist words...)",
                    Style::default().fg(Color::DarkGray),
                )
            } else {
                Span::styled(
                    format!("  {}\u{2588}", self.buf),
                    Style::default().fg(Color::White),
                )
            };
            lines.push(Line::from(display));
        } else {
            lines.push(Line::from(Span::styled(
                "  Quorum reached! Press Enter to reconstruct.",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )));
        }

        // Last result feedback
        if let Some(ref result) = self.last_result {
            lines.push(Line::from(""));
            match result {
                ShareVerifyResult::Accepted {
                    custodian_name,
                    index,
                } => {
                    lines.push(Line::from(Span::styled(
                        format!("  \u{2714} Accepted: #{index} {custodian_name}"),
                        Style::default().fg(Color::Green),
                    )));
                }
                ShareVerifyResult::CommitmentFailed {
                    custodian_name,
                    index,
                } => {
                    lines.push(Line::from(Span::styled(
                        format!(
                            "  \u{2718} COMMITMENT MISMATCH: #{index} {custodian_name} — share rejected"
                        ),
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    )));
                }
                ShareVerifyResult::UnknownIndex(idx) => {
                    lines.push(Line::from(Span::styled(
                        format!("  \u{2718} Unknown share index #{idx} — not in custodian roster"),
                        Style::default().fg(Color::Red),
                    )));
                }
                ShareVerifyResult::DecodeError(msg) => {
                    lines.push(Line::from(Span::styled(
                        format!("  \u{2718} {msg}"),
                        Style::default().fg(Color::Red),
                    )));
                }
            }
        }

        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  [Esc] Cancel",
            Style::default().fg(Color::DarkGray),
        )));

        let para = Paragraph::new(lines).wrap(Wrap { trim: false });
        frame.render_widget(para, inner);
    }
}
