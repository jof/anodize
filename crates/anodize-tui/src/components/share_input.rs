//! Share input component for the Quorum phase.
//!
//! Word-by-word entry with Tab autocomplete and per-word validation.
//! On submission, decodes the wordlist into a `Share`, auto-identifies
//! the custodian via the embedded index byte, and verifies against the
//! commitment stored in `STATE.JSON`.

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
    Accepted { custodian_name: String, index: u8 },
    /// Share decoded but commitment mismatch.
    CommitmentFailed { custodian_name: String, index: u8 },
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

/// Interactive share input widget with word-by-word entry.
pub struct ShareInput {
    /// Words entered so far for the current share.
    words: Vec<String>,
    /// Current word being typed.
    word_buf: String,
    /// Autocomplete candidates for the current prefix.
    completions: Vec<&'static str>,
    /// Number of shares required (threshold k).
    pub threshold: u8,
    /// When true, require all `n` shares (verification mode), not just threshold.
    pub verify_all: bool,
    /// Expected total word count per share (secret_len + 2 bytes = that many words).
    expected_words: usize,
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
        // Share bytes = 1 (index) + secret_len + 1 (checksum) = secret_len + 2
        let expected_words = secret_len + 2;
        Self {
            words: Vec::new(),
            word_buf: String::new(),
            completions: Vec::new(),
            threshold,
            verify_all: false,
            expected_words,
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

    /// True when all shares have been collected (for verification mode).
    pub fn all_collected(&self) -> bool {
        self.collected.len() >= self.sss_meta.total as usize
    }

    /// True when the required number of shares (all or threshold) have been collected.
    pub fn is_complete(&self) -> bool {
        if self.verify_all {
            self.all_collected()
        } else {
            self.quorum_reached()
        }
    }

    /// Handle a key event. Returns true if a share was just submitted.
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char(c) if c.is_ascii_alphabetic() => {
                self.word_buf.push(c.to_ascii_lowercase());
                self.update_completions();
                false
            }
            KeyCode::Backspace => {
                if self.word_buf.is_empty() {
                    // Pop the last accepted word
                    if let Some(word) = self.words.pop() {
                        self.word_buf = word;
                        self.update_completions();
                    }
                } else {
                    self.word_buf.pop();
                    self.update_completions();
                }
                self.last_result = None;
                false
            }
            KeyCode::Tab => {
                // Autocomplete: if exactly one match, accept it
                if self.completions.len() == 1 {
                    return self.try_accept_complete(self.completions[0].to_string());
                }
                false
            }
            KeyCode::Char(' ') | KeyCode::Char('-') | KeyCode::Enter => self.try_accept_current(),
            _ => false,
        }
    }

    fn update_completions(&mut self) {
        if self.word_buf.is_empty() {
            self.completions.clear();
        } else {
            self.completions = anodize_sss::prefix_matches(&self.word_buf);
        }
    }

    fn try_accept_current(&mut self) -> bool {
        if self.word_buf.is_empty() {
            return false;
        }
        // Auto-complete if exactly one match
        if self.completions.len() == 1 {
            let word = self.completions[0].to_string();
            return self.try_accept_complete(word);
        }
        // Accept if exact match
        if anodize_sss::is_valid_word(&self.word_buf) {
            let word = self.word_buf.clone();
            return self.try_accept_complete(word);
        }
        false
    }

    /// Accept a word and auto-submit when all words are collected.
    fn try_accept_complete(&mut self, word: String) -> bool {
        if self.words.len() >= self.expected_words {
            return false;
        }
        self.words.push(word);
        self.word_buf.clear();
        self.completions.clear();
        if self.words.len() == self.expected_words {
            self.submit();
            return true;
        }
        false
    }

    /// Submit completed word list: decode, identify custodian, verify commitment.
    fn submit(&mut self) {
        let input = self.words.join("-");
        self.words.clear();
        self.word_buf.clear();
        self.completions.clear();

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
                "Share Input (Gen {}) — {}/{} shares",
                self.sss_meta.generation,
                self.collected.len(),
                if self.verify_all {
                    self.sss_meta.total
                } else {
                    self.threshold
                }
            ))
            .style(crate::theme::BLOCK)
            .border_style(crate::theme::MODAL_BORDER_CYAN)
            .title_style(crate::theme::MODAL_TITLE_CYAN);

        let inner = block.inner(area);
        frame.render_widget(block, area);

        let dim = Style::default().fg(Color::DarkGray);
        let green = Style::default().fg(Color::Green);

        let mut lines: Vec<Line> = Vec::new();

        // Collected shares summary
        for cs in &self.collected {
            lines.push(Line::from(vec![
                Span::styled("  ✓ ", green),
                Span::styled(
                    format!("#{} {}", cs.index, cs.custodian_name),
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
            ]));
        }

        let required = if self.verify_all {
            self.sss_meta.total as usize
        } else {
            self.threshold as usize
        };
        let remaining = required - self.collected.len().min(required);
        if remaining > 0 {
            // Word progress
            let total_entered = self.words.len();
            lines.push(Line::from(vec![
                Span::styled("  Word ", dim),
                Span::styled(
                    format!("{}/{}", total_entered + 1, self.expected_words),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("  ({remaining} share(s) still needed)"), dim),
            ]));

            // Show accepted words as kebab groups (4 per line)
            if !self.words.is_empty() {
                for chunk in self.words.chunks(4) {
                    let group = chunk.join("-");
                    lines.push(Line::from(Span::styled(
                        format!("  {group}"),
                        Style::default().fg(Color::Green),
                    )));
                }
            }

            // Current word input
            let word_valid =
                !self.word_buf.is_empty() && anodize_sss::is_valid_word(&self.word_buf);
            let word_style = if self.word_buf.is_empty() {
                dim
            } else if word_valid {
                Style::default().fg(Color::Green)
            } else if self.completions.is_empty() {
                Style::default().fg(Color::Red)
            } else {
                Style::default().fg(Color::White)
            };

            lines.push(Line::from(vec![
                Span::raw("  > "),
                Span::styled(format!("{}█", self.word_buf), word_style),
            ]));

            // Autocomplete hint
            if !self.word_buf.is_empty() {
                if self.completions.len() == 1 {
                    lines.push(Line::from(Span::styled(
                        format!("    → {} [Tab]", self.completions[0]),
                        Style::default().fg(Color::DarkGray),
                    )));
                } else if self.completions.len() > 1 && self.completions.len() <= 6 {
                    let hint = self
                        .completions
                        .iter()
                        .copied()
                        .collect::<Vec<_>>()
                        .join(" ");
                    lines.push(Line::from(Span::styled(format!("    {hint}"), dim)));
                } else if self.completions.is_empty() && !self.word_buf.is_empty() {
                    lines.push(Line::from(Span::styled(
                        "    ✘ no matching word",
                        Style::default().fg(Color::Red),
                    )));
                }
            }
        } else {
            lines.push(Line::from(""));
            let done_msg = if self.verify_all {
                "  All shares verified! Proceeding..."
            } else {
                "  Quorum reached! Press [Enter] to reconstruct PIN."
            };
            lines.push(Line::from(Span::styled(
                done_msg,
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )));
        }

        // Last result feedback
        if let Some(ref result) = self.last_result {
            match result {
                ShareVerifyResult::Accepted {
                    custodian_name,
                    index,
                } => {
                    lines.push(Line::from(Span::styled(
                        format!("  ✓ Accepted: #{index} {custodian_name}"),
                        green,
                    )));
                }
                ShareVerifyResult::CommitmentFailed {
                    custodian_name,
                    index,
                } => {
                    lines.push(Line::from(Span::styled(
                        format!(
                            "  ✘ COMMITMENT MISMATCH: #{index} {custodian_name} — share rejected"
                        ),
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    )));
                    lines.push(Line::from(Span::styled(
                        "    Re-enter this share carefully.",
                        Style::default().fg(Color::Yellow),
                    )));
                }
                ShareVerifyResult::UnknownIndex(idx) => {
                    lines.push(Line::from(Span::styled(
                        format!("  ✘ Unknown share index #{idx} — not in custodian roster"),
                        Style::default().fg(Color::Red),
                    )));
                }
                ShareVerifyResult::DecodeError(msg) => {
                    lines.push(Line::from(Span::styled(
                        format!("  ✘ {msg}"),
                        Style::default().fg(Color::Red),
                    )));
                }
            }
        }

        lines.push(Line::from(Span::styled(
            "  [Tab] Complete   [Space/-] Next word   [BS] Undo   [Esc] Cancel",
            dim,
        )));

        // Anchor view to bottom: scroll so the last lines are always visible.
        let content_height = lines.len() as u16;
        let visible_height = inner.height;
        let scroll_offset = content_height.saturating_sub(visible_height);

        let para = Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((scroll_offset, 0));
        frame.render_widget(para, inner);
    }
}
