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
    /// All words collected; awaiting explicit Enter to submit.
    pending_submit: bool,
    /// Last submit had an error; words preserved for editing.
    has_error: bool,
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
            pending_submit: false,
            has_error: false,
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

    /// Handle a key event. Returns true if a share was just submitted and accepted.
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        // Review/error state: all words collected, awaiting explicit Enter
        if self.pending_submit {
            match key.code {
                KeyCode::Enter => {
                    return self.submit();
                }
                KeyCode::Backspace => {
                    self.pending_submit = false;
                    self.has_error = false;
                    self.last_result = None;
                    if let Some(word) = self.words.pop() {
                        self.word_buf = word;
                        self.update_completions();
                    }
                    return false;
                }
                _ => return false,
            }
        }

        match key.code {
            KeyCode::Char(c) if c.is_ascii_alphabetic() => {
                self.word_buf.push(c.to_ascii_lowercase());
                self.update_completions();
                // Auto-complete (not auto-submit) the last word when prefix uniquely resolves
                if self.words.len() == self.expected_words - 1 && self.completions.len() == 1 {
                    let word = self.completions[0].to_string();
                    self.try_accept_complete(word);
                }
                false
            }
            KeyCode::Backspace => {
                if self.word_buf.is_empty() {
                    if let Some(word) = self.words.pop() {
                        self.word_buf = word;
                        self.update_completions();
                    }
                } else {
                    self.word_buf.pop();
                    self.update_completions();
                }
                self.last_result = None;
                self.has_error = false;
                false
            }
            KeyCode::Tab => {
                if self.completions.len() == 1 {
                    self.try_accept_complete(self.completions[0].to_string());
                }
                false
            }
            KeyCode::Char(' ') | KeyCode::Char('-') | KeyCode::Enter => {
                self.try_accept_current();
                false
            }
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

    fn try_accept_current(&mut self) {
        if self.word_buf.is_empty() {
            return;
        }
        if self.completions.len() == 1 {
            let word = self.completions[0].to_string();
            self.try_accept_complete(word);
            return;
        }
        if anodize_sss::is_valid_word(&self.word_buf) {
            let word = self.word_buf.clone();
            self.try_accept_complete(word);
        }
    }

    /// Accept a word. When all words are collected, enter review state
    /// (pending_submit) instead of auto-submitting.
    fn try_accept_complete(&mut self, word: String) {
        if self.words.len() >= self.expected_words {
            return;
        }
        self.words.push(word);
        self.word_buf.clear();
        self.completions.clear();
        self.has_error = false;
        self.last_result = None;
        if self.words.len() == self.expected_words {
            self.pending_submit = true;
        }
    }

    /// Submit completed word list: decode, identify custodian, verify commitment.
    /// Returns true if the share was accepted; false (with error feedback) otherwise.
    /// On error, words are preserved for in-place editing.
    fn submit(&mut self) -> bool {
        let input = self.words.join("-");

        // Decode wordlist → Share
        let share = match Share::from_words(&input, self.secret_len) {
            Ok(s) => s,
            Err(e) => {
                self.last_result = Some(ShareVerifyResult::DecodeError(e.to_string()));
                self.pending_submit = true;
                self.has_error = true;
                return false;
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
                self.pending_submit = true;
                self.has_error = true;
                return false;
            }
        };

        // Check for duplicate
        if self.collected.iter().any(|c| c.index == share.index) {
            self.last_result = Some(ShareVerifyResult::DecodeError(format!(
                "Share #{} ({}) already collected",
                share.index, custodian.name
            )));
            self.pending_submit = true;
            self.has_error = true;
            return false;
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
            self.pending_submit = true;
            self.has_error = true;
            return false;
        }

        // Accepted — clear input state
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
        self.words.clear();
        self.word_buf.clear();
        self.completions.clear();
        self.pending_submit = false;
        self.has_error = false;
        true
    }

    /// Render the share input UI.
    pub fn render(&self, frame: &mut Frame, area: Rect) {
        let border_style = if self.has_error {
            Style::default().fg(Color::Red).bg(Color::Black)
        } else if self.pending_submit {
            Style::default().fg(Color::Yellow).bg(Color::Black)
        } else {
            crate::theme::MODAL_BORDER_CYAN
        };
        let title_style = if self.has_error {
            Style::default()
                .fg(Color::Red)
                .bg(Color::Black)
                .add_modifier(Modifier::BOLD)
        } else if self.pending_submit {
            Style::default()
                .fg(Color::Yellow)
                .bg(Color::Black)
                .add_modifier(Modifier::BOLD)
        } else {
            crate::theme::MODAL_TITLE_CYAN
        };
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
            .border_style(border_style)
            .title_style(title_style);

        let inner = block.inner(area);
        frame.render_widget(block, area);

        let dim = Style::default().fg(Color::DarkGray);
        let green = Style::default().fg(Color::Green);
        let yellow = Style::default().fg(Color::Yellow);

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
            let progress_word = if self.pending_submit {
                self.expected_words
            } else {
                total_entered + 1
            };
            lines.push(Line::from(vec![
                Span::styled("  Word ", dim),
                Span::styled(
                    format!("{}/{}", progress_word, self.expected_words),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("  ({remaining} share(s) still needed)"), dim),
            ]));

            // Show entered words as kebab groups (4 per line)
            let word_color = if self.has_error {
                Color::Yellow
            } else if self.pending_submit {
                Color::White
            } else {
                Color::Green
            };
            if !self.words.is_empty() {
                for chunk in self.words.chunks(4) {
                    let group = chunk.join("-");
                    lines.push(Line::from(Span::styled(
                        format!("  {group}"),
                        Style::default().fg(word_color),
                    )));
                }
            }

            if self.pending_submit {
                // Review / error state — all words entered
                lines.push(Line::from(""));

                // Error feedback inline
                if let Some(ref result) = self.last_result {
                    Self::render_result(&mut lines, result, green);
                }

                if self.has_error {
                    lines.push(Line::from(Span::styled(
                        "  Press [BS] to edit, or [Enter] to re-submit.",
                        yellow,
                    )));
                } else {
                    lines.push(Line::from(Span::styled(
                        format!(
                            "  ✓ {} words entered. Review and press [Enter] to submit.",
                            self.expected_words
                        ),
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    )));
                }

                lines.push(Line::from(Span::styled(
                    "  [Enter] Submit   [BS] Edit   [Esc] Cancel",
                    dim,
                )));
            } else {
                // Active input state
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
                    } else if self.completions.is_empty() {
                        lines.push(Line::from(Span::styled(
                            "    ✘ no matching word",
                            Style::default().fg(Color::Red),
                        )));
                    }
                }

                // Result feedback (e.g. "Accepted" after previous share)
                if let Some(ref result) = self.last_result {
                    Self::render_result(&mut lines, result, green);
                }

                lines.push(Line::from(Span::styled(
                    "  [Tab] Complete   [Space/-] Next word   [BS] Undo   [Esc] Cancel",
                    dim,
                )));
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

        // Anchor view to bottom: scroll so the last lines are always visible.
        let content_height = lines.len() as u16;
        let visible_height = inner.height;
        let scroll_offset = content_height.saturating_sub(visible_height);

        let para = Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((scroll_offset, 0));
        frame.render_widget(para, inner);
    }

    /// Append result feedback lines.
    fn render_result(lines: &mut Vec<Line<'_>>, result: &ShareVerifyResult, green: Style) {
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
                    format!("  ✘ COMMITMENT MISMATCH: #{index} {custodian_name} — share rejected"),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                )));
                lines.push(Line::from(Span::styled(
                    "    Check each word carefully and correct any errors.",
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use anodize_config::state::Custodian;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    /// Build a minimal ShareInput backed by a real share so submit() succeeds.
    fn fixture() -> (ShareInput, String) {
        let secret = b"test";
        let shares = anodize_sss::split(secret, 2, 2).unwrap();
        let share = &shares[0];
        let commitment = share.commitment("Alice");
        let commitment_hex = hex::encode(commitment);

        let meta = SssMetadata {
            generation: 1,
            threshold: 2,
            total: 2,
            custodians: vec![
                Custodian {
                    name: "Alice".into(),
                    index: 1,
                },
                Custodian {
                    name: "Bob".into(),
                    index: 2,
                },
            ],
            pin_verify_hash: String::new(),
            share_commitments: vec![commitment_hex, String::new()],
        };

        let words = share.to_words();
        // to_words returns "a-b-c-d / e-f" — flatten to plain dash-separated
        let flat = words.replace(" / ", "-");
        let input = ShareInput::new(meta, secret.len());
        (input, flat)
    }

    fn type_word(input: &mut ShareInput, word: &str) -> bool {
        let mut submitted = false;
        for c in word.chars() {
            if input.handle_key(key(KeyCode::Char(c))) {
                submitted = true;
            }
        }
        submitted
    }

    /// Helper: type all words via Space separators, auto-completing the last word,
    /// then confirm with Enter. Returns the handle_key result from Enter.
    fn type_all_words_and_submit(input: &mut ShareInput, flat: &str) -> bool {
        let words: Vec<&str> = flat.split('-').collect();
        for &w in &words[..words.len() - 1] {
            type_word(input, w);
            input.handle_key(key(KeyCode::Char(' ')));
        }
        // Last word: type it — auto-complete will set pending_submit
        type_word(input, words.last().unwrap());
        assert!(input.pending_submit, "should enter review after all words");
        // Confirm
        input.handle_key(key(KeyCode::Enter))
    }

    #[test]
    fn last_word_enters_review_then_enter_submits() {
        let (mut input, flat) = fixture();
        let words: Vec<&str> = flat.split('-').collect();
        assert_eq!(words.len(), input.expected_words);

        // Type all words except the last, separating with Space
        for &w in &words[..words.len() - 1] {
            assert!(!type_word(&mut input, w));
            assert!(!input.handle_key(key(KeyCode::Char(' '))));
        }
        assert_eq!(input.words.len(), words.len() - 1);

        // Type the last word — should enter pending_submit, NOT auto-submit
        let last = words.last().unwrap();
        let submitted = type_word(&mut input, last);
        assert!(!submitted, "last word should enter review, not submit");
        assert!(input.pending_submit);
        assert!(input.last_result.is_none());

        // Now Enter to confirm
        let submitted = input.handle_key(key(KeyCode::Enter));
        assert!(submitted, "Enter in review state should submit");
        assert!(matches!(
            input.last_result,
            Some(ShareVerifyResult::Accepted { .. })
        ));
    }

    #[test]
    fn non_last_word_does_not_auto_accept() {
        let (mut input, flat) = fixture();
        let words: Vec<&str> = flat.split('-').collect();

        // Typing the first word character-by-character should NOT auto-submit
        let submitted = type_word(&mut input, words[0]);
        assert!(!submitted);
        assert!(
            input.words.is_empty(),
            "non-last word should stay in buffer"
        );
    }

    #[test]
    fn separator_still_works_for_last_word() {
        let (mut input, flat) = fixture();
        let submitted = type_all_words_and_submit(&mut input, &flat);
        assert!(submitted);
        assert!(matches!(
            input.last_result,
            Some(ShareVerifyResult::Accepted { .. })
        ));
    }

    #[test]
    fn backspace_from_review_edits_last_word() {
        let (mut input, flat) = fixture();
        let words: Vec<&str> = flat.split('-').collect();

        // Enter all words, reaching pending_submit
        for &w in &words[..words.len() - 1] {
            type_word(&mut input, w);
            input.handle_key(key(KeyCode::Char(' ')));
        }
        type_word(&mut input, words.last().unwrap());
        assert!(input.pending_submit);

        // Backspace exits review and pops last word back to buffer
        input.handle_key(key(KeyCode::Backspace));
        assert!(!input.pending_submit);
        assert_eq!(input.words.len(), words.len() - 1);
        assert!(!input.word_buf.is_empty());

        // Re-type the last word and submit
        // Clear the buffer first (it has the popped word)
        while !input.word_buf.is_empty() {
            input.handle_key(key(KeyCode::Backspace));
        }
        type_word(&mut input, words.last().unwrap());
        assert!(input.pending_submit);
        let submitted = input.handle_key(key(KeyCode::Enter));
        assert!(submitted);
    }

    #[test]
    fn error_preserves_words_for_editing() {
        let (mut input, flat) = fixture();
        let words: Vec<&str> = flat.split('-').collect();

        // Enter all words except corrupt the first one
        // Type a wrong first word (use a valid word that's wrong for the share)
        let wrong_word = if words[0] == "able" { "acid" } else { "able" };
        type_word(&mut input, wrong_word);
        input.handle_key(key(KeyCode::Char(' ')));
        for &w in &words[1..words.len() - 1] {
            type_word(&mut input, w);
            input.handle_key(key(KeyCode::Char(' ')));
        }
        type_word(&mut input, words.last().unwrap());

        // Should be in review state
        assert!(input.pending_submit);

        // Submit — should fail (checksum mismatch)
        let submitted = input.handle_key(key(KeyCode::Enter));
        assert!(!submitted, "corrupted share should not be accepted");
        assert!(input.has_error, "should be in error state");
        assert!(input.pending_submit, "should remain in review for editing");
        // Words should be preserved, not cleared
        assert_eq!(input.words.len(), input.expected_words);

        // Backspace to start editing — pops last word into word_buf
        input.handle_key(key(KeyCode::Backspace));
        assert!(!input.pending_submit);
        assert_eq!(input.words.len(), input.expected_words - 1);
        assert!(!input.word_buf.is_empty());

        // Clear word_buf, then pop remaining words back one by one
        while !input.word_buf.is_empty() {
            input.handle_key(key(KeyCode::Backspace));
        }
        while !input.words.is_empty() {
            // BS on empty buf pops a word into buf
            input.handle_key(key(KeyCode::Backspace));
            // clear that word's chars
            while !input.word_buf.is_empty() {
                input.handle_key(key(KeyCode::Backspace));
            }
        }
        assert_eq!(input.words.len(), 0);
    }
}
