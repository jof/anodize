//! Disc Sync — copy missing sessions from a master disc to one or more backup discs.
//!
//! FSM phases:
//!   ScanSource  → WaitTarget → ScanTarget → Confirm → Writing → Done
//!                                                     ↗ (loop)
//! Error is a catch-all displayed at any point.

use std::sync::mpsc;

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

use crate::media::{BurnProgress, SessionEntry};

// ── FSM ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncPhase {
    /// Initial: prompt to scan master disc.
    ScanSource,
    /// Master scanned; waiting for operator to insert backup disc.
    WaitTarget,
    /// Scanning target disc and validating pairing.
    ScanTarget,
    /// Pairing validated; show confirmation before writing.
    Confirm,
    /// Writing missing sessions to target disc.
    Writing,
    /// Sync complete for this backup disc.
    Done,
    /// Error with message.
    Error(String),
}

pub struct DiscSyncState {
    pub phase: SyncPhase,

    // ── Master disc data (stashed across backup-disc swaps) ─────────────
    master_sessions: Vec<SessionEntry>,
    master_genesis: Option<String>,
    master_summary: String,

    // ── Target disc data ────────────────────────────────────────────────
    target_session_count: usize,
    target_summary: String,
    delta_count: usize,

    // ── Burn progress ───────────────────────────────────────────────────
    burn_rx: Option<mpsc::Receiver<BurnProgress>>,
    burn_step: Option<String>,
    burn_track_idx: usize, // which delta track we're on (0-based)
    burn_track_total: usize,

    // ── Rendering ───────────────────────────────────────────────────────
    pub scroll: u16,
    result_message: String,
}

impl DiscSyncState {
    pub fn new() -> Self {
        Self {
            phase: SyncPhase::ScanSource,
            master_sessions: Vec::new(),
            master_genesis: None,
            master_summary: String::new(),
            target_session_count: 0,
            target_summary: String::new(),
            delta_count: 0,
            burn_rx: None,
            burn_step: None,
            burn_track_idx: 0,
            burn_track_total: 0,
            scroll: 0,
            result_message: String::new(),
        }
    }

    /// Reset to initial state (e.g. when exiting the screen).
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    // ── Phase transitions called by App ─────────────────────────────────

    /// Scan the master disc. Returns an action hint for the caller.
    pub fn do_scan_source(&mut self, dev: &std::path::Path) -> Result<(), String> {
        let scan = crate::media::scan_disc(dev)?;

        if scan.sessions.is_empty() {
            return Err("Master disc has no sessions".into());
        }

        self.master_genesis = extract_genesis_hash(&scan.sessions);
        self.master_summary = format!(
            "{} session(s) on master — {}",
            scan.sessions.len(),
            scan.capacity_summary,
        );
        self.master_sessions = scan.sessions;
        self.phase = SyncPhase::WaitTarget;
        self.scroll = 0;
        Ok(())
    }

    /// Scan the target (backup) disc and validate pairing against the master.
    pub fn do_scan_target(&mut self, dev: &std::path::Path) -> Result<(), String> {
        let scan = crate::media::scan_disc(dev)?;

        // Reject blank discs — use MigrateDisc instead.
        if scan.sessions.is_empty() {
            return Err("Backup disc has no sessions — use Migrate Disc for blank media".into());
        }

        let target_sessions = &scan.sessions;
        let master_sessions = &self.master_sessions;

        // ── Validation 1: genesis hash ──────────────────────────────────
        let target_genesis = extract_genesis_hash(target_sessions);
        match (&self.master_genesis, &target_genesis) {
            (Some(mg), Some(tg)) if mg != tg => {
                return Err(format!(
                    "Discs do not share a common genesis.\n  Master: {mg}\n  Backup: {tg}"
                ));
            }
            (Some(_), None) => {
                return Err(
                    "Backup disc has no AUDIT.LOG in its first session — cannot verify genesis"
                        .into(),
                );
            }
            (None, _) => {
                return Err(
                    "Master disc has no AUDIT.LOG in its first session — cannot verify genesis"
                        .into(),
                );
            }
            _ => {}
        }

        // ── Validation 2: audit chain integrity on backup ───────────────
        if !crate::helpers::verify_audit_chain(target_sessions) {
            return Err("Backup disc audit chain is broken — refusing to append".into());
        }

        // ── Validation 3: session prefix match ─────────────────────────
        if target_sessions.len() > master_sessions.len() {
            return Err(format!(
                "Backup disc is ahead of master ({} vs {} sessions)",
                target_sessions.len(),
                master_sessions.len(),
            ));
        }

        for (i, (ts, ms)) in target_sessions
            .iter()
            .zip(master_sessions.iter())
            .enumerate()
        {
            if ts.dir_name != ms.dir_name {
                return Err(format!(
                    "Session {} mismatch — master: {}, backup: {}. \
                     Disc is not a paired copy of the master.",
                    i + 1,
                    ms.dir_name,
                    ts.dir_name,
                ));
            }
        }

        let delta = master_sessions.len() - target_sessions.len();

        // Check capacity
        if (scan.sessions_remaining as usize) < delta {
            return Err(format!(
                "Backup disc has only {} sessions remaining but {} needed",
                scan.sessions_remaining, delta,
            ));
        }

        self.target_session_count = target_sessions.len();
        self.target_summary = scan.capacity_summary.clone();
        self.delta_count = delta;
        self.scroll = 0;

        if delta == 0 {
            self.result_message = "Already up to date. 0 sessions to write.".into();
            self.phase = SyncPhase::Done;
        } else {
            self.phase = SyncPhase::Confirm;
        }
        Ok(())
    }

    /// Begin writing delta tracks to the target disc.
    pub fn start_writing(&mut self, dev: &std::path::Path) {
        self.burn_track_idx = 0;
        self.burn_track_total = self.delta_count;
        self.burn_step = Some("Starting…".into());
        self.phase = SyncPhase::Writing;
        self.scroll = 0;

        let rx = self.start_next_track(dev);
        self.burn_rx = Some(rx);
    }

    /// Kick off the background write for the current track index.
    fn start_next_track(&self, dev: &std::path::Path) -> mpsc::Receiver<BurnProgress> {
        let session_end = self.target_session_count + self.burn_track_idx + 1;
        let all = self.master_sessions[..session_end].to_vec();
        let is_final = false; // never finalize during sync
        let (tx, rx) = mpsc::channel();
        crate::media::write_session(dev, all, is_final, tx);
        rx
    }

    /// Called by App on each tick to poll burn progress.
    pub fn poll_burn(&mut self, dev: &std::path::Path) {
        let rx = match self.burn_rx.as_ref() {
            Some(rx) => rx,
            None => return,
        };
        match rx.try_recv() {
            Ok(BurnProgress::Step(msg)) => {
                self.burn_step = Some(format!(
                    "[Track {}/{}] {}",
                    self.burn_track_idx + 1,
                    self.burn_track_total,
                    msg,
                ));
            }
            Ok(BurnProgress::Done(Ok(()))) => {
                self.burn_track_idx += 1;
                if self.burn_track_idx < self.burn_track_total {
                    let new_rx = self.start_next_track(dev);
                    self.burn_rx = Some(new_rx);
                } else {
                    self.result_message = format!(
                        "Sync complete — {} track(s) written.",
                        self.burn_track_total,
                    );
                    self.phase = SyncPhase::Done;
                    self.burn_step = None;
                    self.burn_rx = None;
                    self.scroll = 0;
                }
            }
            Ok(BurnProgress::Done(Err(e))) => {
                self.phase = SyncPhase::Error(format!(
                    "Write failed on track {}/{}: {e:#}",
                    self.burn_track_idx + 1,
                    self.burn_track_total,
                ));
                self.burn_step = None;
                self.burn_rx = None;
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                self.phase = SyncPhase::Error("Burn thread disconnected unexpectedly".into());
                self.burn_step = None;
                self.burn_rx = None;
            }
        }
    }

    // ── Key handling ────────────────────────────────────────────────────

    /// Returns (consumed, action).
    pub fn handle_key(&mut self, key: KeyEvent) -> (bool, SyncAction) {
        match &self.phase {
            SyncPhase::ScanSource => match key.code {
                KeyCode::Char('1') => (true, SyncAction::ScanSource),
                KeyCode::Esc => (false, SyncAction::None), // let caller handle (back to menu)
                _ => (true, SyncAction::None),
            },
            SyncPhase::WaitTarget => match key.code {
                KeyCode::Char('1') => (true, SyncAction::ScanTarget),
                KeyCode::Esc => (false, SyncAction::None),
                _ => (true, SyncAction::None),
            },
            SyncPhase::ScanTarget => {
                // This phase is transient — scan happens immediately
                (true, SyncAction::None)
            }
            SyncPhase::Confirm => match key.code {
                KeyCode::Enter => (true, SyncAction::StartWrite),
                KeyCode::Esc => {
                    self.phase = SyncPhase::WaitTarget;
                    self.scroll = 0;
                    (true, SyncAction::None)
                }
                _ => (true, SyncAction::None),
            },
            SyncPhase::Writing => {
                // No user input during writes
                (true, SyncAction::None)
            }
            SyncPhase::Done => match key.code {
                KeyCode::Char('1') => {
                    self.phase = SyncPhase::WaitTarget;
                    self.scroll = 0;
                    (true, SyncAction::None)
                }
                KeyCode::Esc => (false, SyncAction::None),
                _ => (true, SyncAction::None),
            },
            SyncPhase::Error(_) => match key.code {
                KeyCode::Esc => (false, SyncAction::None),
                KeyCode::Char('r') => {
                    self.phase = SyncPhase::WaitTarget;
                    self.scroll = 0;
                    (true, SyncAction::None)
                }
                _ => (true, SyncAction::None),
            },
        }
    }

    // ── Rendering ───────────────────────────────────────────────────────

    pub fn render(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(self.title())
            .style(crate::theme::BLOCK)
            .border_style(crate::theme::BORDER)
            .title_style(crate::theme::TITLE);

        let lines = self.build_lines();
        let para = Paragraph::new(Text::from(lines))
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((self.scroll, 0));
        frame.render_widget(para, area);
    }

    fn title(&self) -> &'static str {
        match self.phase {
            SyncPhase::ScanSource => "Disc Sync  [1] scan master  [Esc] back",
            SyncPhase::WaitTarget => "Disc Sync  [1] scan backup  [Esc] back",
            SyncPhase::ScanTarget => "Disc Sync — scanning backup…",
            SyncPhase::Confirm => "Disc Sync  [Enter] write  [Esc] cancel",
            SyncPhase::Writing => "Disc Sync — writing…",
            SyncPhase::Done => "Disc Sync  [1] sync another  [Esc] back",
            SyncPhase::Error(_) => "Disc Sync  [r] retry  [Esc] back",
        }
    }

    fn build_lines(&self) -> Vec<Line<'_>> {
        let mut lines: Vec<Line> = Vec::new();

        let bold = Style::default().add_modifier(Modifier::BOLD);
        let dim = Style::default().fg(Color::DarkGray);
        let green = Style::default().fg(Color::Green);
        let red = Style::default().fg(Color::Red);
        let yellow = Style::default().fg(Color::Yellow);

        // Always show master info if available
        if !self.master_sessions.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("  Master: ", bold),
                Span::raw(&self.master_summary),
            ]));
            if let Some(ref genesis) = self.master_genesis {
                lines.push(Line::from(vec![
                    Span::styled("  Genesis: ", dim),
                    Span::raw(&genesis[..genesis.len().min(16)]),
                    Span::styled("…", dim),
                ]));
            }
            lines.push(Line::from(""));
        }

        match &self.phase {
            SyncPhase::ScanSource => {
                lines.push(Line::from(""));
                lines.push(Line::from(
                    "  Insert the master disc and press [1] to scan.",
                ));
            }
            SyncPhase::WaitTarget => {
                lines.push(Line::from("  Insert a backup disc and press [1] to scan."));
            }
            SyncPhase::ScanTarget => {
                lines.push(Line::from(Span::styled("  Scanning backup disc…", yellow)));
            }
            SyncPhase::Confirm => {
                lines.push(Line::from(vec![
                    Span::styled("  Backup: ", bold),
                    Span::raw(&self.target_summary),
                ]));
                lines.push(Line::from(format!(
                    "  Backup has {} session(s), master has {}.",
                    self.target_session_count,
                    self.master_sessions.len(),
                )));
                lines.push(Line::from(""));
                lines.push(Line::from(vec![Span::styled(
                    format!("  Will write {} new track(s).", self.delta_count),
                    yellow,
                )]));
                lines.push(Line::from(""));
                lines.push(Line::from("  Sessions to copy:"));
                for i in self.target_session_count..self.master_sessions.len() {
                    let s = &self.master_sessions[i];
                    let total_bytes: usize = s.files.iter().map(|f| f.data.len()).sum();
                    let size = if total_bytes >= 1024 {
                        format!("{} KiB", total_bytes / 1024)
                    } else {
                        format!("{total_bytes} B")
                    };
                    lines.push(Line::from(format!(
                        "    {}. {}  ({})",
                        i + 1,
                        s.dir_name,
                        size,
                    )));
                }
                lines.push(Line::from(""));
                lines.push(Line::from(
                    "  Press [Enter] to start writing, [Esc] to cancel.",
                ));
            }
            SyncPhase::Writing => {
                lines.push(Line::from(vec![
                    Span::styled("  Writing: ", bold),
                    Span::raw(format!(
                        "track {}/{}",
                        self.burn_track_idx + 1,
                        self.burn_track_total,
                    )),
                ]));
                if let Some(ref step) = self.burn_step {
                    lines.push(Line::from(format!("  {step}")));
                }
                lines.push(Line::from(""));
                // Progress bar
                if self.burn_track_total > 0 {
                    let pct =
                        (self.burn_track_idx as f64 / self.burn_track_total as f64 * 100.0) as u8;
                    let filled = (pct as usize) / 5;
                    let empty = 20 - filled;
                    let bar = format!("  [{}{}] {}%", "█".repeat(filled), "░".repeat(empty), pct,);
                    lines.push(Line::from(Span::styled(bar, yellow)));
                }
            }
            SyncPhase::Done => {
                lines.push(Line::from(Span::styled(
                    format!("  {}", self.result_message),
                    green,
                )));
                lines.push(Line::from(""));
                lines.push(Line::from("  [1] Sync another backup disc  [Esc] Exit"));
            }
            SyncPhase::Error(msg) => {
                lines.push(Line::from(Span::styled("  Error:", red)));
                for line in msg.lines() {
                    lines.push(Line::from(Span::styled(format!("  {line}"), red)));
                }
                lines.push(Line::from(""));
                lines.push(Line::from("  [r] Retry with different disc  [Esc] Exit"));
            }
        }

        lines
    }
}

/// Action hint returned by handle_key for the App to dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncAction {
    None,
    ScanSource,
    ScanTarget,
    StartWrite,
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Extract the genesis hash (prev_hash of first audit record) from the first
/// session's AUDIT.LOG.
fn extract_genesis_hash(sessions: &[SessionEntry]) -> Option<String> {
    let first = sessions.first()?;
    let audit_file = first.files.iter().find(|f| f.name == "AUDIT.LOG")?;
    let content = String::from_utf8_lossy(&audit_file.data);
    let first_line = content.lines().next()?;
    let record: anodize_audit::Record = serde_json::from_str(first_line).ok()?;
    Some(record.prev_hash)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media::iso9660::IsoFile;
    use crossterm::event::{KeyEvent, KeyModifiers};
    use std::time::SystemTime;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn make_session(name: &str) -> SessionEntry {
        SessionEntry {
            dir_name: name.to_string(),
            timestamp: SystemTime::now(),
            files: vec![],
        }
    }

    fn make_session_with_audit(name: &str, genesis: &str) -> SessionEntry {
        let record = anodize_audit::Record {
            seq: 0,
            timestamp: "2026-01-01T00:00:00Z".into(),
            event: "test".into(),
            op_data: serde_json::json!({}),
            prev_hash: genesis.into(),
            entry_hash: "deadbeef".into(),
        };
        let data = serde_json::to_vec(&record).unwrap();
        SessionEntry {
            dir_name: name.to_string(),
            timestamp: SystemTime::now(),
            files: vec![IsoFile {
                name: "AUDIT.LOG".into(),
                data,
            }],
        }
    }

    // ── extract_genesis_hash ────────────────────────────────────────────

    #[test]
    fn genesis_extracted_from_first_session() {
        let sessions = vec![make_session_with_audit("s1", "abc123")];
        assert_eq!(extract_genesis_hash(&sessions), Some("abc123".into()));
    }

    #[test]
    fn genesis_none_when_no_audit_log() {
        let sessions = vec![make_session("s1")];
        assert_eq!(extract_genesis_hash(&sessions), None);
    }

    #[test]
    fn genesis_none_when_empty() {
        let sessions: Vec<SessionEntry> = vec![];
        assert_eq!(extract_genesis_hash(&sessions), None);
    }

    // ── Key handling FSM ────────────────────────────────────────────────

    #[test]
    fn scan_source_key_1_triggers_scan() {
        let mut state = DiscSyncState::new();
        let (consumed, action) = state.handle_key(key(KeyCode::Char('1')));
        assert!(consumed);
        assert_eq!(action, SyncAction::ScanSource);
    }

    #[test]
    fn scan_source_esc_not_consumed() {
        let mut state = DiscSyncState::new();
        let (consumed, _) = state.handle_key(key(KeyCode::Esc));
        assert!(!consumed);
    }

    #[test]
    fn wait_target_key_1_triggers_scan_target() {
        let mut state = DiscSyncState::new();
        state.phase = SyncPhase::WaitTarget;
        let (consumed, action) = state.handle_key(key(KeyCode::Char('1')));
        assert!(consumed);
        assert_eq!(action, SyncAction::ScanTarget);
    }

    #[test]
    fn confirm_enter_starts_write() {
        let mut state = DiscSyncState::new();
        state.phase = SyncPhase::Confirm;
        let (consumed, action) = state.handle_key(key(KeyCode::Enter));
        assert!(consumed);
        assert_eq!(action, SyncAction::StartWrite);
    }

    #[test]
    fn confirm_esc_returns_to_wait_target() {
        let mut state = DiscSyncState::new();
        state.phase = SyncPhase::Confirm;
        let (consumed, _) = state.handle_key(key(KeyCode::Esc));
        assert!(consumed);
        assert_eq!(state.phase, SyncPhase::WaitTarget);
    }

    #[test]
    fn done_key_1_loops_to_wait_target() {
        let mut state = DiscSyncState::new();
        state.phase = SyncPhase::Done;
        let (consumed, _) = state.handle_key(key(KeyCode::Char('1')));
        assert!(consumed);
        assert_eq!(state.phase, SyncPhase::WaitTarget);
    }

    #[test]
    fn error_r_retries() {
        let mut state = DiscSyncState::new();
        state.phase = SyncPhase::Error("fail".into());
        let (consumed, _) = state.handle_key(key(KeyCode::Char('r')));
        assert!(consumed);
        assert_eq!(state.phase, SyncPhase::WaitTarget);
    }

    // ── Validation logic (unit) ─────────────────────────────────────────

    #[test]
    fn validate_prefix_mismatch() {
        let mut state = DiscSyncState::new();
        state.master_sessions = vec![
            make_session_with_audit("s1", "genesis"),
            make_session("s2-master"),
        ];
        state.master_genesis = Some("genesis".into());
        state.phase = SyncPhase::WaitTarget;

        // Simulate what do_scan_target checks — prefix mismatch at index 1
        let target = vec![
            make_session_with_audit("s1", "genesis"),
            make_session("s2-different"),
        ];
        for (i, (ts, ms)) in target.iter().zip(state.master_sessions.iter()).enumerate() {
            if ts.dir_name != ms.dir_name {
                assert_eq!(i, 1);
                return;
            }
        }
        panic!("expected mismatch at index 1");
    }

    #[test]
    fn validate_genesis_mismatch() {
        let master = vec![make_session_with_audit("s1", "genesis-A")];
        let target = vec![make_session_with_audit("s1", "genesis-B")];
        let mg = extract_genesis_hash(&master);
        let tg = extract_genesis_hash(&target);
        assert_ne!(mg, tg);
    }
}
