use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use anodize_config::Profile;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::action::{Action, Mode, Operation};
use crate::components::confirm_dialog::ConfirmDialog;
use crate::components::mode_bar::ModeBar;
use crate::components::phase_bar::PhaseBar;
use crate::components::status_bar::StatusBar;
use crate::components::Component;
use crate::disc::DiscContext;
use crate::hardware::HardwareManager;
use crate::modes;
use crate::modes::ceremony::CeremonyMode;
use crate::modes::ceremony::CeremonyPhase;
use crate::modes::setup::{SetupMode, SetupPhase};
use crate::modes::utilities::UtilitiesMode;
use crate::ops::{ActiveOperation, OpContext};

/// Maximum elapsed time since the last clock confirmation before a
/// re-confirm is required.  On a live-boot, air-gapped system the clock
/// cannot drift, but the guard catches the case where the operator walks
/// away mid-ceremony and returns much later.
pub const CLOCK_DRIFT_THRESHOLD: Duration = Duration::from_secs(5 * 60);

/// Top-level application state.
pub struct App {
    pub running: bool,
    pub mode: Mode,
    pub status: String,
    pub log_lines: Vec<String>,
    pub log_view: bool,
    pub log_scroll: u16,

    // Sub-contexts
    pub hw: HardwareManager,
    pub disc: DiscContext,

    // Mode components
    pub setup: SetupMode,
    pub ceremony: CeremonyMode,
    pub utilities: UtilitiesMode,

    // Setup completion flag — gates Ceremony mode
    pub setup_complete: bool,

    // CLI flags
    pub shuttle_mount: PathBuf,

    // Clock
    pub confirmed_time: Option<SystemTime>,

    // Shuttle / Profile
    pub profile: Option<Profile>,
    pub profile_toml_bytes: Option<Vec<u8>>,

    // Per-operation context — owns all op-specific state and phase.
    pub active_op: Option<ActiveOperation>,

    // Temporary PIN buffer — used internally by SSS operations, never displayed
    pub pin_buf: String,

    // Two-key confirmation dialog (modal overlay)
    pub confirm_dialog: Option<ConfirmDialog>,

    // When true, the current ClockReconfirm is gating a disc burn (not a
    // signing operation).  After re-confirm, proceed directly to
    // do_start_burn() instead of dispatching crypto.
    pub pending_burn_reconfirm: bool,

    // Content area vertical scroll offset
    pub content_scroll: u16,
}

impl App {
    pub fn new(shuttle_mount: PathBuf) -> Self {
        Self {
            running: true,
            mode: Mode::Setup,
            status: "Welcome to Anodize Root CA Ceremony.".into(),
            log_lines: Vec::new(),
            log_view: false,
            log_scroll: 0,

            hw: HardwareManager::new(),
            disc: DiscContext::new(),

            setup: SetupMode::new(),
            ceremony: CeremonyMode::new(),
            utilities: UtilitiesMode::new(),

            setup_complete: false,
            shuttle_mount,

            confirmed_time: None,
            profile: None,
            profile_toml_bytes: None,
            active_op: None,
            pin_buf: String::new(),
            confirm_dialog: None,
            pending_burn_reconfirm: false,
            content_scroll: 0,
        }
    }

    /// Derive which `Operation` is active from `active_op`.
    pub fn current_op(&self) -> Option<Operation> {
        self.active_op.as_ref().map(|op| op.operation())
    }

    pub fn set_status(&mut self, msg: impl Into<String>) {
        let s: String = msg.into();
        if self.log_lines.last().map(|l| l.as_str()) != Some(s.as_str()) {
            self.log_lines.push(s.clone());
        }
        self.status = s;
        self.content_scroll = 0;
    }

    /// Construct an `OpEnv` borrow-split view for `OpContext` methods.
    ///
    /// Caller must ensure `self.active_op` is not simultaneously borrowed mutably.
    pub fn make_shared(&mut self) -> crate::ops::OpEnv<'_> {
        crate::ops::OpEnv {
            hw: &mut self.hw,
            disc: &mut self.disc,
            profile: self.profile.as_ref(),
            shuttle_mount: &self.shuttle_mount,

            confirmed_time: &mut self.confirmed_time,
            pin_buf: &mut self.pin_buf,
            status: &mut self.status,
            log_lines: &mut self.log_lines,
            content_scroll: &mut self.content_scroll,
        }
    }

    /// Returns `true` if the operator's clock confirmation is recent enough
    /// for a disc-write operation (within [`CLOCK_DRIFT_THRESHOLD`]).
    pub fn clock_is_fresh(&self) -> bool {
        match self.confirmed_time {
            Some(t) => t.elapsed().unwrap_or(Duration::ZERO) < CLOCK_DRIFT_THRESHOLD,
            None => false,
        }
    }

    /// Process a crossterm key event at the app level.
    pub fn handle_key_event(&mut self, key: KeyEvent) -> Action {
        // Confirm dialog intercepts all keys when active
        if let Some(dialog) = &mut self.confirm_dialog {
            if let Some(action) = dialog.handle_key(key) {
                self.confirm_dialog = None;
                return action;
            }
            return Action::Noop; // dialog stays open
        }

        // Ctrl+C: quit with confirmation (blocked during ephemeral ceremony phases)
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            let blocked = if self.mode == Mode::Ceremony {
                if self.ceremony.state == CeremonyPhase::ActiveOp {
                    self.active_op
                        .as_ref()
                        .is_some_and(|op| op.holds_ephemeral_state())
                } else {
                    self.ceremony.holds_ephemeral_state()
                }
            } else {
                false
            };
            if blocked {
                self.set_status("Ctrl+C blocked: press Esc to go back to the menu first.");
                return Action::Noop;
            }
            self.show_quit_confirm();
            return Action::Noop;
        }

        // Ctrl+L clears the screen
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('l') {
            return Action::Render;
        }

        // Log view toggle (except during text entry)
        let in_text_entry = self.mode == Mode::Ceremony
            && if self.ceremony.state == CeremonyPhase::ActiveOp {
                self.active_op.as_ref().is_some_and(|op| op.in_text_entry())
            } else {
                self.ceremony.in_text_entry()
            };

        if !in_text_entry {
            match key.code {
                KeyCode::Char('l') | KeyCode::Char('L') => {
                    self.log_view = !self.log_view;
                    if self.log_view {
                        self.log_scroll = self.log_lines.len().saturating_sub(1) as u16;
                    }
                    return Action::Noop;
                }
                _ => {}
            }
        }

        // Log view scrolling
        if self.log_view {
            match key.code {
                KeyCode::Esc => {
                    self.log_view = false;
                    return Action::Noop;
                }
                KeyCode::Up => {
                    self.log_scroll = self.log_scroll.saturating_sub(1);
                    return Action::Noop;
                }
                KeyCode::Down => {
                    self.log_scroll = self.log_scroll.saturating_add(1);
                    return Action::Noop;
                }
                KeyCode::PageUp => {
                    self.log_scroll = self.log_scroll.saturating_sub(10);
                    return Action::Noop;
                }
                KeyCode::PageDown => {
                    self.log_scroll = self.log_scroll.saturating_add(10);
                    return Action::Noop;
                }
                _ => return Action::Noop,
            }
        }

        // Disc inspector has its own scroll/navigation — intercept before global scroll
        if self.mode == Mode::Utilities
            && self.utilities.screen == crate::modes::utilities::UtilScreen::DiscInspector
        {
            use crate::modes::utilities::disc_inspector::KeyAction;
            let (consumed, deferred) = self.utilities.disc_inspector.handle_key(key);
            // Deferred populates need data from self.disc / self.data which are
            // disjoint from self.utilities, so we extract references first.
            match deferred {
                KeyAction::Refresh => {
                    let banner = crate::modes::utilities::disc_inspector::gather_banner_from(
                        &self.disc, None,
                    );
                    let list = crate::modes::utilities::disc_inspector::gather_session_list_from(
                        &self.disc,
                    );
                    let count = self.disc.prior_sessions.len();
                    let di = &mut self.utilities.disc_inspector;
                    di.banner_lines = banner;
                    di.list_lines = list;
                    di.session_count = count;
                    di.selected_session = 0;
                    di.selected_cert = 0;
                    di.scroll = 0;
                    di.view = crate::modes::utilities::disc_inspector::InspectorView::SessionList;
                    di.detail_lines.clear();
                    di.cert_modal_lines.clear();
                    di.cert_count = 0;
                }
                KeyAction::PopulateDetail => {
                    let idx = self.utilities.disc_inspector.selected_session;
                    if idx < self.disc.prior_sessions.len() {
                        let session = &self.disc.prior_sessions[idx];
                        let revocations = self
                            .disc
                            .session_state
                            .as_ref()
                            .map(|s| s.revocation_list.as_slice())
                            .unwrap_or(&[]);
                        let (lines, ders) =
                            crate::modes::utilities::disc_inspector::gather_session_detail_pub(
                                session,
                                revocations,
                            );
                        let di = &mut self.utilities.disc_inspector;
                        di.detail_lines = lines;
                        di.cert_count = ders.len();
                        di.set_cert_ders(ders);
                    }
                    self.utilities.disc_inspector.selected_cert = 0;
                    self.utilities.disc_inspector.scroll = 0;
                }
                KeyAction::PopulateCertModal => {
                    let revocations = self
                        .disc
                        .session_state
                        .as_ref()
                        .map(|s| s.revocation_list.as_slice())
                        .unwrap_or(&[]);
                    let di = &mut self.utilities.disc_inspector;
                    if di.selected_cert < di.cert_der_count() {
                        di.cert_modal_lines =
                            crate::modes::utilities::disc_inspector::gather_cert_detail_pub(
                                di.cert_der(di.selected_cert),
                                revocations,
                            );
                    }
                    di.scroll = 0;
                }
                KeyAction::None => {}
            }
            if consumed {
                return Action::Noop;
            }
            // Esc not consumed → back to menu
            if key.code == KeyCode::Esc {
                self.utilities.screen = crate::modes::utilities::UtilScreen::Menu;
                return Action::Noop;
            }
        }

        // Disc sync has its own scroll/navigation — intercept before global scroll
        if self.mode == Mode::Utilities
            && self.utilities.screen == crate::modes::utilities::UtilScreen::DiscSync
        {
            use crate::modes::utilities::disc_sync::SyncAction;
            let (consumed, deferred) = self.utilities.disc_sync.handle_key(key);
            match deferred {
                SyncAction::ScanSource => {
                    if let Some(ref dev) = self.disc.optical_dev {
                        if let Err(e) = self.utilities.disc_sync.do_scan_source(dev) {
                            self.utilities.disc_sync.phase =
                                crate::modes::utilities::disc_sync::SyncPhase::Error(e);
                        }
                    } else {
                        self.utilities.disc_sync.phase =
                            crate::modes::utilities::disc_sync::SyncPhase::Error(
                                "No optical device detected".into(),
                            );
                    }
                }
                SyncAction::ScanTarget => {
                    if let Some(ref dev) = self.disc.optical_dev {
                        if let Err(e) = self.utilities.disc_sync.do_scan_target(dev) {
                            self.utilities.disc_sync.phase =
                                crate::modes::utilities::disc_sync::SyncPhase::Error(e);
                        }
                    } else {
                        self.utilities.disc_sync.phase =
                            crate::modes::utilities::disc_sync::SyncPhase::Error(
                                "No optical device detected".into(),
                            );
                    }
                }
                SyncAction::StartWrite => {
                    if let Some(ref dev) = self.disc.optical_dev {
                        self.utilities.disc_sync.start_writing(dev);
                    } else {
                        self.utilities.disc_sync.phase =
                            crate::modes::utilities::disc_sync::SyncPhase::Error(
                                "No optical device detected".into(),
                            );
                    }
                }
                SyncAction::None => {}
            }
            if consumed {
                return Action::Noop;
            }
            // Esc not consumed → back to menu, reset sync state
            if key.code == KeyCode::Esc {
                self.utilities.disc_sync.reset();
                self.utilities.screen = crate::modes::utilities::UtilScreen::Menu;
                return Action::Noop;
            }
        }

        // Content scrolling (arrow keys when not in text entry)
        if !in_text_entry {
            match key.code {
                KeyCode::Up => {
                    self.content_scroll = self.content_scroll.saturating_sub(1);
                    return Action::Noop;
                }
                KeyCode::Down => {
                    self.content_scroll = self.content_scroll.saturating_add(1);
                    return Action::Noop;
                }
                KeyCode::PageUp => {
                    self.content_scroll = self.content_scroll.saturating_sub(10);
                    return Action::Noop;
                }
                KeyCode::PageDown => {
                    self.content_scroll = self.content_scroll.saturating_add(10);
                    return Action::Noop;
                }
                _ => {}
            }
        }

        // F-keys switch modes (F1=Setup, F2=Ceremony, F3=Utilities)
        match key.code {
            KeyCode::F(1) => return Action::SwitchMode(Mode::Setup),
            KeyCode::F(2) => {
                if self.setup_complete {
                    return Action::SwitchMode(Mode::Ceremony);
                } else {
                    self.set_status("Complete Setup before starting Ceremony.");
                    return Action::Noop;
                }
            }
            KeyCode::F(3) => return Action::SwitchMode(Mode::Utilities),
            _ => {}
        }

        // Delegate to the active mode's component
        match self.mode {
            Mode::Setup => self.setup.handle_key_event(key),
            Mode::Ceremony => {
                // ActiveOp: delegate key handling to the per-operation context.
                if self.ceremony.state == CeremonyPhase::ActiveOp {
                    if let Some(mut op) = self.active_op.take() {
                        let mut shared = self.make_shared();
                        let result = op.handle_key(key, &mut shared);
                        self.active_op = Some(op);
                        match result {
                            crate::ops::OpAction::Noop => return Action::Noop,
                            crate::ops::OpAction::Done => {
                                self.active_op = None;
                                self.ceremony.state = CeremonyPhase::Done;
                                return Action::Noop;
                            }
                            crate::ops::OpAction::Abort => {
                                if self
                                    .active_op
                                    .as_ref()
                                    .is_some_and(|op| op.needs_abort_confirmation())
                                {
                                    self.show_abort_confirm(Action::CeremonyCancel);
                                } else {
                                    self.active_op = None;
                                    self.ceremony.state = CeremonyPhase::OperationSelect;
                                }
                                return Action::Noop;
                            }
                            crate::ops::OpAction::SetStatus(msg) => {
                                return Action::SetStatus(msg);
                            }
                            crate::ops::OpAction::StartRecordBurn => {
                                self.do_start_burn();
                                return Action::Noop;
                            }
                            crate::ops::OpAction::WriteIntent => {
                                self.do_write_intent();
                                return Action::Noop;
                            }
                            crate::ops::OpAction::ExecuteOp => {
                                self.do_dispatch_after_clock_reconfirm();
                                return Action::Noop;
                            }
                            crate::ops::OpAction::ShowConfirm {
                                title,
                                body,
                                on_confirm,
                            } => {
                                use crate::ops::ConfirmTarget;
                                let action = match on_confirm {
                                    ConfirmTarget::WriteIntent => Action::DoWriteIntent,
                                    ConfirmTarget::StartRecordBurn => Action::DoStartBurn,
                                    ConfirmTarget::Abort => Action::CeremonyCancel,
                                };
                                self.show_confirm(title, body, action);
                                return Action::Noop;
                            }
                        }
                    }
                    return Action::Noop;
                }

                let action = self.ceremony.handle_key_event(key);
                // Gate full-ceremony-abort actions behind a confirmation
                // dialog when the current phase warrants it.
                if self.ceremony.needs_abort_confirmation() {
                    match action {
                        Action::CeremonyCancel => {
                            self.show_abort_confirm(action);
                            Action::Noop
                        }
                        _ => action,
                    }
                } else {
                    action
                }
            }
            Mode::Utilities => self.utilities.handle_key_event(key),
        }
    }

    /// Process tick events — delegate to active component for background work.
    pub fn handle_tick(&mut self) -> Action {
        // Background polling happens at app level too
        self.background_tick();

        match self.mode {
            Mode::Setup => self.setup.handle_tick(),
            Mode::Ceremony => self.ceremony.handle_tick(),
            Mode::Utilities => self.utilities.handle_tick(),
        }
    }

    /// Background polling for disc/shuttle state + burn completion.
    fn background_tick(&mut self) {
        // Always update shuttle presence for the status bar.
        self.hw.tick_shuttle(&self.shuttle_mount);

        // Full shuttle scan (profile load) during WaitShuttle
        if self.mode == Mode::Setup && self.setup.phase == SetupPhase::WaitShuttle {
            self.tick_wait_shuttle();
        }

        // Disc scan during WaitDisc
        if self.mode == Mode::Setup && self.setup.phase == SetupPhase::WaitDisc {
            self.tick_wait_disc(false);
        }

        // Disc scan when active op requests it (e.g. MigrateDisc WaitTarget)
        if self
            .active_op
            .as_ref()
            .is_some_and(|op| op.wants_disc_scan())
        {
            self.tick_wait_disc(true);
        }

        // Intent burn completion
        if self.ceremony.is_writing_intent() {
            tracing::debug!(
                "background_tick: ceremony is_writing_intent, calling tick_intent_burn"
            );
            self.tick_intent_burn();
        }

        // Record burn completion
        if self.ceremony.is_burning_disc() {
            self.tick_record_burn();
        }

        // Disc sync burn polling
        if self.mode == Mode::Utilities
            && self.utilities.screen == crate::modes::utilities::UtilScreen::DiscSync
            && self.utilities.disc_sync.phase
                == crate::modes::utilities::disc_sync::SyncPhase::Writing
        {
            if let Some(ref dev) = self.disc.optical_dev.clone() {
                self.utilities.disc_sync.poll_burn(dev);
            }
        }
    }

    /// Process an action, updating app state.
    pub fn update(&mut self, action: Action) {
        match action {
            Action::Noop | Action::Render => {}
            Action::Quit => self.running = false,
            Action::SwitchMode(mode) => {
                self.mode = mode;
                self.content_scroll = 0;
            }
            Action::SetStatus(msg) => self.set_status(msg),

            // Setup flow
            Action::ConfirmClock => {
                self.confirmed_time = Some(SystemTime::now());
                self.setup.phase = SetupPhase::WaitShuttle;
                self.set_status("Scanning for shuttle USB with profile.toml…");
            }
            Action::HsmDetected => {
                self.setup.phase = SetupPhase::HsmDetect;
                self.do_detect_hsm();
            }
            Action::HsmWarnAcknowledged => {
                self.setup.phase = SetupPhase::WaitDisc;
                self.set_status(
                    "Token missing acknowledged. Insert write-once disc and press [1].",
                );
            }
            Action::SetupComplete => {
                self.setup_complete = true;
                self.mode = Mode::Ceremony;
                self.set_status(
                    "[1] Init Root  [2] Sign CSR  [3] Revoke  [4] CRL  [5] Re-key  [6] Migrate",
                );
            }
            Action::ConfirmDisc => {
                let ready = self.disc.optical_dev.is_some()
                    && self
                        .disc
                        .sessions_remaining
                        .map(|r| r >= 2)
                        .unwrap_or(false);
                if ready {
                    self.update(Action::SetupComplete);
                }
            }

            // Ceremony operations
            Action::SelectOperation(op) => {
                self.do_select_operation(op);
            }
            // Clock re-confirm: operator attests clock is correct at signing time
            Action::ReconfirmClock => {
                self.confirmed_time = Some(SystemTime::now());
                if self.pending_burn_reconfirm {
                    // Returning from a stale-clock redirect — proceed
                    // directly to disc burn (no extra confirmation dialog).
                    self.pending_burn_reconfirm = false;
                    self.do_start_burn();
                } else {
                    self.do_dispatch_after_clock_reconfirm();
                }
            }

            // Disc/Shuttle
            Action::DoWriteIntent => {
                self.do_write_intent();
            }
            Action::DoStartBurn => {
                if self.clock_is_fresh() {
                    self.do_start_burn();
                } else {
                    self.pending_burn_reconfirm = true;
                    self.ceremony.state = CeremonyPhase::ClockReconfirm;
                    self.set_status(
                        "Clock confirmation expired — please re-confirm before disc write.",
                    );
                }
            }
            Action::DoWriteShuttle => {
                self.do_write_shuttle();
            }

            // Utilities sub-screens
            Action::UtilScreen(idx) => {
                use crate::modes::utilities::{UtilScreen, UtilitiesMode};
                let screen = match idx {
                    1 => UtilScreen::SystemInfo,
                    2 => UtilScreen::AuditLog,
                    3 => UtilScreen::HsmInventory,
                    4 => UtilScreen::DiscInspector,
                    5 => UtilScreen::DiscSync,
                    _ => UtilScreen::Menu,
                };
                if screen == UtilScreen::DiscSync {
                    // Disc sync has its own FSM; reset on entry.
                    self.utilities.disc_sync.reset();
                    self.utilities.screen = screen;
                } else if screen == UtilScreen::DiscInspector {
                    // Disc inspector has its own state; populate from disjoint fields.
                    use crate::modes::utilities::disc_inspector::{
                        gather_banner_from, gather_session_list_from,
                    };
                    let banner = gather_banner_from(&self.disc, None);
                    let list = gather_session_list_from(&self.disc);
                    let count = self.disc.prior_sessions.len();
                    self.utilities.screen = screen;
                    let di = &mut self.utilities.disc_inspector;
                    di.banner_lines = banner;
                    di.list_lines = list;
                    di.session_count = count;
                    di.selected_session = 0;
                    di.selected_cert = 0;
                    di.scroll = 0;
                    di.view = crate::modes::utilities::disc_inspector::InspectorView::SessionList;
                    di.detail_lines.clear();
                    di.cert_modal_lines.clear();
                    di.cert_count = 0;
                } else {
                    let lines = UtilitiesMode::gather_for_screen(screen, self);
                    self.utilities.screen = screen;
                    self.utilities.set_cached_lines(lines);
                }
                self.content_scroll = 0;
            }

            Action::CeremonyCancel => {
                self.active_op = None;
                self.pending_burn_reconfirm = false;
                self.ceremony.state = CeremonyPhase::OperationSelect;
                self.set_status("Cancelled.");
            }
        }
    }

    /// Render the full application frame.
    pub fn render(&self, frame: &mut Frame) {
        // Log view overlay
        if self.log_view {
            let content = self.log_lines.join("\n");
            let block = Block::default()
                .borders(Borders::ALL)
                .title("Status Log  [L/Esc] close  [\u{2191}/\u{2193}/PgUp/PgDn] scroll")
                .style(crate::theme::BLOCK)
                .border_style(crate::theme::BORDER)
                .title_style(crate::theme::TITLE);
            let para = ratatui::widgets::Paragraph::new(content.as_str())
                .block(block)
                .wrap(ratatui::widgets::Wrap { trim: false })
                .scroll((self.log_scroll, 0));
            frame.render_widget(para, frame.area());
            return;
        }

        let area = frame.area();

        // Build header lines
        let is_dev = cfg!(feature = "dev-softhsm-usb");
        let is_burn = cfg!(feature = "dev-burn");
        let mut header_lines: Vec<Line> = vec![Line::from("ANODIZE ROOT CA CEREMONY")];
        if is_dev {
            header_lines.push(Line::from(Span::styled(
                if is_burn {
                    "*** DEV-BURN BUILD — REAL DISC, NOT FOR PRODUCTION ***"
                } else {
                    "*** DEV BUILD — NOT FOR PRODUCTION USE ***"
                },
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )));
        }
        let header_height = header_lines.len() as u16 + 2;

        // Layout: header | mode bar | phase bar | content | status bar | status line
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(header_height), // header
                Constraint::Length(1),             // mode bar
                Constraint::Length(1),             // phase bar
                Constraint::Min(6),                // content area
                Constraint::Length(2),             // hardware status bar
                Constraint::Length(3),             // status line
            ])
            .split(area);

        // Header
        let border_style = if is_dev {
            Style::default().fg(Color::Red)
        } else {
            Style::default()
        };
        let header = Paragraph::new(header_lines)
            .alignment(Alignment::Center)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .style(crate::theme::BLOCK)
                    .border_style(border_style)
                    .title_style(crate::theme::TITLE),
            );
        frame.render_widget(header, chunks[0]);

        // Mode bar
        let mode_bar = ModeBar {
            active: self.mode,
            ceremony_unlocked: self.setup_complete,
        };
        frame.render_widget(mode_bar, chunks[1]);

        // Phase bar
        let phase_steps = match self.mode {
            Mode::Setup => modes::setup_phases(self.setup.phase.index()),
            Mode::Ceremony => {
                let idx = if self.ceremony.state == CeremonyPhase::ActiveOp {
                    self.active_op.as_ref().map_or(1, |op| op.phase_index())
                } else {
                    self.ceremony.phase_index()
                };
                modes::ceremony_phases(idx)
            }
            Mode::Utilities => modes::utility_phases(&self.utilities.screen),
        };
        let phase_bar = PhaseBar {
            steps: &phase_steps,
        };
        frame.render_widget(phase_bar, chunks[2]);

        // Content area — rendered via App methods to avoid borrow splitting
        match self.mode {
            Mode::Setup => self.render_setup_content(frame, chunks[3]),
            Mode::Ceremony => self.render_ceremony_content(frame, chunks[3]),
            Mode::Utilities => self.utilities.render_with_app(frame, chunks[3], self),
        }

        // Hardware status bar
        let status_bar = StatusBar {
            hsm: &self.hw.hsm_state,
            disc: &self.hw.disc_state,
            usb: &self.hw.shuttle_state,
        };
        frame.render_widget(status_bar, chunks[4]);

        // Status line
        let status = Paragraph::new(self.status.as_str())
            .style(Style::default().fg(Color::Yellow))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Status")
                    .style(crate::theme::BLOCK)
                    .border_style(crate::theme::BORDER)
                    .title_style(crate::theme::TITLE),
            );
        frame.render_widget(status, chunks[5]);

        // Confirm dialog overlay (rendered last, on top)
        if let Some(dialog) = &self.confirm_dialog {
            dialog.render(frame, area);
        }
    }

    /// Show a two-key confirmation dialog for a critical action.
    pub fn show_confirm(&mut self, title: impl Into<String>, body: Vec<String>, action: Action) {
        self.confirm_dialog = Some(ConfirmDialog::new(title, body, action));
    }

    /// Show a two-key confirmation dialog before aborting the active ceremony.
    fn show_abort_confirm(&mut self, action: Action) {
        let body = self.abort_confirm_body();
        self.show_confirm("Abort Ceremony?", body, action);
    }

    /// Context-sensitive warning body for the abort confirmation dialog.
    fn abort_confirm_body(&self) -> Vec<String> {
        use CeremonyPhase::*;
        match &self.ceremony.state {
            ClockReconfirm => {
                vec![
                    "HSM session and partially-reconstructed PIN".into(),
                    "will be discarded.".into(),
                ]
            }
            ActiveOp => {
                use crate::ops::OpContext;
                self.active_op
                    .as_ref()
                    .map(|op| op.abort_confirm_body())
                    .unwrap_or_else(|| vec!["All ceremony progress will be lost.".into()])
            }
            _ => vec!["All ceremony progress will be lost.".into()],
        }
    }

    /// Show a quit-confirmation dialog (two-key: [1] then [Enter]).
    fn show_quit_confirm(&mut self) {
        self.show_confirm(
            "Quit Anodize?",
            vec!["All unsaved state will be lost.".into()],
            Action::Quit,
        );
    }
}
