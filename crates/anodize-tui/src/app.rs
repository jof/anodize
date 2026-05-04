use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::time::SystemTime;

use anodize_config::{Profile, RevocationEntry};
use anodize_hsm::{HsmActor, KeyHandle};
use anyhow::Result;
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
use crate::components::status_bar::{HwState, StatusBar};
use crate::components::Component;
use crate::media::SessionEntry;
use crate::modes;
use crate::modes::ceremony::CeremonyMode;
use crate::modes::setup::{SetupMode, SetupPhase};
use crate::modes::utilities::UtilitiesMode;

/// Top-level application state.
pub struct App {
    pub running: bool,
    pub mode: Mode,
    pub status: String,
    pub log_lines: Vec<String>,
    pub log_view: bool,
    pub log_scroll: u16,

    // Hardware state (polled on tick)
    pub hsm_state: HwState,
    pub disc_state: HwState,
    pub usb_state: HwState,

    // Mode components
    pub setup: SetupMode,
    pub ceremony: CeremonyMode,
    pub utilities: UtilitiesMode,

    // Setup completion flag — gates Ceremony mode
    pub setup_complete: bool,

    // CLI flags
    pub skip_disc: bool,
    pub usb_mountpoint: PathBuf,

    // Clock
    pub confirmed_time: Option<SystemTime>,

    // USB / Profile
    pub profile: Option<Profile>,
    pub profile_toml_bytes: Option<Vec<u8>>,

    // Active operation
    pub current_op: Option<Operation>,

    // HSM session
    pub actor: Option<HsmActor>,
    pub root_key: Option<KeyHandle>,

    // Cert held in RAM until disc write succeeds (Mode 1)
    pub cert_der: Option<Vec<u8>>,
    pub fingerprint: Option<String>,

    // CRL held in RAM until disc write succeeds (Modes 1, 3, 4)
    pub crl_der: Option<Vec<u8>>,

    // Root cert DER loaded from disc for modes 2/3/4
    pub root_cert_der: Option<Vec<u8>>,

    // Mode 2: CSR signing
    pub csr_der: Option<Vec<u8>>,
    pub csr_subject_display: Option<String>,
    pub selected_profile_idx: Option<usize>,

    // Modes 3+4: revocation
    pub revocation_list: Vec<RevocationEntry>,
    pub crl_number: Option<u64>,

    // Mode 3: revoke input state
    pub revoke_serial_buf: String,
    pub revoke_reason_buf: String,
    pub revoke_phase: u8, // 0=serial entry, 1=reason entry

    // Mode 5: migration
    pub migrate_sessions: Vec<SessionEntry>,
    pub migrate_chain_ok: bool,
    pub migrate_total_bytes: u64,

    // PIN input — display length is randomised noise, never reveals actual length
    pub pin_buf: String,
    pub pin_display_len: usize,

    // Disc management
    pub optical_dev: Option<PathBuf>,
    pub prior_sessions: Vec<SessionEntry>,
    pub burn_rx: Option<Receiver<Result<()>>>,
    pub sessions_remaining: Option<u16>,

    // WAL intent session written before HSM key operation
    pub intent_session_dir_name: Option<String>,
    pub pending_key_action: Option<u8>, // 1=generate, 2=find-existing
    pub pending_intent_session: Option<SessionEntry>,

    // Two-key confirmation dialog (modal overlay)
    pub confirm_dialog: Option<ConfirmDialog>,

    // Content area vertical scroll offset
    pub content_scroll: u16,
}

impl App {
    pub fn new(usb_mountpoint: PathBuf, skip_disc: bool) -> Self {
        Self {
            running: true,
            mode: Mode::Setup,
            status: "Welcome to Anodize Root CA Ceremony.".into(),
            log_lines: Vec::new(),
            log_view: false,
            log_scroll: 0,

            hsm_state: HwState::Absent,
            disc_state: HwState::Absent,
            usb_state: HwState::Absent,

            setup: SetupMode::new(),
            ceremony: CeremonyMode::new(),
            utilities: UtilitiesMode::new(),

            setup_complete: false,
            skip_disc,
            usb_mountpoint,

            confirmed_time: None,
            profile: None,
            profile_toml_bytes: None,
            current_op: None,
            actor: None,
            root_key: None,
            cert_der: None,
            fingerprint: None,
            crl_der: None,
            root_cert_der: None,
            csr_der: None,
            csr_subject_display: None,
            selected_profile_idx: None,
            revocation_list: Vec::new(),
            crl_number: None,
            revoke_serial_buf: String::new(),
            revoke_reason_buf: String::new(),
            revoke_phase: 0,
            migrate_sessions: Vec::new(),
            migrate_chain_ok: false,
            migrate_total_bytes: 0,
            pin_buf: String::new(),
            pin_display_len: 0,
            optical_dev: None,
            prior_sessions: Vec::new(),
            burn_rx: None,
            sessions_remaining: None,
            intent_session_dir_name: None,
            pending_key_action: None,
            pending_intent_session: None,
            confirm_dialog: None,
            content_scroll: 0,
        }
    }

    pub fn set_status(&mut self, msg: impl Into<String>) {
        let s: String = msg.into();
        if self.log_lines.last().map(|l| l.as_str()) != Some(s.as_str()) {
            self.log_lines.push(s.clone());
        }
        self.status = s;
        self.content_scroll = 0;
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

        // Ctrl+C always quits
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Action::Quit;
        }

        // Ctrl+L clears the screen
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('l') {
            return Action::Render;
        }

        // Log view toggle (except during text entry)
        let in_text_entry = self.setup.phase == SetupPhase::EnterPin
            || (self.mode == Mode::Ceremony && self.ceremony.in_text_entry());

        if !in_text_entry {
            match key.code {
                KeyCode::Char('q') | KeyCode::Char('Q') => return Action::Quit,
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
            Mode::Ceremony => self.ceremony.handle_key_event(key),
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

    /// Background polling for disc/USB state + burn completion.
    fn background_tick(&mut self) {
        // USB scan during WaitUsb
        if self.mode == Mode::Setup && self.setup.phase == SetupPhase::WaitUsb {
            self.tick_wait_usb();
        }

        // Disc scan during WaitDisc
        if self.mode == Mode::Setup && self.setup.phase == SetupPhase::WaitDisc {
            self.tick_wait_disc(false);
        }

        // Disc scan during WaitMigrateTarget
        if self.ceremony.is_waiting_migrate_target() {
            self.tick_wait_disc(true);
        }

        // Intent burn completion
        if self.ceremony.is_writing_intent() {
            self.tick_intent_burn();
        }

        // Record burn completion
        if self.ceremony.is_burning_disc() {
            self.tick_record_burn();
        }
    }

    /// Process an action, updating app state.
    pub fn update(&mut self, action: Action) {
        match action {
            Action::Noop | Action::Tick | Action::Render => {}
            Action::Quit => self.running = false,
            Action::SwitchMode(mode) => {
                self.mode = mode;
                self.content_scroll = 0;
            }
            Action::SetStatus(msg) => self.set_status(msg),

            // Setup flow
            Action::ConfirmClock => {
                self.confirmed_time = Some(SystemTime::now());
                self.setup.phase = SetupPhase::WaitUsb;
                self.set_status("Scanning for USB stick with profile.toml…");
            }
            Action::ProfileLoaded => {
                self.setup.phase = SetupPhase::ProfileLoaded;
                self.set_status("Profile loaded from USB.");
            }
            Action::AdvanceToPinEntry => {
                self.pin_buf.clear();
                self.pin_display_len = 0;
                self.setup.phase = SetupPhase::EnterPin;
                self.set_status("Enter HSM PIN and press Enter. Esc to cancel.");
            }
            Action::PinChar(c) => {
                self.pin_buf.push(c);
                self.pin_display_len = crate::helpers::noise_display_len();
            }
            Action::PinBackspace => {
                self.pin_buf.pop();
                self.pin_display_len = if self.pin_buf.is_empty() {
                    0
                } else {
                    crate::helpers::noise_display_len()
                };
            }
            Action::PinCancel => {
                self.pin_buf.clear();
                self.pin_display_len = 0;
                self.setup.phase = SetupPhase::ProfileLoaded;
                self.status.clear();
            }
            Action::DoLogin => {
                self.do_login();
            }
            Action::HsmLoggedIn => {
                self.setup.phase = SetupPhase::WaitDisc;
                self.hsm_state = HwState::Ready("logged in".into());
                self.set_status(
                    "Logged in. Insert write-once disc (BD-R, DVD-R, CD-R, or M-Disc) and press [1].",
                );
            }
            Action::SetupComplete => {
                self.setup_complete = true;
                self.mode = Mode::Ceremony;
                self.set_status(
                    "[1] Generate Root CA  [2] Sign CSR  [3] Revoke Cert  [4] Issue CRL  [5] Migrate Disc",
                );
            }
            Action::ConfirmDisc => {
                let ready = self.skip_disc
                    || (self.optical_dev.is_some()
                        && self.sessions_remaining.map(|r| r >= 2).unwrap_or(false));
                if ready {
                    self.update(Action::SetupComplete);
                }
            }

            // Ceremony operations
            Action::SelectOperation(op) => {
                self.do_select_operation(op);
            }
            Action::SelectKeyAction(n) => {
                self.pending_key_action = Some(n);
                self.do_write_intent();
            }
            Action::SelectCertProfile(idx) => {
                self.selected_profile_idx = Some(idx);
                self.ceremony.set_state_csr_preview();
                self.set_status("Review CSR and profile. [1] to proceed, [q] to cancel.");
            }
            Action::ConfirmCsrSign => {
                self.show_confirm(
                    "Sign CSR",
                    vec![
                        "This will sign the CSR using the HSM private key".into(),
                        "and write an intent+record session to disc.".into(),
                    ],
                    Action::DoWriteIntent,
                );
            }
            Action::ConfirmCertBurn => {
                self.show_confirm(
                    "Write Certificate to Disc",
                    vec![
                        "This will write the certificate and CRL to disc.".into(),
                        "The disc session is permanent and cannot be erased.".into(),
                    ],
                    Action::DoStartBurn,
                );
            }
            Action::ConfirmCrlSign => {
                self.show_confirm(
                    "Sign and Write CRL",
                    vec![
                        "This will sign the CRL using the HSM private key".into(),
                        "and write an intent+record session to disc.".into(),
                    ],
                    Action::DoWriteIntent,
                );
            }

            // Revocation
            Action::RevokeInputChar(c) => {
                if self.revoke_phase == 0 && c.is_ascii_digit() {
                    self.revoke_serial_buf.push(c);
                } else if self.revoke_phase == 1 {
                    self.revoke_reason_buf.push(c);
                }
            }
            Action::RevokeInputBackspace => {
                if self.revoke_phase == 0 {
                    self.revoke_serial_buf.pop();
                } else {
                    self.revoke_reason_buf.pop();
                }
            }
            Action::RevokeInputConfirm => {
                self.do_add_revocation_entry();
            }
            Action::RevokeInputNextPhase => {
                if self.revoke_phase == 0 && !self.revoke_serial_buf.is_empty() {
                    self.revoke_phase = 1;
                    self.set_status("Reason (optional, Enter to skip): e.g. key-compromise");
                }
            }
            Action::RevokeInputCancel => {
                self.revoke_phase = 0;
                self.set_status("Enter certificate serial number (digits). Press Enter.");
            }

            // Disc/USB
            Action::IntentBurnComplete => {}
            Action::DoWriteIntent => {
                self.do_write_intent();
            }
            Action::DoStartBurn => {
                self.do_start_burn();
            }
            Action::BurnComplete => {}
            Action::DoWriteUsb => {
                self.do_write_usb();
            }

            // Migration
            Action::ConfirmMigrate => {
                self.migrate_sessions = self.prior_sessions.clone();
                self.prior_sessions.clear();
                self.optical_dev = None;
                self.sessions_remaining = None;
                self.ceremony.set_state_wait_migrate_target();
                self.set_status("Eject old disc. Insert blank new disc.");
            }
            Action::ConfirmMigrateTarget => {
                let ready = self.skip_disc
                    || (self.optical_dev.is_some()
                        && self.sessions_remaining.map(|r| r >= 50).unwrap_or(false));
                if ready {
                    self.do_start_burn();
                }
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
                .title("Status Log  [L/Esc] close  [\u{2191}/\u{2193}/PgUp/PgDn] scroll");
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
        let mut header_lines: Vec<Line> = vec![Line::from("ANODIZE ROOT CA CEREMONY")];
        if is_dev {
            header_lines.push(Line::from(Span::styled(
                "*** DEV BUILD — NOT FOR PRODUCTION USE ***",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )));
        }
        if self.skip_disc {
            header_lines.push(Line::from(Span::styled(
                "*** --skip-disc ACTIVE: optical disc write will be skipped ***",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
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
        let border_style = if is_dev || self.skip_disc {
            Style::default().fg(if is_dev { Color::Red } else { Color::Yellow })
        } else {
            Style::default()
        };
        let header = Paragraph::new(header_lines)
            .alignment(Alignment::Center)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(border_style),
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
            Mode::Ceremony => modes::ceremony_phases(
                self.ceremony.op_label(),
                self.ceremony.phase_index(),
            ),
            Mode::Utilities => vec![],
        };
        let phase_bar = PhaseBar {
            steps: &phase_steps,
        };
        frame.render_widget(phase_bar, chunks[2]);

        // Content area — rendered via App methods to avoid borrow splitting
        match self.mode {
            Mode::Setup => self.render_setup_content(frame, chunks[3]),
            Mode::Ceremony => self.render_ceremony_content(frame, chunks[3]),
            Mode::Utilities => self.utilities.render(frame, chunks[3]),
        }

        // Hardware status bar
        let status_bar = StatusBar {
            hsm: &self.hsm_state,
            disc: &self.disc_state,
            usb: &self.usb_state,
        };
        frame.render_widget(status_bar, chunks[4]);

        // Status line
        let status = Paragraph::new(self.status.as_str())
            .style(Style::default().fg(Color::Yellow))
            .block(Block::default().borders(Borders::ALL).title("Status"));
        frame.render_widget(status, chunks[5]);

        // Confirm dialog overlay (rendered last, on top)
        if let Some(dialog) = &self.confirm_dialog {
            dialog.render(frame, area);
        }
    }

    /// Show a two-key confirmation dialog for a critical action.
    pub fn show_confirm(
        &mut self,
        title: impl Into<String>,
        body: Vec<String>,
        action: Action,
    ) {
        self.confirm_dialog = Some(ConfirmDialog::new(title, body, action));
    }
}
