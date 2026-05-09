use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::time::SystemTime;

use anodize_config::state::SessionState;
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
use crate::modes::ceremony::{CeremonyPhase, PlanningState};
use crate::modes::setup::{SetupMode, SetupPhase};
use crate::modes::utilities::UtilitiesMode;

/// Hardware / peripheral polling state.
pub struct HwContext {
    pub hsm_state: HwState,
    pub disc_state: HwState,
    pub shuttle_state: HwState,
    pub actor: Option<HsmActor>,
    pub root_key: Option<KeyHandle>,
}

impl HwContext {
    fn new() -> Self {
        Self {
            hsm_state: HwState::Absent,
            disc_state: HwState::Absent,
            shuttle_state: HwState::Absent,
            actor: None,
            root_key: None,
        }
    }
}

/// Disc / session management state.
pub struct DiscContext {
    pub optical_dev: Option<PathBuf>,
    pub prior_sessions: Vec<SessionEntry>,
    pub burn_rx: Option<Receiver<Result<()>>>,
    pub sessions_remaining: Option<u16>,
    pub intent_session_dir_name: Option<String>,
    pub pending_key_action: Option<u8>, // 1=generate, 2=find-existing
    pub pending_intent_session: Option<SessionEntry>,
    pub session_state: Option<SessionState>,
}

impl DiscContext {
    fn new() -> Self {
        Self {
            optical_dev: None,
            prior_sessions: Vec::new(),
            burn_rx: None,
            sessions_remaining: None,
            intent_session_dir_name: None,
            pending_key_action: None,
            pending_intent_session: None,
            session_state: None,
        }
    }
}

/// Certificate / CRL / CSR / revocation / migration artefacts.
pub struct CeremonyData {
    pub cert_der: Option<Vec<u8>>,
    pub fingerprint: Option<String>,
    pub crl_der: Option<Vec<u8>>,
    pub root_cert_der: Option<Vec<u8>>,
    pub csr_der: Option<Vec<u8>>,
    pub csr_subject_display: Option<String>,
    pub selected_profile_idx: Option<usize>,
    pub revocation_list: Vec<RevocationEntry>,
    pub crl_number: Option<u64>,
    pub revoke_serial_buf: String,
    pub revoke_reason_buf: String,
    pub revoke_phase: u8, // 0=serial entry, 1=reason entry
    pub migrate_sessions: Vec<SessionEntry>,
    pub migrate_chain_ok: bool,
    pub migrate_total_bytes: u64,
}

impl CeremonyData {
    fn new() -> Self {
        Self {
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
        }
    }
}

/// SSS / custodian / share components for InitRoot & RekeyShares.
pub struct SssContext {
    pub custodian_buf: String,
    pub shares: Option<Vec<anodize_sss::Share>>,
    pub custodian_names: Vec<String>,
    pub share_input: Option<crate::components::share_input::ShareInput>,
    pub share_reveal: Option<crate::components::share_reveal::ShareReveal>,
    pub custodian_setup: Option<crate::components::custodian_setup::CustodianSetup>,
}

impl SssContext {
    fn new() -> Self {
        Self {
            custodian_buf: String::new(),
            shares: None,
            custodian_names: Vec::new(),
            share_input: None,
            share_reveal: None,
            custodian_setup: None,
        }
    }
}

/// Top-level application state.
pub struct App {
    pub running: bool,
    pub mode: Mode,
    pub status: String,
    pub log_lines: Vec<String>,
    pub log_view: bool,
    pub log_scroll: u16,

    // Sub-contexts
    pub hw: HwContext,
    pub disc: DiscContext,
    pub data: CeremonyData,
    pub sss: SssContext,

    // Mode components
    pub setup: SetupMode,
    pub ceremony: CeremonyMode,
    pub utilities: UtilitiesMode,

    // Setup completion flag — gates Ceremony mode
    pub setup_complete: bool,

    // CLI flags
    pub skip_disc: bool,
    pub shuttle_mount: PathBuf,

    // Clock
    pub confirmed_time: Option<SystemTime>,

    // Shuttle / Profile
    pub profile: Option<Profile>,
    pub profile_toml_bytes: Option<Vec<u8>>,

    // Active operation
    pub current_op: Option<Operation>,

    // Temporary PIN buffer — used internally by SSS operations, never displayed
    pub pin_buf: String,

    // Two-key confirmation dialog (modal overlay)
    pub confirm_dialog: Option<ConfirmDialog>,

    // Content area vertical scroll offset
    pub content_scroll: u16,
}

impl App {
    pub fn new(shuttle_mount: PathBuf, skip_disc: bool) -> Self {
        Self {
            running: true,
            mode: Mode::Setup,
            status: "Welcome to Anodize Root CA Ceremony.".into(),
            log_lines: Vec::new(),
            log_view: false,
            log_scroll: 0,

            hw: HwContext::new(),
            disc: DiscContext::new(),
            data: CeremonyData::new(),
            sss: SssContext::new(),

            setup: SetupMode::new(),
            ceremony: CeremonyMode::new(),
            utilities: UtilitiesMode::new(),

            setup_complete: false,
            skip_disc,
            shuttle_mount,

            confirmed_time: None,
            profile: None,
            profile_toml_bytes: None,
            current_op: None,
            pin_buf: String::new(),
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
        let in_text_entry = self.mode == Mode::Ceremony && self.ceremony.in_text_entry();

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
                        &self.disc, &self.data,
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

        // CustodianSetup component delegation
        if self.mode == Mode::Ceremony {
            if self.ceremony.state == CeremonyPhase::Planning(PlanningState::CustodianSetup)
                || self.ceremony.state
                    == CeremonyPhase::Planning(PlanningState::RekeyCustodianSetup)
            {
                if let Some(ref mut setup) = self.sss.custodian_setup {
                    setup.handle_key(key);
                    if setup.aborted {
                        self.sss.custodian_setup = None;
                        let is_rekey = self.ceremony.state
                            == CeremonyPhase::Planning(PlanningState::RekeyCustodianSetup);
                        if is_rekey {
                            return Action::RekeyAbort;
                        } else {
                            return Action::InitRootAbort;
                        }
                    }
                    if setup.confirmed {
                        let names = setup.names.clone();
                        let threshold = setup.threshold;
                        self.sss.custodian_setup = None;
                        let is_rekey = self.ceremony.state
                            == CeremonyPhase::Planning(PlanningState::RekeyCustodianSetup);
                        if is_rekey {
                            self.sss.custodian_names = names;
                            self.do_rekey_confirm_custodians_with_threshold(threshold);
                        } else {
                            self.sss.custodian_names = names;
                            self.do_init_root_confirm_custodians_with_threshold(threshold);
                        }
                    }
                }
                return Action::Noop;
            }
        }

        // InitRoot share reveal/verify: delegate to owned components
        if self.mode == Mode::Ceremony {
            if self.ceremony.state == CeremonyPhase::Planning(PlanningState::ShareReveal) {
                if key.code == KeyCode::Esc {
                    return Action::InitRootAbort;
                }
                if let Some(ref mut reveal) = self.sss.share_reveal {
                    if reveal.handle_key(key) {
                        // All shares revealed → advance to verification round
                        self.sss.share_reveal = None;
                        if let Some(ref state) = self.disc.session_state {
                            let mut si = crate::components::share_input::ShareInput::new(
                                state.sss.clone(),
                                32, // PIN is 32 bytes
                            );
                            si.verify_all = true;
                            self.sss.share_input = Some(si);
                        }
                        self.ceremony.state = CeremonyPhase::Planning(PlanningState::ShareVerify);
                        self.set_status(
                            "Verification round: every custodian must re-enter their share.",
                        );
                    }
                }
                return Action::Noop;
            }
            if self.ceremony.state == CeremonyPhase::Planning(PlanningState::ShareVerify) {
                if key.code == KeyCode::Esc {
                    return Action::InitRootAbort;
                }
                if let Some(ref mut input) = self.sss.share_input {
                    input.handle_key(key);
                    if input.is_complete() {
                        self.sss.share_input = None;
                        self.sss.shares = None;
                        // All shares verified → proceed to HSM key generation
                        self.ceremony.state = CeremonyPhase::Planning(PlanningState::KeyAction);
                        self.set_status(
                            "All shares verified. [1] Generate root keypair  [2] Use existing key",
                        );
                    }
                }
                return Action::Noop;
            }

            // Quorum phase: collect shares → reconstruct PIN → HSM login → execute
            if self.ceremony.state == CeremonyPhase::Quorum {
                if key.code == KeyCode::Esc {
                    self.sss.share_input = None;
                    self.current_op = None;
                    self.ceremony.state = CeremonyPhase::OperationSelect;
                    self.set_status("Quorum aborted.");
                    return Action::Noop;
                }
                if let Some(ref mut input) = self.sss.share_input {
                    input.handle_key(key);
                    if input.quorum_reached() {
                        self.do_quorum_complete();
                    }
                }
                return Action::Noop;
            }

            // RekeyShares: quorum input → reconstruct PIN
            if self.ceremony.state == CeremonyPhase::Planning(PlanningState::RekeyQuorum) {
                if key.code == KeyCode::Esc {
                    return Action::RekeyAbort;
                }
                if let Some(ref mut input) = self.sss.share_input {
                    input.handle_key(key);
                    if input.quorum_reached() {
                        // Reconstruct PIN and verify
                        self.do_rekey_quorum_complete();
                    }
                }
                return Action::Noop;
            }

            // KeyBackup: quorum input → reconstruct PIN → discover devices
            if self.ceremony.state == CeremonyPhase::Planning(PlanningState::BackupQuorum) {
                if key.code == KeyCode::Esc {
                    self.sss.share_input = None;
                    self.current_op = None;
                    self.ceremony.state = CeremonyPhase::OperationSelect;
                    self.set_status("Backup aborted.");
                    return Action::Noop;
                }
                if let Some(ref mut input) = self.sss.share_input {
                    input.handle_key(key);
                    if input.quorum_reached() {
                        self.do_backup_quorum_complete();
                    }
                }
                return Action::Noop;
            }

            // KeyBackup: device selection phase — forward keys to backup FSM
            if self.ceremony.state == CeremonyPhase::Planning(PlanningState::BackupDevices) {
                if key.code == KeyCode::Esc {
                    // Check if backup FSM can go back, or abort to op select
                    use crate::modes::utilities::backup::BackupPhase;
                    match self.utilities.backup.phase {
                        BackupPhase::SelectSource => {
                            self.current_op = None;
                            self.ceremony.state = CeremonyPhase::OperationSelect;
                            self.set_status("Backup aborted.");
                        }
                        _ => {
                            self.utilities.backup.go_back();
                        }
                    }
                    return Action::Noop;
                }
                // Number keys: forward to backup FSM
                if let KeyCode::Char(c) = key.code {
                    if let Some(d) = c.to_digit(10) {
                        let action = self.utilities.backup.handle_key_digit(d as u8);
                        if action == crate::modes::utilities::backup::BackupAction::Execute {
                            // All inputs collected → write intent WAL to disc,
                            // then tick_intent_burn will execute + record burn.
                            self.do_write_intent();
                        }
                        return Action::Noop;
                    }
                }
                if key.code == KeyCode::Enter {
                    let action = self.utilities.backup.handle_enter();
                    if action == crate::modes::utilities::backup::BackupAction::Execute {
                        self.do_write_intent();
                    }
                    return Action::Noop;
                }
                return Action::Noop;
            }

            if self.ceremony.state == CeremonyPhase::Planning(PlanningState::RekeyShareReveal) {
                if key.code == KeyCode::Esc {
                    return Action::RekeyAbort;
                }
                if let Some(ref mut reveal) = self.sss.share_reveal {
                    if reveal.handle_key(key) {
                        self.sss.share_reveal = None;
                        if let Some(ref state) = self.disc.session_state {
                            let mut si = crate::components::share_input::ShareInput::new(
                                state.sss.clone(),
                                32,
                            );
                            si.verify_all = true;
                            self.sss.share_input = Some(si);
                        }
                        self.ceremony.state =
                            CeremonyPhase::Planning(PlanningState::RekeyShareVerify);
                        self.set_status(
                            "Verify new shares: every custodian must re-enter their share.",
                        );
                    }
                }
                return Action::Noop;
            }
            if self.ceremony.state == CeremonyPhase::Planning(PlanningState::RekeyShareVerify) {
                if key.code == KeyCode::Esc {
                    return Action::RekeyAbort;
                }
                if let Some(ref mut input) = self.sss.share_input {
                    input.handle_key(key);
                    if input.is_complete() {
                        self.sss.share_input = None;
                        self.sss.shares = None;
                        // All shares verified → burn updated STATE.JSON directly
                        self.do_start_burn();
                    }
                }
                return Action::Noop;
            }
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

    /// Background polling for disc/shuttle state + burn completion.
    fn background_tick(&mut self) {
        // Shuttle scan during WaitShuttle
        if self.mode == Mode::Setup && self.setup.phase == SetupPhase::WaitShuttle {
            self.tick_wait_shuttle();
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
            tracing::debug!(
                "background_tick: ceremony is_writing_intent, calling tick_intent_burn"
            );
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
                self.setup.phase = SetupPhase::WaitShuttle;
                self.set_status("Scanning for shuttle USB with profile.toml…");
            }
            Action::ProfileLoaded => {
                self.setup.phase = SetupPhase::ProfileLoaded;
                self.set_status("Profile loaded from shuttle.");
            }
            Action::HsmDetected => {
                self.setup.phase = SetupPhase::HsmDetect;
                self.do_detect_hsm();
            }
            Action::HsmDetectFailed(msg) => {
                self.hw.hsm_state = HwState::Error(msg.clone());
                self.set_status(format!("HSM detection failed: {msg}"));
                self.setup.phase = SetupPhase::ProfileLoaded;
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
                let ready = self.skip_disc
                    || (self.disc.optical_dev.is_some()
                        && self
                            .disc
                            .sessions_remaining
                            .map(|r| r >= 2)
                            .unwrap_or(false));
                if ready {
                    self.update(Action::SetupComplete);
                }
            }

            // Ceremony operations
            Action::SelectOperation(op) => {
                self.do_select_operation(op);
            }
            Action::SelectKeyAction(n) => {
                self.disc.pending_key_action = Some(n);
                self.do_write_intent();
            }
            Action::SelectCertProfile(idx) => {
                self.data.selected_profile_idx = Some(idx);
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
                if self.data.revoke_phase == 0 && c.is_ascii_digit() {
                    self.data.revoke_serial_buf.push(c);
                } else if self.data.revoke_phase == 1 {
                    self.data.revoke_reason_buf.push(c);
                }
            }
            Action::RevokeInputBackspace => {
                if self.data.revoke_phase == 0 {
                    self.data.revoke_serial_buf.pop();
                } else {
                    self.data.revoke_reason_buf.pop();
                }
            }
            Action::RevokeInputConfirm => {
                self.do_add_revocation_entry();
            }
            Action::RevokeInputNextPhase => {
                if self.data.revoke_phase == 0 && !self.data.revoke_serial_buf.is_empty() {
                    self.data.revoke_phase = 1;
                    self.set_status("Reason (optional, Enter to skip): e.g. key-compromise");
                }
            }
            Action::RevokeInputCancel => {
                self.data.revoke_phase = 0;
                self.set_status("Enter certificate serial number (digits). Press Enter.");
            }

            // Clock re-confirm: operator attests clock is correct at signing time
            Action::ReconfirmClock => {
                self.confirmed_time = Some(SystemTime::now());
                self.do_dispatch_after_clock_reconfirm();
            }

            // Disc/Shuttle
            Action::IntentBurnComplete => {}
            Action::DoWriteIntent => {
                self.do_write_intent();
            }
            Action::DoStartBurn => {
                self.do_start_burn();
            }
            Action::BurnComplete => {}
            Action::DoWriteShuttle => {
                self.do_write_shuttle();
            }

            // InitRoot ceremony
            Action::InitRootAbort => {
                self.sss.custodian_buf.clear();
                self.sss.shares = None;
                self.sss.custodian_names.clear();
                self.sss.share_input = None;
                self.sss.share_reveal = None;
                self.sss.custodian_setup = None;
                self.current_op = None;
                self.ceremony.state = CeremonyPhase::OperationSelect;
                self.set_status("InitRoot aborted.");
            }
            Action::RekeyAbort => {
                self.sss.custodian_buf.clear();
                self.sss.shares = None;
                self.sss.custodian_names.clear();
                self.sss.share_input = None;
                self.sss.share_reveal = None;
                self.sss.custodian_setup = None;
                self.current_op = None;
                self.ceremony.state = CeremonyPhase::OperationSelect;
                self.set_status("RekeyShares aborted.");
            }
            Action::RetryPostCommit => {
                if let Err(e) = self.post_intent_init_root() {
                    tracing::error!("RetryPostCommit: {e}");
                    self.set_status(e);
                    self.ceremony.state = CeremonyPhase::PostCommitError;
                }
            }

            // Migration
            Action::ConfirmMigrate => {
                self.data.migrate_sessions = self.disc.prior_sessions.clone();
                self.disc.prior_sessions.clear();
                self.disc.optical_dev = None;
                self.disc.sessions_remaining = None;
                self.ceremony.set_state_wait_migrate_target();
                self.set_status("Eject old disc. Insert blank new disc.");
            }
            // Utilities sub-screens
            Action::UtilScreen(idx) => {
                use crate::modes::utilities::{UtilScreen, UtilitiesMode};
                let screen = match idx {
                    1 => UtilScreen::SystemInfo,
                    2 => UtilScreen::AuditLog,
                    3 => UtilScreen::HsmInventory,
                    4 => UtilScreen::DiscInspector,
                    _ => UtilScreen::Menu,
                };
                if screen == UtilScreen::DiscInspector {
                    // Disc inspector has its own state; populate from disjoint fields.
                    use crate::modes::utilities::disc_inspector::{
                        gather_banner_from, gather_session_list_from,
                    };
                    let banner = gather_banner_from(&self.disc, &self.data);
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

            Action::BackupExecute => {
                // Execute the confirmed backup/pair operation (ceremony mode).
                if let Some(ref profile) = self.profile {
                    if let Ok(backup_impl) = anodize_hsm::create_backup(profile.hsm.backend) {
                        let pin = secrecy::SecretString::new(self.pin_buf.clone());
                        self.utilities.backup.execute(backup_impl.as_ref(), &pin);
                    }
                }
            }

            Action::ConfirmMigrateTarget => {
                let ready = self.skip_disc
                    || (self.disc.optical_dev.is_some()
                        && self
                            .disc
                            .sessions_remaining
                            .map(|r| r >= 50)
                            .unwrap_or(false));
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
            Mode::Ceremony => modes::ceremony_phases(self.ceremony.phase_index()),
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
            .block(Block::default().borders(Borders::ALL).title("Status"));
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
}
