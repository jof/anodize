//! Ceremony TUI — disc-before-USB state machine.
//!
//! Key invariants (enforced structurally):
//! - `UsbWrite` is only reachable from `DiscDone`.
//! - `DiscDone` is only set after a successful optical disc session burn (or --skip-disc).
//! - USB write is therefore impossible without a committed disc write.

mod media;

use std::io::stdout;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::time::SystemTime;

use anodize_audit::{genesis_hash, AuditLog};
use anodize_ca::{build_root_cert, issue_crl, sign_intermediate_csr, CaError, P384HsmSigner};
use anodize_config::{
    load as load_profile, parse_revocation_list, serialize_revocation_list, PinSource, Profile,
    RevocationEntry,
};
use anodize_hsm::{Hsm, HsmActor, KeyHandle, KeySpec, Pkcs11Hsm};
use anyhow::Result;
use clap::Parser;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use der::{Decode, Encode};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame, Terminal,
};
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use x509_cert::certificate::Certificate;

use media::{IsoFile, SessionEntry};

#[derive(Parser)]
#[command(name = "anodize-ceremony", about = "Root CA key ceremony")]
struct Cli {
    /// Mount point for USB stick (created if absent).
    #[arg(long, default_value = "/tmp/anodize-usb")]
    usb_mount: PathBuf,

    /// Skip optical disc burn; write disc artifacts to /tmp/anodize-staging instead.
    /// For development and testing only — never use in a real ceremony.
    #[arg(long)]
    skip_disc: bool,
}

/// Which CA operation is being performed.
#[derive(Debug, Clone, PartialEq)]
enum Operation {
    GenerateRootCa,
    SignCsr,
    RevokeCert,
    IssueCrl,
    MigrateDisc,
}

/// Ceremony state machine. Transitions are strictly forward (no back-tracking).
#[derive(Debug, Clone, PartialEq)]
enum AppState {
    ClockCheck,      // Confirm system clock is correct
    WaitUsb,         // Scan for USB containing profile.toml (auto-advance)
    ProfileLoaded,   // Profile read; show CA info; [1] to continue
    EnterPin,        // HSM PIN entry
    WaitDisc,        // Wait for appendable write-once disc — BEFORE key operation
    OperationSelect, // Choose which ceremony mode to run
    // Mode 1: Generate Root CA
    KeyAction,     // Generate new key or find existing
    WritingIntent, // Background burn of intent session; HSM op follows on success
    CertPreview,   // Show cert + fingerprint; [1] to burn cert session
    BurningDisc,   // Background burn of cert/CRL/data session in progress
    DiscDone,      // Disc written; [1] to write USB; [q] to skip USB
    // Mode 2: Sign CSR
    LoadCsr,    // CSR loaded from USB; select cert profile
    CsrPreview, // Show CSR subject + selected profile; [1] to proceed
    // Mode 3: Revoke Cert + Issue CRL
    RevokeInput,   // Enter serial number + reason (phase 0=serial, 1=reason)
    RevokePreview, // Show updated revocation list + CRL number; [1] to proceed
    // Mode 4: Issue CRL refresh
    CrlPreview, // Show current revocation list + CRL number; [1] to proceed
    // Mode 5: Migrate Disc
    MigrateConfirm,    // Show chain verification + RAM check; [1] to proceed
    WaitMigrateTarget, // Wait for blank target disc
    Done,              // Complete
}

struct App {
    // Clock
    confirmed_time: Option<SystemTime>,

    // USB
    usb_mountpoint: PathBuf,
    profile: Option<Profile>,
    profile_toml_bytes: Option<Vec<u8>>,

    // TUI state
    state: AppState,
    status: String,
    log_lines: Vec<String>,
    log_view: bool,
    log_scroll: u16,

    // Active operation
    current_op: Option<Operation>,

    // HSM session
    actor: Option<HsmActor>,
    root_key: Option<KeyHandle>,

    // Cert held in RAM until disc write succeeds (Mode 1)
    cert_der: Option<Vec<u8>>,
    fingerprint: Option<String>,

    // CRL held in RAM until disc write succeeds (Modes 1, 3, 4)
    crl_der: Option<Vec<u8>>,

    // Root cert DER loaded from disc for modes 2/3/4
    root_cert_der: Option<Vec<u8>>,

    // Mode 2: CSR signing
    csr_der: Option<Vec<u8>>,
    csr_subject_display: Option<String>,
    selected_profile_idx: Option<usize>,

    // Modes 3+4: revocation
    revocation_list: Vec<RevocationEntry>,
    crl_number: Option<u64>,

    // Mode 3: revoke input state
    revoke_serial_buf: String,
    revoke_reason_buf: String,
    revoke_phase: u8, // 0=serial entry, 1=reason entry

    // Mode 5: migration
    migrate_sessions: Vec<SessionEntry>,
    migrate_chain_ok: bool,
    migrate_total_bytes: u64,

    // PIN input — display length is randomised noise, never reveals actual length
    pin_buf: String,
    pin_display_len: usize,

    // Disc management
    optical_dev: Option<PathBuf>,
    prior_sessions: Vec<SessionEntry>,
    burn_rx: Option<Receiver<Result<()>>>,
    #[cfg_attr(feature = "dev-usb-disc", allow(dead_code))]
    skip_disc: bool,
    sessions_remaining: Option<u16>,

    // WAL intent session written before HSM key operation
    intent_session_dir_name: Option<String>,
    pending_key_action: Option<u8>, // 1=generate, 2=find-existing
    pending_intent_session: Option<SessionEntry>,

    // Dev-mode disc USB
    #[cfg(feature = "dev-usb-disc")]
    disc_usb: Option<media::usb_disc::DiscUsb>,
    #[cfg(feature = "dev-usb-disc")]
    profile_dev: Option<PathBuf>,
}

impl App {
    fn new(usb_mountpoint: PathBuf, skip_disc: bool) -> Self {
        Self {
            confirmed_time: None,
            usb_mountpoint,
            profile: None,
            profile_toml_bytes: None,
            state: AppState::ClockCheck,
            status: String::new(),
            log_lines: Vec::new(),
            log_view: false,
            log_scroll: 0,
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
            skip_disc,
            sessions_remaining: None,
            intent_session_dir_name: None,
            pending_key_action: None,
            pending_intent_session: None,
            #[cfg(feature = "dev-usb-disc")]
            disc_usb: None,
            #[cfg(feature = "dev-usb-disc")]
            profile_dev: None,
        }
    }

    fn set_status(&mut self, msg: impl Into<String>) {
        let s: String = msg.into();
        if self.log_lines.last().map(|l| l.as_str()) != Some(s.as_str()) {
            self.log_lines.push(s.clone());
        }
        self.status = s;
    }

    fn handle_key(&mut self, code: KeyCode) {
        match self.state.clone() {
            AppState::ClockCheck => {
                if code == KeyCode::Char('1') {
                    self.confirmed_time = Some(SystemTime::now());
                    self.state = AppState::WaitUsb;
                    self.set_status("Scanning for USB stick with profile.toml…");
                }
            }

            AppState::WaitUsb => {} // auto-advance on USB discovery in background_tick

            AppState::ProfileLoaded => {
                if code == KeyCode::Char('1') {
                    self.pin_buf.clear();
                    self.pin_display_len = 0;
                    self.state = AppState::EnterPin;
                    self.set_status("Enter HSM PIN and press Enter. Esc to cancel.");
                }
            }

            AppState::EnterPin => match code {
                KeyCode::Char(c) => {
                    self.pin_buf.push(c);
                    self.pin_display_len = noise_display_len();
                }
                KeyCode::Backspace => {
                    self.pin_buf.pop();
                    self.pin_display_len = if self.pin_buf.is_empty() {
                        0
                    } else {
                        noise_display_len()
                    };
                }
                KeyCode::Enter => self.do_login(),
                KeyCode::Esc => {
                    self.pin_buf.clear();
                    self.pin_display_len = 0;
                    self.state = AppState::ProfileLoaded;
                    self.status.clear();
                }
                _ => {}
            },

            AppState::WaitDisc => {
                if code == KeyCode::Char('1') {
                    #[cfg(feature = "dev-usb-disc")]
                    let ready = self.disc_usb.is_some();
                    #[cfg(not(feature = "dev-usb-disc"))]
                    let ready = self.skip_disc
                        || (self.optical_dev.is_some()
                            && self.sessions_remaining.map(|r| r >= 2).unwrap_or(false));
                    if ready {
                        self.state = AppState::OperationSelect;
                        self.set_status("[1] Generate Root CA  [2] Sign CSR  \
                            [3] Revoke Cert  [4] Issue CRL  [5] Migrate Disc");
                    }
                }
            }

            AppState::OperationSelect => match code {
                KeyCode::Char('1') => {
                    self.current_op = Some(Operation::GenerateRootCa);
                    self.state = AppState::KeyAction;
                    self.set_status("[1] Generate new P-384 keypair (fresh)  \
                         [2] Use existing key (resume)");
                }
                KeyCode::Char('2') => {
                    self.current_op = Some(Operation::SignCsr);
                    self.do_load_csr();
                }
                KeyCode::Char('3') => {
                    self.current_op = Some(Operation::RevokeCert);
                    self.do_load_revocation();
                    if self.state == AppState::RevokeInput {
                        self.revoke_phase = 0;
                        self.revoke_serial_buf.clear();
                        self.revoke_reason_buf.clear();
                        self.set_status("Enter certificate serial number (digits). Press Enter to continue.");
                    }
                }
                KeyCode::Char('4') => {
                    self.current_op = Some(Operation::IssueCrl);
                    self.do_load_revocation();
                    if self.state == AppState::CrlPreview {
                        self.set_status("Review CRL details. [1] to proceed, [q] to cancel.");
                    }
                }
                KeyCode::Char('5') => {
                    self.current_op = Some(Operation::MigrateDisc);
                    self.do_migrate_confirm();
                }
                _ => {}
            },

            AppState::KeyAction => match code {
                KeyCode::Char('1') => {
                    self.pending_key_action = Some(1);
                    self.do_write_intent();
                }
                KeyCode::Char('2') => {
                    self.pending_key_action = Some(2);
                    self.do_write_intent();
                }
                _ => {}
            },

            AppState::WritingIntent => {} // auto-advance when intent burn completes

            AppState::LoadCsr => {
                // User selects a cert profile by number
                if let KeyCode::Char(c) = code {
                    if let Some(d) = c.to_digit(10) {
                        let idx = d as usize;
                        let n = self
                            .profile
                            .as_ref()
                            .map(|p| p.cert_profiles.len())
                            .unwrap_or(0);
                        if idx >= 1 && idx <= n {
                            self.selected_profile_idx = Some(idx - 1);
                            self.state = AppState::CsrPreview;
                            self.set_status("Review CSR and profile. [1] to proceed, [q] to cancel.");
                        }
                    }
                }
            }

            AppState::CsrPreview => {
                if code == KeyCode::Char('1') {
                    self.do_write_intent();
                }
            }

            AppState::RevokeInput => match (self.revoke_phase, code) {
                (0, KeyCode::Char(c)) if c.is_ascii_digit() => {
                    self.revoke_serial_buf.push(c);
                }
                (0, KeyCode::Backspace) => {
                    self.revoke_serial_buf.pop();
                }
                (0, KeyCode::Enter) if !self.revoke_serial_buf.is_empty() => {
                    self.revoke_phase = 1;
                    self.set_status("Reason (optional, Enter to skip): e.g. key-compromise");
                }
                (1, KeyCode::Char(c)) => {
                    self.revoke_reason_buf.push(c);
                }
                (1, KeyCode::Backspace) => {
                    self.revoke_reason_buf.pop();
                }
                (1, KeyCode::Enter) => {
                    self.do_add_revocation_entry();
                }
                (1, KeyCode::Esc) => {
                    self.revoke_phase = 0;
                    self.set_status("Enter certificate serial number (digits). Press Enter.");
                }
                _ => {}
            },

            AppState::RevokePreview => {
                if code == KeyCode::Char('1') {
                    self.do_write_intent();
                }
            }

            AppState::CrlPreview => {
                if code == KeyCode::Char('1') {
                    self.do_write_intent();
                }
            }

            AppState::CertPreview => {
                if code == KeyCode::Char('1') {
                    self.do_start_burn();
                }
            }

            AppState::BurningDisc => {} // auto-advance on burn completion

            AppState::DiscDone => {
                if code == KeyCode::Char('1') {
                    self.do_write_usb();
                }
            }

            AppState::MigrateConfirm => {
                if code == KeyCode::Char('1') {
                    // Store sessions from old disc; reset disc tracking for new disc scan
                    self.migrate_sessions = self.prior_sessions.clone();
                    self.prior_sessions.clear();
                    self.optical_dev = None;
                    self.sessions_remaining = None;
                    #[cfg(feature = "dev-usb-disc")]
                    {
                        self.disc_usb = None;
                    }
                    self.state = AppState::WaitMigrateTarget;
                    self.set_status("Eject old disc. Insert blank new disc.");
                }
            }

            AppState::WaitMigrateTarget => {
                if code == KeyCode::Char('1') {
                    #[cfg(feature = "dev-usb-disc")]
                    let ready = self.disc_usb.is_some();
                    #[cfg(not(feature = "dev-usb-disc"))]
                    let ready = self.skip_disc
                        || (self.optical_dev.is_some()
                            && self.sessions_remaining.map(|r| r >= 50).unwrap_or(false));
                    if ready {
                        self.do_start_burn();
                    }
                }
            }

            AppState::Done => {}
        }
    }

    /// Called every ~100 ms when no key event is pending.
    fn background_tick(&mut self) {
        match self.state {
            AppState::WaitUsb => {
                let diagnostics = media::usb_scan_diagnostics();
                let candidates = media::scan_usb_partitions();
                if candidates.is_empty() {
                    self.set_status(format!("Scanning… {diagnostics}"));
                    return;
                }
                match media::find_profile_usb(&candidates, &self.usb_mountpoint) {
                    Ok(Some((profile_path, dev_path))) => {
                        #[cfg(feature = "dev-usb-disc")]
                        {
                            self.profile_dev = Some(dev_path);
                        }
                        #[cfg(not(feature = "dev-usb-disc"))]
                        let _ = dev_path;
                        #[cfg(feature = "dev-softhsm-usb")]
                        if let Err(e) = configure_softhsm_from_usb(&self.usb_mountpoint) {
                            self.set_status(format!("SoftHSM2 USB setup failed: {e}"));
                            let _ = media::unmount(&self.usb_mountpoint);
                            return;
                        }
                        let raw_bytes = std::fs::read(&profile_path).unwrap_or_default();
                        match load_profile(&profile_path) {
                            Ok(profile) => {
                                if profile.hsm.pin_source != PinSource::Prompt {
                                    profile.hsm.pin_source.warn_if_unsafe();
                                    self.set_status("ERROR: pin_source is not 'prompt' — unsuitable for \
                                         ceremony. Fix profile.toml and re-insert USB.");
                                    let _ = media::unmount(&self.usb_mountpoint);
                                    return;
                                }
                                if let Err(e) = profile.hsm.check_module_allowed() {
                                    self.set_status(format!("PKCS#11 module not allowed: {e}"));
                                    let _ = media::unmount(&self.usb_mountpoint);
                                    return;
                                }
                                self.profile = Some(profile);
                                self.profile_toml_bytes = Some(raw_bytes);
                                self.state = AppState::ProfileLoaded;
                                self.set_status("Profile loaded from USB.");
                            }
                            Err(e) => {
                                self.set_status(format!("Profile parse error: {e}"));
                                let _ = media::unmount(&self.usb_mountpoint);
                            }
                        }
                    }
                    Ok(None) => {
                        self.set_status(format!(
                            "No profile.toml found ({diagnostics}) — \
                             insert USB with profile.toml."
                        ));
                    }
                    Err(e) => {
                        self.set_status(format!("Mount failed ({diagnostics}): {e}"));
                    }
                }
            }

            AppState::WaitDisc | AppState::WaitMigrateTarget => {
                #[cfg(feature = "dev-usb-disc")]
                {
                    let probe = std::path::Path::new("/tmp/anodize-disc-usb-probe");
                    let profile_dev = self.profile_dev.as_deref();
                    match media::usb_disc::find_disc_usb(profile_dev, probe) {
                        Some(disc) => {
                            let same_uuid = self
                                .disc_usb
                                .as_ref()
                                .map(|d| d.uuid == disc.uuid)
                                .unwrap_or(false);
                            if !same_uuid {
                                self.prior_sessions =
                                    media::usb_disc::read_disc_usb_sessions(&disc, probe);
                            }
                            let n = self.prior_sessions.len();
                            let label = if self.state == AppState::WaitMigrateTarget {
                                "target disc USB"
                            } else {
                                "disc USB"
                            };
                            self.set_status(format!(
                                "{label} ready ({}, {n} session(s)). Press [1].",
                                disc.uuid
                            ));
                            self.disc_usb = Some(disc);
                        }
                        None => {
                            self.disc_usb = None;
                            let label = if self.state == AppState::WaitMigrateTarget {
                                "blank target disc USB"
                            } else {
                                "disc USB"
                            };
                            self.set_status(format!("No {label} found. Insert USB with ANODIZE_DISC_ID."));
                        }
                    }
                }
                #[cfg(not(feature = "dev-usb-disc"))]
                {
                    if self.skip_disc {
                        self.optical_dev = Some(PathBuf::from("/run/anodize/staging"));
                        self.sessions_remaining = Some(100);
                        let label = if self.state == AppState::WaitMigrateTarget {
                            "--skip-disc mode: target disc ready. Press [1]."
                        } else {
                            "--skip-disc mode: disc ready. Press [1]."
                        };
                        self.set_status(label);
                        return;
                    }

                    let drives = media::scan_optical_drives();
                    let mut rw_rejection: Option<String> = None;
                    let need_blank = self.state == AppState::WaitMigrateTarget;
                    for dev in &drives {
                        match media::disc_is_appendable(dev) {
                            Ok(()) => {
                                let prior = media::read_disc_sessions(dev).unwrap_or_default();
                                let n = prior.len();
                                let (cap_summary, remaining) = media::disc_capacity_summary(dev);
                                self.sessions_remaining = Some(remaining);
                                if need_blank && n > 0 {
                                    self.set_status(format!(
                                        "Disc in {} has {n} session(s) — need a blank disc for migration.",
                                        dev.display()
                                    ));
                                    continue;
                                }
                                if !need_blank && remaining < 2 {
                                    self.set_status(format!(
                                        "Disc in {} is full ({cap_summary}). \
                                         Need 2 sessions for WAL. Insert a new disc.",
                                        dev.display()
                                    ));
                                    continue;
                                }
                                self.optical_dev = Some(dev.clone());
                                if !need_blank {
                                    self.prior_sessions = prior;
                                }
                                self.set_status(if need_blank {
                                    format!(
                                        "Blank disc in {} ({cap_summary}). Press [1] to write.",
                                        dev.display()
                                    )
                                } else if n == 0 {
                                    format!(
                                        "Blank disc in {} ({cap_summary}). Press [1] to continue.",
                                        dev.display()
                                    )
                                } else {
                                    format!(
                                        "Disc in {} — {n} prior session(s), {cap_summary}. \
                                         Press [1] to continue.",
                                        dev.display()
                                    )
                                });
                                return;
                            }
                            Err(ref e) if e.contains("rewritable") => {
                                rw_rejection = Some(e.clone());
                            }
                            Err(_) => {}
                        }
                    }
                    self.optical_dev = None;
                    if let Some(msg) = rw_rejection {
                        self.set_status(msg);
                    } else if drives.is_empty() {
                        self.set_status("No optical drive detected. Insert drive and disc.");
                    } else {
                        self.set_status("No blank/appendable disc found. Insert write-once disc \
                             (BD-R, DVD-R, CD-R, or M-Disc).");
                    }
                }
            }

            AppState::WritingIntent => {
                if let Some(rx) = &self.burn_rx {
                    if let Ok(result) = rx.try_recv() {
                        self.burn_rx = None;
                        match result {
                            Err(e) => {
                                self.set_status(format!("Intent disc write failed: {e}"));
                                self.state = AppState::WaitDisc;
                                self.optical_dev = None;
                                #[cfg(feature = "dev-usb-disc")]
                                {
                                    self.disc_usb = None;
                                }
                            }
                            Ok(()) => {
                                if let Some(intent) = self.pending_intent_session.take() {
                                    self.intent_session_dir_name = Some(intent.dir_name.clone());
                                    self.prior_sessions.push(intent);
                                }
                                match self.current_op.clone() {
                                    Some(Operation::GenerateRootCa) => {
                                        match self.pending_key_action {
                                            Some(1) => self.do_generate_and_build(),
                                            Some(2) => self.do_find_and_build(),
                                            _ => {
                                                self.set_status("Unknown key action");
                                                self.state = AppState::WaitDisc;
                                            }
                                        }
                                    }
                                    Some(Operation::SignCsr) => self.do_sign_csr(),
                                    Some(Operation::RevokeCert) => self.do_sign_crl_for_revoke(),
                                    Some(Operation::IssueCrl) => self.do_sign_crl_refresh(),
                                    _ => {
                                        self.set_status("Unknown operation after intent");
                                        self.state = AppState::WaitDisc;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            AppState::BurningDisc => {
                if let Some(rx) = &self.burn_rx {
                    if let Ok(result) = rx.try_recv() {
                        self.burn_rx = None;
                        match result {
                            Ok(()) => {
                                self.state = AppState::DiscDone;
                                #[cfg(feature = "dev-usb-disc")]
                                let disc_label = self
                                    .disc_usb
                                    .as_ref()
                                    .map(|d| d.uuid.clone())
                                    .unwrap_or_else(|| "disc USB".into());
                                #[cfg(not(feature = "dev-usb-disc"))]
                                let disc_label = self
                                    .optical_dev
                                    .as_deref()
                                    .map(|p| p.display().to_string())
                                    .unwrap_or_else(|| "/run/anodize/staging".into());
                                let op_label = match self.current_op {
                                    Some(Operation::GenerateRootCa) => "Root CA + CRL",
                                    Some(Operation::SignCsr) => "Intermediate cert",
                                    Some(Operation::RevokeCert) => "Revocation + CRL",
                                    Some(Operation::IssueCrl) => "CRL refresh",
                                    Some(Operation::MigrateDisc) => "Disc migration",
                                    None => "session",
                                };
                                self.set_status(format!("{op_label} written to disc: {disc_label}"));
                            }
                            Err(e) => {
                                self.set_status(format!("Burn failed: {e} — reinsert disc and retry."));
                                self.state = AppState::WaitDisc;
                                self.optical_dev = None;
                                #[cfg(feature = "dev-usb-disc")]
                                {
                                    self.disc_usb = None;
                                }
                            }
                        }
                    }
                }
            }

            _ => {}
        }
    }

    // ── HSM login ──────────────────────────────────────────────────────────────

    fn do_login(&mut self) {
        let pin: String = self.pin_buf.drain(..).collect();
        let pin = SecretString::new(pin);
        let cfg = match &self.profile {
            Some(p) => &p.hsm,
            None => {
                self.set_status("No profile loaded");
                return;
            }
        };

        let hsm = match Pkcs11Hsm::new(&cfg.module_path, &cfg.token_label) {
            Ok(h) => h,
            Err(e) => {
                self.set_status(format!("HSM open failed: {e}"));
                return;
            }
        };
        let mut actor = HsmActor::spawn(hsm);
        if let Err(e) = actor.login(&pin) {
            self.set_status(format!("Login failed: {e}"));
            return;
        }
        self.actor = Some(actor);
        self.state = AppState::WaitDisc;
        self.set_status(if cfg!(feature = "dev-usb-disc") {
            "Logged in. Insert disc USB with ANODIZE_DISC_ID (separate from profile USB)."
        } else {
            "Logged in. Insert write-once disc (BD-R, DVD-R, CD-R, or M-Disc) and press [1]."
        });
    }

    // ── Mode 2: Load CSR ───────────────────────────────────────────────────────

    fn do_load_csr(&mut self) {
        let csr_path = self.usb_mountpoint.join("csr.der");
        let csr_bytes = match std::fs::read(&csr_path) {
            Ok(b) => b,
            Err(e) => {
                self.set_status(format!("Cannot read csr.der from USB: {e}"));
                self.current_op = None;
                return;
            }
        };

        // Validate it's parseable as a CSR; extract subject for operator review
        let csr_subject = match x509_cert::request::CertReq::from_der(&csr_bytes) {
            Ok(csr) => csr.info.subject.to_string(),
            Err(e) => {
                self.set_status(format!("csr.der is not a valid DER-encoded CSR: {e}"));
                self.current_op = None;
                return;
            }
        };
        self.csr_subject_display = Some(csr_subject);

        let profiles_len = self
            .profile
            .as_ref()
            .map(|p| p.cert_profiles.len())
            .unwrap_or(0);
        if profiles_len == 0 {
            self.set_status("No [[cert_profiles]] defined in profile.toml. Add at least one profile.");
            self.current_op = None;
            return;
        }

        self.csr_der = Some(csr_bytes);
        self.state = AppState::LoadCsr;
        self.set_status(format!("CSR loaded. Select profile [1]–[{profiles_len}]."));
    }

    // ── Mode 3: Add revocation entry ──────────────────────────────────────────

    fn do_add_revocation_entry(&mut self) {
        let serial: u64 = match self.revoke_serial_buf.parse() {
            Ok(n) => n,
            Err(_) => {
                self.set_status(format!(
                    "Invalid serial number: {:?}. Must be a u64.",
                    self.revoke_serial_buf
                ));
                return;
            }
        };

        if self.revocation_list.iter().any(|e| e.serial == serial) {
            self.set_status(format!("Serial {serial} is already in the revocation list — duplicate not added."));
            return;
        }

        let reason = if self.revoke_reason_buf.is_empty() {
            None
        } else {
            Some(self.revoke_reason_buf.clone())
        };

        // Use current time formatted as RFC 3339
        let rev_time = {
            use time::OffsetDateTime;
            let odt = OffsetDateTime::now_utc();
            format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                odt.year(),
                odt.month() as u8,
                odt.day(),
                odt.hour(),
                odt.minute(),
                odt.second()
            )
        };

        self.revocation_list.push(RevocationEntry {
            serial,
            revocation_time: rev_time,
            reason,
        });

        // Determine CRL number
        if self.crl_number.is_none() {
            self.crl_number = Some(next_crl_number_from_sessions(&self.prior_sessions));
        }

        self.state = AppState::RevokePreview;
        self.set_status("Review revocation. [1] to commit to disc, [q] to cancel.");
    }

    // ── Modes 3+4: Load revocation list from disc ─────────────────────────────

    fn do_load_revocation(&mut self) {
        // Load root cert DER from disc (needed for signing)
        self.root_cert_der = load_root_cert_der_from_sessions(&self.prior_sessions);
        if self.root_cert_der.is_none() {
            self.set_status("No ROOT.CRT found on disc. Generate root CA first.");
            self.current_op = None;
            return;
        }

        // Load revocation list from disc (may be empty if no revocations yet)
        self.revocation_list = load_revocation_from_sessions(&self.prior_sessions);

        // Determine next CRL number
        self.crl_number = Some(next_crl_number_from_sessions(&self.prior_sessions));

        match self.current_op {
            Some(Operation::RevokeCert) => {
                self.state = AppState::RevokeInput;
            }
            Some(Operation::IssueCrl) => {
                self.state = AppState::CrlPreview;
            }
            _ => {}
        }
    }

    // ── Mode 5: Migrate confirm ───────────────────────────────────────────────

    fn do_migrate_confirm(&mut self) {
        // RAM check: sum all file data in prior_sessions
        let total_bytes: u64 = self
            .prior_sessions
            .iter()
            .flat_map(|s| s.files.iter())
            .map(|f| f.data.len() as u64)
            .sum();
        self.migrate_total_bytes = total_bytes;

        const RAM_WARN_THRESHOLD: u64 = 512 * 1024 * 1024; // 512 MiB
        if total_bytes > RAM_WARN_THRESHOLD {
            self.set_status(format!(
                "WARNING: disc data ({} MiB) exceeds 512 MiB RAM threshold. \
                 Proceed only if you have sufficient free memory.",
                total_bytes / (1024 * 1024)
            ));
        }

        // Verify hash chain across all sessions
        self.migrate_chain_ok = verify_audit_chain(&self.prior_sessions);

        self.state = AppState::MigrateConfirm;
        let chain_status = if self.migrate_chain_ok { "OK" } else { "FAIL" };
        self.set_status(format!(
            "Chain: {chain_status}  {} session(s)  {} bytes. \
             [1] to proceed, [q] to abort.",
            self.prior_sessions.len(),
            total_bytes
        ));
    }

    // ── Key operations (Mode 1) ────────────────────────────────────────────────

    fn do_generate_and_build(&mut self) {
        let label = match &self.profile {
            Some(p) => p.hsm.key_label.clone(),
            None => {
                self.set_status("No profile");
                return;
            }
        };
        let key = {
            let actor = match self.actor.as_mut() {
                Some(a) => a,
                None => {
                    self.set_status("No HSM session");
                    return;
                }
            };
            match actor.generate_keypair(&label, KeySpec::EcdsaP384) {
                Ok(k) => k,
                Err(e) => {
                    self.set_status(format!("Key generation failed: {e}"));
                    return;
                }
            }
        };
        self.root_key = Some(key);
        self.set_status(format!("Generated P-384 keypair (label={label:?})"));
        self.do_build_cert();
    }

    fn do_find_and_build(&mut self) {
        let label = match &self.profile {
            Some(p) => p.hsm.key_label.clone(),
            None => {
                self.set_status("No profile");
                return;
            }
        };
        let key = {
            let actor = match self.actor.as_ref() {
                Some(a) => a,
                None => {
                    self.set_status("No HSM session");
                    return;
                }
            };
            match actor.find_key(&label) {
                Ok(k) => k,
                Err(e) => {
                    self.set_status(format!("Key not found: {e}"));
                    return;
                }
            }
        };
        self.root_key = Some(key);
        self.set_status(format!("Found existing key (label={label:?})"));
        self.do_build_cert();
    }

    fn do_build_cert(&mut self) {
        if let Some(ct) = self.confirmed_time {
            if !clock_drift_ok(ct) {
                self.set_status("Clock drift > 5 min since ClockCheck — restart ceremony to re-confirm clock.");
                return;
            }
        }
        let actor = match self.actor.clone() {
            Some(a) => a,
            None => {
                self.set_status("No HSM session");
                return;
            }
        };
        let key = match self.root_key {
            Some(k) => k,
            None => {
                self.set_status("No key handle");
                return;
            }
        };
        let signer = match P384HsmSigner::new(actor, key) {
            Ok(s) => s,
            Err(e) => {
                self.set_status(format!("Signer error: {e}"));
                return;
            }
        };
        let ca = match &self.profile {
            Some(p) => &p.ca,
            None => {
                self.set_status("No profile");
                return;
            }
        };
        let cert = match build_root_cert(
            &signer,
            &ca.common_name,
            &ca.organization,
            &ca.country,
            7305,
        ) {
            Ok(c) => c,
            Err(e) => {
                self.set_status(mechanism_error_msg("Cert build failed", &e));
                return;
            }
        };
        let cert_der = match cert.to_der() {
            Ok(d) => d,
            Err(e) => {
                self.set_status(format!("DER encode failed: {e}"));
                return;
            }
        };

        // Issue initial CRL (#1, empty) alongside root cert
        let base_time = self.confirmed_time.unwrap_or_else(SystemTime::now);
        let next_update = base_time + std::time::Duration::from_secs(365 * 24 * 3600);
        let crl_der = match issue_crl(&signer, &cert, &[], next_update, 1) {
            Ok(d) => d,
            Err(e) => {
                self.set_status(mechanism_error_msg("Initial CRL build failed", &e));
                return;
            }
        };

        let fp = sha256_fingerprint(&cert_der);
        self.fingerprint = Some(fp);
        self.cert_der = Some(cert_der);
        self.crl_der = Some(crl_der);
        self.state = AppState::CertPreview;
        self.set_status("Certificate built. Verify fingerprint before writing.");
    }

    // ── Mode 2: Sign CSR ──────────────────────────────────────────────────────

    fn do_sign_csr(&mut self) {
        if let Some(ct) = self.confirmed_time {
            if !clock_drift_ok(ct) {
                self.set_status("Clock drift > 5 min since ClockCheck — restart ceremony to re-confirm clock.");
                return;
            }
        }
        let label = match self.profile.as_ref().map(|p| p.hsm.key_label.clone()) {
            Some(l) => l,
            None => {
                self.set_status("No profile");
                return;
            }
        };
        let actor = match self.actor.clone() {
            Some(a) => a,
            None => {
                self.set_status("No HSM session");
                return;
            }
        };
        let root_key = match actor.find_key(&label) {
            Ok(k) => k,
            Err(e) => {
                self.set_status(format!("Root key not found: {e}"));
                return;
            }
        };
        let signer = match P384HsmSigner::new(actor, root_key) {
            Ok(s) => s,
            Err(e) => {
                self.set_status(format!("Signer error: {e}"));
                return;
            }
        };

        let root_cert_der = match &self.root_cert_der {
            Some(d) => d.clone(),
            None => {
                self.set_status("Root cert not loaded from disc");
                return;
            }
        };
        let root_cert = match Certificate::from_der(&root_cert_der) {
            Ok(c) => c,
            Err(e) => {
                self.set_status(format!("Root cert DER decode failed: {e}"));
                return;
            }
        };

        let csr_der = match self.csr_der.as_ref() {
            Some(d) => d.clone(),
            None => {
                self.set_status("No CSR loaded");
                return;
            }
        };

        let (validity_days, path_len) = match self
            .profile
            .as_ref()
            .and_then(|p| self.selected_profile_idx.map(|i| &p.cert_profiles[i]))
        {
            Some(prof) => (prof.validity_days, prof.path_len),
            None => {
                self.set_status("No cert profile selected");
                return;
            }
        };

        let cdp_url = self.profile.as_ref().and_then(|p| p.ca.cdp_url.as_deref());

        let cert = match sign_intermediate_csr(
            &signer,
            &root_cert,
            &csr_der,
            path_len,
            validity_days,
            cdp_url,
        ) {
            Ok(c) => c,
            Err(CaError::CsrSignatureInvalid) => {
                self.set_status("CSR signature verification failed — CSR may be corrupt");
                return;
            }
            Err(CaError::CsrExtensionRejected(oid)) => {
                self.set_status(format!("CSR contains rejected extension OID: {oid}"));
                return;
            }
            Err(e) => {
                self.set_status(mechanism_error_msg("CSR signing failed", &e));
                return;
            }
        };

        let cert_der = match cert.to_der() {
            Ok(d) => d,
            Err(e) => {
                self.set_status(format!("DER encode failed: {e}"));
                return;
            }
        };

        let fp = sha256_fingerprint(&cert_der);
        self.fingerprint = Some(fp);
        self.cert_der = Some(cert_der);
        self.state = AppState::CertPreview;
        self.set_status("Intermediate cert signed. Verify fingerprint before writing.");
    }

    // ── Mode 3: Sign CRL for revocation ──────────────────────────────────────

    fn do_sign_crl_for_revoke(&mut self) {
        self.do_sign_crl_inner();
    }

    // ── Mode 4: Sign CRL refresh ──────────────────────────────────────────────

    fn do_sign_crl_refresh(&mut self) {
        self.do_sign_crl_inner();
    }

    fn do_sign_crl_inner(&mut self) {
        if let Some(ct) = self.confirmed_time {
            if !clock_drift_ok(ct) {
                self.set_status("Clock drift > 5 min since ClockCheck — restart ceremony to re-confirm clock.");
                return;
            }
        }
        let label = match self.profile.as_ref().map(|p| p.hsm.key_label.clone()) {
            Some(l) => l,
            None => {
                self.set_status("No profile");
                return;
            }
        };
        let actor = match self.actor.clone() {
            Some(a) => a,
            None => {
                self.set_status("No HSM session");
                return;
            }
        };
        let root_key = match actor.find_key(&label) {
            Ok(k) => k,
            Err(e) => {
                self.set_status(format!("Root key not found: {e}"));
                return;
            }
        };
        let signer = match P384HsmSigner::new(actor, root_key) {
            Ok(s) => s,
            Err(e) => {
                self.set_status(format!("Signer error: {e}"));
                return;
            }
        };

        let root_cert_der = match &self.root_cert_der {
            Some(d) => d.clone(),
            None => {
                self.set_status("Root cert not on disc");
                return;
            }
        };
        let root_cert = match Certificate::from_der(&root_cert_der) {
            Ok(c) => c,
            Err(e) => {
                self.set_status(format!("Root cert DER decode: {e}"));
                return;
            }
        };

        let crl_number = match self.crl_number {
            Some(n) => n,
            None => {
                self.set_status("CRL number not determined");
                return;
            }
        };

        // Convert RevocationEntry list to (serial, SystemTime, reason) triples
        let revoked: Vec<(u64, SystemTime, Option<anodize_ca::CrlReason>)> = self
            .revocation_list
            .iter()
            .map(|e| {
                let t = parse_rfc3339_to_system_time(&e.revocation_time)
                    .unwrap_or_else(SystemTime::now);
                let reason = e
                    .reason
                    .as_deref()
                    .map(anodize_ca::reason_str_to_crl_reason);
                (e.serial, t, reason)
            })
            .collect();

        let base_time = self.confirmed_time.unwrap_or_else(SystemTime::now);
        let next_update = base_time + std::time::Duration::from_secs(365 * 24 * 3600);

        let crl_der = match issue_crl(&signer, &root_cert, &revoked, next_update, crl_number) {
            Ok(d) => d,
            Err(e) => {
                self.set_status(mechanism_error_msg("CRL signing failed", &e));
                return;
            }
        };

        self.crl_der = Some(crl_der);
        self.do_start_burn();
    }

    // ── WAL intent write ───────────────────────────────────────────────────────

    fn do_write_intent(&mut self) {
        // For Mode 2+, load root cert from disc before intent write
        if matches!(
            self.current_op,
            Some(Operation::SignCsr) | Some(Operation::RevokeCert) | Some(Operation::IssueCrl)
        ) && self.root_cert_der.is_none()
        {
            self.root_cert_der = load_root_cert_der_from_sessions(&self.prior_sessions);
            if self.root_cert_der.is_none() {
                self.set_status("No ROOT.CRT found on disc. Generate root CA first.");
                return;
            }
        }

        let raw_bytes = match self.profile_toml_bytes.clone() {
            Some(b) => b,
            None => {
                self.set_status("Profile bytes missing");
                return;
            }
        };

        #[cfg(not(feature = "dev-usb-disc"))]
        if !self.skip_disc && self.sessions_remaining.map(|r| r < 2).unwrap_or(false) {
            self.set_status("Disc full — cannot write intent session. Insert new disc.");
            return;
        }

        let ts = self.confirmed_time.unwrap_or_else(SystemTime::now);
        let dir_name = media::session_dir_name(ts) + "-intent";

        #[cfg(not(feature = "dev-usb-disc"))]
        let staging = PathBuf::from("/run/anodize/staging");
        #[cfg(feature = "dev-usb-disc")]
        let staging = PathBuf::from("/tmp/anodize-staging");
        if let Err(e) = std::fs::create_dir_all(&staging) {
            self.set_status(format!("Cannot create staging dir: {e}"));
            return;
        }
        let log_path = staging.join("audit.log");
        let genesis = genesis_hash(&raw_bytes);
        let genesis_hex: String = genesis.iter().map(|b| format!("{b:02x}")).collect();
        let mut log = match AuditLog::create(&log_path, &genesis) {
            Ok(l) => l,
            Err(e) => {
                self.set_status(format!("Audit log create failed: {e}"));
                return;
            }
        };

        let intent_event = self.build_intent_audit_event(&genesis_hex);
        let (event_name, event_data) = match intent_event {
            Some(e) => e,
            None => return, // error already set in status
        };

        if let Err(e) = log.append(&event_name, event_data) {
            self.set_status(format!("Audit intent append failed: {e}"));
            return;
        }
        drop(log);

        let partial_log_bytes = match std::fs::read(&log_path) {
            Ok(b) => b,
            Err(e) => {
                self.set_status(format!("Cannot read intent audit log: {e}"));
                return;
            }
        };

        let intent_session = SessionEntry {
            dir_name: dir_name.clone(),
            timestamp: ts,
            files: vec![IsoFile {
                name: "AUDIT.LOG".into(),
                data: partial_log_bytes,
            }],
        };
        let mut all_sessions = self.prior_sessions.clone();
        all_sessions.push(intent_session.clone());

        let (tx, rx) = mpsc::channel();
        self.burn_rx = Some(rx);
        self.pending_intent_session = Some(intent_session);

        #[cfg(feature = "dev-usb-disc")]
        {
            let disc = match self.disc_usb.clone() {
                Some(d) => d,
                None => {
                    self.set_status("No disc USB — cannot write intent");
                    self.burn_rx = None;
                    self.pending_intent_session = None;
                    return;
                }
            };
            let iso = media::iso9660::build_iso(&all_sessions);
            std::thread::spawn(move || {
                tx.send(media::usb_disc::write_iso_to_disc_usb(&disc, &iso))
                    .ok();
            });
        }

        #[cfg(not(feature = "dev-usb-disc"))]
        {
            if self.skip_disc {
                let iso = media::iso9660::build_iso(&all_sessions);
                let iso_path = staging.join("ceremony.iso");
                match std::fs::write(&iso_path, &iso) {
                    Ok(()) => {
                        tx.send(Ok(())).ok();
                    }
                    Err(e) => {
                        tx.send(Err(anyhow::anyhow!("write intent ISO: {e}"))).ok();
                    }
                }
            } else if let Some(dev) = self.optical_dev.clone() {
                media::write_session(&dev, all_sessions, false, tx);
            } else {
                self.set_status("No optical device — cannot write intent");
                self.burn_rx = None;
                self.pending_intent_session = None;
                return;
            }
        }

        self.state = AppState::WritingIntent;
        self.set_status("Writing intent to disc. Operation will follow…");
    }

    /// Build the intent audit event (name, data) for the current operation.
    fn build_intent_audit_event(&self, genesis_hex: &str) -> Option<(String, serde_json::Value)> {
        match &self.current_op {
            Some(Operation::GenerateRootCa) => {
                let (cn, org, country) = self
                    .profile
                    .as_ref()
                    .map(|p| {
                        (
                            p.ca.common_name.clone(),
                            p.ca.organization.clone(),
                            p.ca.country.clone(),
                        )
                    })
                    .unwrap_or_default();
                let action_str = match self.pending_key_action {
                    Some(1) => "generate",
                    Some(2) => "find-existing",
                    _ => "unknown",
                };
                Some((
                    "cert.root.intent".into(),
                    serde_json::json!({
                        "operation": "sign-root-cert",
                        "key_action": action_str,
                        "cert_params": {
                            "subject": {
                                "common_name": cn,
                                "organization": org,
                                "country": country,
                            },
                            "validity_days": 7305,
                            "key_algorithm": "ecdsa-p384",
                        },
                        "profile_toml_sha256": genesis_hex,
                    }),
                ))
            }
            Some(Operation::SignCsr) => {
                let csr_hex = self
                    .csr_der
                    .as_ref()
                    .map(|b| {
                        b.iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<String>()
                    })
                    .unwrap_or_default();
                let profile_name = self
                    .profile
                    .as_ref()
                    .and_then(|p| {
                        self.selected_profile_idx
                            .map(|i| p.cert_profiles[i].name.clone())
                    })
                    .unwrap_or_default();
                Some((
                    "cert.csr.intent".into(),
                    serde_json::json!({
                        "operation": "sign-csr",
                        "csr_der_hex": csr_hex,
                        "profile_name": profile_name,
                    }),
                ))
            }
            Some(Operation::RevokeCert) => {
                let serial: u64 = self.revoke_serial_buf.parse().unwrap_or(0);
                let reason = if self.revoke_reason_buf.is_empty() {
                    serde_json::Value::Null
                } else {
                    serde_json::Value::String(self.revoke_reason_buf.clone())
                };
                Some((
                    "cert.revoke.intent".into(),
                    serde_json::json!({
                        "operation": "revoke-and-issue-crl",
                        "serial": serial,
                        "reason": reason,
                        "crl_number": self.crl_number.unwrap_or(0),
                        "revocation_count": self.revocation_list.len(),
                    }),
                ))
            }
            Some(Operation::IssueCrl) => Some((
                "crl.intent".into(),
                serde_json::json!({
                    "operation": "issue-crl",
                    "crl_number": self.crl_number.unwrap_or(0),
                    "revocation_count": self.revocation_list.len(),
                }),
            )),
            _ => None,
        }
    }

    // ── Disc burn ──────────────────────────────────────────────────────────────

    fn do_start_burn(&mut self) {
        #[cfg(not(feature = "dev-usb-disc"))]
        let staging = PathBuf::from("/run/anodize/staging");
        #[cfg(feature = "dev-usb-disc")]
        let staging = PathBuf::from("/tmp/anodize-staging");

        // Build session based on current operation
        let new_session = match self.build_burn_session(&staging) {
            Some(s) => s,
            None => return, // error already in status
        };

        let all_sessions = if self.current_op == Some(Operation::MigrateDisc) {
            // Migration: write stored sessions verbatim (no new session)
            self.migrate_sessions.clone()
        } else {
            let mut sessions = self.prior_sessions.clone();
            sessions.push(new_session);
            sessions
        };

        let (tx, rx) = mpsc::channel();
        self.burn_rx = Some(rx);

        #[cfg(feature = "dev-usb-disc")]
        {
            let disc = match self.disc_usb.clone() {
                Some(d) => d,
                None => {
                    self.set_status("No disc USB — cannot write");
                    self.burn_rx = None;
                    return;
                }
            };
            let iso = media::iso9660::build_iso(&all_sessions);
            std::thread::spawn(move || {
                tx.send(media::usb_disc::write_iso_to_disc_usb(&disc, &iso))
                    .ok();
            });
            self.state = AppState::BurningDisc;
            self.set_status("Writing ISO to disc USB…");
        }

        #[cfg(not(feature = "dev-usb-disc"))]
        {
            if self.skip_disc {
                let iso = media::iso9660::build_iso(&all_sessions);
                let iso_path = staging.join("ceremony.iso");
                match std::fs::write(&iso_path, &iso) {
                    Ok(()) => {
                        tx.send(Ok(())).ok();
                    }
                    Err(e) => {
                        tx.send(Err(anyhow::anyhow!("write staging ISO: {e}"))).ok();
                    }
                }
            } else if let Some(dev) = &self.optical_dev {
                media::write_session(dev, all_sessions, false, tx);
            } else {
                self.set_status("No optical device — cannot burn");
                self.burn_rx = None;
                return;
            }

            self.state = AppState::BurningDisc;
            self.set_status("Burning disc session… (this may take a few minutes)");
        }
    }

    /// Build the SessionEntry for the current operation's disc burn.
    fn build_burn_session(&mut self, staging: &std::path::Path) -> Option<SessionEntry> {
        let ts = self.confirmed_time.unwrap_or_else(SystemTime::now);
        let dir_name = media::session_dir_name(ts);

        match self.current_op.clone() {
            Some(Operation::GenerateRootCa) => {
                let cert_der = self.cert_der.clone()?;
                let crl_der = self.crl_der.clone()?;

                // Append cert.root.issue + crl.issue to audit log
                let log_path = staging.join("audit.log");
                let mut log = match AuditLog::open(&log_path) {
                    Ok(l) => l,
                    Err(e) => {
                        self.set_status(format!("Audit log reopen failed: {e}"));
                        return None;
                    }
                };
                let fp = self.fingerprint.clone().unwrap_or_default();
                let ca_name = self
                    .profile
                    .as_ref()
                    .map(|p| p.ca.common_name.clone())
                    .unwrap_or_default();
                if let Err(e) = log.append(
                    "cert.root.issue",
                    serde_json::json!({
                        "subject": ca_name,
                        "fingerprint": fp,
                        "intent_session": self.intent_session_dir_name.as_deref().unwrap_or(""),
                    }),
                ) {
                    self.set_status(format!("Audit log append failed: {e}"));
                    return None;
                }
                if let Err(e) = log.append(
                    "crl.issue",
                    serde_json::json!({
                        "crl_number": 1,
                        "revocation_count": 0,
                        "intent_session": self.intent_session_dir_name.as_deref().unwrap_or(""),
                    }),
                ) {
                    self.set_status(format!("CRL audit append failed: {e}"));
                    return None;
                }
                drop(log);

                let audit_bytes = match std::fs::read(&log_path) {
                    Ok(b) => b,
                    Err(e) => {
                        self.set_status(format!("Cannot read audit log: {e}"));
                        return None;
                    }
                };

                Some(SessionEntry {
                    dir_name,
                    timestamp: ts,
                    files: vec![
                        IsoFile {
                            name: "ROOT.CRT".into(),
                            data: cert_der,
                        },
                        IsoFile {
                            name: "ROOT.CRL".into(),
                            data: crl_der,
                        },
                        IsoFile {
                            name: "AUDIT.LOG".into(),
                            data: audit_bytes,
                        },
                    ],
                })
            }

            Some(Operation::SignCsr) => {
                let cert_der = self.cert_der.clone()?;

                let log_path = staging.join("audit.log");
                let mut log = match AuditLog::open(&log_path) {
                    Ok(l) => l,
                    Err(e) => {
                        self.set_status(format!("Audit log reopen failed: {e}"));
                        return None;
                    }
                };
                let fp = self.fingerprint.clone().unwrap_or_default();
                let profile_name = self
                    .profile
                    .as_ref()
                    .and_then(|p| {
                        self.selected_profile_idx
                            .map(|i| p.cert_profiles[i].name.clone())
                    })
                    .unwrap_or_default();
                if let Err(e) = log.append(
                    "cert.intermediate.issue",
                    serde_json::json!({
                        "fingerprint": fp,
                        "profile": profile_name,
                        "intent_session": self.intent_session_dir_name.as_deref().unwrap_or(""),
                    }),
                ) {
                    self.set_status(format!("Audit log append failed: {e}"));
                    return None;
                }
                drop(log);

                let audit_bytes = match std::fs::read(&log_path) {
                    Ok(b) => b,
                    Err(e) => {
                        self.set_status(format!("Cannot read audit log: {e}"));
                        return None;
                    }
                };

                Some(SessionEntry {
                    dir_name,
                    timestamp: ts,
                    files: vec![
                        IsoFile {
                            name: "INTERMEDIATE.CRT".into(),
                            data: cert_der,
                        },
                        IsoFile {
                            name: "AUDIT.LOG".into(),
                            data: audit_bytes,
                        },
                    ],
                })
            }

            Some(Operation::RevokeCert) => {
                let crl_der = self.crl_der.clone()?;
                let revoked_toml = serialize_revocation_list(&self.revocation_list).into_bytes();
                let crl_number = self.crl_number.unwrap_or(0);

                let log_path = staging.join("audit.log");
                let mut log = match AuditLog::open(&log_path) {
                    Ok(l) => l,
                    Err(e) => {
                        self.set_status(format!("Audit log reopen failed: {e}"));
                        return None;
                    }
                };
                let serial: u64 = self.revoke_serial_buf.parse().unwrap_or(0);
                let reason = if self.revoke_reason_buf.is_empty() {
                    serde_json::Value::Null
                } else {
                    serde_json::Value::String(self.revoke_reason_buf.clone())
                };
                if let Err(e) = log.append(
                    "cert.revoke",
                    serde_json::json!({
                        "serial": serial,
                        "reason": reason,
                        "intent_session": self.intent_session_dir_name.as_deref().unwrap_or(""),
                    }),
                ) {
                    self.set_status(format!("Audit log append failed: {e}"));
                    return None;
                }
                if let Err(e) = log.append(
                    "crl.issue",
                    serde_json::json!({
                        "crl_number": crl_number,
                        "revocation_count": self.revocation_list.len(),
                        "intent_session": self.intent_session_dir_name.as_deref().unwrap_or(""),
                    }),
                ) {
                    self.set_status(format!("CRL audit append failed: {e}"));
                    return None;
                }
                drop(log);

                let audit_bytes = match std::fs::read(&log_path) {
                    Ok(b) => b,
                    Err(e) => {
                        self.set_status(format!("Cannot read audit log: {e}"));
                        return None;
                    }
                };

                Some(SessionEntry {
                    dir_name,
                    timestamp: ts,
                    files: vec![
                        IsoFile {
                            name: "REVOKED.TOML".into(),
                            data: revoked_toml,
                        },
                        IsoFile {
                            name: "ROOT.CRL".into(),
                            data: crl_der,
                        },
                        IsoFile {
                            name: "AUDIT.LOG".into(),
                            data: audit_bytes,
                        },
                    ],
                })
            }

            Some(Operation::IssueCrl) => {
                let crl_der = self.crl_der.clone()?;
                let crl_number = self.crl_number.unwrap_or(0);

                let log_path = staging.join("audit.log");
                let mut log = match AuditLog::open(&log_path) {
                    Ok(l) => l,
                    Err(e) => {
                        self.set_status(format!("Audit log reopen failed: {e}"));
                        return None;
                    }
                };
                if let Err(e) = log.append(
                    "crl.issue",
                    serde_json::json!({
                        "crl_number": crl_number,
                        "revocation_count": self.revocation_list.len(),
                        "intent_session": self.intent_session_dir_name.as_deref().unwrap_or(""),
                    }),
                ) {
                    self.set_status(format!("Audit log append failed: {e}"));
                    return None;
                }
                drop(log);

                let audit_bytes = match std::fs::read(&log_path) {
                    Ok(b) => b,
                    Err(e) => {
                        self.set_status(format!("Cannot read audit log: {e}"));
                        return None;
                    }
                };

                Some(SessionEntry {
                    dir_name,
                    timestamp: ts,
                    files: vec![
                        IsoFile {
                            name: "ROOT.CRL".into(),
                            data: crl_der,
                        },
                        IsoFile {
                            name: "AUDIT.LOG".into(),
                            data: audit_bytes,
                        },
                    ],
                })
            }

            Some(Operation::MigrateDisc) => {
                // Migration doesn't add a new session; all_sessions = migrate_sessions
                // Return a dummy session that won't be used
                Some(SessionEntry {
                    dir_name,
                    timestamp: ts,
                    files: vec![],
                })
            }

            None => {
                self.set_status("No operation set");
                None
            }
        }
    }

    // ── USB write ──────────────────────────────────────────────────────────────

    fn do_write_usb(&mut self) {
        assert_eq!(
            self.state,
            AppState::DiscDone,
            "USB write reached without disc write"
        );

        let usb = self.usb_mountpoint.clone();

        #[cfg(not(feature = "dev-usb-disc"))]
        let staging_log = PathBuf::from("/run/anodize/staging/audit.log");
        #[cfg(feature = "dev-usb-disc")]
        let staging_log = PathBuf::from("/tmp/anodize-staging/audit.log");

        match self.current_op.clone() {
            Some(Operation::GenerateRootCa) => {
                if let Some(cert_der) = &self.cert_der {
                    if let Err(e) = std::fs::write(usb.join("root.crt"), cert_der) {
                        self.set_status(format!("USB write failed (root.crt): {e}"));
                        return;
                    }
                }
                if let Some(crl_der) = &self.crl_der {
                    if let Err(e) = std::fs::write(usb.join("root.crl"), crl_der) {
                        self.set_status(format!("USB write failed (root.crl): {e}"));
                        return;
                    }
                }
            }
            Some(Operation::SignCsr) => {
                if let Some(cert_der) = &self.cert_der {
                    if let Err(e) = std::fs::write(usb.join("intermediate.crt"), cert_der) {
                        self.set_status(format!("USB write failed (intermediate.crt): {e}"));
                        return;
                    }
                }
            }
            Some(Operation::RevokeCert) => {
                let revoked_toml = serialize_revocation_list(&self.revocation_list);
                if let Err(e) = std::fs::write(usb.join("revoked.toml"), &revoked_toml) {
                    self.set_status(format!("USB write failed (revoked.toml): {e}"));
                    return;
                }
                if let Some(crl_der) = &self.crl_der {
                    if let Err(e) = std::fs::write(usb.join("root.crl"), crl_der) {
                        self.set_status(format!("USB write failed (root.crl): {e}"));
                        return;
                    }
                }
            }
            Some(Operation::IssueCrl) => {
                if let Some(crl_der) = &self.crl_der {
                    if let Err(e) = std::fs::write(usb.join("root.crl"), crl_der) {
                        self.set_status(format!("USB write failed (root.crl): {e}"));
                        return;
                    }
                }
            }
            Some(Operation::MigrateDisc) | None => {
                // No USB export for migration
                self.state = AppState::Done;
                self.set_status("Migration complete.");
                return;
            }
        }

        // Copy audit log to USB for all non-migration operations
        let usb_log = usb.join("audit.log");
        if let Err(e) = std::fs::copy(&staging_log, &usb_log) {
            self.set_status(format!("Audit log copy to USB failed: {e}"));
            return;
        }

        self.state = AppState::Done;
        self.set_status(format!("USB write complete: {}", usb.display()));
    }
}

// ── Noise PIN masking ─────────────────────────────────────────────────────────

fn noise_display_len() -> usize {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as usize;
    8 + (nanos % 13)
}

// ── Error helpers ─────────────────────────────────────────────────────────────

fn mechanism_error_msg(prefix: &str, e: &CaError) -> String {
    if e.is_mechanism_unsupported() {
        "HSM does not support CKM_ECDSA_SHA384. \
         Ubuntu SoftHSM2 is built without it — use 'make qemu-dev-curses' \
         (Nix SoftHSM2) or a YubiHSM 2."
            .to_string()
    } else {
        format!("{prefix}: {e}")
    }
}

// ── Fingerprint ───────────────────────────────────────────────────────────────

fn sha256_fingerprint(der: &[u8]) -> String {
    let hash = Sha256::digest(der);
    hash.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .chunks(2)
        .map(|c| c.join(""))
        .collect::<Vec<_>>()
        .join(":")
}

// ── Disc session helpers ──────────────────────────────────────────────────────

/// Load ROOT.CRT DER bytes from the first session on disc that contains it.
fn load_root_cert_der_from_sessions(sessions: &[SessionEntry]) -> Option<Vec<u8>> {
    sessions.iter().find_map(|s| {
        s.files
            .iter()
            .find(|f| f.name == "ROOT.CRT")
            .map(|f| f.data.clone())
    })
}

/// Load the most recent REVOKED.TOML from disc sessions.
fn load_revocation_from_sessions(sessions: &[SessionEntry]) -> Vec<RevocationEntry> {
    for session in sessions.iter().rev() {
        if let Some(file) = session.files.iter().find(|f| f.name == "REVOKED.TOML") {
            if let Ok(entries) = parse_revocation_list(&file.data) {
                return entries;
            }
        }
    }
    Vec::new()
}

/// Determine the next CRL number by scanning audit logs in disc sessions.
/// Returns last issued crl_number + 1, or 2 if no prior CRL issue found
/// (1 is reserved for the initial CRL from root CA generation).
fn next_crl_number_from_sessions(sessions: &[SessionEntry]) -> u64 {
    let mut last = 0u64;
    for session in sessions.iter() {
        if let Some(file) = session.files.iter().find(|f| f.name == "AUDIT.LOG") {
            for line in file.data.split(|&b| b == b'\n') {
                if line.is_empty() {
                    continue;
                }
                if let Ok(record) = serde_json::from_slice::<serde_json::Value>(line) {
                    if record.get("event").and_then(|v| v.as_str()) == Some("crl.issue") {
                        if let Some(n) = record
                            .get("op_data")
                            .and_then(|d| d.get("crl_number"))
                            .and_then(|v| v.as_u64())
                        {
                            if n > last {
                                last = n;
                            }
                        }
                    }
                }
            }
        }
    }
    last + 1
}

/// Verify the audit hash chain within each disc session independently.
///
/// Each session's AUDIT.LOG is an independent chain anchored to
/// SHA-256(profile.toml). We verify internal consistency (each record's
/// prev_hash == prior record's entry_hash) but do not attempt cross-session
/// linkage, because each session starts a fresh chain from the same genesis.
fn verify_audit_chain(sessions: &[SessionEntry]) -> bool {
    for session in sessions.iter() {
        if let Some(file) = session.files.iter().find(|f| f.name == "AUDIT.LOG") {
            let mut prev_hash: Option<String> = None;
            for line in file.data.split(|&b| b == b'\n') {
                if line.is_empty() {
                    continue;
                }
                if let Ok(record) = serde_json::from_slice::<serde_json::Value>(line) {
                    if let Some(ph) = prev_hash.as_deref() {
                        if record.get("prev_hash").and_then(|v| v.as_str()) != Some(ph) {
                            return false;
                        }
                    }
                    prev_hash = record
                        .get("entry_hash")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_owned());
                }
            }
        }
    }
    true
}

/// Parse an RFC 3339 timestamp string to SystemTime. Falls back to UNIX_EPOCH on error.
fn parse_rfc3339_to_system_time(s: &str) -> Option<SystemTime> {
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;
    let odt = OffsetDateTime::parse(s, &Rfc3339).ok()?;
    let unix_secs = odt.unix_timestamp();
    let unix_nanos = odt.unix_timestamp_nanos();
    let nanos = (unix_nanos - (unix_secs as i128) * 1_000_000_000) as u32;
    if unix_secs >= 0 {
        Some(SystemTime::UNIX_EPOCH + std::time::Duration::new(unix_secs as u64, nanos))
    } else {
        None
    }
}

/// Returns true if the wall clock is within 5 minutes of the operator-confirmed time.
/// A larger drift suggests the CMOS clock changed after ClockCheck and certificate
/// timestamps would diverge from what the operator verified.
fn clock_drift_ok(confirmed: SystemTime) -> bool {
    let now = SystemTime::now();
    let drift = if now >= confirmed {
        now.duration_since(confirmed)
    } else {
        confirmed.duration_since(now)
    };
    drift.map(|d| d.as_secs() <= 300).unwrap_or(false)
}

// ── SoftHSM2 USB backend (dev-softhsm-usb feature) ───────────────────────────

#[cfg(feature = "dev-softhsm-usb")]
fn configure_softhsm_from_usb(usb_mountpoint: &std::path::Path) -> Result<()> {
    let token_dir = usb_mountpoint.join("softhsm2/tokens");
    if !token_dir.exists() {
        return Ok(());
    }
    let conf_path = std::path::PathBuf::from("/tmp/anodize-softhsm2.conf");
    let conf = format!(
        "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n",
        token_dir.display()
    );
    std::fs::write(&conf_path, conf)?;
    unsafe { std::env::set_var("SOFTHSM2_CONF", &conf_path) };
    Ok(())
}

// ── Rendering ─────────────────────────────────────────────────────────────────

fn render_log(frame: &mut Frame, app: &App) {
    let content = app.log_lines.join("\n");
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Status Log  [L/Esc] close  [\u{2191}/\u{2193}/PgUp/PgDn] scroll");
    let para = Paragraph::new(content.as_str())
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((app.log_scroll, 0));
    frame.render_widget(para, frame.area());
}

fn render(frame: &mut Frame, app: &App) {
    if app.log_view {
        render_log(frame, app);
        return;
    }

    let area = frame.area();

    // Build header lines dynamically so runtime flags (skip_disc) and
    // compile-time flags (dev features) both contribute warning rows.
    let is_dev = cfg!(any(feature = "dev-usb-disc", feature = "dev-softhsm-usb"));
    let mut header_lines: Vec<Line> = vec![Line::from("ANODIZE ROOT CA CEREMONY")];
    if is_dev {
        header_lines.push(Line::from(Span::styled(
            "*** DEV BUILD — NOT FOR PRODUCTION USE ***",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));
    }
    if app.skip_disc {
        header_lines.push(Line::from(Span::styled(
            "*** --skip-disc ACTIVE: optical disc write will be skipped ***",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )));
    }
    // height = content lines + 2 border lines
    let header_height = header_lines.len() as u16 + 2;
    let border_style = if is_dev || app.skip_disc {
        Style::default().fg(if is_dev { Color::Red } else { Color::Yellow })
    } else {
        Style::default()
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(header_height),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(area);

    {
        let title = Paragraph::new(header_lines)
            .alignment(Alignment::Center)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(border_style),
            );
        frame.render_widget(title, chunks[0]);
    }

    let screen_title = match app.state {
        AppState::ClockCheck => "Clock Verification",
        AppState::WaitUsb => "Waiting for USB",
        AppState::ProfileLoaded => "Profile Loaded",
        AppState::EnterPin => "HSM Authentication",
        AppState::WaitDisc => {
            if cfg!(feature = "dev-usb-disc") {
                "Insert Disc USB"
            } else {
                "Insert Disc"
            }
        }
        AppState::OperationSelect => "Select Operation",
        AppState::KeyAction => "Key Management",
        AppState::WritingIntent => "Committing Intent to Disc\u{2026}",
        AppState::LoadCsr => "Select Certificate Profile",
        AppState::CsrPreview => "CSR Review \u{2014} VERIFY BEFORE SIGNING",
        AppState::CertPreview => "Certificate Preview \u{2014} VERIFY FINGERPRINT",
        AppState::RevokeInput => "Revoke Certificate",
        AppState::RevokePreview => "Revocation Preview \u{2014} VERIFY BEFORE COMMITTING",
        AppState::CrlPreview => "CRL Issuance Preview",
        AppState::BurningDisc => {
            if cfg!(feature = "dev-usb-disc") {
                "Writing Session to Disc USB\u{2026}"
            } else {
                "Writing Session\u{2026}"
            }
        }
        AppState::DiscDone => {
            if cfg!(feature = "dev-usb-disc") {
                "Disc USB Written"
            } else {
                "Disc Session Written"
            }
        }
        AppState::MigrateConfirm => "Disc Migration \u{2014} Verify Chain",
        AppState::WaitMigrateTarget => "Insert Blank Target Disc",
        AppState::Done => "Ceremony Complete",
    };
    let main_block = Block::default().borders(Borders::ALL).title(screen_title);
    let inner = main_block.inner(chunks[1]);
    frame.render_widget(main_block, chunks[1]);
    let body = build_body(app);
    frame.render_widget(Paragraph::new(body).wrap(Wrap { trim: false }), inner);

    let status = Paragraph::new(app.status.as_str())
        .style(Style::default().fg(Color::Yellow))
        .block(Block::default().borders(Borders::ALL).title("Status  [L] log"));
    frame.render_widget(status, chunks[2]);
}

fn build_body(app: &App) -> Text<'static> {
    use time::OffsetDateTime;

    let lines: Vec<String> = match &app.state {
        AppState::ClockCheck => {
            let now = SystemTime::now();
            let odt = OffsetDateTime::from(now);
            vec![
                String::new(),
                format!(
                    "  System clock (UTC):  {:04}-{:02}-{:02}  {:02}:{:02}:{:02}",
                    odt.year(),
                    odt.month() as u8,
                    odt.day(),
                    odt.hour(),
                    odt.minute(),
                    odt.second()
                ),
                String::new(),
                "  Timestamps derived from this value appear permanently in the".into(),
                "  optical disc archive and audit log. Verify against a reference clock.".into(),
                String::new(),
                "  [1]  Time is correct — continue".into(),
                "  [q]  Exit to correct clock, then relaunch".into(),
            ]
        }

        AppState::WaitUsb => vec![
            String::new(),
            "  Insert USB stick containing profile.toml.".into(),
            String::new(),
            "  Scanning automatically…".into(),
        ],

        AppState::ProfileLoaded => {
            let p = app.profile.as_ref().unwrap();
            vec![
                String::new(),
                format!("  CA Subject  : {}", p.ca.common_name),
                format!("  Org         : {}", p.ca.organization),
                format!("  Country     : {}", p.ca.country),
                format!("  HSM token   : {}", p.hsm.token_label),
                format!("  USB mount   : {}", app.usb_mountpoint.display()),
                String::new(),
                "  [1]  Begin ceremony (HSM PIN entry)".into(),
                "  [q]  Quit".into(),
            ]
        }

        AppState::EnterPin => {
            let stars = "*".repeat(app.pin_display_len);
            vec![
                String::new(),
                format!("  PIN: {stars}"),
                String::new(),
                "  Press Enter to log in, Esc to cancel.".into(),
            ]
        }

        AppState::WaitDisc => {
            #[cfg(feature = "dev-usb-disc")]
            let disc_info = match &app.disc_usb {
                Some(disc) => format!(
                    "  Disc USB ready ({})  ({} prior session(s))",
                    disc.uuid,
                    app.prior_sessions.len()
                ),
                None => "  No disc USB found. Insert USB with ANODIZE_DISC_ID.".into(),
            };
            #[cfg(not(feature = "dev-usb-disc"))]
            let disc_info = match &app.optical_dev {
                Some(dev) => {
                    let cap = app
                        .sessions_remaining
                        .map(|r| format!(", {r} sessions remaining"))
                        .unwrap_or_default();
                    format!(
                        "  Disc ready in {}  ({} prior session(s){cap})",
                        dev.display(),
                        app.prior_sessions.len()
                    )
                }
                None => "  No appendable disc detected. Insert write-once disc.".into(),
            };
            vec![
                String::new(),
                disc_info,
                String::new(),
                "  [1]  Confirm disc and select operation".into(),
                "  [q]  Abort".into(),
            ]
        }

        AppState::OperationSelect => {
            let n_sessions = app.prior_sessions.len();
            let disc_label = if n_sessions == 0 {
                "  Blank disc — no prior sessions.".into()
            } else {
                format!("  Disc: {n_sessions} prior session(s).")
            };
            vec![
                String::new(),
                disc_label,
                String::new(),
                "  [1]  Generate new root CA (fresh or resume key)".into(),
                "  [2]  Sign intermediate CSR  (requires csr.der on USB)".into(),
                "  [3]  Revoke a certificate   (adds entry + issues new CRL)".into(),
                "  [4]  Issue CRL refresh      (re-signs current revocation list)".into(),
                "  [5]  Migrate disc           (copy all sessions to new disc)".into(),
                String::new(),
                "  [q]  Quit".into(),
            ]
        }

        AppState::KeyAction => {
            let label = app
                .profile
                .as_ref()
                .map(|p| p.hsm.key_label.as_str())
                .unwrap_or("?");
            vec![
                String::new(),
                format!("  Key label: {label:?}"),
                String::new(),
                "  [1]  Generate new P-384 keypair (fresh ceremony)".into(),
                "  [2]  Use existing key by label  (resume)".into(),
                String::new(),
                "  Selecting either option writes an intent record to disc".into(),
                "  before using the HSM. Do not remove the disc.".into(),
            ]
        }

        AppState::WritingIntent => vec![
            String::new(),
            "  Writing intent session to disc.".into(),
            "  HSM signing will begin after disc commit completes.".into(),
            "  Do not remove the disc or power off.".into(),
        ],

        AppState::LoadCsr => {
            let profiles = app
                .profile
                .as_ref()
                .map(|p| p.cert_profiles.as_slice())
                .unwrap_or(&[]);
            let mut lines = vec![
                String::new(),
                "  CSR loaded from USB (csr.der).".into(),
                String::new(),
                "  Select certificate profile:".into(),
                String::new(),
            ];
            for (i, prof) in profiles.iter().enumerate() {
                let path_str = prof
                    .path_len
                    .map(|n| format!("  path_len={n}"))
                    .unwrap_or_default();
                lines.push(format!(
                    "  [{}]  {}  (validity={} days{})",
                    i + 1,
                    prof.name,
                    prof.validity_days,
                    path_str
                ));
            }
            lines.push(String::new());
            lines.push("  [q]  Cancel".into());
            lines
        }

        AppState::CsrPreview => {
            let subject = app.csr_subject_display.as_deref().unwrap_or("(unknown)");
            let profile_name = app
                .profile
                .as_ref()
                .and_then(|p| {
                    app.selected_profile_idx
                        .map(|i| p.cert_profiles[i].name.as_str())
                })
                .unwrap_or("?");
            vec![
                String::new(),
                format!("  CSR Subject : {subject}"),
                format!("  Profile     : {profile_name}"),
                String::new(),
                "  The CSR DER bytes are recorded in the intent audit log.".into(),
                String::new(),
                "  [1]  Sign CSR and write to disc".into(),
                "  [q]  Cancel".into(),
            ]
        }

        AppState::CertPreview => {
            let fp = app.fingerprint.as_deref().unwrap_or("(none)");
            let ca = app.profile.as_ref().map(|p| &p.ca);
            let (cn, org, country) = ca
                .map(|c| {
                    (
                        c.common_name.as_str(),
                        c.organization.as_str(),
                        c.country.as_str(),
                    )
                })
                .unwrap_or(("?", "?", "?"));
            let has_crl = app.crl_der.is_some();
            let mut lines = vec![
                String::new(),
                format!("  Subject  : CN={cn}, O={org}, C={country}"),
                "  Validity : 7305 days (20 years)".into(),
                String::new(),
                "  SHA-256 Fingerprint:".into(),
                format!("  {fp}"),
            ];
            if has_crl {
                lines.push(String::new());
                lines.push("  Initial CRL #1 (empty) will be included in this session.".into());
            }
            lines.push(String::new());
            lines.push("  Compare this fingerprint against your paper checklist.".into());
            lines.push(String::new());
            lines.push("  [1]  Proceed to disc write".into());
            lines.push("  [q]  Abort".into());
            lines
        }

        AppState::RevokeInput => {
            let phase_hint = if app.revoke_phase == 0 {
                "Enter serial number (digits only):"
            } else {
                "Enter reason (optional, press Enter to skip):"
            };
            vec![
                String::new(),
                format!("  {} revoked cert(s) on record.", app.revocation_list.len()),
                String::new(),
                format!("  {phase_hint}"),
                String::new(),
                format!("  Serial : {}", app.revoke_serial_buf),
                format!("  Reason : {}", app.revoke_reason_buf),
                String::new(),
                "  Enter to confirm each field. Esc (on reason) to go back.".into(),
            ]
        }

        AppState::RevokePreview => {
            let crl_num = app.crl_number.unwrap_or(0);
            let mut lines = vec![
                String::new(),
                format!("  New CRL number: {crl_num}"),
                String::new(),
                "  Updated revocation list:".into(),
                String::new(),
            ];
            for entry in &app.revocation_list {
                let reason = entry.reason.as_deref().unwrap_or("(no reason)");
                lines.push(format!(
                    "    serial={:>20}  time={}  reason={}",
                    entry.serial, entry.revocation_time, reason
                ));
            }
            lines.push(String::new());
            lines.push("  [1]  Sign CRL and write to disc".into());
            lines.push("  [q]  Cancel".into());
            lines
        }

        AppState::CrlPreview => {
            let crl_num = app.crl_number.unwrap_or(0);
            let count = app.revocation_list.len();
            let mut lines = vec![
                String::new(),
                format!("  CRL number      : {crl_num}"),
                format!("  Revoked entries : {count}"),
                String::new(),
            ];
            if count == 0 {
                lines.push("  (No certificates have been revoked.)".into());
            } else {
                for entry in &app.revocation_list {
                    let reason = entry.reason.as_deref().unwrap_or("(no reason)");
                    lines.push(format!(
                        "    serial={:>20}  time={}  reason={}",
                        entry.serial, entry.revocation_time, reason
                    ));
                }
            }
            lines.push(String::new());
            lines.push("  [1]  Sign CRL and write to disc".into());
            lines.push("  [q]  Cancel".into());
            lines
        }

        AppState::BurningDisc => vec![
            String::new(),
            if cfg!(feature = "dev-usb-disc") {
                "  Writing ISO 9660 session to disc USB\u{2026}"
            } else {
                "  Writing ISO 9660 session to optical disc\u{2026}"
            }
            .into(),
            String::new(),
            "  Please wait. Do not remove the disc or USB.".into(),
        ],

        AppState::DiscDone => {
            let op_label = match app.current_op {
                Some(Operation::GenerateRootCa) => "Root CA cert + initial CRL",
                Some(Operation::SignCsr) => "Intermediate certificate",
                Some(Operation::RevokeCert) => "Revocation record + CRL",
                Some(Operation::IssueCrl) => "CRL refresh",
                Some(Operation::MigrateDisc) => "Disc migration",
                None => "Session",
            };
            let fp = app.fingerprint.as_deref().unwrap_or("(none)");
            let mut lines = vec![
                String::new(),
                format!("  {op_label} written to disc successfully."),
            ];
            if app.fingerprint.is_some() {
                lines.push(String::new());
                lines.push(format!("  Fingerprint: {fp}"));
            }
            lines.push(String::new());
            match app.current_op {
                Some(Operation::MigrateDisc) => {
                    lines.push("  [q]  Quit (migration complete; no USB export)".into());
                }
                _ => {
                    lines.push("  [1]  Copy artifacts to USB".into());
                    lines.push("  [q]  Quit without USB copy (disc is the primary record)".into());
                }
            }
            lines
        }

        AppState::MigrateConfirm => {
            let chain_str = if app.migrate_chain_ok {
                "OK \u{2714}"
            } else {
                "FAIL \u{2718}"
            };
            let mb = app.migrate_total_bytes / (1024 * 1024);
            vec![
                String::new(),
                format!("  Sessions  : {}", app.prior_sessions.len()),
                format!("  Audit chain: {chain_str}"),
                format!(
                    "  Total data: {} MiB ({} bytes)",
                    mb, app.migrate_total_bytes
                ),
                String::new(),
                "  Verify chain is OK before proceeding.".into(),
                String::new(),
                "  [1]  Eject old disc, insert blank new disc".into(),
                "  [q]  Abort".into(),
            ]
        }

        AppState::WaitMigrateTarget => {
            let session_count = app.migrate_sessions.len();
            #[cfg(feature = "dev-usb-disc")]
            let disc_info = match &app.disc_usb {
                Some(disc) => format!("  Blank disc USB ready ({}). Press [1].", disc.uuid),
                None => "  Waiting for blank disc USB…".into(),
            };
            #[cfg(not(feature = "dev-usb-disc"))]
            let disc_info = match &app.optical_dev {
                Some(dev) => format!("  Blank disc in {}. Press [1].", dev.display()),
                None => "  Waiting for blank write-once disc…".into(),
            };
            vec![
                String::new(),
                format!("  Ready to copy {session_count} session(s) to new disc."),
                String::new(),
                disc_info,
                String::new(),
                "  [1]  Write all sessions to new disc".into(),
                "  [q]  Abort".into(),
            ]
        }

        AppState::Done => vec![
            String::new(),
            "  Ceremony complete.".into(),
            String::new(),
            match app.current_op {
                Some(Operation::MigrateDisc) => {
                    "  Disc migration finished. Store new disc and archive old disc.".into()
                }
                _ => format!("  USB  : {}  \u{2713}", app.usb_mountpoint.display()),
            },
            String::new(),
            if cfg!(feature = "dev-usb-disc") {
                "  Remove and store both disc USB and profile USB separately."
            } else {
                "  Remove and store both disc and USB separately."
            }
            .into(),
            "  The HSM holds the private key; no key material was written to disk.".into(),
            String::new(),
            "  [q]  Quit".into(),
        ],
    };

    Text::from(lines.join("\n"))
}

// ── Event loop ────────────────────────────────────────────────────────────────

fn run(terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>, app: &mut App) -> Result<()> {
    loop {
        terminal.draw(|f| render(f, app))?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.modifiers.contains(KeyModifiers::CONTROL) {
                    match key.code {
                        KeyCode::Char('c') => break,
                        KeyCode::Char('l') => terminal.clear()?,
                        _ => {}
                    }
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q')
                        if app.state != AppState::EnterPin
                            && app.state != AppState::RevokeInput =>
                    {
                        break;
                    }
                    // Toggle full-screen log view (excluded from text-entry states)
                    KeyCode::Char('l') | KeyCode::Char('L')
                        if app.state != AppState::EnterPin
                            && app.state != AppState::RevokeInput =>
                    {
                        app.log_view = !app.log_view;
                        if app.log_view {
                            app.log_scroll =
                                app.log_lines.len().saturating_sub(1) as u16;
                        }
                    }
                    KeyCode::Esc if app.log_view => {
                        app.log_view = false;
                    }
                    KeyCode::Up if app.log_view => {
                        app.log_scroll = app.log_scroll.saturating_sub(1);
                    }
                    KeyCode::Down if app.log_view => {
                        app.log_scroll = app.log_scroll.saturating_add(1);
                    }
                    KeyCode::PageUp if app.log_view => {
                        app.log_scroll = app.log_scroll.saturating_sub(10);
                    }
                    KeyCode::PageDown if app.log_view => {
                        app.log_scroll = app.log_scroll.saturating_add(10);
                    }
                    other => app.handle_key(other),
                }
            }
        } else {
            app.background_tick();
        }
    }
    Ok(())
}

// ── Dev build serial warning ──────────────────────────────────────────────────

#[cfg(any(feature = "dev-usb-disc", feature = "dev-softhsm-usb"))]
fn warn_dev_serial() {
    use std::io::Write;
    if let Ok(mut tty) = std::fs::OpenOptions::new().write(true).open("/dev/ttyS0") {
        let _ = writeln!(tty);
        let _ = writeln!(tty, "*** ANODIZE DEV BUILD — NOT FOR PRODUCTION USE ***");
        let _ = writeln!(
            tty,
            "*** dev-usb-disc and/or dev-softhsm-usb features enabled  ***"
        );
        let _ = writeln!(tty);
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();

    #[cfg(any(feature = "dev-usb-disc", feature = "dev-softhsm-usb"))]
    warn_dev_serial();

    enable_raw_mode()?;
    execute!(stdout(), EnterAlternateScreen, EnableMouseCapture)?;

    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(cli.usb_mount, cli.skip_disc);
    let result = run(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    let _ = media::unmount(&app.usb_mountpoint);

    result
}
