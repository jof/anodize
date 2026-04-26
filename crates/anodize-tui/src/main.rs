//! Ceremony TUI — disc-before-USB state machine.
//!
//! Key invariants (enforced structurally):
//! - `UsbWrite` is only reachable from `DiscDone`.
//! - `DiscDone` is only set after a successful M-Disc session burn (or --skip-disc).
//! - USB write is therefore impossible without a committed disc write.

mod media;

use std::io::stdout;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::time::SystemTime;

use anodize_audit::{genesis_hash, AuditLog};
use anodize_ca::{build_root_cert, P384HsmSigner};
use anodize_config::{load as load_profile, PinSource, Profile};
use anodize_hsm::{Hsm, HsmActor, KeyHandle, KeySpec, Pkcs11Hsm};
use anyhow::Result;
use clap::Parser;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use der::Encode;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Style},
    text::Text,
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame, Terminal,
};
use secrecy::SecretString;
use sha2::{Digest, Sha256};

use media::{IsoFile, SessionEntry};

#[derive(Parser)]
#[command(name = "anodize-ceremony", about = "Root CA key ceremony")]
struct Cli {
    /// Mount point for USB stick (created if absent).
    #[arg(long, default_value = "/run/anodize/usb")]
    usb_mount: PathBuf,

    /// Skip M-Disc burn; write disc artifacts to /run/anodize/staging instead.
    /// For development and testing only — never use in a real ceremony.
    #[arg(long)]
    skip_disc: bool,
}

/// Ceremony state machine. Transitions are strictly forward (no back-tracking).
#[derive(Debug, Clone, PartialEq)]
enum AppState {
    ClockCheck,    // First: confirm system clock is correct
    WaitUsb,       // Scan for USB containing profile.toml (auto-advance)
    ProfileLoaded, // Profile read; show CA info; [1] to continue
    EnterPin,      // HSM PIN entry
    KeyAction,     // Generate new key or find existing
    CertPreview,   // Show cert + fingerprint; [1] to proceed to disc
    WaitDisc,      // Wait for appendable M-Disc (or staging in skip_disc mode)
    BurningDisc,   // Background burn in progress
    DiscDone,      // Disc written; [1] to write USB; [q] to skip USB
    Done,          // Complete
}

struct App {
    // Clock
    confirmed_time: Option<SystemTime>,

    // USB
    usb_mountpoint: PathBuf,
    profile: Option<Profile>,

    // TUI state
    state: AppState,
    status: String,

    // HSM session
    actor: Option<HsmActor>,
    root_key: Option<KeyHandle>,

    // Cert held in RAM until disc write succeeds
    cert_der: Option<Vec<u8>>,
    fingerprint: Option<String>,

    // PIN input — display length is randomised noise, never reveals actual length
    pin_buf: String,
    pin_display_len: usize,

    // Disc management
    optical_dev: Option<PathBuf>,
    prior_sessions: Vec<SessionEntry>,
    burn_rx: Option<Receiver<Result<()>>>,
    skip_disc: bool,
}

impl App {
    fn new(usb_mountpoint: PathBuf, skip_disc: bool) -> Self {
        Self {
            confirmed_time: None,
            usb_mountpoint,
            profile: None,
            state: AppState::ClockCheck,
            status: String::new(),
            actor: None,
            root_key: None,
            cert_der: None,
            fingerprint: None,
            pin_buf: String::new(),
            pin_display_len: 0,
            optical_dev: None,
            prior_sessions: Vec::new(),
            burn_rx: None,
            skip_disc,
        }
    }

    fn handle_key(&mut self, code: KeyCode) {
        match self.state.clone() {
            AppState::ClockCheck => {
                if code == KeyCode::Char('1') {
                    self.confirmed_time = Some(SystemTime::now());
                    self.state = AppState::WaitUsb;
                    self.status = "Scanning for USB stick with profile.toml…".into();
                }
            }

            AppState::WaitUsb => {} // auto-advance on USB discovery in background_tick

            AppState::ProfileLoaded => {
                if code == KeyCode::Char('1') {
                    self.pin_buf.clear();
                    self.pin_display_len = 0;
                    self.state = AppState::EnterPin;
                    self.status = "Enter HSM PIN and press Enter. Esc to cancel.".into();
                }
            }

            AppState::EnterPin => match code {
                KeyCode::Char(c) => {
                    self.pin_buf.push(c);
                    self.pin_display_len = noise_display_len();
                }
                KeyCode::Backspace => {
                    self.pin_buf.pop();
                    self.pin_display_len =
                        if self.pin_buf.is_empty() { 0 } else { noise_display_len() };
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

            AppState::KeyAction => match code {
                KeyCode::Char('1') => self.do_generate_and_build(),
                KeyCode::Char('2') => self.do_find_and_build(),
                _ => {}
            },

            AppState::CertPreview => {
                if code == KeyCode::Char('1') {
                    self.state = AppState::WaitDisc;
                    self.status = "Insert blank M-Disc into optical drive…".into();
                }
            }

            AppState::WaitDisc => {
                if code == KeyCode::Char('1')
                    && (self.skip_disc || self.optical_dev.is_some())
                {
                    self.do_start_burn();
                }
            }

            AppState::BurningDisc => {} // auto-advance on burn completion

            // USB write is only reachable from DiscDone — invariant enforced here.
            AppState::DiscDone => {
                if code == KeyCode::Char('1') {
                    self.do_write_usb();
                }
            }

            AppState::Done => {}
        }
    }

    /// Called every ~100 ms when no key event is pending.
    fn background_tick(&mut self) {
        match self.state {
            AppState::WaitUsb => {
                let candidates = media::scan_usb_partitions();
                if candidates.is_empty() {
                    return;
                }
                match media::find_profile_usb(&candidates, &self.usb_mountpoint) {
                    Ok(Some(profile_path)) => {
                        match load_profile(&profile_path) {
                            Ok(profile) => {
                                if profile.hsm.pin_source != PinSource::Prompt {
                                    self.status =
                                        "WARNING: pin_source is not 'prompt' — \
                                         unsuitable for ceremony".into();
                                }
                                self.profile = Some(profile);
                                self.state = AppState::ProfileLoaded;
                                self.status = "Profile loaded from USB.".into();
                            }
                            Err(e) => {
                                self.status = format!("Profile parse error: {e}");
                                let _ = media::unmount(&self.usb_mountpoint);
                            }
                        }
                    }
                    Ok(None) => {
                        self.status = "USB found but no profile.toml — \
                                       insert USB with profile.toml.".into();
                    }
                    Err(_) => {} // mount failure — try again next tick
                }
            }

            AppState::WaitDisc => {
                if self.skip_disc {
                    // In skip-disc mode treat staging dir as "disc ready"
                    self.optical_dev = Some(PathBuf::from("/run/anodize/staging"));
                    self.status =
                        "--skip-disc mode: disc artifacts will be written to \
                         /run/anodize/staging. Press [1] to continue.".into();
                    return;
                }

                let drives = media::scan_optical_drives();
                for dev in &drives {
                    if media::disc_is_appendable(dev) {
                        // Read existing sessions if disc is incomplete
                        let prior = media::read_disc_sessions(dev).unwrap_or_default();
                        let n = prior.len();
                        self.optical_dev = Some(dev.clone());
                        self.prior_sessions = prior;
                        self.status = if n == 0 {
                            format!(
                                "Blank disc in {}. Press [1] to burn session.",
                                dev.display()
                            )
                        } else {
                            format!(
                                "Disc in {} has {n} prior session(s). \
                                 Press [1] to append new session.",
                                dev.display()
                            )
                        };
                        return;
                    }
                }
                // No suitable disc found
                self.optical_dev = None;
                if drives.is_empty() {
                    self.status = "No optical drive detected. Insert drive and disc.".into();
                } else {
                    self.status =
                        "No blank/appendable disc found. Insert blank M-Disc.".into();
                }
            }

            AppState::BurningDisc => {
                if let Some(rx) = &self.burn_rx {
                    if let Ok(result) = rx.try_recv() {
                        self.burn_rx = None;
                        match result {
                            Ok(()) => {
                                self.state = AppState::DiscDone;
                                let disc_label = self
                                    .optical_dev
                                    .as_deref()
                                    .map(|p| p.display().to_string())
                                    .unwrap_or_else(|| "/run/anodize/staging".into());
                                self.status =
                                    format!("M-Disc session written: {disc_label}");
                            }
                            Err(e) => {
                                self.status = format!("Burn failed: {e} — reinsert disc and retry.");
                                self.state = AppState::WaitDisc;
                                self.optical_dev = None;
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
            None => { self.status = "No profile loaded".into(); return; }
        };

        let hsm = match Pkcs11Hsm::new(&cfg.module_path, &cfg.token_label) {
            Ok(h) => h,
            Err(e) => { self.status = format!("HSM open failed: {e}"); return; }
        };
        let mut actor = HsmActor::spawn(hsm);
        if let Err(e) = actor.login(&pin) {
            self.status = format!("Login failed: {e}");
            return;
        }
        self.actor = Some(actor);
        self.status = "Logged in.".into();
        self.state = AppState::KeyAction;
    }

    // ── Key operations ─────────────────────────────────────────────────────────

    fn do_generate_and_build(&mut self) {
        let label = match &self.profile {
            Some(p) => p.hsm.key_label.clone(),
            None => { self.status = "No profile".into(); return; }
        };
        let key = {
            let actor = match self.actor.as_mut() {
                Some(a) => a,
                None => { self.status = "No HSM session".into(); return; }
            };
            match actor.generate_keypair(&label, KeySpec::EcdsaP384) {
                Ok(k) => k,
                Err(e) => { self.status = format!("Key generation failed: {e}"); return; }
            }
        };
        self.root_key = Some(key);
        self.status = format!("Generated P-384 keypair (label={label:?})");
        self.do_build_cert();
    }

    fn do_find_and_build(&mut self) {
        let label = match &self.profile {
            Some(p) => p.hsm.key_label.clone(),
            None => { self.status = "No profile".into(); return; }
        };
        let key = {
            let actor = match self.actor.as_ref() {
                Some(a) => a,
                None => { self.status = "No HSM session".into(); return; }
            };
            match actor.find_key(&label) {
                Ok(k) => k,
                Err(e) => { self.status = format!("Key not found: {e}"); return; }
            }
        };
        self.root_key = Some(key);
        self.status = format!("Found existing key (label={label:?})");
        self.do_build_cert();
    }

    fn do_build_cert(&mut self) {
        let actor = match self.actor.clone() {
            Some(a) => a,
            None => { self.status = "No HSM session".into(); return; }
        };
        let key = match self.root_key {
            Some(k) => k,
            None => { self.status = "No key handle".into(); return; }
        };
        let signer = match P384HsmSigner::new(actor, key) {
            Ok(s) => s,
            Err(e) => { self.status = format!("Signer error: {e}"); return; }
        };
        let ca = match &self.profile {
            Some(p) => &p.ca,
            None => { self.status = "No profile".into(); return; }
        };
        let cert = match build_root_cert(&signer, &ca.common_name, &ca.organization, &ca.country, 7305) {
            Ok(c) => c,
            Err(e) => { self.status = format!("Cert build failed: {e}"); return; }
        };
        let der = match cert.to_der() {
            Ok(d) => d,
            Err(e) => { self.status = format!("DER encode failed: {e}"); return; }
        };
        let fp = sha256_fingerprint(&der);
        self.fingerprint = Some(fp);
        self.cert_der = Some(der);
        self.state = AppState::CertPreview;
        self.status = "Certificate built. Verify fingerprint before writing.".into();
    }

    // ── Disc burn ──────────────────────────────────────────────────────────────

    fn do_start_burn(&mut self) {
        let cert_der = match &self.cert_der {
            Some(d) => d.clone(),
            None => { self.status = "No cert in memory".into(); return; }
        };

        // Build audit log in staging dir
        let staging = PathBuf::from("/run/anodize/staging");
        if let Err(e) = std::fs::create_dir_all(&staging) {
            self.status = format!("Cannot create staging dir: {e}");
            return;
        }
        let log_path = staging.join("audit.log");
        let genesis = genesis_hash(&cert_der);
        let mut log = match AuditLog::create(&log_path, &genesis) {
            Ok(l) => l,
            Err(e) => { self.status = format!("Audit log create failed: {e}"); return; }
        };
        let fp = self.fingerprint.clone().unwrap_or_default();
        let ca_name = self.profile.as_ref().map(|p| p.ca.common_name.clone()).unwrap_or_default();
        if let Err(e) = log.append(
            "cert.root.issue",
            serde_json::json!({ "subject": ca_name, "fingerprint": fp }),
        ) {
            self.status = format!("Audit log append failed: {e}");
            return;
        }
        drop(log); // flush to disk

        let audit_bytes = match std::fs::read(&log_path) {
            Ok(b) => b,
            Err(e) => { self.status = format!("Cannot read audit log: {e}"); return; }
        };

        // Build session record for this ceremony
        let ts = self.confirmed_time.unwrap_or_else(SystemTime::now);
        let dir_name = media::session_dir_name(ts);
        let new_session = SessionEntry {
            dir_name,
            timestamp: ts,
            files: vec![
                IsoFile { name: "ROOT.CRT".into(),  data: cert_der },
                IsoFile { name: "AUDIT.LOG".into(), data: audit_bytes },
            ],
        };

        // All sessions: prior (from disc) + new
        let mut all_sessions = self.prior_sessions.clone();
        all_sessions.push(new_session);

        let (tx, rx) = mpsc::channel();
        self.burn_rx = Some(rx);

        if self.skip_disc {
            // Write ISO to staging path instead of burning
            let iso = media::iso9660::build_iso(&all_sessions);
            let iso_path = staging.join("ceremony.iso");
            match std::fs::write(&iso_path, &iso) {
                Ok(()) => { tx.send(Ok(())).ok(); }
                Err(e) => { tx.send(Err(anyhow::anyhow!("write staging ISO: {e}"))).ok(); }
            }
        } else if let Some(dev) = &self.optical_dev {
            media::write_session(dev, all_sessions, false, tx);
        } else {
            self.status = "No optical device — cannot burn".into();
            self.burn_rx = None;
            return;
        }

        self.state = AppState::BurningDisc;
        self.status = "Burning M-Disc session… (this may take a few minutes)".into();
    }

    // ── USB write ──────────────────────────────────────────────────────────────

    fn do_write_usb(&mut self) {
        // Guard: only reachable from DiscDone
        assert_eq!(self.state, AppState::DiscDone, "USB write reached without disc write");

        let cert_der = match &self.cert_der {
            Some(d) => d.clone(),
            None => { self.status = "No cert in memory".into(); return; }
        };
        let usb = &self.usb_mountpoint;

        // The USB is already mounted from WaitUsb; just write files into it
        if let Err(e) = std::fs::write(usb.join("root.crt"), &cert_der) {
            self.status = format!("USB write failed (root.crt): {e}");
            return;
        }

        let staging_log = PathBuf::from("/run/anodize/staging/audit.log");
        let usb_log = usb.join("audit.log");
        if let Err(e) = std::fs::copy(&staging_log, &usb_log) {
            self.status = format!("Audit log copy to USB failed: {e}");
            return;
        }

        self.state = AppState::Done;
        self.status = format!("USB write complete: {}", usb.display());
    }
}

// ── Noise PIN masking ─────────────────────────────────────────────────────────

/// Returns a random display length in [8, 20] using subsecond nanos as noise.
/// Never reveals the actual PIN length — prevents shoulder-surf length disclosure.
fn noise_display_len() -> usize {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as usize;
    8 + (nanos % 13)
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

// ── Rendering ─────────────────────────────────────────────────────────────────

fn render(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(10), Constraint::Length(3)])
        .split(area);

    let title = Paragraph::new("ANODIZE ROOT CA CEREMONY")
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[0]);

    let screen_title = match app.state {
        AppState::ClockCheck    => "Clock Verification",
        AppState::WaitUsb       => "Waiting for USB",
        AppState::ProfileLoaded => "Profile Loaded",
        AppState::EnterPin      => "HSM Authentication",
        AppState::KeyAction     => "Key Management",
        AppState::CertPreview   => "Certificate Preview — VERIFY FINGERPRINT",
        AppState::WaitDisc      => "Insert M-Disc",
        AppState::BurningDisc   => "Writing M-Disc Session…",
        AppState::DiscDone      => "M-Disc Session Written",
        AppState::Done          => "Ceremony Complete",
    };
    let main_block = Block::default().borders(Borders::ALL).title(screen_title);
    let inner = main_block.inner(chunks[1]);
    frame.render_widget(main_block, chunks[1]);
    let body = build_body(app);
    frame.render_widget(Paragraph::new(body).wrap(Wrap { trim: false }), inner);

    let status = Paragraph::new(app.status.as_str())
        .style(Style::default().fg(Color::Yellow))
        .block(Block::default().borders(Borders::ALL).title("Status"));
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
                    odt.year(), odt.month() as u8, odt.day(),
                    odt.hour(), odt.minute(), odt.second()
                ),
                String::new(),
                "  Timestamps derived from this value appear permanently in the".into(),
                "  M-Disc archive and audit log. Verify against a reference clock.".into(),
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

        AppState::KeyAction => {
            let label = app.profile.as_ref().map(|p| p.hsm.key_label.as_str()).unwrap_or("?");
            vec![
                String::new(),
                format!("  Key label: {label:?}"),
                String::new(),
                "  [1]  Generate new P-384 keypair (fresh ceremony)".into(),
                "  [2]  Use existing key by label  (resume)".into(),
            ]
        }

        AppState::CertPreview => {
            let fp = app.fingerprint.as_deref().unwrap_or("(none)");
            let ca = app.profile.as_ref().map(|p| &p.ca);
            let (cn, org, country) = ca
                .map(|c| (c.common_name.as_str(), c.organization.as_str(), c.country.as_str()))
                .unwrap_or(("?", "?", "?"));
            vec![
                String::new(),
                format!("  Subject  : CN={cn}, O={org}, C={country}"),
                "  Validity : 7305 days (20 years)".into(),
                String::new(),
                "  SHA-256 Fingerprint:".into(),
                format!("  {fp}"),
                String::new(),
                "  Compare this fingerprint against your paper checklist.".into(),
                String::new(),
                "  [1]  Proceed to M-Disc write".into(),
                "  [q]  Abort".into(),
            ]
        }

        AppState::WaitDisc => {
            let disc_info = match &app.optical_dev {
                Some(dev) => format!(
                    "  Disc ready in {}  ({} prior session(s))",
                    dev.display(),
                    app.prior_sessions.len()
                ),
                None => "  No appendable disc detected. Insert blank M-Disc.".into(),
            };
            vec![
                String::new(),
                disc_info,
                String::new(),
                "  [1]  Burn session to disc (only if disc shown above)".into(),
                "  [q]  Abort".into(),
            ]
        }

        AppState::BurningDisc => vec![
            String::new(),
            "  Writing ISO 9660 session to M-Disc…".into(),
            String::new(),
            "  Please wait. Do not remove the disc or USB.".into(),
        ],

        AppState::DiscDone => {
            let fp = app.fingerprint.as_deref().unwrap_or("(none)");
            vec![
                String::new(),
                "  M-Disc session written successfully.".into(),
                String::new(),
                format!("  Fingerprint: {fp}"),
                String::new(),
                "  [1]  Copy artifacts to USB".into(),
                "  [q]  Quit without USB copy (disc is the primary record)".into(),
            ]
        }

        AppState::Done => vec![
            String::new(),
            "  Ceremony complete.".into(),
            String::new(),
            format!("  USB  : {}  \u{2713}", app.usb_mountpoint.display()),
            String::new(),
            "  Remove and store both M-Disc and USB separately.".into(),
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
                        if app.state != AppState::EnterPin =>
                    {
                        break;
                    }
                    other => app.handle_key(other),
                }
            }
        } else {
            // 100 ms tick — background scanning
            app.background_tick();
        }
    }
    Ok(())
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();

    enable_raw_mode()?;
    execute!(stdout(), EnterAlternateScreen, EnableMouseCapture)?;

    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(cli.usb_mount, cli.skip_disc);
    let result = run(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    // Best-effort USB unmount on exit
    let _ = media::unmount(&app.usb_mountpoint);

    result
}
