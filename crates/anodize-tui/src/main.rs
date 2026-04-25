//! Ceremony TUI — disc-before-USB state machine.
//!
//! The key invariant is structural: `AppState::UsbWrite` is only reachable from
//! `AppState::DiscDone`, and `DiscDone` is only set after a successful disc write.
//! The USB write step is therefore impossible to reach without a completed disc write.

use std::io::stdout;
use std::path::PathBuf;

use anodize_audit::{genesis_hash, AuditLog};
use anodize_ca::{build_root_cert, P384HsmSigner};
use anodize_config::{load as load_profile, PinSource, Profile};
use anodize_hsm::{Hsm, HsmActor, KeyHandle, KeySpec, Pkcs11Hsm};
use anyhow::{Context, Result};
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

#[derive(Parser)]
#[command(name = "anodize-ceremony", about = "Root CA key ceremony")]
struct Cli {
    /// Path to profile.toml
    #[arg(short, long, value_name = "FILE")]
    profile: PathBuf,
    /// M-Disc mount point — cert and audit log written here first
    #[arg(long, default_value = "/media/disc")]
    disc: PathBuf,
    /// USB mount point — written only after M-Disc commit succeeds
    #[arg(long, default_value = "/media/usb")]
    usb: PathBuf,
}

/// Ceremony state machine. Transitions are forward-only except on error.
/// `UsbWrite` is only reachable from `DiscDone` — enforced by the match arms below.
#[derive(Debug, Clone, PartialEq)]
enum AppState {
    Welcome,
    EnterPin,
    KeyAction,
    CertPreview,
    DiscDone,
    Done,
}

struct App {
    profile: Profile,
    disc_path: PathBuf,
    usb_path: PathBuf,

    state: AppState,
    status: String,

    // HSM session — kept alive for CRL issuance later
    actor: Option<HsmActor>,
    root_key: Option<KeyHandle>,

    // Cert in RAM until disc write commits it
    cert_der: Option<Vec<u8>>,
    fingerprint: Option<String>,

    // Masked PIN buffer
    pin_buf: String,
}

impl App {
    fn new(profile: Profile, disc_path: PathBuf, usb_path: PathBuf) -> Self {
        Self {
            profile,
            disc_path,
            usb_path,
            state: AppState::Welcome,
            status: String::new(),
            actor: None,
            root_key: None,
            cert_der: None,
            fingerprint: None,
            pin_buf: String::new(),
        }
    }

    fn handle_key(&mut self, code: KeyCode) {
        match self.state.clone() {
            AppState::Welcome => {
                if code == KeyCode::Char('1') {
                    self.pin_buf.clear();
                    self.state = AppState::EnterPin;
                    self.status = "Enter HSM PIN and press Enter. Esc to cancel.".into();
                }
            }

            AppState::EnterPin => match code {
                KeyCode::Char(c) => {
                    self.pin_buf.push(c);
                }
                KeyCode::Backspace => {
                    self.pin_buf.pop();
                }
                KeyCode::Enter => self.do_login(),
                KeyCode::Esc => {
                    self.pin_buf.clear();
                    self.state = AppState::Welcome;
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
                    self.do_write_disc();
                }
            }

            // USB write is only reachable from DiscDone — invariant enforced here.
            AppState::DiscDone => {
                if code == KeyCode::Char('1') {
                    self.do_write_usb();
                }
            }

            AppState::Done => {}
        }
    }

    fn do_login(&mut self) {
        let pin: String = self.pin_buf.drain(..).collect();
        let pin = SecretString::new(pin);
        let cfg = &self.profile.hsm;

        let hsm = match Pkcs11Hsm::new(&cfg.module_path, &cfg.token_label) {
            Ok(h) => h,
            Err(e) => {
                self.status = format!("HSM open failed: {e}");
                return;
            }
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

    fn do_generate_and_build(&mut self) {
        let label = self.profile.hsm.key_label.clone();
        let key = {
            let actor = match self.actor.as_mut() {
                Some(a) => a,
                None => {
                    self.status = "No HSM session".into();
                    return;
                }
            };
            match actor.generate_keypair(&label, KeySpec::EcdsaP384) {
                Ok(k) => k,
                Err(e) => {
                    self.status = format!("Key generation failed: {e}");
                    return;
                }
            }
        };
        self.root_key = Some(key);
        self.status = format!("Generated P-384 keypair (label={label:?})");
        self.do_build_cert();
    }

    fn do_find_and_build(&mut self) {
        let label = self.profile.hsm.key_label.clone();
        let key = {
            let actor = match self.actor.as_ref() {
                Some(a) => a,
                None => {
                    self.status = "No HSM session".into();
                    return;
                }
            };
            match actor.find_key(&label) {
                Ok(k) => k,
                Err(e) => {
                    self.status = format!("Key not found: {e}");
                    return;
                }
            }
        };
        self.root_key = Some(key);
        self.status = format!("Found existing key (label={label:?})");
        self.do_build_cert();
    }

    fn do_build_cert(&mut self) {
        let actor = match self.actor.clone() {
            Some(a) => a,
            None => {
                self.status = "No HSM session".into();
                return;
            }
        };
        let key = match self.root_key {
            Some(k) => k,
            None => {
                self.status = "No key handle".into();
                return;
            }
        };
        let signer = match P384HsmSigner::new(actor, key) {
            Ok(s) => s,
            Err(e) => {
                self.status = format!("Signer error: {e}");
                return;
            }
        };
        let ca = &self.profile.ca;
        let cert = match build_root_cert(
            &signer,
            &ca.common_name,
            &ca.organization,
            &ca.country,
            7305,
        ) {
            Ok(c) => c,
            Err(e) => {
                self.status = format!("Cert build failed: {e}");
                return;
            }
        };
        let der = match cert.to_der() {
            Ok(d) => d,
            Err(e) => {
                self.status = format!("DER encode failed: {e}");
                return;
            }
        };
        let fp = sha256_fingerprint(&der);
        self.fingerprint = Some(fp);
        self.cert_der = Some(der);
        self.state = AppState::CertPreview;
        self.status = "Certificate built. Verify fingerprint before writing.".into();
    }

    fn do_write_disc(&mut self) {
        let cert_der = match &self.cert_der {
            Some(d) => d.clone(),
            None => {
                self.status = "No cert in memory".into();
                return;
            }
        };
        let disc = self.disc_path.clone();

        if let Err(e) = std::fs::create_dir_all(&disc) {
            self.status = format!("Cannot create disc path {}: {e}", disc.display());
            return;
        }

        if let Err(e) = std::fs::write(disc.join("root.crt"), &cert_der) {
            self.status = format!("Disc write failed (root.crt): {e}");
            return;
        }

        let log_path = disc.join("audit.log");
        let genesis = genesis_hash(&cert_der);
        let mut log = match AuditLog::create(&log_path, &genesis) {
            Ok(l) => l,
            Err(e) => {
                self.status = format!("Audit log create failed: {e}");
                return;
            }
        };
        let fp = self.fingerprint.clone().unwrap_or_default();
        let ca_name = self.profile.ca.common_name.clone();
        if let Err(e) = log.append(
            "cert.root.issue",
            serde_json::json!({ "subject": ca_name, "fingerprint": fp }),
        ) {
            self.status = format!("Audit log append failed: {e}");
            return;
        }

        // Only now is the state transition allowed.
        self.state = AppState::DiscDone;
        self.status = format!("M-Disc write complete: {}", disc.display());
    }

    fn do_write_usb(&mut self) {
        // Guard: this method is only callable from DiscDone (see handle_key match).
        // Belt-and-suspenders check to make the invariant explicit.
        assert!(
            self.state == AppState::DiscDone,
            "USB write reached without disc write — invariant violated"
        );

        let cert_der = match &self.cert_der {
            Some(d) => d.clone(),
            None => {
                self.status = "No cert in memory".into();
                return;
            }
        };
        let usb = self.usb_path.clone();

        if let Err(e) = std::fs::create_dir_all(&usb) {
            self.status = format!("Cannot create USB path {}: {e}", usb.display());
            return;
        }

        if let Err(e) = std::fs::write(usb.join("root.crt"), &cert_der) {
            self.status = format!("USB write failed (root.crt): {e}");
            return;
        }

        let disc_log = self.disc_path.join("audit.log");
        let usb_log = usb.join("audit.log");
        if let Err(e) = std::fs::copy(&disc_log, &usb_log) {
            self.status = format!("Audit log copy to USB failed: {e}");
            return;
        }

        self.state = AppState::Done;
        self.status = format!("USB write complete: {}", usb.display());
    }
}

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

fn render(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(area);

    // ── Title ──
    let title = Paragraph::new("ANODIZE ROOT CA CEREMONY")
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[0]);

    // ── Main panel ──
    let screen_title = match app.state {
        AppState::Welcome => "Welcome",
        AppState::EnterPin => "HSM Authentication",
        AppState::KeyAction => "Key Management",
        AppState::CertPreview => "Certificate Preview — VERIFY FINGERPRINT",
        AppState::DiscDone => "M-Disc Written",
        AppState::Done => "Ceremony Complete",
    };
    let main_block = Block::default().borders(Borders::ALL).title(screen_title);
    let inner = main_block.inner(chunks[1]);
    frame.render_widget(main_block, chunks[1]);

    let body = build_body(app);
    let paragraph = Paragraph::new(body).wrap(Wrap { trim: false });
    frame.render_widget(paragraph, inner);

    // ── Status bar ──
    let status = Paragraph::new(app.status.as_str())
        .style(Style::default().fg(Color::Yellow))
        .block(Block::default().borders(Borders::ALL).title("Status"));
    frame.render_widget(status, chunks[2]);
}

fn build_body(app: &App) -> Text<'static> {
    let lines: Vec<String> = match &app.state {
        AppState::Welcome => vec![
            String::new(),
            format!("  CA Subject : {}", app.profile.ca.common_name),
            format!("  Org        : {}", app.profile.ca.organization),
            format!("  Country    : {}", app.profile.ca.country),
            format!("  HSM token  : {}", app.profile.hsm.token_label),
            format!("  Disc path  : {}", app.disc_path.display()),
            format!("  USB path   : {}", app.usb_path.display()),
            String::new(),
            "  [1]  Start ceremony".into(),
            "  [q]  Quit".into(),
        ],

        AppState::EnterPin => {
            let stars = "*".repeat(app.pin_buf.len());
            vec![
                String::new(),
                format!("  PIN: {stars}"),
                String::new(),
                "  Press Enter to log in, Esc to cancel.".into(),
            ]
        }

        AppState::KeyAction => vec![
            String::new(),
            format!("  Key label: {:?}", app.profile.hsm.key_label),
            String::new(),
            "  [1]  Generate new P-384 keypair (fresh ceremony)".into(),
            "  [2]  Use existing key by label  (resume)".into(),
        ],

        AppState::CertPreview => {
            let fp = app.fingerprint.as_deref().unwrap_or("(none)");
            let ca = &app.profile.ca;
            vec![
                String::new(),
                format!(
                    "  Subject  : CN={}, O={}, C={}",
                    ca.common_name, ca.organization, ca.country
                ),
                "  Validity : 7305 days (20 years)".into(),
                String::new(),
                "  SHA-256 Fingerprint:".into(),
                format!("  {fp}"),
                String::new(),
                "  Compare this fingerprint against your paper checklist.".into(),
                "  If they match, press 1 to commit to M-Disc.".into(),
                String::new(),
                "  [1]  Write to M-Disc  (IRREVERSIBLE — verify fingerprint first)".into(),
                "  [q]  Abort".into(),
            ]
        }

        AppState::DiscDone => {
            let fp = app.fingerprint.as_deref().unwrap_or("(none)");
            vec![
                String::new(),
                format!("  M-Disc: {}  ✓", app.disc_path.display()),
                "         root.crt + audit.log written".into(),
                String::new(),
                format!("  Fingerprint: {fp}"),
                String::new(),
                "  You may now write the same artifacts to USB.".into(),
                String::new(),
                "  [1]  Write to USB".into(),
                "  [q]  Quit (USB write skipped — disc copy is the primary record)".into(),
            ]
        }

        AppState::Done => vec![
            String::new(),
            "  Ceremony complete.".into(),
            String::new(),
            format!("  Disc : {}  ✓", app.disc_path.display()),
            format!("  USB  : {}  ✓", app.usb_path.display()),
            String::new(),
            "  Remove and store both media separately.".into(),
            "  The HSM holds the private key; no key material was written to disk.".into(),
            String::new(),
            "  [q]  Quit".into(),
        ],
    };

    Text::from(lines.join("\n"))
}

fn run(terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>, app: &mut App) -> Result<()> {
    loop {
        terminal.draw(|f| render(f, app))?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                // Ctrl-C always exits.
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                    break;
                }

                match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') if app.state != AppState::EnterPin => {
                        break;
                    }
                    other => app.handle_key(other),
                }
            }
        }

        if app.state == AppState::Done {
            // Stay on Done screen until operator presses q.
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let profile = load_profile(&cli.profile)
        .with_context(|| format!("cannot load profile {:?}", cli.profile))?;

    // Warn early if PIN source is unsafe — before entering the TUI.
    if profile.hsm.pin_source != PinSource::Prompt {
        eprintln!("WARNING: pin_source is not 'prompt' — this is not suitable for a live ceremony");
    }

    enable_raw_mode()?;
    execute!(stdout(), EnterAlternateScreen, EnableMouseCapture)?;

    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(profile, cli.disc, cli.usb);
    let result = run(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}
