use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::Rect,
    text::Text,
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

use crate::action::Action;
use crate::components::Component;

/// Sub-phases of the Setup mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupPhase {
    ClockCheck,
    WaitUsb,
    ProfileLoaded,
    EnterPin,
    WaitDisc,
}

impl SetupPhase {
    pub fn index(&self) -> usize {
        match self {
            Self::ClockCheck => 0,
            Self::WaitUsb => 1,
            Self::ProfileLoaded => 2,
            Self::EnterPin => 3,
            Self::WaitDisc => 4,
        }
    }
}

/// Setup mode component: walks through clock verification, USB detection,
/// profile loading, HSM PIN entry, and disc readiness.
pub struct SetupMode {
    pub phase: SetupPhase,
}

impl SetupMode {
    pub fn new() -> Self {
        Self {
            phase: SetupPhase::ClockCheck,
        }
    }

    /// Render with access to parent App state (for profile info, PIN display, disc state).
    pub fn render_with_app(
        &self,
        frame: &mut Frame,
        area: Rect,
        app: &crate::app::App,
    ) {
        let title = match self.phase {
            SetupPhase::ClockCheck => "Clock Verification",
            SetupPhase::WaitUsb => "Waiting for USB",
            SetupPhase::ProfileLoaded => "Profile Loaded",
            SetupPhase::EnterPin => "HSM Authentication",
            SetupPhase::WaitDisc => "Insert Disc",
        };

        let content = match self.phase {
            SetupPhase::ClockCheck => {
                let now = std::time::SystemTime::now();
                let odt = time::OffsetDateTime::from(now);
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
            SetupPhase::WaitUsb => vec![
                String::new(),
                "  Insert USB stick containing profile.toml.".into(),
                String::new(),
                "  Scanning automatically…".into(),
            ],
            SetupPhase::ProfileLoaded => {
                if let Some(p) = &app.profile {
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
                } else {
                    vec![String::new(), "  Profile loaded. Press [1] to continue.".into()]
                }
            }
            SetupPhase::EnterPin => {
                let stars = "*".repeat(app.pin_display_len);
                vec![
                    String::new(),
                    format!("  PIN: {stars}"),
                    String::new(),
                    "  Press Enter to log in, Esc to cancel.".into(),
                ]
            }
            SetupPhase::WaitDisc => {
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
        };

        let block = Block::default().borders(Borders::ALL).title(title);
        let para = Paragraph::new(Text::from(content.join("\n")))
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((app.content_scroll, 0));
        frame.render_widget(para, area);
    }
}

impl Component for SetupMode {
    fn handle_key_event(&mut self, key: KeyEvent) -> Action {
        match self.phase {
            SetupPhase::ClockCheck => {
                if key.code == KeyCode::Char('1') {
                    return Action::ConfirmClock;
                }
            }
            SetupPhase::WaitUsb => {} // auto-advance in background_tick
            SetupPhase::ProfileLoaded => {
                if key.code == KeyCode::Char('1') {
                    return Action::AdvanceToPinEntry;
                }
            }
            SetupPhase::EnterPin => match key.code {
                KeyCode::Char(c) => return Action::PinChar(c),
                KeyCode::Backspace => return Action::PinBackspace,
                KeyCode::Enter => return Action::DoLogin,
                KeyCode::Esc => return Action::PinCancel,
                _ => {}
            },
            SetupPhase::WaitDisc => {
                if key.code == KeyCode::Char('1') {
                    return Action::ConfirmDisc;
                }
            }
        }
        Action::Noop
    }

    fn handle_tick(&mut self) -> Action {
        Action::Noop
    }

    fn render(&self, frame: &mut Frame, area: Rect) {
        // Fallback render without app context (used if called generically)
        let block = Block::default().borders(Borders::ALL).title("Setup");
        let para = Paragraph::new("  (Setup mode)").block(block);
        frame.render_widget(para, area);
    }
}
