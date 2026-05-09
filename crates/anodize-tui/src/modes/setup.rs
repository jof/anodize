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
    WaitShuttle,
    ProfileLoaded,
    HsmDetect,
    HsmWarnTokenMissing,
    WaitDisc,
}

impl SetupPhase {
    pub fn index(&self) -> usize {
        match self {
            Self::ClockCheck => 0,
            Self::WaitShuttle => 1,
            Self::ProfileLoaded => 2,
            Self::HsmDetect => 3,
            Self::HsmWarnTokenMissing => 3,
            Self::WaitDisc => 4,
        }
    }
}

/// Setup mode component: walks through clock verification, shuttle detection,
/// profile loading, HSM detection, and disc readiness.
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
    pub fn render_with_app(&self, frame: &mut Frame, area: Rect, app: &crate::app::App) {
        let title = match self.phase {
            SetupPhase::ClockCheck => "Clock Verification",
            SetupPhase::WaitShuttle => "Waiting for Shuttle",
            SetupPhase::ProfileLoaded => "Profile Loaded",
            SetupPhase::HsmDetect => "HSM Detection",
            SetupPhase::HsmWarnTokenMissing => "HSM Detection",
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
                    "  optical disc archive and audit log. Verify against a reference clock."
                        .into(),
                    String::new(),
                    "  [1]  Time is correct — continue".into(),
                    "  [q]  Exit to correct clock, then relaunch".into(),
                ]
            }
            SetupPhase::WaitShuttle => vec![
                String::new(),
                "  Insert shuttle USB containing profile.toml.".into(),
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
                        format!("  Shuttle     : {}", app.shuttle_mount.display()),
                        String::new(),
                        "  [1]  Detect HSM and continue".into(),
                        "  [q]  Quit".into(),
                    ]
                } else {
                    vec![
                        String::new(),
                        "  Profile loaded. Press [1] to continue.".into(),
                    ]
                }
            }
            SetupPhase::HsmDetect => {
                let hsm_info = match &app.hw.hsm_state {
                    crate::components::status_bar::HwState::Absent => {
                        "  Detecting PKCS#11 module and HSM token…".into()
                    }
                    crate::components::status_bar::HwState::Present(info) => {
                        format!("  HSM detected: {info}")
                    }
                    crate::components::status_bar::HwState::Ready(info) => {
                        format!("  HSM ready: {info}")
                    }
                    crate::components::status_bar::HwState::Error(msg) => {
                        format!("  HSM error: {msg}")
                    }
                };
                vec![
                    String::new(),
                    hsm_info,
                    String::new(),
                    "  The HSM will be authenticated later via SSS quorum.".into(),
                    "  No PIN entry is required at this stage.".into(),
                ]
            }
            SetupPhase::HsmWarnTokenMissing => {
                let label = app
                    .profile
                    .as_ref()
                    .map(|p| p.hsm.token_label.as_str())
                    .unwrap_or("(unknown)");
                vec![
                    String::new(),
                    format!("  WARNING: HSM token '{label}' does not exist yet."),
                    String::new(),
                    "  The PKCS#11 module was loaded successfully, but the expected".into(),
                    "  token slot was not found. This is normal for a first-time".into(),
                    "  InitRoot ceremony — the token will be created during that step.".into(),
                    String::new(),
                    "  Only the InitRoot operation will be available.".into(),
                    String::new(),
                    "  [1]  Acknowledge and continue".into(),
                    "  [q]  Quit".into(),
                ]
            }
            SetupPhase::WaitDisc => {
                let disc_info = match &app.disc.optical_dev {
                    Some(dev) => {
                        let cap = app
                            .disc
                            .sessions_remaining
                            .map(|r| format!(", {r} sessions remaining"))
                            .unwrap_or_default();
                        format!(
                            "  Disc ready in {}  ({} prior session(s){cap})",
                            dev.display(),
                            app.disc.prior_sessions.len()
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

        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .style(crate::theme::BLOCK)
            .border_style(crate::theme::BORDER)
            .title_style(crate::theme::TITLE);
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
            SetupPhase::WaitShuttle => {} // auto-advance in background_tick
            SetupPhase::ProfileLoaded => {
                if key.code == KeyCode::Char('1') {
                    return Action::HsmDetected; // triggers HSM detection in app.update()
                }
            }
            SetupPhase::HsmDetect => {} // auto-advance after detection completes
            SetupPhase::HsmWarnTokenMissing => {
                if key.code == KeyCode::Char('1') {
                    return Action::HsmWarnAcknowledged;
                }
            }
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
        let block = Block::default()
            .borders(Borders::ALL)
            .title("Setup")
            .style(crate::theme::BLOCK)
            .border_style(crate::theme::BORDER)
            .title_style(crate::theme::TITLE);
        let para = Paragraph::new("  (Setup mode)").block(block);
        frame.render_widget(para, area);
    }
}
