use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::Rect,
    text::Text,
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

use crate::action::Action;
use crate::app::App;
use crate::components::Component;

/// Which sub-screen is active within Utilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UtilScreen {
    Menu,
    SystemInfo,
    AuditLog,
    HsmBrowser,
}

/// Utilities mode component: system info, audit log browser, HSM slot browser.
pub struct UtilitiesMode {
    pub screen: UtilScreen,
    /// Cached lines for the current sub-screen (populated on entry).
    cached_lines: Vec<String>,
}

impl UtilitiesMode {
    pub fn new() -> Self {
        Self {
            screen: UtilScreen::Menu,
            cached_lines: Vec::new(),
        }
    }

    /// Gather content lines for a screen without mutating self.
    /// Used by App::update to break the borrow split.
    pub fn gather_for_screen(screen: UtilScreen, app: &App) -> Vec<String> {
        match screen {
            UtilScreen::Menu => Vec::new(),
            UtilScreen::SystemInfo => Self::gather_system_info(app),
            UtilScreen::AuditLog => Self::gather_audit_log(app),
            UtilScreen::HsmBrowser => Self::gather_hsm_info(app),
        }
    }

    /// Set the cached lines (used after gather_for_screen).
    pub fn set_cached_lines(&mut self, lines: Vec<String>) {
        self.cached_lines = lines;
    }

    // ── System Info ──────────────────────────────────────────────────────────

    fn gather_system_info(app: &App) -> Vec<String> {
        let mut lines = Vec::new();

        // Kernel
        if let Ok(ver) = std::fs::read_to_string("/proc/version") {
            lines.push(format!("  Kernel: {}", ver.trim()));
        }
        lines.push(String::new());

        // OS release
        if let Ok(release) = std::fs::read_to_string("/etc/os-release") {
            for rl in release.lines() {
                if rl.starts_with("PRETTY_NAME=") {
                    let val = rl.trim_start_matches("PRETTY_NAME=").trim_matches('"');
                    lines.push(format!("  OS: {val}"));
                }
            }
        }

        // Uptime
        if let Ok(uptime_str) = std::fs::read_to_string("/proc/uptime") {
            if let Some(secs_str) = uptime_str.split_whitespace().next() {
                if let Ok(secs) = secs_str.parse::<f64>() {
                    let h = secs as u64 / 3600;
                    let m = (secs as u64 % 3600) / 60;
                    let s = secs as u64 % 60;
                    lines.push(format!("  Uptime: {h}h {m}m {s}s"));
                }
            }
        }

        // Memory
        if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
            let mut total = String::new();
            let mut avail = String::new();
            for ml in meminfo.lines() {
                if ml.starts_with("MemTotal:") {
                    total = ml.split_whitespace().nth(1).unwrap_or("?").to_string();
                } else if ml.starts_with("MemAvailable:") {
                    avail = ml.split_whitespace().nth(1).unwrap_or("?").to_string();
                }
            }
            if !total.is_empty() {
                lines.push(format!("  Memory: {avail} kB available / {total} kB total"));
            }
        }

        lines.push(String::new());

        // Ceremony state
        lines.push(format!("  USB mount: {}", app.shuttle_mount.display()));
        lines.push(format!("  Skip disc: {}", app.skip_disc));
        if let Some(ref p) = app.profile {
            lines.push(format!("  Profile: {} / {}", p.ca.common_name, p.ca.organization));
            lines.push(format!("  HSM module: {}", p.hsm.module_path.display()));
            lines.push(format!("  Token label: {}", p.hsm.token_label));
        } else {
            lines.push("  Profile: (not loaded)".into());
        }
        lines.push(format!("  HSM logged in: {}", app.hw.actor.is_some()));
        if let Some(ref dev) = app.disc.optical_dev {
            lines.push(format!("  Optical device: {}", dev.display()));
        }
        if let Some(rem) = app.disc.sessions_remaining {
            lines.push(format!("  Disc sessions remaining: {rem}"));
        }
        if let Some(ref fp) = app.data.fingerprint {
            lines.push(format!("  Root cert fingerprint: {fp}"));
        }

        lines.push(String::new());

        // Block devices
        lines.push("  Block devices:".into());
        if let Ok(entries) = std::fs::read_dir("/sys/block") {
            let mut devs: Vec<String> = entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            devs.sort();
            for d in devs {
                let size_path = format!("/sys/block/{d}/size");
                let size = std::fs::read_to_string(&size_path)
                    .ok()
                    .and_then(|s| s.trim().parse::<u64>().ok())
                    .map(|sectors| sectors * 512 / 1024 / 1024)
                    .unwrap_or(0);
                lines.push(format!("    /dev/{d}  ({size} MiB)"));
            }
        }

        lines
    }

    // ── Audit Log Browser ────────────────────────────────────────────────────

    fn gather_audit_log(app: &App) -> Vec<String> {
        let mut lines = Vec::new();

        // Try staging log first, then USB log
        let candidates = [
            std::path::PathBuf::from("/run/anodize/staging/audit.log"),
            app.shuttle_mount.join("audit.log"),
        ];
        let log_path = candidates.iter().find(|p| p.exists());

        // Collect AUDIT.LOG content from disc sessions (prior_sessions)
        let disc_audit: Vec<u8> = app
            .disc.prior_sessions
            .iter()
            .rev()
            .find_map(|s| {
                s.files
                    .iter()
                    .find(|f| f.name == "AUDIT.LOG")
                    .map(|f| f.data.clone())
            })
            .unwrap_or_default();

        if log_path.is_none() && disc_audit.is_empty() {
            lines.push("  No audit log found.".into());
            lines.push(String::new());
            lines.push("  Checked:".into());
            for c in &candidates {
                lines.push(format!("    {}", c.display()));
            }
            lines.push("    Disc sessions (AUDIT.LOG)".into());
            return lines;
        }

        // Prefer filesystem log for integrity verification
        if let Some(path) = log_path {
            lines.push(format!("  Log: {}", path.display()));
            lines.push(String::new());

            match anodize_audit::verify_log(path) {
                Ok(count) => {
                    lines.push(format!("  Chain integrity: OK ({count} records)"));
                }
                Err(e) => {
                    lines.push(format!("  Chain integrity: FAILED — {e}"));
                }
            }
            lines.push(String::new());

            match std::fs::read_to_string(path) {
                Ok(content) => Self::append_audit_records(&mut lines, content.as_bytes()),
                Err(e) => lines.push(format!("  Read error: {e}")),
            }
        } else {
            // Show disc-based audit log
            lines.push(format!(
                "  Source: disc ({} session(s))",
                app.disc.prior_sessions.len()
            ));
            lines.push(String::new());
            Self::append_audit_records(&mut lines, &disc_audit);
        }

        lines
    }

    /// Parse audit log bytes (JSONL) and append formatted records to `lines`.
    fn append_audit_records(lines: &mut Vec<String>, data: &[u8]) {
        let content = String::from_utf8_lossy(data);
        for (i, line) in content.lines().enumerate() {
            match serde_json::from_str::<anodize_audit::Record>(line) {
                Ok(rec) => {
                    lines.push(format!(
                        "  #{:<4} {} {}",
                        rec.seq, rec.timestamp, rec.event
                    ));
                    // Show op_data if it has content
                    if !rec.op_data.is_null()
                        && rec.op_data != serde_json::Value::Object(Default::default())
                    {
                        if let Ok(pretty) = serde_json::to_string(&rec.op_data) {
                            lines.push(format!("         {pretty}"));
                        }
                    }
                }
                Err(e) => {
                    lines.push(format!("  [line {i}] parse error: {e}"));
                }
            }
        }
    }

    // ── HSM Slot Browser ─────────────────────────────────────────────────────

    fn gather_hsm_info(app: &App) -> Vec<String> {
        let mut lines = Vec::new();

        let Some(ref profile) = app.profile else {
            lines.push("  Profile not loaded — cannot query PKCS#11 module.".into());
            return lines;
        };

        let cfg_token = profile.hsm.token_label.as_str();
        let cfg_key = profile.hsm.key_label.as_str();
        let cfg_spec = format!("{:?}", profile.hsm.key_spec);
        let logged_in = app.hw.actor.is_some();

        lines.push(format!("  Module: {}", profile.hsm.module_path.display()));
        lines.push(String::new());

        let Some(ref actor) = app.hw.actor else {
            lines.push("  HSM not connected — log in first to browse slots.".into());
            return lines;
        };

        match actor.list_slot_details() {
            Ok(slots) => {
                if slots.is_empty() {
                    lines.push("  (no slots with tokens found)".into());
                }
                for (i, si) in slots.iter().enumerate() {
                    let is_active = si.token_label == cfg_token;
                    let tag = if is_active { "  ★ " } else { "    " };

                    lines.push(format!("{tag}Slot {i}  (id {}):", si.slot_id));
                    lines.push(format!("{tag}└─ Token: \"{}\"", si.token_label));

                    if !si.model.is_empty() {
                        lines.push(format!("{tag}   ├─ Model: {}", si.model));
                    }
                    if !si.serial_number.is_empty() {
                        lines.push(format!("{tag}   ├─ Serial: {}", si.serial_number));
                    }

                    // PIN status
                    let pin_status = if si.user_pin_locked {
                        "LOCKED"
                    } else if si.user_pin_initialized {
                        "initialized"
                    } else {
                        "not initialized"
                    };
                    lines.push(format!(
                        "{tag}   ├─ User PIN: {}  ({}-{} chars)",
                        pin_status, si.min_pin_len, si.max_pin_len
                    ));
                    lines.push(format!(
                        "{tag}   ├─ Login required: {}",
                        if si.login_required { "yes" } else { "no" }
                    ));

                    if is_active {
                        lines.push(format!(
                            "{tag}   ├─ Session: {}",
                            if logged_in {
                                "logged in"
                            } else {
                                "not logged in"
                            }
                        ));
                        lines.push(format!(
                            "{tag}   └─ Key: \"{}\" ({})",
                            cfg_key, cfg_spec
                        ));
                        lines.push(format!(
                            "{tag}      └─ Private key protected by User PIN"
                        ));
                    } else {
                        lines.push(format!("{tag}   └─ (not the configured token)"));
                    }

                    if i + 1 < slots.len() {
                        lines.push(String::new());
                    }
                }
            }
            Err(e) => {
                lines.push(format!("  Slot enumeration failed: {e}"));
            }
        }

        lines
    }

    /// Render the utilities content with access to App state.
    pub fn render_with_app(&self, frame: &mut Frame, area: Rect, app: &App) {
        match self.screen {
            UtilScreen::Menu => {
                let block = Block::default()
                    .borders(Borders::ALL)
                    .title("Utilities");
                let content = vec![
                    "",
                    "  [1]  System Info",
                    "  [2]  Audit Log Browser",
                    "  [3]  PKCS#11 / HSM Info",
                    "",
                    "  [Esc]  Back",
                ];
                let para = Paragraph::new(Text::from(content.join("\n")))
                    .block(block)
                    .wrap(Wrap { trim: false });
                frame.render_widget(para, area);
            }
            UtilScreen::SystemInfo => {
                let block = Block::default()
                    .borders(Borders::ALL)
                    .title("System Info  [Esc] back");
                let para = Paragraph::new(Text::from(self.cached_lines.join("\n")))
                    .block(block)
                    .wrap(Wrap { trim: false })
                    .scroll((app.content_scroll, 0));
                frame.render_widget(para, area);
            }
            UtilScreen::AuditLog => {
                let block = Block::default()
                    .borders(Borders::ALL)
                    .title("Audit Log  [Esc] back");
                let para = Paragraph::new(Text::from(self.cached_lines.join("\n")))
                    .block(block)
                    .wrap(Wrap { trim: false })
                    .scroll((app.content_scroll, 0));
                frame.render_widget(para, area);
            }
            UtilScreen::HsmBrowser => {
                let block = Block::default()
                    .borders(Borders::ALL)
                    .title("PKCS#11 / HSM Info  [Esc] back");
                let para = Paragraph::new(Text::from(self.cached_lines.join("\n")))
                    .block(block)
                    .wrap(Wrap { trim: false })
                    .scroll((app.content_scroll, 0));
                frame.render_widget(para, area);
            }
        }
    }
}

impl Component for UtilitiesMode {
    fn handle_key_event(&mut self, key: KeyEvent) -> Action {
        match self.screen {
            UtilScreen::Menu => match key.code {
                KeyCode::Char('1') => Action::UtilScreen(1),
                KeyCode::Char('2') => Action::UtilScreen(2),
                KeyCode::Char('3') => Action::UtilScreen(3),
                _ => Action::Noop,
            },
            // Sub-screens: Esc returns to menu, 'r' refreshes
            _ => match key.code {
                KeyCode::Esc => {
                    self.screen = UtilScreen::Menu;
                    Action::Noop
                }
                KeyCode::Char('r') => {
                    // Signal the app to re-enter the current screen (refresh)
                    let screen_idx = match self.screen {
                        UtilScreen::SystemInfo => 1,
                        UtilScreen::AuditLog => 2,
                        UtilScreen::HsmBrowser => 3,
                        UtilScreen::Menu => return Action::Noop,
                    };
                    Action::UtilScreen(screen_idx)
                }
                _ => Action::Noop,
            },
        }
    }

    fn render(&self, frame: &mut Frame, area: Rect) {
        // Fallback — render_with_app is preferred
        let block = Block::default()
            .borders(Borders::ALL)
            .title("Utilities");
        let para = Paragraph::new(Text::from("  Press F3 to enter Utilities"))
            .block(block)
            .wrap(Wrap { trim: false });
        frame.render_widget(para, area);
    }
}
