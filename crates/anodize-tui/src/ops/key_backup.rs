//! KeyBackup operation context.
//!
//! Absorbs the former `BackupState` FSM from `modes/utilities/backup.rs`.
//! The full lifecycle lives in `BackupCtx`: quorum → device discovery →
//! source/dest selection → action choice → confirm → execute → done.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use ratatui::Frame;

use anodize_hsm::{BackupResult, BackupTarget};

use super::{ConfirmTarget, OpAction, OpContext, OpEnv};
use crate::media::{IsoFile, SessionEntry};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackupPhase {
    /// Collecting threshold shares to reconstruct PIN.
    Quorum,
    /// Displaying device list, waiting for source selection.
    SelectSource,
    /// Waiting for dest selection (source already chosen).
    SelectDest,
    /// Showing key inventory on both devices.
    Overview,
    /// Offering Pair or Backup action.
    ChooseAction,
    /// Confirmation prompt before executing.
    Confirm,
    /// An error occurred (user presses Esc to abort).
    Error(String),
}

pub struct BackupCtx {
    pub phase: BackupPhase,
    // Quorum
    pub share_input: Option<crate::components::share_input::ShareInput>,
    pub pin_hex: Option<String>,
    // Device selection (absorbed from BackupState)
    pub targets: Vec<BackupTarget>,
    pub source_idx: Option<usize>,
    pub dest_idx: Option<usize>,
    /// true = pair, false = backup.
    pub action_is_pair: bool,
    pub result: Option<BackupResult>,
    pub wrap_key_desc: Option<String>,
    /// Pre-rendered lines for device-selection phases.
    pub lines: Vec<String>,
}

impl BackupCtx {
    pub fn new(sss_meta: anodize_config::state::SssMetadata) -> Self {
        let share_input = Some(crate::components::share_input::ShareInput::new(
            sss_meta, 32,
        ));
        Self {
            phase: BackupPhase::Quorum,
            share_input,
            pin_hex: None,
            targets: Vec::new(),
            source_idx: None,
            dest_idx: None,
            action_is_pair: false,
            result: None,
            wrap_key_desc: None,
            lines: Vec::new(),
        }
    }

    // ── quorum completion ────────────────────────────────────────────────

    fn try_quorum_complete(&mut self, shared: &mut OpEnv<'_>) -> OpAction {
        let shares: Vec<anodize_sss::Share> = self
            .share_input
            .as_ref()
            .map(|si| si.collected.iter().map(|c| c.share.clone()).collect())
            .unwrap_or_default();
        self.share_input = None;
        match shared.quorum_complete(&shares) {
            Ok(()) => {
                self.pin_hex = Some(shared.pin_buf.clone());
                // Discover backup-capable devices.
                self.discover_devices(shared);
                OpAction::Noop
            }
            Err(e) => {
                shared.set_status(e.to_string());
                OpAction::Abort
            }
        }
    }

    fn discover_devices(&mut self, shared: &mut OpEnv<'_>) {
        let Some(profile) = shared.profile else {
            self.phase = BackupPhase::Error("No profile loaded.".into());
            self.render_lines();
            return;
        };
        match anodize_hsm::create_backup(profile.hsm.backend) {
            Ok(backup_impl) => {
                let pin = secrecy::SecretString::new(self.pin_hex.clone().unwrap_or_default());
                match backup_impl.enumerate_backup_targets(Some(&pin)) {
                    Ok(targets) => {
                        self.targets = targets;
                        if self.targets.is_empty() {
                            self.phase = BackupPhase::Error("No HSM devices/tokens found.".into());
                        } else {
                            self.phase = BackupPhase::SelectSource;
                        }
                    }
                    Err(e) => {
                        self.phase = BackupPhase::Error(format!("Discovery failed: {e}"));
                    }
                }
            }
            Err(e) => {
                self.phase = BackupPhase::Error(format!("Backend init: {e}"));
            }
        }
        self.render_lines();
        shared.set_status("PIN verified. Select source and destination devices.");
        tracing::info!("KeyBackup: quorum reached, PIN verified, entering device selection");
    }

    // ── device-selection helpers (absorbed from BackupState) ─────────────

    fn select(&mut self, idx: usize) {
        match self.phase {
            BackupPhase::SelectSource if idx < self.targets.len() => {
                self.source_idx = Some(idx);
                self.phase = BackupPhase::SelectDest;
                self.render_lines();
            }
            BackupPhase::SelectDest if idx < self.targets.len() && Some(idx) != self.source_idx => {
                self.dest_idx = Some(idx);
                self.phase = BackupPhase::Overview;
                self.render_lines();
            }
            BackupPhase::ChooseAction => {
                match idx {
                    0 => {
                        self.action_is_pair = true;
                        self.phase = BackupPhase::Confirm;
                    }
                    1 => {
                        self.action_is_pair = false;
                        self.phase = BackupPhase::Confirm;
                    }
                    _ => {}
                }
                self.render_lines();
            }
            _ => {}
        }
    }

    fn go_back(&mut self) -> bool {
        match self.phase {
            BackupPhase::SelectSource => return false,
            BackupPhase::SelectDest => {
                self.source_idx = None;
                self.phase = BackupPhase::SelectSource;
            }
            BackupPhase::Overview => {
                self.dest_idx = None;
                self.phase = BackupPhase::SelectDest;
            }
            BackupPhase::ChooseAction => {
                self.phase = BackupPhase::Overview;
            }
            BackupPhase::Confirm => {
                self.phase = BackupPhase::ChooseAction;
            }
            BackupPhase::Error(_) => return false,
            BackupPhase::Quorum => return false,
        }
        self.render_lines();
        true
    }

    /// Execute the chosen action (pair or backup).
    fn do_execute(&mut self, shared: &mut OpEnv<'_>) {
        let Some(profile) = shared.profile else {
            self.phase = BackupPhase::Error("No profile loaded.".into());
            self.render_lines();
            return;
        };
        let pin = secrecy::SecretString::new(self.pin_hex.clone().unwrap_or_default());
        let src = self.targets[self.source_idx.unwrap()].identifier.clone();
        let dst = self.targets[self.dest_idx.unwrap()].identifier.clone();

        match anodize_hsm::create_backup(profile.hsm.backend) {
            Ok(backup_impl) => {
                if self.action_is_pair {
                    match backup_impl.pair_devices(&src, &dst, &pin) {
                        Ok(desc) => {
                            self.wrap_key_desc = Some(desc);
                        }
                        Err(e) => {
                            self.phase = BackupPhase::Error(format!("Pair failed: {e}"));
                            self.render_lines();
                            return;
                        }
                    }
                } else {
                    match backup_impl.backup_key(&src, &dst, &pin, "") {
                        Ok(result) => {
                            self.result = Some(result);
                        }
                        Err(e) => {
                            self.phase = BackupPhase::Error(format!("Backup failed: {e}"));
                            self.render_lines();
                            return;
                        }
                    }
                }
            }
            Err(e) => {
                self.phase = BackupPhase::Error(format!("Backend init: {e}"));
                self.render_lines();
                return;
            }
        }

        // Enroll the destination device in the fleet if operation succeeded.
        if let Some(dest_idx) = self.dest_idx {
            let dest_id = self.targets[dest_idx].identifier.clone();
            let dest_desc = self.targets[dest_idx].description.clone();
            let backend_kind = profile.hsm.backend;

            if let Some(ref mut state) = shared.disc.session_state {
                let already = state.fleet.devices.iter().any(|d| d.device_id == dest_id);
                if !already {
                    let now = {
                        let d = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default();
                        format!("{}Z", d.as_secs())
                    };
                    use anodize_config::state::{HsmDevice, HsmDeviceStatus};
                    state.fleet.devices.push(HsmDevice {
                        device_id: dest_id.clone(),
                        model: dest_desc,
                        backend: backend_kind,
                        enrolled_at: now.clone(),
                        last_seen_at: now,
                        status: HsmDeviceStatus::Active,
                    });
                    tracing::info!(
                        device_id = %dest_id,
                        fleet_size = state.fleet.devices.len(),
                        "KeyBackup: enrolled destination device in fleet"
                    );
                }
            }
        }
    }

    // ── rendering helpers ────────────────────────────────────────────────

    fn render_lines(&mut self) {
        self.lines.clear();
        match &self.phase {
            BackupPhase::Quorum => {}
            BackupPhase::SelectSource => {
                self.lines.push("  Select SOURCE device:".into());
                self.lines.push(String::new());
                self.append_target_list(None);
                self.lines.push(String::new());
                self.lines
                    .push("  Press [1]-[9] to select, [Esc] back".into());
            }
            BackupPhase::SelectDest => {
                let src_name = &self.targets[self.source_idx.unwrap()].identifier;
                self.lines.push(format!("  Source: {src_name}"));
                self.lines.push(String::new());
                self.lines.push("  Select DESTINATION device:".into());
                self.lines.push(String::new());
                self.append_target_list(self.source_idx);
                self.lines.push(String::new());
                self.lines
                    .push("  Press [1]-[9] to select, [Esc] back".into());
            }
            BackupPhase::Overview => {
                let src = &self.targets[self.source_idx.unwrap()];
                let dst = &self.targets[self.dest_idx.unwrap()];
                self.lines.push("  Device Overview:".into());
                self.lines.push(String::new());
                self.lines.push(format!(
                    "  Source: {} \u{2014} {}",
                    src.identifier, src.description
                ));
                self.lines.push(format!(
                    "    Wrap key: {}  Signing key: {}",
                    if src.has_wrap_key { "yes" } else { "no" },
                    if src.has_signing_key { "yes" } else { "no" },
                ));
                self.lines.push(String::new());
                self.lines.push(format!(
                    "  Dest:   {} \u{2014} {}",
                    dst.identifier, dst.description
                ));
                self.lines.push(format!(
                    "    Wrap key: {}  Signing key: {}",
                    if dst.has_wrap_key { "yes" } else { "no" },
                    if dst.has_signing_key { "yes" } else { "no" },
                ));
                self.lines.push(String::new());
                self.lines
                    .push("  Press [Enter] to continue, [Esc] back".into());
            }
            BackupPhase::ChooseAction => {
                self.lines.push("  Choose action:".into());
                self.lines.push(String::new());
                self.lines
                    .push("  [1]  Pair \u{2014} install shared wrap key on both devices".into());
                self.lines
                    .push("  [2]  Backup \u{2014} export key from source, import into dest".into());
                self.lines.push(String::new());
                self.lines.push("  [Esc] back".into());
            }
            BackupPhase::Confirm => {
                let src = &self.targets[self.source_idx.unwrap()].identifier;
                let dst = &self.targets[self.dest_idx.unwrap()].identifier;
                let action = if self.action_is_pair {
                    "PAIR (install wrap key)"
                } else {
                    "BACKUP (export/import signing key)"
                };
                self.lines.push("  Confirm operation:".into());
                self.lines.push(String::new());
                self.lines.push(format!("  Action:  {action}"));
                self.lines.push(format!("  Source:  {src}"));
                self.lines.push(format!("  Dest:    {dst}"));
                self.lines.push(String::new());
                self.lines
                    .push("  Press [Enter] to execute, [Esc] cancel".into());
            }
            BackupPhase::Error(msg) => {
                self.lines.push(format!("  Error: {msg}"));
                self.lines.push(String::new());
                self.lines.push("  Press [Esc] to return".into());
            }
        }
    }

    fn append_target_list(&mut self, skip: Option<usize>) {
        for (i, t) in self.targets.iter().enumerate() {
            let marker = if skip == Some(i) {
                "  -  ".to_string()
            } else {
                format!("  [{}]  ", i + 1)
            };
            let flags = format!(
                "{}{}{}",
                if t.needs_bootstrap { " [factory]" } else { "" },
                if t.has_wrap_key { " [wrap]" } else { "" },
                if t.has_signing_key { " [key]" } else { "" },
            );
            self.lines.push(format!(
                "{marker}{} \u{2014} {}{flags}",
                t.identifier, t.description
            ));
        }
    }

    // ── public accessors for build_intent_audit_event / build_burn_session ──

    pub fn source_id(&self) -> String {
        self.source_idx
            .and_then(|i| self.targets.get(i))
            .map(|t| t.identifier.clone())
            .unwrap_or_default()
    }

    pub fn dest_id(&self) -> String {
        self.dest_idx
            .and_then(|i| self.targets.get(i))
            .map(|t| t.identifier.clone())
            .unwrap_or_default()
    }

    pub fn succeeded(&self) -> bool {
        // If we're not in Error phase after execute, it succeeded.
        !matches!(self.phase, BackupPhase::Error(_))
    }
}

impl OpContext for BackupCtx {
    fn phase_index(&self) -> usize {
        match self.phase {
            BackupPhase::Quorum => 3,
            _ => 1,
        }
    }

    fn title(&self) -> &str {
        match self.phase {
            BackupPhase::Quorum => "Key Backup \u{2014} Reconstruct PIN",
            BackupPhase::Error(_) => "Key Backup \u{2014} Error",
            _ => "Key Backup \u{2014} Device Selection",
        }
    }

    fn build_body(&self) -> Vec<String> {
        match self.phase {
            BackupPhase::Quorum => {
                vec![
                    String::new(),
                    "  Collecting threshold shares to reconstruct the HSM PIN.".into(),
                    String::new(),
                    "  The share input component is active.".into(),
                    "  [Esc]  Abort".into(),
                ]
            }
            _ => self.lines.clone(),
        }
    }

    fn handle_key(&mut self, key: KeyEvent, shared: &mut OpEnv<'_>) -> OpAction {
        match self.phase {
            BackupPhase::Quorum => {
                if key.code == KeyCode::Esc {
                    return OpAction::Abort;
                }
                if let Some(ref mut si) = self.share_input {
                    si.handle_key(key);
                    if si.quorum_reached() {
                        return self.try_quorum_complete(shared);
                    }
                }
                OpAction::Noop
            }
            BackupPhase::Error(_) => {
                if key.code == KeyCode::Esc {
                    return OpAction::Abort;
                }
                OpAction::Noop
            }
            BackupPhase::Confirm => match key.code {
                KeyCode::Enter => OpAction::ShowConfirm {
                    title: "Execute HSM Operation".into(),
                    body: vec![
                        format!(
                            "Action: {}",
                            if self.action_is_pair {
                                "PAIR (install wrap key)"
                            } else {
                                "BACKUP (export/import signing key)"
                            }
                        ),
                        format!("Source: {}", self.source_id()),
                        format!("Dest:   {}", self.dest_id()),
                    ],
                    on_confirm: ConfirmTarget::WriteIntent,
                },
                KeyCode::Esc => {
                    self.go_back();
                    OpAction::Noop
                }
                _ => OpAction::Noop,
            },
            BackupPhase::Overview => match key.code {
                KeyCode::Enter => {
                    self.phase = BackupPhase::ChooseAction;
                    self.render_lines();
                    OpAction::Noop
                }
                KeyCode::Esc => {
                    self.go_back();
                    OpAction::Noop
                }
                _ => OpAction::Noop,
            },
            // SelectSource, SelectDest, ChooseAction
            _ => {
                if key.code == KeyCode::Esc {
                    if !self.go_back() {
                        return OpAction::Abort;
                    }
                    return OpAction::Noop;
                }
                if let KeyCode::Char(c) = key.code {
                    if let Some(d) = c.to_digit(10) {
                        if d > 0 {
                            self.select((d - 1) as usize);
                        }
                    }
                }
                OpAction::Noop
            }
        }
    }

    fn holds_ephemeral_state(&self) -> bool {
        true
    }

    fn needs_abort_confirmation(&self) -> bool {
        !matches!(self.phase, BackupPhase::Error(_))
    }

    fn in_text_entry(&self) -> bool {
        matches!(self.phase, BackupPhase::Quorum)
    }

    fn render_overlay(&self, frame: &mut Frame, area: Rect) {
        if let Some(ref input) = self.share_input {
            input.render(frame, area);
        }
    }

    fn build_intent_audit_event(
        &self,
        genesis_hex: &str,
        _shared: &OpEnv<'_>,
    ) -> Option<(String, serde_json::Value)> {
        let action = if self.action_is_pair {
            "pair-devices"
        } else {
            "backup-signing-key"
        };
        Some((
            "hsm.backup.intent".into(),
            serde_json::json!({
                "operation": action,
                "source": self.source_id(),
                "destination": self.dest_id(),
                "profile_toml_sha256": genesis_hex,
            }),
        ))
    }

    fn build_record_session(
        &mut self,
        dir_name: String,
        ts: std::time::SystemTime,
        staging: &std::path::Path,
        shared: &mut OpEnv<'_>,
    ) -> Option<SessionEntry> {
        use anodize_audit::AuditLog;

        let log_path = staging.join("audit.log");
        let mut log = match AuditLog::open(&log_path) {
            Ok(l) => l,
            Err(e) => {
                shared.set_status(format!("Audit log reopen failed: {e}"));
                return None;
            }
        };

        let event_name = if self.action_is_pair {
            "hsm.backup.pair"
        } else {
            "hsm.backup.key"
        };
        let pk_match = self.result.as_ref().map(|r| r.public_keys_match);
        if let Err(e) = log.append(
            event_name,
            serde_json::json!({
                "operation": if self.action_is_pair { "pair-devices" } else { "backup-signing-key" },
                "source": self.source_id(),
                "destination": self.dest_id(),
                "success": self.succeeded(),
                "wrap_key": self.wrap_key_desc.as_deref().unwrap_or(""),
                "public_keys_match": pk_match,
            }),
        ) {
            shared.set_status(format!("Audit log append failed: {e}"));
            return None;
        }
        drop(log);

        let audit_bytes = match std::fs::read(&log_path) {
            Ok(b) => b,
            Err(e) => {
                shared.set_status(format!("Cannot read audit log: {e}"));
                return None;
            }
        };

        Some(SessionEntry {
            dir_name,
            timestamp: ts,
            files: vec![IsoFile {
                name: "AUDIT.LOG".into(),
                data: audit_bytes,
            }],
        })
    }

    fn advance_after_intent_burn(&mut self, shared: &mut OpEnv<'_>) {
        // Intent burned → execute the backup/pair operation, then record burn happens.
        self.do_execute(shared);
        if self.succeeded() {
            shared.set_status("Backup succeeded. Writing record to disc\u{2026}");
        } else {
            shared.set_status("Backup failed \u{2014} recording result to disc\u{2026}");
        }
    }
}
