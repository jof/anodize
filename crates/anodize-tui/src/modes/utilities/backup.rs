use anodize_hsm::{BackupResult, BackupTarget, HsmBackup};
use secrecy::SecretString;

/// Return value from key-dispatch helpers so callers know when to execute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupAction {
    /// No special action needed.
    Noop,
    /// The FSM is in Confirm and Enter was pressed — caller should run execute().
    Execute,
}

/// FSM states for the backup sub-screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackupPhase {
    /// Enumerating connected devices/tokens.
    Discover,
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
    /// Operation in progress (or just completed).
    Execute,
    /// Showing verification results.
    Done,
    /// An error occurred.
    Error(String),
}

/// Persistent state for the HSM Key Backup sub-screen.
pub struct BackupState {
    pub phase: BackupPhase,
    pub targets: Vec<BackupTarget>,
    pub source_idx: Option<usize>,
    pub dest_idx: Option<usize>,
    /// Which action the user chose: true = pair, false = backup.
    pub action_is_pair: bool,
    pub result: Option<BackupResult>,
    pub wrap_key_desc: Option<String>,
    /// Rendered lines for the current phase.
    pub lines: Vec<String>,
}

impl BackupState {
    pub fn new() -> Self {
        Self {
            phase: BackupPhase::Discover,
            targets: Vec::new(),
            source_idx: None,
            dest_idx: None,
            action_is_pair: false,
            result: None,
            wrap_key_desc: None,
            lines: Vec::new(),
        }
    }

    /// Reset to initial state.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Run device discovery and advance to SelectSource.
    pub fn discover(&mut self, backup: &dyn HsmBackup, pin: Option<&SecretString>) {
        match backup.enumerate_backup_targets(pin) {
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
        self.render_lines();
    }

    /// Handle a numbered key press for source/dest selection.
    pub fn select(&mut self, idx: usize) {
        match self.phase {
            BackupPhase::SelectSource => {
                if idx < self.targets.len() {
                    self.source_idx = Some(idx);
                    self.phase = BackupPhase::SelectDest;
                    self.render_lines();
                }
            }
            BackupPhase::SelectDest => {
                if idx < self.targets.len() && Some(idx) != self.source_idx {
                    self.dest_idx = Some(idx);
                    self.phase = BackupPhase::Overview;
                    self.render_lines();
                }
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

    /// Advance from Overview to ChooseAction.
    pub fn confirm_overview(&mut self) {
        if self.phase == BackupPhase::Overview {
            self.phase = BackupPhase::ChooseAction;
            self.render_lines();
        }
    }

    /// Execute the chosen action (pair or backup).
    pub fn execute(&mut self, backup: &dyn HsmBackup, pin: &SecretString) {
        if self.phase != BackupPhase::Confirm {
            return;
        }
        let src = self.targets[self.source_idx.unwrap()].identifier.clone();
        let dst = self.targets[self.dest_idx.unwrap()].identifier.clone();

        self.phase = BackupPhase::Execute;
        self.render_lines();

        if self.action_is_pair {
            match backup.pair_devices(&src, &dst, pin) {
                Ok(desc) => {
                    self.wrap_key_desc = Some(desc);
                    self.phase = BackupPhase::Done;
                }
                Err(e) => {
                    self.phase = BackupPhase::Error(format!("Pair failed: {e}"));
                }
            }
        } else {
            match backup.backup_key(&src, &dst, pin, "") {
                Ok(result) => {
                    self.result = Some(result);
                    self.phase = BackupPhase::Done;
                }
                Err(e) => {
                    self.phase = BackupPhase::Error(format!("Backup failed: {e}"));
                }
            }
        }
        self.render_lines();
    }

    /// Go back one step.
    pub fn go_back(&mut self) -> bool {
        match self.phase {
            BackupPhase::SelectSource | BackupPhase::Discover => return false, // exit backup screen
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
            BackupPhase::Done | BackupPhase::Error(_) | BackupPhase::Execute => {
                self.reset();
            }
        }
        self.render_lines();
        true
    }

    /// Build display lines for the current phase.
    pub fn render_lines(&mut self) {
        self.lines.clear();

        match &self.phase {
            BackupPhase::Discover => {
                self.lines.push("  Discovering HSM devices...".into());
            }
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
                    "  Source: {} — {}",
                    src.identifier, src.description
                ));
                self.lines.push(format!(
                    "    Wrap key: {}  Signing key: {}",
                    if src.has_wrap_key { "yes" } else { "no" },
                    if src.has_signing_key { "yes" } else { "no" },
                ));
                self.lines.push(String::new());
                self.lines.push(format!(
                    "  Dest:   {} — {}",
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
                    .push("  [1]  Pair — install shared wrap key on both devices".into());
                self.lines
                    .push("  [2]  Backup — export key from source, import into dest".into());
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
            BackupPhase::Execute => {
                self.lines.push("  Executing...".into());
            }
            BackupPhase::Done => {
                if self.action_is_pair {
                    let desc = self.wrap_key_desc.as_deref().unwrap_or("?");
                    self.lines.push("  ✓ Pair complete".into());
                    self.lines.push(String::new());
                    self.lines.push(format!("  Wrap key: {desc}"));
                    self.lines.push(format!(
                        "  Source: {}",
                        self.targets[self.source_idx.unwrap()].identifier
                    ));
                    self.lines.push(format!(
                        "  Dest:   {}",
                        self.targets[self.dest_idx.unwrap()].identifier
                    ));
                } else if let Some(ref r) = self.result {
                    let status = if r.public_keys_match {
                        "✓ PUBLIC KEYS MATCH"
                    } else {
                        "✗ PUBLIC KEYS DO NOT MATCH"
                    };
                    self.lines.push(format!("  {status}"));
                    self.lines.push(String::new());
                    self.lines.push(format!("  Key:    {}", r.key_id));
                    self.lines.push(format!("  Source: {}", r.source_id));
                    self.lines.push(format!("  Dest:   {}", r.dest_id));
                }
                self.lines.push(String::new());
                self.lines.push("  Press [Esc] to return".into());
            }
            BackupPhase::Error(msg) => {
                self.lines.push(format!("  Error: {msg}"));
                self.lines.push(String::new());
                self.lines.push("  Press [Esc] to return".into());
            }
        }
    }

    /// Handle a digit key press (1-based). Returns Execute if the confirm step should run.
    pub fn handle_key_digit(&mut self, digit: u8) -> BackupAction {
        if digit == 0 {
            return BackupAction::Noop;
        }
        let idx = (digit - 1) as usize;
        self.select(idx);
        BackupAction::Noop
    }

    /// Handle an Enter key press. Returns Execute if the confirm step should run.
    pub fn handle_enter(&mut self) -> BackupAction {
        match self.phase {
            BackupPhase::Overview => {
                self.confirm_overview();
                BackupAction::Noop
            }
            BackupPhase::Confirm => BackupAction::Execute,
            _ => BackupAction::Noop,
        }
    }

    fn append_target_list(&mut self, skip: Option<usize>) {
        for (i, t) in self.targets.iter().enumerate() {
            let marker = if skip == Some(i) {
                "  -  "
            } else {
                &format!("  [{}]  ", i + 1)
            };
            let flags = format!(
                "{}{}{}",
                if t.needs_bootstrap { " [factory]" } else { "" },
                if t.has_wrap_key { " [wrap]" } else { "" },
                if t.has_signing_key { " [key]" } else { "" },
            );
            self.lines.push(format!(
                "{marker}{} — {}{flags}",
                t.identifier, t.description
            ));
        }
    }
}
