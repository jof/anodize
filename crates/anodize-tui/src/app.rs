use std::path::PathBuf;
use std::time::SystemTime;

use anodize_config::Profile;
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
use crate::components::status_bar::StatusBar;
use crate::components::Component;
use crate::disc::DiscContext;
use crate::hardware::HardwareManager;
use crate::modes;
use crate::modes::ceremony::CeremonyMode;
use crate::modes::ceremony::CeremonyPhase;
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

    // Sub-contexts
    pub hw: HardwareManager,
    pub disc: DiscContext,

    // Mode components
    pub setup: SetupMode,
    pub ceremony: CeremonyMode,
    pub utilities: UtilitiesMode,

    // Setup completion flag — gates Ceremony mode
    pub setup_complete: bool,

    // CLI flags
    pub shuttle_mount: PathBuf,

    // Clock
    pub confirmed_time: Option<SystemTime>,

    // Shuttle / Profile
    pub profile: Option<Profile>,
    pub profile_toml_bytes: Option<Vec<u8>>,

    // Two-key confirmation dialog (modal overlay)
    pub confirm_dialog: Option<ConfirmDialog>,

    // Content area vertical scroll offset
    pub content_scroll: u16,

    // When `Some`, the Ceremony mode is driving a coroutine-based ceremony.
    pub ceremony_run: Option<crate::ceremony::run::CeremonyRun>,
}

impl App {
    pub fn new(shuttle_mount: PathBuf) -> Self {
        Self {
            running: true,
            mode: Mode::Setup,
            status: "Welcome to Anodize Root CA Ceremony.".into(),
            log_lines: Vec::new(),
            log_view: false,
            log_scroll: 0,

            hw: HardwareManager::new(),
            disc: DiscContext::new(),

            setup: SetupMode::new(),
            ceremony: CeremonyMode::new(),
            utilities: UtilitiesMode::new(),

            setup_complete: false,
            shuttle_mount,

            confirmed_time: None,
            profile: None,
            profile_toml_bytes: None,
            confirm_dialog: None,
            content_scroll: 0,
            ceremony_run: None,
        }
    }

    /// Start the InitRoot ceremony. No existing
    /// STATE.JSON is required — this is the genesis operation.
    pub fn start_init_root(&mut self) {
        use crate::ceremony::io::{Env, InitRootPlan, RootCertParams};
        use crate::ceremony::run::{CeremonyRun, VaultConfig};
        use anodize_config::state::SssMetadata;

        let Some(profile) = self.profile.as_ref() else {
            self.set_status("No profile loaded.");
            return;
        };

        let env = Env {
            sss: SssMetadata {
                generation: 0,
                threshold: 0,
                total: 0,
                custodians: Vec::new(),
                pin_verify_hash: String::new(),
                share_commitments: Vec::new(),
            },
            plan: InitRootPlan {
                ca: RootCertParams {
                    common_name: profile.ca.common_name.clone(),
                    organization: profile.ca.organization.clone(),
                    country: profile.ca.country.clone(),
                    state: profile.ca.state.clone(),
                    validity_days: 7305,
                },
            },
        };
        let vault = VaultConfig {
            backend: profile.hsm.backend,
            token_label: profile.hsm.token_label.clone(),
            key_label: profile.hsm.key_label.clone(),
            fleet_ids: Vec::new(), // no existing fleet
        };
        let archive = self.archive_config();

        self.ceremony_run = Some(CeremonyRun::spawn_init_root(env, vault, archive));
        self.ceremony.state = CeremonyPhase::OperationSelect;
        self.set_status("InitRoot ceremony started.");
    }

    /// Start the IssueCrl ceremony. Builds the read-only `Env` plus
    /// vault/archive configs from live setup + disc state, then spawns the
    /// coroutine.
    pub fn start_issue_crl(&mut self) {
        use crate::ceremony::io::{CrlPlan, Env};
        use crate::ceremony::run::{CeremonyRun, VaultConfig};
        use crate::helpers::{
            load_revocation_from_sessions, load_root_cert_der_from_sessions,
            next_crl_number_from_sessions,
        };

        let Some(profile) = self.profile.as_ref() else {
            self.set_status("No profile loaded.");
            return;
        };
        let Some(state) = self.disc.session_state.as_ref() else {
            self.set_status("No STATE.JSON on disc \u{2014} run InitRoot first.");
            return;
        };
        let Some(root_cert_der) = load_root_cert_der_from_sessions(&self.disc.prior_sessions)
        else {
            self.set_status("No ROOT.CRT found on disc. Generate root CA first.");
            return;
        };

        let env = Env {
            sss: state.sss.clone(),
            plan: CrlPlan {
                crl_number: next_crl_number_from_sessions(&self.disc.prior_sessions),
                revocation_list: load_revocation_from_sessions(&self.disc.prior_sessions),
                root_cert_der,
            },
        };
        let vault = VaultConfig {
            backend: profile.hsm.backend,
            token_label: profile.hsm.token_label.clone(),
            key_label: profile.hsm.key_label.clone(),
            fleet_ids: state
                .fleet
                .active_device_ids()
                .into_iter()
                .map(String::from)
                .collect(),
        };
        let archive = self.archive_config();

        self.ceremony_run = Some(CeremonyRun::spawn_issue_crl(env, vault, archive));
        self.ceremony.state = CeremonyPhase::OperationSelect;
        self.set_status("IssueCrl ceremony started.");
    }

    /// Start the RevokeCert ceremony.
    pub fn start_revoke_cert(&mut self) {
        use crate::ceremony::io::{Env, RevokePlan};
        use crate::ceremony::run::{CeremonyRun, VaultConfig};
        use crate::helpers::{
            gather_cert_list_from_sessions, load_revocation_from_sessions,
            load_root_cert_der_from_sessions, next_crl_number_from_sessions,
        };

        let Some(profile) = self.profile.as_ref() else {
            self.set_status("No profile loaded.");
            return;
        };
        let Some(state) = self.disc.session_state.as_ref() else {
            self.set_status("No STATE.JSON on disc \u{2014} run InitRoot first.");
            return;
        };
        let Some(root_cert_der) = load_root_cert_der_from_sessions(&self.disc.prior_sessions)
        else {
            self.set_status("No ROOT.CRT found on disc. Generate root CA first.");
            return;
        };

        let revocation_list = load_revocation_from_sessions(&self.disc.prior_sessions);
        let cert_list = gather_cert_list_from_sessions(&self.disc.prior_sessions, &revocation_list);
        let env = Env {
            sss: state.sss.clone(),
            plan: RevokePlan {
                cert_list,
                revocation_list,
                crl_number: next_crl_number_from_sessions(&self.disc.prior_sessions),
                root_cert_der,
            },
        };
        let vault = VaultConfig {
            backend: profile.hsm.backend,
            token_label: profile.hsm.token_label.clone(),
            key_label: profile.hsm.key_label.clone(),
            fleet_ids: state
                .fleet
                .active_device_ids()
                .into_iter()
                .map(String::from)
                .collect(),
        };
        let archive = self.archive_config();

        self.ceremony_run = Some(CeremonyRun::spawn_revoke_cert(env, vault, archive));
        self.ceremony.state = CeremonyPhase::OperationSelect;
        self.set_status("RevokeCert ceremony started.");
    }

    /// Start the SignCsr ceremony. Reads + validates
    /// csr.der from the shuttle and pre-renders each profile's preview.
    pub fn start_sign_csr(&mut self) {
        use crate::ceremony::io::{CsrProfileChoice, Env, SignCsrPlan};
        use crate::ceremony::run::{CeremonyRun, VaultConfig};
        use crate::helpers::{
            build_cert_preview, collect_serial_numbers_from_sessions,
            load_root_cert_der_from_sessions,
        };
        use der::Decode as _;

        let Some(profile) = self.profile.as_ref() else {
            self.set_status("No profile loaded.");
            return;
        };
        let Some(state) = self.disc.session_state.as_ref() else {
            self.set_status("No STATE.JSON on disc \u{2014} run InitRoot first.");
            return;
        };
        if profile.cert_profiles.is_empty() {
            self.set_status("No [[cert_profiles]] defined in profile.toml.");
            return;
        }
        let Some(root_cert_der) = load_root_cert_der_from_sessions(&self.disc.prior_sessions)
        else {
            self.set_status("No ROOT.CRT found on disc. Generate root CA first.");
            return;
        };

        let csr_path = self.shuttle_mount.join("csr.der");
        let csr_der = match std::fs::read(&csr_path) {
            Ok(b) => b,
            Err(e) => {
                self.set_status(format!(
                    "Cannot read csr.der from shuttle: {e} \u{2014} ensure csr.der is on the USB."
                ));
                return;
            }
        };
        if let Err(e) = x509_cert::request::CertReq::from_der(&csr_der) {
            self.set_status(format!("csr.der is not a valid DER-encoded CSR: {e}"));
            return;
        }

        let cdp_url = profile.ca.cdp_url.clone();
        let existing_serials = collect_serial_numbers_from_sessions(&self.disc.prior_sessions);
        let profiles: Vec<CsrProfileChoice> = profile
            .cert_profiles
            .iter()
            .enumerate()
            .map(|(i, prof)| {
                let path_str = prof
                    .path_len
                    .map(|n| format!("  path_len={n}"))
                    .unwrap_or_default();
                CsrProfileChoice {
                    name: prof.name.clone(),
                    label: format!(
                        "[{}] {}  (validity={} days{})",
                        i + 1,
                        prof.name,
                        prof.validity_days,
                        path_str
                    ),
                    validity_days: prof.validity_days,
                    path_len: prof.path_len,
                    preview: build_cert_preview(
                        &csr_der,
                        prof,
                        &profile.ca.common_name,
                        &profile.ca.organization,
                        &profile.ca.country,
                        profile.ca.state.as_deref(),
                        cdp_url.as_deref(),
                        Some(root_cert_der.as_slice()),
                    ),
                }
            })
            .collect();

        let env = Env {
            sss: state.sss.clone(),
            plan: SignCsrPlan {
                csr_der,
                root_cert_der,
                cdp_url,
                profiles,
                existing_serials,
            },
        };
        let vault = VaultConfig {
            backend: profile.hsm.backend,
            token_label: profile.hsm.token_label.clone(),
            key_label: profile.hsm.key_label.clone(),
            fleet_ids: state
                .fleet
                .active_device_ids()
                .into_iter()
                .map(String::from)
                .collect(),
        };
        let archive = self.archive_config();

        self.ceremony_run = Some(CeremonyRun::spawn_sign_csr(env, vault, archive));
        self.ceremony.state = CeremonyPhase::OperationSelect;
        self.set_status("SignCsr ceremony started.");
    }

    /// Start the RekeyShares ceremony.
    pub fn start_rekey_shares(&mut self) {
        use crate::ceremony::io::{Env, RekeyPlan};
        use crate::ceremony::run::{CeremonyRun, VaultConfig};

        let Some(profile) = self.profile.as_ref() else {
            self.set_status("No profile loaded.");
            return;
        };
        let Some(state) = self.disc.session_state.as_ref() else {
            self.set_status("No STATE.JSON on disc \u{2014} run InitRoot first.");
            return;
        };

        let env = Env {
            sss: state.sss.clone(),
            plan: RekeyPlan,
        };
        let vault = VaultConfig {
            backend: profile.hsm.backend,
            token_label: profile.hsm.token_label.clone(),
            key_label: profile.hsm.key_label.clone(),
            fleet_ids: state
                .fleet
                .active_device_ids()
                .into_iter()
                .map(String::from)
                .collect(),
        };
        let archive = self.archive_config();

        self.ceremony_run = Some(CeremonyRun::spawn_rekey_shares(env, vault, archive));
        self.ceremony.state = CeremonyPhase::OperationSelect;
        self.set_status("RekeyShares ceremony started.");
    }

    /// Start the KeyBackup ceremony.
    pub fn start_key_backup(&mut self) {
        use crate::ceremony::io::{Env, KeyBackupPlan};
        use crate::ceremony::run::{CeremonyRun, VaultConfig};

        let Some(profile) = self.profile.as_ref() else {
            self.set_status("No profile loaded.");
            return;
        };
        let Some(state) = self.disc.session_state.as_ref() else {
            self.set_status("No STATE.JSON \u{2014} run InitRoot first.");
            return;
        };

        let env = Env {
            sss: state.sss.clone(),
            plan: KeyBackupPlan {
                backend: profile.hsm.backend,
                base_fleet: state.fleet.clone(),
            },
        };
        let vault = VaultConfig {
            backend: profile.hsm.backend,
            token_label: profile.hsm.token_label.clone(),
            key_label: profile.hsm.key_label.clone(),
            fleet_ids: state
                .fleet
                .active_device_ids()
                .into_iter()
                .map(String::from)
                .collect(),
        };
        let archive = self.archive_config();

        self.ceremony_run = Some(CeremonyRun::spawn_key_backup(env, vault, archive));
        self.ceremony.state = CeremonyPhase::OperationSelect;
        self.set_status("KeyBackup ceremony started.");
    }

    /// Start the RefreshDisc ceremony (dev-burn only).
    #[cfg(feature = "dev-burn")]
    pub fn start_refresh_disc(&mut self) {
        use crate::ceremony::io::{Env, RefreshDiscPlan};
        use crate::ceremony::run::CeremonyRun;
        use anodize_config::state::SssMetadata;

        let dir_name = crate::media::session_dir_name(std::time::SystemTime::now());

        let sss = self
            .disc
            .session_state
            .as_ref()
            .map(|s| s.sss.clone())
            .unwrap_or_else(|| SssMetadata {
                generation: 0,
                threshold: 0,
                total: 0,
                custodians: Vec::new(),
                pin_verify_hash: String::new(),
                share_commitments: Vec::new(),
            });

        let env = Env {
            sss,
            plan: RefreshDiscPlan { dir_name },
        };
        let archive = self.archive_config();

        self.ceremony_run = Some(CeremonyRun::spawn_refresh_disc(env, archive));
        self.ceremony.state = CeremonyPhase::OperationSelect;
        self.set_status("RefreshDisc ceremony started.");
    }

    /// Start the MigrateDisc ceremony.
    pub fn start_migrate_disc(&mut self) {
        use crate::ceremony::io::{Env, MigrateDiscPlan, MigrationFile};
        use crate::ceremony::run::CeremonyRun;
        use crate::helpers::verify_audit_chain;
        use anodize_config::state::SssMetadata;

        let sessions = &self.disc.prior_sessions;
        if sessions.is_empty() {
            self.set_status("No sessions on disc to migrate.");
            return;
        }

        let chain_ok = verify_audit_chain(sessions);
        let session_count = sessions.len();
        let total_bytes: u64 = sessions
            .last()
            .map(|s| s.files.iter().map(|f| f.data.len() as u64).sum())
            .unwrap_or(0);
        let source_fingerprint = sessions
            .last()
            .and_then(|s| s.files.iter().find(|f| f.name == "AUDIT.LOG"))
            .and_then(|f| {
                f.data
                    .split(|&b| b == b'\n')
                    .rev()
                    .find(|line| !line.is_empty())
                    .and_then(|line| serde_json::from_slice::<serde_json::Value>(line).ok())
                    .and_then(|v| v.get("entry_hash")?.as_str().map(String::from))
            });
        let files: Vec<MigrationFile> = sessions
            .last()
            .map(|s| {
                s.files
                    .iter()
                    .map(|f| MigrationFile {
                        name: f.name.clone(),
                        data: f.data.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        let sss = self
            .disc
            .session_state
            .as_ref()
            .map(|s| s.sss.clone())
            .unwrap_or_else(|| SssMetadata {
                generation: 0,
                threshold: 0,
                total: 0,
                custodians: Vec::new(),
                pin_verify_hash: String::new(),
                share_commitments: Vec::new(),
            });

        let env = Env {
            sss,
            plan: MigrateDiscPlan {
                session_count,
                chain_ok,
                source_fingerprint,
                total_bytes,
                files,
            },
        };
        let archive = self.archive_config();

        self.ceremony_run = Some(CeremonyRun::spawn_migrate_disc(env, archive));
        self.ceremony.state = CeremonyPhase::OperationSelect;
        self.set_status("MigrateDisc ceremony started.");
    }

    /// Start the ValidateDisc ceremony.
    pub fn start_validate_disc(&mut self) {
        use std::collections::BTreeMap;

        use anodize_audit::validate::{
            format_report, validate_disc_status, validate_session_continuity, DiscStatus, Finding,
            SessionSnapshot, Severity, StateFields,
        };
        use sha2::{Digest, Sha256};

        use crate::ceremony::io::{Env, ValidateDiscPlan};
        use crate::ceremony::run::{CeremonyRun, VaultConfig};

        let Some(profile) = self.profile.as_ref() else {
            self.set_status("No profile loaded.");
            return;
        };

        // Build session snapshots from prior sessions.
        let mut snapshots: Vec<SessionSnapshot> = Vec::new();
        for (i, sess) in self.disc.prior_sessions.iter().enumerate() {
            let file_hashes: BTreeMap<String, String> = sess
                .files
                .iter()
                .map(|f| {
                    let hash = format!("{:x}", Sha256::digest(&f.data));
                    (f.name.clone(), hash)
                })
                .collect();
            let has_migration = file_hashes
                .keys()
                .any(|k| k.eq_ignore_ascii_case("MIGRATION.JSON"));
            let state = if let Some(ref s) = self.disc.session_state {
                StateFields {
                    root_cert_sha256: s.root_cert_sha256.clone(),
                    crl_number: s.crl_number,
                    last_audit_hash: s.last_audit_hash.clone(),
                    last_hsm_log_seq: s.last_hsm_log_seq,
                    is_migration: has_migration,
                    custodian_names: s.sss.custodians.iter().map(|c| c.name.clone()).collect(),
                }
            } else {
                StateFields {
                    root_cert_sha256: String::new(),
                    crl_number: 0,
                    last_audit_hash: String::new(),
                    last_hsm_log_seq: None,
                    is_migration: has_migration,
                    custodian_names: vec![],
                }
            };
            snapshots.push(SessionSnapshot {
                index: i,
                file_hashes,
                audit_records: Vec::new(),
                state,
            });
        }

        // Run disc-level checks.
        let mut findings: Vec<Finding> = Vec::new();
        let disc_status = if self.disc.optical_dev.is_some() {
            DiscStatus::Incomplete
        } else {
            DiscStatus::Blank
        };
        findings.extend(validate_disc_status(disc_status));
        findings.extend(validate_session_continuity(&snapshots));

        // Audit chain check.
        let staging_log = std::path::PathBuf::from("/run/anodize/staging/audit.log");
        if staging_log.exists() {
            match anodize_audit::verify_log(&staging_log) {
                Ok(_count) => {
                    findings.push(Finding {
                        severity: Severity::Pass,
                        check: "audit_chain".into(),
                        message: "Audit log hash chain verified".into(),
                    });
                }
                Err(e) => {
                    findings.push(Finding {
                        severity: Severity::Error,
                        check: "audit_chain".into(),
                        message: format!("Audit log hash chain FAILED: {e}"),
                    });
                }
            }
        } else {
            findings.push(Finding {
                severity: Severity::Warn,
                check: "audit_chain".into(),
                message: "No staging audit log found".into(),
            });
        }

        let initial_report = format_report(&findings);
        let has_hsm = self.hw.actor.is_some();
        let staging_audit_bytes = std::fs::read(&staging_log).ok();
        let last_hsm_log_seq = self
            .disc
            .session_state
            .as_ref()
            .and_then(|s| s.last_hsm_log_seq);

        let sss = self
            .disc
            .session_state
            .as_ref()
            .map(|s| s.sss.clone())
            .unwrap_or_else(|| anodize_config::state::SssMetadata {
                generation: 0,
                threshold: 0,
                total: 0,
                custodians: vec![],
                pin_verify_hash: String::new(),
                share_commitments: vec![],
            });

        let env = Env {
            sss,
            plan: ValidateDiscPlan {
                initial_report,
                has_hsm,
                staging_audit_bytes,
                last_hsm_log_seq,
            },
        };
        let vault = VaultConfig {
            backend: profile.hsm.backend,
            token_label: profile.hsm.token_label.clone(),
            key_label: profile.hsm.key_label.clone(),
            fleet_ids: self
                .disc
                .session_state
                .as_ref()
                .map(|s| {
                    s.fleet
                        .active_device_ids()
                        .into_iter()
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default(),
        };
        let archive = self.archive_config();

        self.ceremony_run = Some(CeremonyRun::spawn_validate_disc(env, vault, archive));
        self.ceremony.state = CeremonyPhase::OperationSelect;
        self.set_status("ValidateDisc ceremony started.");
    }

    /// Build the disc/shuttle archive configuration from live disc state.
    fn archive_config(&self) -> crate::ceremony::run::ArchiveConfig {
        crate::ceremony::run::ArchiveConfig {
            dev: self.disc.optical_dev.clone(),
            prior_sessions: self.disc.prior_sessions.clone(),
            shuttle_mount: self.shuttle_mount.clone(),
            staging: PathBuf::from("/run/anodize/staging"),
            profile_bytes: self.profile_toml_bytes.clone().unwrap_or_default(),
            timestamp: SystemTime::now(),
            sessions_remaining: self.disc.sessions_remaining,
            base_state: self.disc.session_state.clone(),
        }
    }

    /// Dismiss a finished ceremony run and replay setup (HSM + disc) checks.
    fn finish_ceremony_run(&mut self) {
        if let Some(run) = self.ceremony_run.take() {
            run.join();
        }
        self.disc = DiscContext::new();
        self.do_detect_hsm();
        self.mode = Mode::Setup;
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

        // Ctrl+C: quit with confirmation (blocked during ephemeral ceremony phases)
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            let blocked = if self.mode == Mode::Ceremony {
                // A live script ceremony holds ephemeral state (PIN, HSM
                // session) until it reaches a terminal prompt.
                self.ceremony_run
                    .as_ref()
                    .is_some_and(|run| !run.is_finished())
            } else {
                false
            };
            if blocked {
                self.set_status("Ctrl+C blocked: press Esc to go back to the menu first.");
                return Action::Noop;
            }
            self.show_quit_confirm();
            return Action::Noop;
        }

        // F12: toggle log view (always available, even during text entry)
        if key.code == KeyCode::F(12) {
            self.log_view = !self.log_view;
            if self.log_view {
                self.log_scroll = u16::MAX;
            }
            return Action::Noop;
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
                        &self.disc, None,
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

        // Disc sync has its own scroll/navigation — intercept before global scroll
        if self.mode == Mode::Utilities
            && self.utilities.screen == crate::modes::utilities::UtilScreen::DiscSync
        {
            use crate::modes::utilities::disc_sync::SyncAction;
            let (consumed, deferred) = self.utilities.disc_sync.handle_key(key);
            match deferred {
                SyncAction::ScanSource => {
                    if let Some(ref dev) = self.disc.optical_dev {
                        if let Err(e) = self.utilities.disc_sync.do_scan_source(dev) {
                            self.utilities.disc_sync.phase =
                                crate::modes::utilities::disc_sync::SyncPhase::Error(e);
                        }
                    } else {
                        self.utilities.disc_sync.phase =
                            crate::modes::utilities::disc_sync::SyncPhase::Error(
                                "No optical device detected".into(),
                            );
                    }
                }
                SyncAction::ScanTarget => {
                    if let Some(ref dev) = self.disc.optical_dev {
                        if let Err(e) = self.utilities.disc_sync.do_scan_target(dev) {
                            self.utilities.disc_sync.phase =
                                crate::modes::utilities::disc_sync::SyncPhase::Error(e);
                        }
                    } else {
                        self.utilities.disc_sync.phase =
                            crate::modes::utilities::disc_sync::SyncPhase::Error(
                                "No optical device detected".into(),
                            );
                    }
                }
                SyncAction::StartWrite => {
                    if let Some(ref dev) = self.disc.optical_dev {
                        self.utilities.disc_sync.start_writing(dev);
                    } else {
                        self.utilities.disc_sync.phase =
                            crate::modes::utilities::disc_sync::SyncPhase::Error(
                                "No optical device detected".into(),
                            );
                    }
                }
                SyncAction::None => {}
            }
            if consumed {
                return Action::Noop;
            }
            // Esc not consumed → back to menu, reset sync state
            if key.code == KeyCode::Esc {
                self.utilities.disc_sync.reset();
                self.utilities.screen = crate::modes::utilities::UtilScreen::Menu;
                return Action::Noop;
            }
        }

        // Content scrolling (arrow keys when not in text entry).
        // Skip when a ceremony run is active — it handles its own scroll.
        let in_text_entry = self.mode == Mode::Ceremony
            && if let Some(run) = self.ceremony_run.as_ref() {
                run.wants_text_input()
            } else {
                self.ceremony.in_text_entry()
            };
        if !in_text_entry && self.ceremony_run.is_none() {
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
            Mode::Ceremony => {
                // When a ceremony run is active, keys go to the coroutine
                // or dismiss a finished run.
                if self.ceremony_run.is_some() {
                    let finished = self
                        .ceremony_run
                        .as_ref()
                        .map(|r| r.is_finished())
                        .unwrap_or(true);
                    if finished {
                        if matches!(
                            key.code,
                            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') | KeyCode::Char('Q')
                        ) {
                            self.finish_ceremony_run();
                        }
                    } else if let Some(run) = self.ceremony_run.as_mut() {
                        run.on_key(key);
                    }
                    return Action::Noop;
                }

                self.ceremony.handle_key_event(key)
            }
            Mode::Utilities => self.utilities.handle_key_event(key),
        }
    }

    /// Process tick events — delegate to active component for background work.
    pub fn handle_tick(&mut self) -> Action {
        // Background polling happens at app level too
        self.background_tick();

        match self.mode {
            Mode::Setup => self.setup.handle_tick(),
            Mode::Ceremony => {
                if let Some(run) = self.ceremony_run.as_mut() {
                    let notes = run.on_tick();
                    for msg in notes {
                        self.set_status(msg);
                    }
                    return Action::Noop;
                }
                self.ceremony.handle_tick()
            }
            Mode::Utilities => self.utilities.handle_tick(),
        }
    }

    /// Background polling for disc/shuttle state + burn completion.
    fn background_tick(&mut self) {
        // Always update shuttle presence for the status bar.
        self.hw.tick_shuttle(&self.shuttle_mount);

        // Full shuttle scan (profile load) during WaitShuttle
        if self.mode == Mode::Setup && self.setup.phase == SetupPhase::WaitShuttle {
            self.tick_wait_shuttle();
        }

        // Disc scan during WaitDisc
        if self.mode == Mode::Setup && self.setup.phase == SetupPhase::WaitDisc {
            self.tick_wait_disc(false);
        }

        // Disc sync burn polling
        if self.mode == Mode::Utilities
            && self.utilities.screen == crate::modes::utilities::UtilScreen::DiscSync
            && self.utilities.disc_sync.phase
                == crate::modes::utilities::disc_sync::SyncPhase::Writing
        {
            if let Some(ref dev) = self.disc.optical_dev.clone() {
                self.utilities.disc_sync.poll_burn(dev);
            }
        }
    }

    /// Process an action, updating app state.
    pub fn update(&mut self, action: Action) {
        match action {
            Action::Noop => {}
            Action::Quit => self.running = false,
            Action::SwitchMode(mode) => {
                self.mode = mode;
                self.content_scroll = 0;
            }
            // Setup flow
            Action::ConfirmClock => {
                self.confirmed_time = Some(SystemTime::now());
                self.setup.phase = SetupPhase::WaitShuttle;
                self.set_status("Scanning for shuttle USB with profile.toml…");
            }
            Action::HsmDetected => {
                self.setup.phase = SetupPhase::HsmDetect;
                self.do_detect_hsm();
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
                let ready = self.disc.optical_dev.is_some()
                    && self
                        .disc
                        .sessions_remaining
                        .map(|r| r >= 2)
                        .unwrap_or(false);
                if ready {
                    self.update(Action::SetupComplete);
                }
            }

            // Ceremony operations
            Action::SelectOperation(op) => match op {
                Operation::InitRoot => self.start_init_root(),
                Operation::IssueCrl => self.start_issue_crl(),
                Operation::RevokeCert => self.start_revoke_cert(),
                Operation::SignCsr => self.start_sign_csr(),
                Operation::RekeyShares => self.start_rekey_shares(),
                Operation::KeyBackup => self.start_key_backup(),
                Operation::MigrateDisc => self.start_migrate_disc(),
                Operation::ValidateDisc => self.start_validate_disc(),
                #[cfg(feature = "dev-burn")]
                Operation::RefreshDisc => self.start_refresh_disc(),
            },
            // Utilities sub-screens
            Action::UtilScreen(idx) => {
                use crate::modes::utilities::{UtilScreen, UtilitiesMode};
                let screen = match idx {
                    1 => UtilScreen::SystemInfo,
                    2 => UtilScreen::AuditLog,
                    3 => UtilScreen::HsmInventory,
                    4 => UtilScreen::DiscInspector,
                    5 => UtilScreen::DiscSync,
                    _ => UtilScreen::Menu,
                };
                if screen == UtilScreen::DiscSync {
                    // Disc sync has its own FSM; reset on entry.
                    self.utilities.disc_sync.reset();
                    self.utilities.screen = screen;
                } else if screen == UtilScreen::DiscInspector {
                    // Disc inspector has its own state; populate from disjoint fields.
                    use crate::modes::utilities::disc_inspector::{
                        gather_banner_from, gather_session_list_from,
                    };
                    let banner = gather_banner_from(&self.disc, None);
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
        }
    }

    /// Render the full application frame.
    pub fn render(&self, frame: &mut Frame) {
        // Log view overlay
        if self.log_view {
            let content = self.log_lines.join("\n");
            let block = Block::default()
                .borders(Borders::ALL)
                .title("Status Log  [F12/Esc] close  [\u{2191}/\u{2193}/PgUp/PgDn] scroll")
                .style(crate::theme::BLOCK)
                .border_style(crate::theme::BORDER)
                .title_style(crate::theme::TITLE);
            let inner_height = frame.area().height.saturating_sub(2);
            let max_scroll = (self.log_lines.len() as u16).saturating_sub(inner_height);
            let scroll = self.log_scroll.min(max_scroll);
            let para = ratatui::widgets::Paragraph::new(content.as_str())
                .block(block)
                .wrap(ratatui::widgets::Wrap { trim: false })
                .scroll((scroll, 0));
            frame.render_widget(para, frame.area());
            return;
        }

        let area = frame.area();

        // Build header lines
        let is_dev = cfg!(feature = "dev-softhsm-usb");
        let is_burn = cfg!(feature = "dev-burn");
        let mut header_lines: Vec<Line> = vec![Line::from("ANODIZE ROOT CA CEREMONY")];
        if is_dev {
            header_lines.push(Line::from(Span::styled(
                if is_burn {
                    "*** DEV-BURN BUILD — REAL DISC, NOT FOR PRODUCTION ***"
                } else {
                    "*** DEV BUILD — NOT FOR PRODUCTION USE ***"
                },
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
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
        let border_style = if is_dev {
            Style::default().fg(Color::Red)
        } else {
            Style::default()
        };
        let header = Paragraph::new(header_lines)
            .alignment(Alignment::Center)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .style(crate::theme::BLOCK)
                    .border_style(border_style)
                    .title_style(crate::theme::TITLE),
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
            Mode::Ceremony => modes::ceremony_phases(0),
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
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Status")
                    .style(crate::theme::BLOCK)
                    .border_style(crate::theme::BORDER)
                    .title_style(crate::theme::TITLE),
            );
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

    /// Show a quit-confirmation dialog (two-key: [1] then [Enter]).
    fn show_quit_confirm(&mut self) {
        self.show_confirm(
            "Quit Anodize?",
            vec!["All unsaved state will be lost.".into()],
            Action::Quit,
        );
    }
}
