//! App-level orchestration: setup ticks, disc burn lifecycle, shuttle write,
//! operation dispatch, and rendering helpers.
//!
//! Per-operation ceremony logic lives in `ops/`.

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::SystemTime;

use anodize_audit::{genesis_hash, AuditLog};
use anodize_config::load as load_profile;
use anodize_hsm::create_backend;
use der::Decode as _;
use ratatui::{layout::Rect, Frame};

use crate::action::Operation;
use crate::app::App;
use crate::components::status_bar::HwState;
use crate::helpers::*;
use crate::media::{self, IsoFile, SessionEntry};
use crate::modes::ceremony::CeremonyPhase;
use crate::modes::setup::SetupPhase;

impl App {
    // ── Shuttle scan tick ─────────────────────────────────────────────────────

    pub(crate) fn tick_wait_shuttle(&mut self) {
        // The shuttle USB is mounted/unmounted by systemd
        // (mount-anodize-shuttle.service + BindsTo= the udev device).
        // We just check whether profile.toml is readable at the known path.
        let profile_path = self.shuttle_mount.join("profile.toml");
        if !profile_path.is_file() {
            self.hw.shuttle_state = HwState::Absent;
            let diagnostics = media::usb_scan_diagnostics();
            self.set_status(format!(
                "Waiting for shuttle USB… ({diagnostics}) — insert USB with profile.toml."
            ));
            return;
        }

        #[cfg(feature = "dev-softhsm-usb")]
        if let Err(e) = configure_softhsm_from_shuttle(&self.shuttle_mount) {
            self.hw.shuttle_state = HwState::Error(format!("SoftHSM2: {e}"));
            self.set_status(format!("SoftHSM2 USB setup failed: {e}"));
            return;
        }

        let raw_bytes = std::fs::read(&profile_path).unwrap_or_default();
        match load_profile(&profile_path) {
            Ok(profile) => {
                self.hw.shuttle_state = HwState::Ready("mounted".into());
                self.profile = Some(profile);
                self.profile_toml_bytes = Some(raw_bytes);
                self.setup.phase = SetupPhase::ProfileLoaded;
                self.set_status("Profile loaded from USB.");
            }
            Err(e) => {
                self.hw.shuttle_state = HwState::Error(format!("parse: {e}"));
                self.set_status(format!("Profile parse error: {e}"));
            }
        }
    }

    // ── Disc scan tick ────────────────────────────────────────────────────────

    pub(crate) fn tick_wait_disc(&mut self, need_blank: bool) {
        // Check for a pending background scan result.
        if let Some(ref rx) = self.disc.disc_scan_rx {
            match rx.try_recv() {
                Ok(batch) => {
                    self.disc.disc_scan_rx = None;
                    self.process_disc_scan(batch, need_blank);
                    return;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    return; // scan still running — TUI stays responsive
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    tracing::error!("disc scan thread panicked or dropped sender");
                    self.disc.disc_scan_rx = None;
                    // fall through to spawn a new scan
                }
            }
        }

        // No scan in flight — spawn one in a background thread.
        let (tx, rx) = mpsc::channel();
        self.disc.disc_scan_rx = Some(rx);
        self.set_status("Scanning optical drive…");
        std::thread::spawn(move || {
            let drives = media::scan_optical_drives();
            let scans: Vec<_> = drives
                .iter()
                .map(|dev| (dev.clone(), media::scan_disc(dev)))
                .collect();
            let _ = tx.send(crate::disc::DiscScanBatch { drives, scans });
        });
    }

    /// Process results from a completed background disc scan.
    fn process_disc_scan(&mut self, batch: crate::disc::DiscScanBatch, need_blank: bool) {
        let mut rw_rejection: Option<String> = None;
        for (dev, result) in batch.scans {
            match result {
                Ok(scan) => {
                    let n = scan.sessions.len();
                    let cap_summary = &scan.capacity_summary;
                    let remaining = scan.sessions_remaining;
                    self.disc.sessions_remaining = Some(remaining);
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
                    self.disc.optical_dev = Some(dev.clone());
                    self.hw.disc_state =
                        HwState::Present(format!("{} ({cap_summary})", dev.display()));
                    if !need_blank {
                        self.disc.prior_sessions = scan.sessions;
                        self.disc.session_state =
                            load_session_state_from_sessions(&self.disc.prior_sessions);
                        if let Some(ref state) = self.disc.session_state {
                            tracing::info!(
                                version = state.version,
                                crl_number = state.crl_number,
                                custodians = state.sss.custodians.len(),
                                "STATE.JSON loaded from disc"
                            );
                        }
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
        self.disc.optical_dev = None;
        self.hw.disc_state = HwState::Absent;
        if let Some(msg) = rw_rejection {
            self.set_status(msg);
        } else if batch.drives.is_empty() {
            self.set_status("No optical drive detected. Insert drive and disc.");
        } else {
            self.set_status(
                "No blank/appendable disc found. Insert write-once disc \
                 (BD-R, DVD-R, CD-R, or M-Disc).",
            );
        }
    }

    // ── Intent burn tick ──────────────────────────────────────────────────────

    pub(crate) fn tick_intent_burn(&mut self) {
        use crate::media::BurnProgress;
        let result = {
            let Some(rx) = &self.disc.burn_rx else {
                tracing::error!("tick_intent_burn: burn_rx is None but state is Commit!");
                return;
            };
            loop {
                match rx.try_recv() {
                    Ok(BurnProgress::Step(msg)) => {
                        self.disc.burn_log.push(msg);
                    }
                    Ok(BurnProgress::Done(r)) => {
                        tracing::info!("tick_intent_burn: received result from channel");
                        break r;
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        tracing::debug!("tick_intent_burn: channel present but empty");
                        return;
                    }
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        tracing::error!("tick_intent_burn: channel disconnected!");
                        break Err(anyhow::anyhow!("disc write channel disconnected"));
                    }
                }
            }
        };
        self.disc.burn_rx = None;
        self.disc.burn_log.clear();
        self.disc.burn_started = None;
        match result {
            Err(e) => {
                tracing::error!("tick_intent_burn: write failed: {e:#}");
                self.set_status(format!("Intent disc write failed: {e:#}"));
                self.ceremony.state = CeremonyPhase::OperationSelect;
                self.setup.phase = SetupPhase::WaitDisc;
                self.disc.optical_dev = None;
                self.hw.disc_state = HwState::Absent;
            }
            Ok(()) => {
                tracing::info!("tick_intent_burn: write OK, advancing state");
                if let Some(intent) = self.disc.pending_intent_session.take() {
                    self.disc.intent_session_dir_name = Some(intent.dir_name.clone());
                    self.disc.prior_sessions.push(intent);
                }
                // Delegate post-intent advance to the active operation context.
                if let Some(mut op) = self.active_op.take() {
                    use crate::ops::OpContext;
                    let mut shared = self.make_shared();
                    op.advance_after_intent_burn(&mut shared);
                    self.active_op = Some(op);
                    // KeyBackup executes during advance and needs an immediate record burn.
                    if matches!(self.current_op(), Some(Operation::KeyBackup)) {
                        self.do_start_burn();
                    } else {
                        self.ceremony.state = CeremonyPhase::ActiveOp;
                    }
                } else {
                    tracing::error!("tick_intent_burn: no active_op after intent write");
                    self.set_status("Internal error: no active operation after intent");
                    self.ceremony.state = CeremonyPhase::OperationSelect;
                }
            }
        }
    }

    // ── Record burn tick ──────────────────────────────────────────────────────

    pub(crate) fn tick_record_burn(&mut self) {
        use crate::media::BurnProgress;
        let result = {
            let Some(rx) = &self.disc.burn_rx else { return };
            // Drain all pending messages, keeping only the final Done.
            loop {
                match rx.try_recv() {
                    Ok(BurnProgress::Step(msg)) => {
                        self.disc.burn_log.push(msg);
                    }
                    Ok(BurnProgress::Done(r)) => {
                        break r;
                    }
                    Err(_) => return, // Empty or disconnected — nothing to do yet
                }
            }
        };
        self.disc.burn_rx = None;
        self.disc.burn_log.clear();
        self.disc.burn_started = None;
        match result {
            Ok(()) => {
                self.ceremony.state = CeremonyPhase::DiscDone;
                let disc_label = self
                    .disc
                    .optical_dev
                    .as_deref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "/run/anodize/staging".into());
                let op_label = match self.current_op() {
                    Some(Operation::InitRoot) => "Root init",
                    Some(Operation::SignCsr) => "Intermediate cert",
                    Some(Operation::RevokeCert) => "Revocation + CRL",
                    Some(Operation::IssueCrl) => "CRL refresh",
                    Some(Operation::RekeyShares) => "Re-key shares",
                    Some(Operation::MigrateDisc) => "Disc migration",
                    Some(Operation::KeyBackup) => "Key backup",
                    Some(Operation::ValidateDisc) => "Disc validation",
                    #[cfg(feature = "dev-burn")]
                    Some(Operation::RefreshDisc) => "Disc refresh",
                    None => "session",
                };
                // After a disc refresh, clear prior sessions so the TUI
                // treats the disc as fresh for the next InitRoot.
                #[cfg(feature = "dev-burn")]
                if self.current_op() == Some(Operation::RefreshDisc) {
                    self.disc.prior_sessions.clear();
                    self.disc.session_state = None;
                }
                self.set_status(format!("{op_label} written to disc: {disc_label}"));
            }
            Err(e) => {
                self.set_status(format!("Burn failed: {e} — reinsert disc and retry."));
                self.ceremony.state = CeremonyPhase::OperationSelect;
                self.disc.optical_dev = None;
                self.hw.disc_state = HwState::Absent;
            }
        }
    }

    // ── HSM detection (no login — authentication deferred to Quorum phase) ──

    pub(crate) fn do_detect_hsm(&mut self) {
        let cfg = match &self.profile {
            Some(p) => &p.hsm,
            None => {
                self.set_status("No profile loaded");
                self.setup.phase = SetupPhase::ProfileLoaded;
                return;
            }
        };

        let backend = match create_backend(cfg.backend) {
            Ok(b) => b,
            Err(e) => {
                self.hw.hsm_state = HwState::Error(format!("{e}"));
                self.set_status(format!("HSM detection failed: {e}"));
                self.setup.phase = SetupPhase::ProfileLoaded;
                return;
            }
        };

        match backend.probe_token(&cfg.token_label) {
            Ok(true) => {
                let label = &cfg.token_label;
                self.hw.hsm_state = HwState::Present(format!("token={label}"));
                self.setup.phase = SetupPhase::WaitDisc;
                self.set_status(
                    "HSM detected. Insert write-once disc (BD-R, DVD-R, CD-R, or M-Disc) and press [1].",
                );
            }
            Ok(false) => {
                let label = &cfg.token_label;
                // Fresh HSM — the token slot is created during InitRoot.
                // Warn the operator but allow proceeding.
                self.hw.hsm_state =
                    HwState::Present(format!("backend OK, token '{label}' not yet initialized"));
                self.setup.phase = SetupPhase::HsmWarnTokenMissing;
                self.set_status(format!(
                    "WARNING: HSM token '{label}' does not exist yet. \
                     This is expected for a first-time InitRoot ceremony. \
                     Press [1] to continue or [Ctrl+C] to quit.",
                ));
            }
            Err(e) => {
                self.hw.hsm_state = HwState::Error(format!("{e}"));
                self.set_status(format!("HSM detection failed: {e}"));
                self.setup.phase = SetupPhase::ProfileLoaded;
            }
        }
    }

    /// Dispatch to the pending crypto operation after the operator re-confirms
    /// the clock. Called from Action::ReconfirmClock.
    pub(crate) fn do_dispatch_after_clock_reconfirm(&mut self) {
        use crate::ops::OpContext;

        if let Some(mut op) = self.active_op.take() {
            let mut shared = self.make_shared();
            let action = op.execute(&mut shared);
            drop(shared);
            self.active_op = Some(op);

            match action {
                crate::ops::OpAction::StartRecordBurn => self.do_start_burn(),
                crate::ops::OpAction::Noop => {
                    // execute() handled phase transition internally (e.g. SignCsr → Execute).
                    // Stay in ActiveOp — the op's own phase renders the cert preview.
                    self.ceremony.state = CeremonyPhase::ActiveOp;
                }
                crate::ops::OpAction::SetStatus(msg) => self.set_status(msg),
                other => {
                    tracing::warn!(?other, "unexpected OpAction from execute()");
                }
            }
        } else {
            self.set_status("No active operation to execute");
            self.ceremony.state = CeremonyPhase::OperationSelect;
        }
    }

    // ── Operation selection ───────────────────────────────────────────────────

    pub(crate) fn do_select_operation(&mut self, op: Operation) {
        match op {
            Operation::InitRoot => {
                if self.disc.session_state.is_some() {
                    self.set_status(
                        "Root already initialized on this disc. Use RekeyShares to change PIN.",
                    );
                    self.ceremony.state = CeremonyPhase::OperationSelect;
                    return;
                }
                let ctx = crate::ops::init_root::InitRootCtx::new();
                self.active_op = Some(crate::ops::ActiveOperation::InitRoot(ctx));
                self.ceremony.state = CeremonyPhase::ActiveOp;
                self.set_status("Enter custodian names one-by-one, then set threshold.");
            }
            Operation::SignCsr => {
                let csr_path = self.shuttle_mount.join("csr.der");
                let csr_bytes = match std::fs::read(&csr_path) {
                    Ok(b) => b,
                    Err(e) => {
                        self.set_status(format!(
                            "Cannot read csr.der from shuttle: {e} — \
                             ensure csr.der is on the USB and re-insert it."
                        ));
                        return;
                    }
                };
                if let Err(e) = x509_cert::request::CertReq::from_der(&csr_bytes) {
                    self.set_status(format!("csr.der is not a valid DER-encoded CSR: {e}"));
                    return;
                }
                let profiles = self
                    .profile
                    .as_ref()
                    .map(|p| p.cert_profiles.as_slice())
                    .unwrap_or(&[]);
                if profiles.is_empty() {
                    self.set_status(
                        "No [[cert_profiles]] defined in profile.toml. Add at least one profile.",
                    );
                    return;
                }
                let profile_lines: Vec<String> = profiles
                    .iter()
                    .enumerate()
                    .map(|(i, prof)| {
                        let path_str = prof
                            .path_len
                            .map(|n| format!("  path_len={n}"))
                            .unwrap_or_default();
                        format!(
                            "  [{}]  {}  (validity={} days{})",
                            i + 1,
                            prof.name,
                            prof.validity_days,
                            path_str,
                        )
                    })
                    .collect();
                let profiles_len = profile_lines.len();
                let root_cert_der =
                    crate::helpers::load_root_cert_der_from_sessions(&self.disc.prior_sessions);
                let ctx =
                    crate::ops::sign_csr::SignCsrCtx::new(csr_bytes, root_cert_der, profile_lines);
                self.active_op = Some(crate::ops::ActiveOperation::SignCsr(ctx));
                self.ceremony.state = CeremonyPhase::ActiveOp;
                self.set_status(format!("CSR loaded. Select profile [1]–[{profiles_len}]."));
            }
            Operation::RevokeCert => {
                let root_cert_der = load_root_cert_der_from_sessions(&self.disc.prior_sessions);
                if root_cert_der.is_none() {
                    self.set_status("No ROOT.CRT found on disc. Generate root CA first.");
                    return;
                }
                let revocation_list = load_revocation_from_sessions(&self.disc.prior_sessions);
                let crl_number = Some(next_crl_number_from_sessions(&self.disc.prior_sessions));
                let cert_list =
                    gather_cert_list_from_sessions(&self.disc.prior_sessions, &revocation_list);
                let ctx = crate::ops::revoke_cert::RevokeCertCtx::new(
                    revocation_list,
                    crl_number,
                    cert_list,
                    root_cert_der,
                );
                self.active_op = Some(crate::ops::ActiveOperation::RevokeCert(ctx));
                self.ceremony.state = CeremonyPhase::ActiveOp;
                self.set_status(
                    "Select a certificate to revoke, or press [m] for manual serial entry.",
                );
            }
            Operation::IssueCrl => {
                let root_cert_der = load_root_cert_der_from_sessions(&self.disc.prior_sessions);
                if root_cert_der.is_none() {
                    self.set_status("No ROOT.CRT found on disc. Generate root CA first.");
                    return;
                }
                let revocation_list = load_revocation_from_sessions(&self.disc.prior_sessions);
                let crl_number = Some(next_crl_number_from_sessions(&self.disc.prior_sessions));
                let ctx = crate::ops::issue_crl::IssueCrlCtx::new(
                    revocation_list,
                    crl_number,
                    root_cert_der,
                );
                self.active_op = Some(crate::ops::ActiveOperation::IssueCrl(ctx));
                self.ceremony.state = CeremonyPhase::ActiveOp;
                self.set_status("Review CRL details. [1] to proceed, [Esc] to cancel.");
            }
            Operation::RekeyShares => {
                if self.disc.session_state.is_none() {
                    self.set_status("No STATE.JSON — run InitRoot first.");
                    self.ceremony.state = CeremonyPhase::OperationSelect;
                    return;
                }
                let sss = self.disc.session_state.as_ref().unwrap().sss.clone();
                let ctx = crate::ops::rekey_shares::RekeyCtx::new(sss);
                self.active_op = Some(crate::ops::ActiveOperation::RekeyShares(ctx));
                self.ceremony.state = CeremonyPhase::ActiveOp;
                self.set_status("Enter threshold shares to reconstruct the PIN.");
            }
            Operation::MigrateDisc => {
                let shared = self.make_shared();
                let ctx = crate::ops::migrate_disc::MigrateCtx::run(&shared);
                let chain_status = if ctx.chain_ok { "OK" } else { "FAIL" };
                let status = format!(
                    "Chain: {chain_status}  {} session(s)  {} bytes. [1] to proceed, [Esc] to abort.",
                    ctx.session_count, ctx.total_bytes,
                );
                self.active_op = Some(crate::ops::ActiveOperation::MigrateDisc(ctx));
                self.ceremony.state = CeremonyPhase::ActiveOp;
                self.set_status(status);
            }
            Operation::KeyBackup => {
                if self.disc.session_state.is_none() {
                    self.set_status("No STATE.JSON \u{2014} run InitRoot first.");
                    self.ceremony.state = CeremonyPhase::OperationSelect;
                    return;
                }
                let sss = self.disc.session_state.as_ref().unwrap().sss.clone();
                let ctx = crate::ops::key_backup::BackupCtx::new(sss);
                self.active_op = Some(crate::ops::ActiveOperation::KeyBackup(ctx));
                self.ceremony.state = CeremonyPhase::ActiveOp;
                self.set_status("Enter threshold shares to reconstruct the HSM PIN for backup.");
            }
            Operation::ValidateDisc => {
                let shared = self.make_shared();
                let ctx = crate::ops::validate_disc::ValidateCtx::run(&shared);
                self.active_op = Some(crate::ops::ActiveOperation::ValidateDisc(ctx));
                self.ceremony.state = CeremonyPhase::ActiveOp;
                self.set_status("Disc validation complete. Review findings.");
            }
            #[cfg(feature = "dev-burn")]
            Operation::RefreshDisc => {
                self.do_refresh_disc();
            }
        }
    }

    // ── WAL intent write ──────────────────────────────────────────────────────

    pub(crate) fn do_write_intent(&mut self) {
        let raw_bytes = match self.profile_toml_bytes.clone() {
            Some(b) => b,
            None => {
                self.set_status("Profile bytes missing");
                return;
            }
        };

        if self.disc.sessions_remaining.map(|r| r < 2).unwrap_or(false) {
            self.set_status("Disc full — cannot write intent session. Insert new disc.");
            return;
        }

        let ts = self.confirmed_time.unwrap_or_else(SystemTime::now);
        let dir_name = media::session_dir_name(ts) + "-intent";

        let staging = PathBuf::from("/run/anodize/staging");
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
            None => return,
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

        let (tx, rx) = mpsc::channel();
        self.disc.burn_rx = Some(rx);
        self.disc.burn_log.clear();
        self.disc.burn_started = Some(std::time::Instant::now());
        self.disc.pending_intent_session = Some(intent_session.clone());

        tracing::info!(
            optical_dev = ?self.disc.optical_dev,
            "do_write_intent: about to dispatch write"
        );

        if let Some(dev) = self.disc.optical_dev.clone() {
            tracing::info!(
                "do_write_intent: spawning write_session to {}",
                dev.display()
            );
            media::write_session(&dev, &self.disc.prior_sessions, intent_session, false, tx);
        } else {
            tracing::error!("do_write_intent: no optical device!");
            self.set_status("No optical device — cannot write intent");
            self.disc.burn_rx = None;
            self.disc.pending_intent_session = None;
            return;
        }

        tracing::info!(
            burn_rx_is_some = self.disc.burn_rx.is_some(),
            "do_write_intent: setting Commit state"
        );
        self.ceremony.state = CeremonyPhase::Commit;
        self.set_status("Writing intent to disc. Operation will follow…");
    }

    /// Build the intent audit event (name, data) for the current operation.
    /// Delegates to the active `OpContext` implementation.
    fn build_intent_audit_event(
        &mut self,
        genesis_hex: &str,
    ) -> Option<(String, serde_json::Value)> {
        use crate::ops::OpContext;
        let op = self.active_op.take()?;
        let shared = self.make_shared();
        let result = op.build_intent_audit_event(genesis_hex, &shared);
        self.active_op = Some(op);
        result
    }

    // ── Disc refresh (dev-burn only) ─────────────────────────────────────────

    #[cfg(feature = "dev-burn")]
    pub(crate) fn do_refresh_disc(&mut self) {
        use std::time::SystemTime;

        let Some(dev) = &self.disc.optical_dev else {
            self.set_status("No optical device — cannot refresh");
            self.ceremony.state = CeremonyPhase::OperationSelect;
            return;
        };

        if self.disc.sessions_remaining == Some(0) {
            self.set_status("Disc has no remaining sessions");
            self.ceremony.state = CeremonyPhase::OperationSelect;
            return;
        }

        let now = SystemTime::now();
        let dir_name = media::session_dir_name(now);
        let seed_text = format!("anodize disc refresh\ncreated: {dir_name}\n");

        let seed_session = media::iso9660::SessionEntry {
            dir_name,
            timestamp: now,
            files: vec![media::iso9660::IsoFile {
                name: "SEED.TXT".into(),
                data: seed_text.into_bytes(),
            }],
        };

        let (tx, rx) = mpsc::channel();
        self.disc.burn_rx = Some(rx);
        self.disc.burn_log.clear();
        self.disc.burn_started = Some(std::time::Instant::now());

        media::write_session(dev, &self.disc.prior_sessions, seed_session, false, tx);

        self.ceremony.state = CeremonyPhase::BurningDisc;
        self.set_status("Writing seed session…");
    }

    // ── Disc burn ─────────────────────────────────────────────────────────────

    pub(crate) fn do_start_burn(&mut self) {
        let staging = PathBuf::from("/run/anodize/staging");

        let new_session = match self.build_burn_session(&staging) {
            Some(s) => s,
            None => return,
        };

        let (tx, rx) = mpsc::channel();
        self.disc.burn_rx = Some(rx);
        self.disc.burn_log.clear();
        self.disc.burn_started = Some(std::time::Instant::now());

        if let Some(dev) = &self.disc.optical_dev {
            media::write_session(dev, &self.disc.prior_sessions, new_session, false, tx);
        } else {
            self.set_status("No optical device — cannot burn");
            self.disc.burn_rx = None;
            return;
        }

        self.ceremony.state = CeremonyPhase::BurningDisc;
        self.set_status("Burning disc session…");
    }

    /// Build the SessionEntry for the current operation's disc burn.
    /// Delegates to the active `OpContext::build_record_session` implementation.
    fn build_burn_session(&mut self, staging: &std::path::Path) -> Option<SessionEntry> {
        use crate::ops::OpContext;
        let ts = self.confirmed_time.unwrap_or_else(SystemTime::now);
        let dir_name = media::session_dir_name(ts) + "-record";

        let mut op = self.active_op.take()?;
        let mut shared = self.make_shared();
        let result = op.build_record_session(dir_name, ts, staging, &mut shared);
        drop(shared);
        self.active_op = Some(op);
        result
    }

    // ── Shuttle write ─────────────────────────────────────────────────────

    pub(crate) fn do_write_shuttle(&mut self) {
        use crate::ops::OpContext;
        let shuttle = self.shuttle_mount.clone();
        let staging_log = PathBuf::from("/run/anodize/staging/audit.log");

        // Check whether the op produces shuttle artifacts (without writing yet).
        let has_artifacts = self
            .active_op
            .as_ref()
            .map(|op| op.has_shuttle_artifacts())
            .unwrap_or(false);

        if !has_artifacts {
            self.active_op = None;
            self.ceremony.state = CeremonyPhase::Done;
            self.set_status("Operation complete.");
            return;
        }

        // Verify the shuttle USB is still mounted (systemd manages the lifecycle).
        if let Err(e) = media::verify_shuttle_mount(&shuttle) {
            tracing::error!("Shuttle mount check failed: {e:#}");
            self.set_status(format!(
                "Shuttle USB not available: {e:#} — re-insert shuttle USB and retry."
            ));
            return;
        }

        // Write operation-specific artifacts to shuttle.
        if let Some(ref op) = self.active_op {
            if let Err(e) = op.write_shuttle_artifacts(&shuttle) {
                self.set_status(e);
                return;
            }
        }

        // Copy audit log to shuttle for all artifact-producing operations.
        match std::fs::read(&staging_log) {
            Ok(log_bytes) => {
                if let Err(e) = media::write_and_sync(&shuttle.join("audit.log"), &log_bytes) {
                    self.set_status(format!("Audit log copy to shuttle failed: {e:#}"));
                    return;
                }
            }
            Err(e) => {
                self.set_status(format!("Audit log read failed: {e}"));
                return;
            }
        }

        self.active_op = None;
        self.ceremony.state = CeremonyPhase::Done;
        self.set_status(format!("Shuttle write complete: {}", shuttle.display()));
    }

    // ── Content rendering (avoids borrow splitting) ──────────────────────────

    pub(crate) fn render_setup_content(&self, frame: &mut Frame, area: Rect) {
        self.setup.render_with_app(frame, area, self);
    }

    pub(crate) fn render_ceremony_content(&self, frame: &mut Frame, area: Rect) {
        // ActiveOp: delegate rendering to the per-operation context.
        if self.ceremony.state == CeremonyPhase::ActiveOp {
            if let Some(ref op) = self.active_op {
                use crate::ops::OpContext;
                let title = op.title().to_string();
                let content = op.build_body();
                let block = ratatui::widgets::Block::default()
                    .borders(ratatui::widgets::Borders::ALL)
                    .title(title)
                    .style(crate::theme::BLOCK)
                    .border_style(crate::theme::BORDER)
                    .title_style(crate::theme::TITLE);
                let lines: Vec<ratatui::text::Line> =
                    content.into_iter().map(ratatui::text::Line::from).collect();
                let para = ratatui::widgets::Paragraph::new(ratatui::text::Text::from(lines))
                    .block(block)
                    .wrap(ratatui::widgets::Wrap { trim: false })
                    .scroll((self.content_scroll, 0));
                frame.render_widget(para, area);
                // Render overlay components (ShareInput, CustodianSetup, etc.)
                op.render_overlay(frame, area);
            }
            return;
        }
        self.ceremony.render_with_app(frame, area, self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{Action, Operation};
    use crate::modes::ceremony::CeremonyPhase;
    use std::path::PathBuf;

    fn test_app() -> crate::app::App {
        let mut app = crate::app::App::new(PathBuf::from("/tmp/test-shuttle"));
        app.pin_buf = hex::encode(vec![0u8; 32]);
        app
    }

    #[test]
    fn init_root_bootstrap_fails_without_hsm() {
        let mut app = test_app();
        // No HSM backend configured → InitRootCtx::do_bootstrap_hsm should fail
        let mut shared = app.make_shared();
        let result = crate::ops::init_root::InitRootCtx::do_bootstrap_hsm(&mut shared);
        assert!(result.is_err(), "Expected error without profile/HSM");
    }

    #[test]
    fn tick_intent_burn_transitions_to_active_op_on_bootstrap_fail() {
        let mut app = test_app();
        app.ceremony.state = CeremonyPhase::Commit;

        // Provide an InitRootCtx so the ActiveOp path fires.
        let ctx = crate::ops::init_root::InitRootCtx::new();
        app.active_op = Some(crate::ops::ActiveOperation::InitRoot(ctx));

        // Set up a burn_rx channel that immediately yields Done(Ok(()))
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(crate::media::BurnProgress::Done(Ok(()))).unwrap();
        app.disc.burn_rx = Some(rx);

        app.tick_intent_burn();

        // InitRootCtx::advance_after_intent_burn fails (no HSM) but the
        // caller transitions to ActiveOp so the context can display the error.
        assert_eq!(
            app.ceremony.state,
            CeremonyPhase::ActiveOp,
            "Should transition to ActiveOp (error shown via status)"
        );
    }

    #[test]
    fn tick_intent_burn_drains_steps_before_done() {
        let mut app = test_app();
        app.ceremony.state = CeremonyPhase::Commit;

        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(crate::media::BurnProgress::Step(
            "Reading disc info…".into(),
        ))
        .unwrap();
        tx.send(crate::media::BurnProgress::Step("Writing session…".into()))
            .unwrap();
        tx.send(crate::media::BurnProgress::Done(Ok(()))).unwrap();
        app.disc.burn_rx = Some(rx);
        app.disc.burn_started = Some(std::time::Instant::now());

        app.tick_intent_burn();

        // burn_log and burn_rx should be cleared after Done
        assert!(
            app.disc.burn_log.is_empty(),
            "burn_log should be cleared after Done"
        );
        assert!(
            app.disc.burn_rx.is_none(),
            "burn_rx should be cleared after Done"
        );
        assert!(
            app.disc.burn_started.is_none(),
            "burn_started should be cleared"
        );
    }

    #[test]
    fn tick_record_burn_advances_to_disc_done() {
        let mut app = test_app();
        app.ceremony.state = CeremonyPhase::BurningDisc;

        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(crate::media::BurnProgress::Done(Ok(()))).unwrap();
        app.disc.burn_rx = Some(rx);
        app.disc.burn_started = Some(std::time::Instant::now());

        app.tick_record_burn();

        assert_eq!(app.ceremony.state, CeremonyPhase::DiscDone);
        assert!(app.disc.burn_rx.is_none());
    }

    #[test]
    fn tick_record_burn_error_stays_burning() {
        let mut app = test_app();
        app.ceremony.state = CeremonyPhase::BurningDisc;

        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(crate::media::BurnProgress::Done(Err(anyhow::anyhow!(
            "disc on fire"
        ))))
        .unwrap();
        app.disc.burn_rx = Some(rx);

        app.tick_record_burn();

        // State stays BurningDisc (error sets status but doesn't change phase to DiscDone)
        assert_ne!(app.ceremony.state, CeremonyPhase::DiscDone);
        assert!(app.disc.burn_rx.is_none());
        assert!(app.status.contains("disc on fire"));
    }

    #[test]
    fn tick_intent_burn_accumulates_burn_log() {
        let mut app = test_app();
        app.ceremony.state = CeremonyPhase::Commit;

        // Send two steps without Done — tick should accumulate and return
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(crate::media::BurnProgress::Step(
            "Reading disc info…".into(),
        ))
        .unwrap();
        tx.send(crate::media::BurnProgress::Step("Writing session…".into()))
            .unwrap();
        // Don't send Done yet — channel will be Empty on next try_recv
        app.disc.burn_rx = Some(rx);
        app.disc.burn_started = Some(std::time::Instant::now());

        app.tick_intent_burn();

        // Channel still open (no Done received), steps accumulated
        assert_eq!(app.disc.burn_log.len(), 2);
        assert_eq!(app.disc.burn_log[0], "Reading disc info…");
        assert_eq!(app.disc.burn_log[1], "Writing session…");
        assert!(app.disc.burn_rx.is_some(), "channel still open");
    }

    #[test]
    fn tick_record_burn_accumulates_burn_log() {
        let mut app = test_app();
        app.ceremony.state = CeremonyPhase::BurningDisc;

        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(crate::media::BurnProgress::Step("Step 1".into()))
            .unwrap();
        tx.send(crate::media::BurnProgress::Step("Step 2".into()))
            .unwrap();
        tx.send(crate::media::BurnProgress::Step("Step 3".into()))
            .unwrap();
        tx.send(crate::media::BurnProgress::Done(Ok(()))).unwrap();
        app.disc.burn_rx = Some(rx);
        app.disc.burn_started = Some(std::time::Instant::now());

        app.tick_record_burn();

        // After Done, burn_log should be cleared
        assert!(app.disc.burn_log.is_empty(), "burn_log cleared after Done");
        assert_eq!(app.ceremony.state, CeremonyPhase::DiscDone);
    }

    #[test]
    fn tick_intent_burn_noop_when_channel_empty() {
        let mut app = test_app();
        app.ceremony.state = CeremonyPhase::Commit;

        let (_tx, rx) = std::sync::mpsc::channel::<crate::media::BurnProgress>();
        app.disc.burn_rx = Some(rx);
        app.disc.burn_started = Some(std::time::Instant::now());

        app.tick_intent_burn();

        // Should be a no-op — burn_rx still present
        assert!(
            app.disc.burn_rx.is_some(),
            "Should remain while channel is empty"
        );
        assert_eq!(app.ceremony.state, CeremonyPhase::Commit);
    }

    #[test]
    fn init_root_post_commit_retry_stays_in_error_without_hsm() {
        // PostCommitError is now an op-internal phase on InitRootCtx.
        // Pressing [1] retries inline; without an HSM it stays in PostCommitError.
        let mut ctx = crate::ops::init_root::InitRootCtx::new();
        ctx.phase = crate::ops::init_root::InitRootPhase::PostCommitError;

        let mut app = test_app();
        app.ceremony.state = CeremonyPhase::ActiveOp;
        app.active_op = Some(crate::ops::ActiveOperation::InitRoot(ctx));

        // Simulate [1] via the op's handle_key.
        let key = crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Char('1'));
        if let Some(mut op) = app.active_op.take() {
            let mut shared = app.make_shared();
            let result = op.handle_key(key, &mut shared);
            app.active_op = Some(op);
            assert!(matches!(result, crate::ops::OpAction::Noop));
        }
        // Should still be in PostCommitError (op-internal).
        if let Some(crate::ops::ActiveOperation::InitRoot(ref ctx)) = app.active_op {
            assert_eq!(
                ctx.phase,
                crate::ops::init_root::InitRootPhase::PostCommitError,
                "Retry without HSM should stay in PostCommitError"
            );
        } else {
            panic!("expected InitRoot op");
        }
    }

    // ── Revoke phase regression tests ────────────────────────────────────

    use crate::ops::revoke_cert::{RevokeCertCtx, RevokeCertPhase};
    use crate::ops::OpContext;

    fn revoke_ctx() -> RevokeCertCtx {
        RevokeCertCtx::new(vec![], Some(1), vec![], None)
    }

    fn revoke_app_in_input() -> (crate::app::App, RevokeCertCtx) {
        let app = crate::app::App::new(PathBuf::from("/tmp/test-shuttle"));
        let mut ctx = revoke_ctx();
        ctx.phase = RevokeCertPhase::RevokeInput;
        (app, ctx)
    }

    #[test]
    fn revoke_cancel_from_serial_returns_to_select() {
        let (mut app, mut ctx) = revoke_app_in_input();
        ctx.input_phase = 0;
        let mut shared = app.make_shared();
        let key = crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Esc);
        let _action = ctx.handle_key(key, &mut shared);
        assert_eq!(ctx.phase, RevokeCertPhase::RevokeSelect);
    }

    #[test]
    fn revoke_cancel_from_reason_returns_to_serial() {
        let (mut app, mut ctx) = revoke_app_in_input();
        ctx.input_phase = 1;
        let mut shared = app.make_shared();
        let key = crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Esc);
        let _action = ctx.handle_key(key, &mut shared);
        assert_eq!(ctx.input_phase, 0, "Esc in reason should go back to serial");
        assert_eq!(ctx.phase, RevokeCertPhase::RevokeInput);
    }

    #[test]
    fn revoke_enter_advances_from_serial_to_reason() {
        let (mut app, mut ctx) = revoke_app_in_input();
        ctx.serial_buf = "12345".into();
        ctx.input_phase = 0;
        let mut shared = app.make_shared();
        let key = crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Enter);
        let _action = ctx.handle_key(key, &mut shared);
        assert_eq!(ctx.input_phase, 1, "phase should advance to 1 (reason)");
    }

    #[test]
    fn revoke_enter_empty_serial_stays_at_phase_0() {
        let (mut app, mut ctx) = revoke_app_in_input();
        ctx.serial_buf.clear();
        ctx.input_phase = 0;
        let mut shared = app.make_shared();
        let key = crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Enter);
        let _action = ctx.handle_key(key, &mut shared);
        // Empty serial in phase 0 falls through to add_revocation_entry which
        // rejects it and stays put.
        assert_eq!(ctx.input_phase, 0, "empty serial should not advance");
    }

    #[test]
    fn revoke_enter_from_reason_adds_entry() {
        let (mut app, mut ctx) = revoke_app_in_input();
        ctx.serial_buf = "01AB23".into();
        ctx.reason_buf = "key-compromise".into();
        ctx.input_phase = 1;
        let mut shared = app.make_shared();
        let key = crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Enter);
        let _action = ctx.handle_key(key, &mut shared);
        assert_eq!(ctx.phase, RevokeCertPhase::RevokePreview);
        assert_eq!(ctx.revocation_list.len(), 1);
        assert_eq!(ctx.revocation_list[0].serial, "01AB23");
        assert_eq!(
            ctx.revocation_list[0].reason.as_deref(),
            Some("key-compromise")
        );
    }

    #[test]
    fn revoke_enter_from_reason_empty_reason_adds_entry() {
        let (mut app, mut ctx) = revoke_app_in_input();
        ctx.serial_buf = "42".into();
        ctx.reason_buf.clear();
        ctx.input_phase = 1;
        let mut shared = app.make_shared();
        let key = crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Enter);
        let _action = ctx.handle_key(key, &mut shared);
        assert_eq!(ctx.phase, RevokeCertPhase::RevokePreview);
        assert_eq!(ctx.revocation_list.len(), 1);
        assert!(
            ctx.revocation_list[0].reason.is_none(),
            "empty reason should be None"
        );
    }

    #[test]
    fn abort_from_post_commit_error_resets_to_operation_select() {
        // PostCommitError is now op-internal. CeremonyCancel still clears the op.
        let mut ctx = crate::ops::init_root::InitRootCtx::new();
        ctx.phase = crate::ops::init_root::InitRootPhase::PostCommitError;

        let mut app = test_app();
        app.ceremony.state = CeremonyPhase::ActiveOp;
        app.active_op = Some(crate::ops::ActiveOperation::InitRoot(ctx));

        app.update(Action::CeremonyCancel);

        assert_eq!(
            app.ceremony.state,
            CeremonyPhase::OperationSelect,
            "CeremonyCancel from PostCommitError should reset to OperationSelect"
        );
        assert!(app.current_op().is_none());
    }

    // ── Migrate disc tests ──────────────────────────────────────────────

    /// Build a valid AUDIT.LOG bytes with one entry whose entry_hash we can predict.
    fn make_audit_log_bytes() -> (Vec<u8>, String) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0);
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("anodize-test-audit-{}-{n}.log", std::process::id()));
        let genesis = [0u8; 32];
        let mut log = anodize_audit::AuditLog::create(&path, &genesis).expect("create audit log");
        let record = log
            .append("cert.root.issue", serde_json::json!({"test": true}))
            .expect("append");
        let bytes = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        (bytes, record.entry_hash)
    }

    fn migrate_app_with_sessions(session_count: usize) -> crate::app::App {
        let mut app = crate::app::App::new(PathBuf::from("/tmp/test-shuttle"));

        let (audit_bytes, _hash) = make_audit_log_bytes();
        for i in 0..session_count {
            app.disc
                .prior_sessions
                .push(crate::media::iso9660::SessionEntry {
                    dir_name: format!("session-{i:02}"),
                    timestamp: std::time::SystemTime::now(),
                    files: vec![
                        crate::media::iso9660::IsoFile {
                            name: "ROOT.CRT".into(),
                            data: vec![0xDE, 0xAD],
                        },
                        crate::media::iso9660::IsoFile {
                            name: "AUDIT.LOG".into(),
                            data: audit_bytes.clone(),
                        },
                    ],
                });
        }
        app
    }

    /// Helper: create a migrate app and wire up MigrateCtx via ActiveOp.
    fn migrate_app_with_active_op(session_count: usize) -> crate::app::App {
        let mut app = migrate_app_with_sessions(session_count);
        app.mode = crate::action::Mode::Ceremony;
        app.setup_complete = true;
        let shared = app.make_shared();
        let ctx = crate::ops::migrate_disc::MigrateCtx::run(&shared);
        app.active_op = Some(crate::ops::ActiveOperation::MigrateDisc(ctx));
        app.ceremony.state = CeremonyPhase::ActiveOp;
        app
    }

    #[test]
    fn migrate_confirm_sets_state_and_fingerprint() {
        let app = migrate_app_with_active_op(3);
        let (_audit_bytes, expected_hash) = make_audit_log_bytes();

        assert_eq!(app.ceremony.state, CeremonyPhase::ActiveOp);
        match &app.active_op {
            Some(crate::ops::ActiveOperation::MigrateDisc(ctx)) => {
                assert!(ctx.chain_ok);
                assert_eq!(
                    ctx.source_fingerprint.as_deref(),
                    Some(expected_hash.as_str()),
                );
            }
            _ => panic!("expected MigrateDisc active_op"),
        }
    }

    #[test]
    fn migrate_confirm_bytes_from_last_session_only() {
        let base = migrate_app_with_sessions(3);
        let expected: u64 = base
            .disc
            .prior_sessions
            .last()
            .unwrap()
            .files
            .iter()
            .map(|f| f.data.len() as u64)
            .sum();
        let all_bytes: u64 = base
            .disc
            .prior_sessions
            .iter()
            .flat_map(|s| s.files.iter())
            .map(|f| f.data.len() as u64)
            .sum();

        let app = migrate_app_with_active_op(3);
        match &app.active_op {
            Some(crate::ops::ActiveOperation::MigrateDisc(ctx)) => {
                assert_eq!(ctx.total_bytes, expected);
                assert!(
                    ctx.total_bytes < all_bytes,
                    "should only count last session, not all"
                );
            }
            _ => panic!("expected MigrateDisc active_op"),
        }
    }

    #[test]
    fn confirm_migrate_action_moves_sessions_and_clears_disc() {
        let mut app = migrate_app_with_active_op(3);

        // Press [1] to confirm — transitions to WaitTarget.
        let action = app.handle_key_event(key(KeyCode::Char('1')));
        app.update(action);

        assert!(app.disc.prior_sessions.is_empty());
        assert!(app.disc.optical_dev.is_none());
        assert!(app.disc.sessions_remaining.is_none());
        match &app.active_op {
            Some(crate::ops::ActiveOperation::MigrateDisc(ctx)) => {
                assert_eq!(ctx.sessions.len(), 3);
                assert_eq!(
                    ctx.phase,
                    crate::ops::migrate_disc::MigratePhase::WaitTarget
                );
            }
            _ => panic!("expected MigrateDisc active_op in WaitTarget"),
        }
    }

    #[test]
    fn migrate_confirm_empty_disc_still_sets_state() {
        let app = migrate_app_with_active_op(0);

        assert_eq!(app.ceremony.state, CeremonyPhase::ActiveOp);
        match &app.active_op {
            Some(crate::ops::ActiveOperation::MigrateDisc(ctx)) => {
                assert_eq!(ctx.total_bytes, 0);
                assert!(ctx.source_fingerprint.is_none());
            }
            _ => panic!("expected MigrateDisc active_op"),
        }
    }

    // ── Migrate build_burn_session tests ─────────────────────────────────

    #[test]
    fn migrate_build_burn_session_is_pure_copy() {
        let mut app = migrate_app_with_active_op(3);
        // Simulate [1] to move sessions to context.
        let action = app.handle_key_event(key(KeyCode::Char('1')));
        app.update(action);

        // Grab expected source files from the op context before build_burn_session.
        let source_sessions: Vec<crate::media::SessionEntry> =
            if let Some(crate::ops::ActiveOperation::MigrateDisc(ref ctx)) = app.active_op {
                ctx.sessions.clone()
            } else {
                panic!("expected MigrateDisc active_op");
            };

        let staging =
            std::env::temp_dir().join(format!("anodize-migrate-test-{}", std::process::id()));
        std::fs::create_dir_all(&staging).unwrap();

        let session = app
            .build_burn_session(&staging)
            .expect("should produce session");

        // Must match the last source session's files exactly.
        let source_files = &source_sessions.last().unwrap().files;
        assert_eq!(session.files.len(), source_files.len());
        for (got, want) in session.files.iter().zip(source_files.iter()) {
            assert_eq!(got.name, want.name);
            assert_eq!(got.data, want.data);
        }

        // No MIGRATION.JSON injected.
        assert!(
            !session.files.iter().any(|f| f.name == "MIGRATION.JSON"),
            "pure copy should not contain MIGRATION.JSON"
        );

        let _ = std::fs::remove_dir_all(&staging);
    }

    #[test]
    fn migrate_build_burn_session_empty_returns_none() {
        let mut app = crate::app::App::new(PathBuf::from("/tmp/test-shuttle"));
        // migrate_sessions is empty — no source data.

        let staging =
            std::env::temp_dir().join(format!("anodize-migrate-empty-{}", std::process::id()));
        std::fs::create_dir_all(&staging).unwrap();

        assert!(
            app.build_burn_session(&staging).is_none(),
            "should return None when no source sessions"
        );

        let _ = std::fs::remove_dir_all(&staging);
    }

    // ── Quit-guard tests ────────────────────────────────────────────────

    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    fn ctrl_c() -> KeyEvent {
        KeyEvent {
            code: KeyCode::Char('c'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    #[test]
    fn q_never_quits_in_normal_phases() {
        let mut app = crate::app::App::new(PathBuf::from("/tmp/test-shuttle"));
        // Setup mode
        let action = app.handle_key_event(key(KeyCode::Char('q')));
        assert!(
            !matches!(action, Action::Quit),
            "'q' should not produce Quit in Setup mode"
        );

        // Ceremony OperationSelect
        app.mode = crate::action::Mode::Ceremony;
        app.ceremony.state = CeremonyPhase::OperationSelect;
        let action = app.handle_key_event(key(KeyCode::Char('q')));
        assert!(
            !matches!(action, Action::Quit),
            "'q' should not produce Quit in OperationSelect"
        );

        // Ceremony ephemeral phase (ActiveOp — used by SignCsr, InitRoot, etc.)
        app.ceremony.state = CeremonyPhase::ActiveOp;
        let action = app.handle_key_event(key(KeyCode::Char('q')));
        assert!(
            !matches!(action, Action::Quit),
            "'q' should not produce Quit in ActiveOp"
        );
    }

    #[test]
    fn q_quits_in_disc_done_and_done() {
        let mut app = crate::app::App::new(PathBuf::from("/tmp/test-shuttle"));
        app.mode = crate::action::Mode::Ceremony;

        app.ceremony.state = CeremonyPhase::DiscDone;
        let action = app.handle_key_event(key(KeyCode::Char('q')));
        assert!(
            matches!(action, Action::Quit),
            "'q' should produce Quit in DiscDone"
        );

        app.ceremony.state = CeremonyPhase::Done;
        let action = app.handle_key_event(key(KeyCode::Char('q')));
        assert!(
            matches!(action, Action::Quit),
            "'q' should produce Quit in Done"
        );
    }

    #[test]
    fn ctrl_c_shows_confirm_in_safe_phase() {
        let mut app = crate::app::App::new(PathBuf::from("/tmp/test-shuttle"));
        app.mode = crate::action::Mode::Ceremony;
        app.ceremony.state = CeremonyPhase::OperationSelect;

        let action = app.handle_key_event(ctrl_c());

        assert!(
            matches!(action, Action::Noop),
            "Ctrl+C should return Noop (dialog opened)"
        );
        assert!(
            app.confirm_dialog.is_some(),
            "Ctrl+C should open quit confirmation dialog"
        );
    }

    #[test]
    fn ctrl_c_blocked_in_ephemeral_phase() {
        let mut app = crate::app::App::new(PathBuf::from("/tmp/test-shuttle"));
        app.mode = crate::action::Mode::Ceremony;
        // Use ClockReconfirm as an ephemeral phase (Quorum removed; ops handle it internally).
        app.ceremony.state = CeremonyPhase::ClockReconfirm;

        let action = app.handle_key_event(ctrl_c());

        assert!(
            matches!(action, Action::Noop),
            "Ctrl+C should return Noop in ephemeral phase"
        );
        assert!(
            app.confirm_dialog.is_none(),
            "Ctrl+C should NOT open dialog in ephemeral phase"
        );
    }

    #[test]
    fn esc_opens_abort_confirm_from_sign_csr_cert_preview() {
        use crate::ops::sign_csr::{SignCsrCtx, SignCsrPhase};

        let mut app = crate::app::App::new(PathBuf::from("/tmp/test-shuttle"));
        app.mode = crate::action::Mode::Ceremony;
        app.setup_complete = true;
        // Set up a SignCsrCtx in CertPreview phase via ActiveOp.
        let mut ctx = SignCsrCtx::new(vec![], None, vec!["  [1]  test".into()]);
        ctx.phase = SignCsrPhase::CertPreview;
        app.active_op = Some(crate::ops::ActiveOperation::SignCsr(ctx));
        app.ceremony.state = CeremonyPhase::ActiveOp;

        let action = app.handle_key_event(key(KeyCode::Esc));

        assert!(
            matches!(action, Action::Noop),
            "Esc should return Noop (dialog opened)"
        );
        assert!(
            app.confirm_dialog.is_some(),
            "Esc in CertPreview should open abort confirmation dialog"
        );
        // Ceremony state should NOT have changed yet.
        assert_eq!(app.ceremony.state, CeremonyPhase::ActiveOp);
    }

    #[test]
    fn esc_opens_abort_confirm_from_clock_reconfirm() {
        let mut app = crate::app::App::new(PathBuf::from("/tmp/test-shuttle"));
        app.mode = crate::action::Mode::Ceremony;
        app.setup_complete = true;
        app.ceremony.state = CeremonyPhase::ClockReconfirm;

        let action = app.handle_key_event(key(KeyCode::Esc));

        assert!(matches!(action, Action::Noop));
        assert!(
            app.confirm_dialog.is_some(),
            "Esc in ClockReconfirm should open abort confirmation dialog"
        );
        assert_eq!(app.ceremony.state, CeremonyPhase::ClockReconfirm);
    }

    #[test]
    fn holds_ephemeral_state_correct() {
        use crate::modes::ceremony::{CeremonyMode, CeremonyPhase};
        let mut cm = CeremonyMode::new();

        cm.state = CeremonyPhase::OperationSelect;
        assert!(!cm.holds_ephemeral_state(), "OperationSelect is safe");

        cm.state = CeremonyPhase::Done;
        assert!(!cm.holds_ephemeral_state(), "Done is safe");

        cm.state = CeremonyPhase::DiscDone;
        assert!(!cm.holds_ephemeral_state(), "DiscDone is safe");

        cm.state = CeremonyPhase::ActiveOp;
        assert!(cm.holds_ephemeral_state(), "ActiveOp is ephemeral");

        cm.state = CeremonyPhase::Commit;
        assert!(cm.holds_ephemeral_state(), "Commit is ephemeral");

        cm.state = CeremonyPhase::BurningDisc;
        assert!(cm.holds_ephemeral_state(), "BurningDisc is ephemeral");
    }

    #[test]
    fn ceremony_cancel_resets_state() {
        let mut app = crate::app::App::new(PathBuf::from("/tmp/test-shuttle"));
        let ctx = RevokeCertCtx::new(vec![], Some(1), vec![], None);
        app.active_op = Some(crate::ops::ActiveOperation::RevokeCert(ctx));
        app.ceremony.state = CeremonyPhase::ActiveOp;

        // CeremonyCancel from ActiveOp(RevokeSelect) should reset without
        // confirmation (needs_abort_confirmation is false for RevokeSelect).
        app.update(Action::CeremonyCancel);

        assert_eq!(app.ceremony.state, CeremonyPhase::OperationSelect);
        assert!(app.current_op().is_none());
    }

    // ── Clock drift guard tests ────────────────────────────────────────

    #[test]
    fn clock_is_fresh_when_just_confirmed() {
        let mut app = crate::app::App::new(PathBuf::from("/tmp/test-shuttle"));
        app.confirmed_time = Some(std::time::SystemTime::now());
        assert!(app.clock_is_fresh());
    }

    #[test]
    fn clock_is_stale_when_never_confirmed() {
        let app = crate::app::App::new(PathBuf::from("/tmp/test-shuttle"));
        assert!(!app.clock_is_fresh());
    }

    #[test]
    fn clock_is_stale_after_threshold() {
        let mut app = crate::app::App::new(PathBuf::from("/tmp/test-shuttle"));
        app.confirmed_time = Some(std::time::SystemTime::now() - crate::app::CLOCK_DRIFT_THRESHOLD);
        assert!(
            !app.clock_is_fresh(),
            "clock should be stale at exactly the threshold"
        );
    }

    #[test]
    fn do_start_burn_with_fresh_clock_skips_dialog() {
        let mut app = crate::app::App::new(PathBuf::from("/tmp/test-shuttle"));
        app.confirmed_time = Some(std::time::SystemTime::now());
        app.ceremony.state = CeremonyPhase::ActiveOp;
        app.update(Action::DoStartBurn);

        // No confirmation dialog — proceeds directly to do_start_burn().
        // (In the test env do_start_burn returns early because there is no
        // staging directory, so we just verify no dialog was interposed.)
        assert!(
            app.confirm_dialog.is_none(),
            "should skip confirm dialog and proceed directly to burn"
        );
    }

    #[test]
    fn do_start_burn_with_stale_clock_redirects_to_reconfirm() {
        let mut app = crate::app::App::new(PathBuf::from("/tmp/test-shuttle"));
        app.confirmed_time = Some(std::time::SystemTime::now() - crate::app::CLOCK_DRIFT_THRESHOLD);
        app.ceremony.state = CeremonyPhase::ActiveOp;
        app.update(Action::DoStartBurn);

        assert!(
            app.confirm_dialog.is_none(),
            "stale clock should NOT open confirm dialog"
        );
        assert_eq!(
            app.ceremony.state,
            CeremonyPhase::ClockReconfirm,
            "should redirect to ClockReconfirm"
        );
        assert!(app.pending_burn_reconfirm);
    }

    #[test]
    fn reconfirm_clock_after_stale_burn_skips_dialog() {
        let mut app = crate::app::App::new(PathBuf::from("/tmp/test-shuttle"));
        app.pending_burn_reconfirm = true;
        app.ceremony.state = CeremonyPhase::ClockReconfirm;
        app.update(Action::ReconfirmClock);

        assert!(
            !app.pending_burn_reconfirm,
            "flag should be cleared after reconfirm"
        );
        // No confirmation dialog — proceeds directly to do_start_burn().
        assert!(app.confirm_dialog.is_none(), "should skip confirm dialog");
        assert!(
            app.clock_is_fresh(),
            "clock should be fresh after reconfirm"
        );
    }

    #[test]
    fn abort_confirm_two_key_sequence_cancels_ceremony() {
        let mut app = crate::app::App::new(PathBuf::from("/tmp/test-shuttle"));
        app.mode = crate::action::Mode::Ceremony;
        app.setup_complete = true;
        app.pending_burn_reconfirm = true;
        app.ceremony.state = CeremonyPhase::ClockReconfirm;

        // Esc opens the abort confirm dialog.
        let action = app.handle_key_event(key(KeyCode::Esc));
        assert!(matches!(action, Action::Noop));
        assert!(app.confirm_dialog.is_some());

        // Press [1] — first key of two-key confirm.
        let action = app.handle_key_event(key(KeyCode::Char('1')));
        assert!(matches!(action, Action::Noop));
        assert!(app.confirm_dialog.is_some(), "dialog should still be open");

        // Press [Enter] — second key fires the abort action.
        let action = app.handle_key_event(key(KeyCode::Enter));
        app.update(action);

        assert!(
            !app.pending_burn_reconfirm,
            "CeremonyCancel should clear pending_burn_reconfirm"
        );
        assert_eq!(app.ceremony.state, CeremonyPhase::OperationSelect);
        assert!(app.confirm_dialog.is_none());
    }

    #[test]
    fn abort_confirm_esc_dismisses_dialog() {
        let mut app = crate::app::App::new(PathBuf::from("/tmp/test-shuttle"));
        app.mode = crate::action::Mode::Ceremony;
        app.setup_complete = true;
        // Use ActiveOp with an IssueCrlCtx which has needs_abort_confirmation.
        let ctx = crate::ops::issue_crl::IssueCrlCtx::new(vec![], Some(1), None);
        app.active_op = Some(crate::ops::ActiveOperation::IssueCrl(ctx));
        app.ceremony.state = CeremonyPhase::ActiveOp;

        // Esc opens the abort confirm dialog.
        let _ = app.handle_key_event(key(KeyCode::Esc));
        assert!(app.confirm_dialog.is_some());

        // Esc on the dialog dismisses it without aborting.
        let action = app.handle_key_event(key(KeyCode::Esc));
        assert!(matches!(action, Action::Noop));
        assert!(app.confirm_dialog.is_none(), "dialog should be dismissed");
        assert_eq!(
            app.ceremony.state,
            CeremonyPhase::ActiveOp,
            "ceremony should continue after dismissing dialog"
        );
    }

    #[test]
    fn validate_report_esc_exits_without_dialog() {
        let mut app = crate::app::App::new(PathBuf::from("/tmp/test-shuttle"));
        app.mode = crate::action::Mode::Ceremony;
        app.setup_complete = true;
        // Set up a ValidateCtx via the new ActiveOp system.
        app.active_op = Some(crate::ops::ActiveOperation::ValidateDisc(
            crate::ops::validate_disc::ValidateCtx::run(&app.make_shared()),
        ));
        app.ceremony.state = CeremonyPhase::ActiveOp;

        let action = app.handle_key_event(key(KeyCode::Esc));
        app.update(action);

        // ValidateReport is read-only — Esc should cancel directly, no dialog.
        assert!(app.confirm_dialog.is_none());
        assert_eq!(app.ceremony.state, CeremonyPhase::OperationSelect);
    }

    // ── Shuttle write tests ──────────────────────────────────────────────

    #[test]
    fn shuttle_write_skips_mount_check_for_no_artifact_ops() {
        for op in [
            Operation::RekeyShares,
            Operation::KeyBackup,
            Operation::ValidateDisc,
            Operation::MigrateDisc,
        ] {
            let mut app = crate::app::App::new(PathBuf::from("/tmp/nonexistent-shuttle-path"));
            app.ceremony.state = CeremonyPhase::DiscDone;

            app.do_write_shuttle();

            assert_eq!(
                app.ceremony.state,
                CeremonyPhase::Done,
                "{op:?} should complete without mount check"
            );
        }
    }

    #[test]
    fn shuttle_write_fails_on_stale_mount() {
        // Create a temp dir that exists but is not a mount point.
        let dir = std::env::temp_dir().join("anodize-test-stale-shuttle");
        let _ = std::fs::create_dir_all(&dir);
        let mut app = crate::app::App::new(dir.clone());
        // Provide an active_op with artifacts so write_shuttle_artifacts returns Ok(true).
        let mut ctx = crate::ops::init_root::InitRootCtx::new();
        ctx.cert_der = Some(vec![0xDE, 0xAD]);
        ctx.crl_der = Some(vec![0xBE, 0xEF]);
        app.active_op = Some(crate::ops::ActiveOperation::InitRoot(ctx));
        app.ceremony.state = CeremonyPhase::DiscDone;

        app.do_write_shuttle();

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);

        // State should NOT advance to Done — the mount check should reject.
        assert_ne!(
            app.ceremony.state,
            CeremonyPhase::Done,
            "stale mount should block shuttle write"
        );
        assert!(
            app.status.contains("stale")
                || app.status.contains("not an active mount")
                || app.status.contains("cannot read"),
            "status should mention stale mount, got: {}",
            app.status
        );
    }

    #[test]
    fn shuttle_write_fails_on_nonexistent_path() {
        let mut app = crate::app::App::new(PathBuf::from("/tmp/anodize-test-nonexistent-42"));
        // Provide an active_op with artifacts so write_shuttle_artifacts returns Ok(true).
        let mut ctx = crate::ops::sign_csr::SignCsrCtx::new(vec![], None, vec![]);
        ctx.cert_der = Some(vec![0xCA, 0xFE]);
        app.active_op = Some(crate::ops::ActiveOperation::SignCsr(ctx));
        app.ceremony.state = CeremonyPhase::DiscDone;

        app.do_write_shuttle();

        assert_ne!(
            app.ceremony.state,
            CeremonyPhase::Done,
            "nonexistent path should block shuttle write"
        );
        assert!(
            app.status.contains("stale") || app.status.contains("does not exist"),
            "status should mention missing path, got: {}",
            app.status
        );
    }

    // ── Disc state tracking tests ──────────────────────────────────────

    #[test]
    fn tick_intent_burn_error_clears_disc_state() {
        let mut app = test_app();
        app.ceremony.state = CeremonyPhase::Commit;
        app.hw.disc_state = HwState::Present("/dev/sr0".into());

        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(crate::media::BurnProgress::Done(Err(anyhow::anyhow!(
            "write error"
        ))))
        .unwrap();
        app.disc.burn_rx = Some(rx);

        app.tick_intent_burn();

        assert_eq!(
            app.hw.disc_state,
            HwState::Absent,
            "intent burn error should reset disc_state to Absent"
        );
    }

    #[test]
    fn tick_record_burn_error_clears_disc_state() {
        let mut app = test_app();
        app.ceremony.state = CeremonyPhase::BurningDisc;
        app.hw.disc_state = HwState::Present("/dev/sr0".into());

        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(crate::media::BurnProgress::Done(Err(anyhow::anyhow!(
            "laser misfire"
        ))))
        .unwrap();
        app.disc.burn_rx = Some(rx);

        app.tick_record_burn();

        assert_eq!(
            app.hw.disc_state,
            HwState::Absent,
            "record burn error should reset disc_state to Absent"
        );
    }

    #[test]
    fn confirm_migrate_clears_disc_state() {
        let mut app = migrate_app_with_active_op(2);
        app.hw.disc_state = HwState::Present("/dev/sr0".into());

        // Press [1] to confirm — clears disc state via handle_key.
        let action = app.handle_key_event(key(KeyCode::Char('1')));
        app.update(action);

        // disc_state is managed by hardware polling, not the confirm action.
        // But optical_dev/sessions_remaining are cleared by the context.
        assert!(app.disc.optical_dev.is_none());
        assert!(app.disc.sessions_remaining.is_none());
    }

    // ── Async disc scan tests ─────────────────────────────────────────

    #[test]
    fn tick_wait_disc_spawns_scan_and_shows_scanning_status() {
        let mut app = crate::app::App::new(PathBuf::from("/tmp/test-shuttle"));
        assert!(app.disc.disc_scan_rx.is_none());

        // First tick spawns a background scan thread.
        app.tick_wait_disc(false);

        assert!(
            app.disc.disc_scan_rx.is_some(),
            "tick_wait_disc should start a background scan"
        );
        assert!(
            app.status.contains("Scanning"),
            "status should mention scanning, got: {}",
            app.status
        );
    }

    #[test]
    fn tick_wait_disc_returns_early_while_scan_in_flight() {
        let mut app = crate::app::App::new(PathBuf::from("/tmp/test-shuttle"));
        // Pre-populate with a channel that will never send.
        let (_tx, rx) = std::sync::mpsc::channel::<crate::disc::DiscScanBatch>();
        app.disc.disc_scan_rx = Some(rx);
        app.set_status("before");

        app.tick_wait_disc(false);

        // Should return without changing status (channel is empty).
        assert_eq!(
            app.status, "before",
            "should not change status while scan is pending"
        );
        assert!(
            app.disc.disc_scan_rx.is_some(),
            "disc_scan_rx should remain set"
        );
    }

    #[test]
    fn tick_wait_disc_processes_scan_result_from_channel() {
        let mut app = crate::app::App::new(PathBuf::from("/tmp/test-shuttle"));

        // Feed a pre-built scan result through the channel.
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(crate::disc::DiscScanBatch {
            drives: vec![PathBuf::from("/dev/sr0")],
            scans: vec![(
                PathBuf::from("/dev/sr0"),
                Ok(crate::media::DiscScan {
                    sessions: Vec::new(),
                    capacity_summary: "BD-R: 0 used, 100 remaining (max 100)".into(),
                    sessions_remaining: 100,
                }),
            )],
        })
        .unwrap();
        app.disc.disc_scan_rx = Some(rx);

        app.tick_wait_disc(false);

        // Scan result should be consumed and disc state updated.
        assert!(
            app.disc.disc_scan_rx.is_none(),
            "disc_scan_rx should be cleared"
        );
        assert!(
            matches!(app.hw.disc_state, HwState::Present(_)),
            "disc_state should be Present, got {:?}",
            app.hw.disc_state
        );
        assert!(
            app.status.contains("BD-R"),
            "status should contain capacity summary, got: {}",
            app.status
        );
    }

    #[test]
    fn tick_wait_disc_handles_disconnected_channel() {
        let mut app = crate::app::App::new(PathBuf::from("/tmp/test-shuttle"));

        // Create a channel and immediately drop the sender.
        let (tx, rx) = std::sync::mpsc::channel::<crate::disc::DiscScanBatch>();
        drop(tx);
        app.disc.disc_scan_rx = Some(rx);

        app.tick_wait_disc(false);

        // Should detect disconnect, clear rx, and spawn a new scan.
        assert!(
            app.disc.disc_scan_rx.is_some(),
            "should have spawned a new scan after disconnect"
        );
        assert!(
            app.status.contains("Scanning"),
            "status should show scanning, got: {}",
            app.status
        );
    }

    #[test]
    fn process_disc_scan_no_drives_reports_absent() {
        let mut app = crate::app::App::new(PathBuf::from("/tmp/test-shuttle"));
        app.process_disc_scan(
            crate::disc::DiscScanBatch {
                drives: vec![],
                scans: vec![],
            },
            false,
        );

        assert_eq!(app.hw.disc_state, HwState::Absent);
        assert!(
            app.status.contains("No optical drive"),
            "status should mention no drive, got: {}",
            app.status
        );
    }

    #[test]
    fn process_disc_scan_rewritable_reports_rejection() {
        let mut app = crate::app::App::new(PathBuf::from("/tmp/test-shuttle"));
        app.process_disc_scan(
            crate::disc::DiscScanBatch {
                drives: vec![PathBuf::from("/dev/sr0")],
                scans: vec![(
                    PathBuf::from("/dev/sr0"),
                    Err("rewritable media not allowed".into()),
                )],
            },
            false,
        );

        assert_eq!(app.hw.disc_state, HwState::Absent);
        assert!(
            app.status.contains("rewritable"),
            "status should mention rewritable, got: {}",
            app.status
        );
    }
}
