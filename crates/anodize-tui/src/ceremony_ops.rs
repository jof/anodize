//! Ceremony operation methods on App.
//!
//! This is a separate `impl App` block to keep app.rs focused on dispatch/rendering
//! and this file focused on the ceremony business logic.

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::SystemTime;

use anodize_audit::{genesis_hash, AuditLog};
use anodize_ca::{build_root_cert, issue_crl, sign_intermediate_csr, P384HsmSigner};
use anodize_config::{load as load_profile, serialize_revocation_list, RevocationEntry};
use anodize_hsm::{create_backend, Hsm, HsmActor, KeySpec};
use der::{Decode, Encode};
use ratatui::{layout::Rect, Frame};
use secrecy::SecretString;
use x509_cert::certificate::Certificate;

use crate::action::Operation;
use crate::app::App;
use crate::components::status_bar::HwState;
use crate::helpers::*;
use crate::media::{self, IsoFile, SessionEntry};
use crate::modes::ceremony::{CeremonyPhase, PlanningState};
use crate::modes::setup::SetupPhase;

impl App {
    // ── Shuttle scan tick ─────────────────────────────────────────────────────

    pub(crate) fn tick_wait_shuttle(&mut self) {
        let diagnostics = media::usb_scan_diagnostics();
        let candidates = media::scan_usb_partitions();
        if candidates.is_empty() {
            self.set_status(format!("Scanning… {diagnostics}"));
            return;
        }
        match media::find_profile_usb(&candidates, &self.shuttle_mount) {
            Ok(Some((profile_path, dev_path))) => {
                let _ = dev_path;
                #[cfg(feature = "dev-softhsm-usb")]
                if let Err(e) = configure_softhsm_from_shuttle(&self.shuttle_mount) {
                    self.set_status(format!("SoftHSM2 USB setup failed: {e}"));
                    let _ = media::unmount(&self.shuttle_mount);
                    return;
                }
                let raw_bytes = std::fs::read(&profile_path).unwrap_or_default();
                match load_profile(&profile_path) {
                    Ok(profile) => {
                        self.profile = Some(profile);
                        self.profile_toml_bytes = Some(raw_bytes);
                        self.setup.phase = SetupPhase::ProfileLoaded;
                        self.set_status("Profile loaded from USB.");
                    }
                    Err(e) => {
                        self.set_status(format!("Profile parse error: {e}"));
                        let _ = media::unmount(&self.shuttle_mount);
                    }
                }
            }
            Ok(None) => {
                self.set_status(format!(
                    "No profile.toml found ({diagnostics}) — insert USB with profile.toml."
                ));
            }
            Err(e) => {
                self.set_status(format!("Mount failed ({diagnostics}): {e}"));
            }
        }
    }

    // ── Disc scan tick ────────────────────────────────────────────────────────

    pub(crate) fn tick_wait_disc(&mut self, need_blank: bool) {
        if self.skip_disc {
            self.disc.optical_dev = Some(PathBuf::from("/run/anodize/staging"));
            self.disc.sessions_remaining = Some(100);
            let label = if need_blank {
                "--skip-disc mode: target disc ready. Press [1]."
            } else {
                "--skip-disc mode: disc ready. Press [1]."
            };
            self.set_status(label);
            return;
        }

        let drives = media::scan_optical_drives();
        let mut rw_rejection: Option<String> = None;
        for dev in &drives {
            match media::scan_disc(dev) {
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
                    if !need_blank {
                        self.disc.prior_sessions = scan.sessions;
                        self.disc.session_state =
                            load_session_state_from_sessions(&self.disc.prior_sessions);
                        if let Some(ref state) = self.disc.session_state {
                            // Populate revocation list and CRL number from state
                            self.data.crl_number = Some(state.crl_number);
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
        if let Some(msg) = rw_rejection {
            self.set_status(msg);
        } else if drives.is_empty() {
            self.set_status("No optical drive detected. Insert drive and disc.");
        } else {
            self.set_status(
                "No blank/appendable disc found. Insert write-once disc \
                 (BD-R, DVD-R, CD-R, or M-Disc).",
            );
        }
    }

    // ── Post-intent InitRoot: HSM bootstrap + keygen + cert build ─────────────

    pub(crate) fn post_intent_init_root(&mut self) -> Result<(), String> {
        // For key generation (action 1) the token may not exist yet — open
        // the first available slot.  For find-existing (action 2) the token
        // must already exist so use the normal path.
        if self.disc.pending_key_action == Some(1) {
            self.do_bootstrap_hsm()?;
        } else {
            let pin = self.pin_buf.clone();
            self.do_login_with_pin(&pin)?;
        }

        match self.disc.pending_key_action {
            Some(1) => self.do_generate_and_build(),
            Some(2) => self.do_find_and_build(),
            _ => Err("Unknown key action".into()),
        }
    }

    // ── Intent burn tick ──────────────────────────────────────────────────────

    pub(crate) fn tick_intent_burn(&mut self) {
        let result = match &self.disc.burn_rx {
            Some(rx) => match rx.try_recv() {
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    tracing::debug!("tick_intent_burn: channel present but empty");
                    return;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    tracing::error!("tick_intent_burn: channel disconnected!");
                    Some(Err(anyhow::anyhow!("disc write channel disconnected")))
                }
                Ok(r) => {
                    tracing::info!("tick_intent_burn: received result from channel");
                    Some(r)
                }
            },
            None => {
                tracing::error!("tick_intent_burn: burn_rx is None but state is Commit!");
                return;
            }
        };
        self.disc.burn_rx = None;
        match result {
            Some(Err(e)) => {
                tracing::error!("tick_intent_burn: write failed: {e:#}");
                self.set_status(format!("Intent disc write failed: {e:#}"));
                self.ceremony.state = CeremonyPhase::OperationSelect;
                self.setup.phase = SetupPhase::WaitDisc;
                self.disc.optical_dev = None;
            }
            Some(Ok(())) => {
                tracing::info!("tick_intent_burn: write OK, advancing state");
                if let Some(intent) = self.disc.pending_intent_session.take() {
                    self.disc.intent_session_dir_name = Some(intent.dir_name.clone());
                    self.disc.prior_sessions.push(intent);
                }
                match self.current_op.clone() {
                    Some(Operation::InitRoot) => {
                        if let Err(e) = self.post_intent_init_root() {
                            tracing::error!("tick_intent_burn: post-commit InitRoot failed: {e}");
                            self.set_status(e);
                            self.ceremony.state = CeremonyPhase::PostCommitError;
                        }
                    }
                    Some(Operation::SignCsr)
                    | Some(Operation::RevokeCert)
                    | Some(Operation::IssueCrl) => {
                        self.enter_quorum_phase();
                    }
                    Some(Operation::KeyBackup) => {
                        // Quorum already completed during Planning(BackupQuorum).
                        // Execute the backup operation, then burn the result.
                        self.do_backup_execute();
                        if self.utilities.backup.phase
                            == crate::modes::utilities::backup::BackupPhase::Done
                        {
                            self.set_status("Backup succeeded. Writing record to disc…");
                        } else {
                            self.set_status("Backup failed — recording result to disc…");
                        }
                        self.do_start_burn();
                    }
                    _ => {
                        self.set_status("Unknown operation after intent");
                        self.ceremony.state = CeremonyPhase::OperationSelect;
                    }
                }
            }
            None => unreachable!(),
        }
    }

    // ── Record burn tick ──────────────────────────────────────────────────────

    pub(crate) fn tick_record_burn(&mut self) {
        if let Some(rx) = &self.disc.burn_rx {
            if let Ok(result) = rx.try_recv() {
                self.disc.burn_rx = None;
                match result {
                    Ok(()) => {
                        self.ceremony.state = CeremonyPhase::DiscDone;
                        let disc_label = self
                            .disc
                            .optical_dev
                            .as_deref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| "/run/anodize/staging".into());
                        let op_label = match self.current_op {
                            Some(Operation::InitRoot) => "Root init",
                            Some(Operation::SignCsr) => "Intermediate cert",
                            Some(Operation::RevokeCert) => "Revocation + CRL",
                            Some(Operation::IssueCrl) => "CRL refresh",
                            Some(Operation::RekeyShares) => "Re-key shares",
                            Some(Operation::MigrateDisc) => "Disc migration",
                            Some(Operation::KeyBackup) => "Key backup",
                            None => "session",
                        };
                        self.set_status(format!("{op_label} written to disc: {disc_label}"));
                    }
                    Err(e) => {
                        self.set_status(format!("Burn failed: {e} — reinsert disc and retry."));
                        self.ceremony.state = CeremonyPhase::OperationSelect;
                        self.disc.optical_dev = None;
                    }
                }
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
                     Press [1] to continue or [q] to quit.",
                ));
            }
            Err(e) => {
                self.hw.hsm_state = HwState::Error(format!("{e}"));
                self.set_status(format!("HSM detection failed: {e}"));
                self.setup.phase = SetupPhase::ProfileLoaded;
            }
        }
    }

    // ── HSM bootstrap (InitRoot key generation — token may not exist yet) ────

    pub(crate) fn do_bootstrap_hsm(&mut self) -> Result<(), String> {
        let pin_bytes = match hex::decode(&self.pin_buf) {
            Ok(b) => b,
            Err(e) => return Err(format!("Internal PIN decode error: {e}")),
        };
        let user_pin = SecretString::new(hex::encode(&pin_bytes));

        let cfg = match &self.profile {
            Some(p) => &p.hsm,
            None => return Err("No profile loaded".into()),
        };

        let backend = match create_backend(cfg.backend) {
            Ok(b) => b,
            Err(e) => return Err(format!("HSM backend error: {e}")),
        };

        let mut tokens = match backend.list_tokens() {
            Ok(t) => t,
            Err(e) => return Err(format!("HSM enumerate failed: {e}")),
        };

        // No initialized tokens — check for empty/uninitialized slots that
        // C_InitToken can provision (e.g. SoftHSM2 with an empty token dir).
        if tokens.is_empty() {
            tokens = match backend.list_all_slots() {
                Ok(s) => s,
                Err(e) => return Err(format!("HSM slot enumerate failed: {e}")),
            };
        }

        if tokens.is_empty() {
            return Err("No HSM slots found. Insert a YubiHSM or HSM device.".into());
        }

        // Pick the first uninitialised slot, or fall back to the first slot.
        let target = tokens
            .iter()
            .find(|t| !t.user_pin_initialized)
            .or_else(|| tokens.first());
        let target = match target {
            Some(t) => t.clone(),
            None => return Err("No suitable HSM token found.".into()),
        };

        tracing::info!(
            serial = %target.serial_number,
            slot_id = target.slot_id,
            label = %target.token_label,
            initialized = target.token_initialized,
            pin_initialized = target.user_pin_initialized,
            "do_bootstrap_hsm: selected token"
        );

        // SO PIN — use the same secret for now; production may want a
        // separate SO PIN split.
        let so_pin = user_pin.clone();

        let hsm = match backend.bootstrap(target.slot_id, &so_pin, &user_pin, &cfg.token_label) {
            Ok(h) => h,
            Err(e) => return Err(format!("HSM bootstrap failed: {e}")),
        };

        let serial = target.serial_number.clone();
        let actor = HsmActor::spawn(hsm);
        self.hw.actor = Some(actor);
        self.hw.hsm_state = HwState::Ready(format!(
            "bootstrapped (serial={serial}, label={})",
            cfg.token_label
        ));
        tracing::info!(serial, label = %cfg.token_label, "do_bootstrap_hsm: token ready");
        Ok(())
    }

    // ── HSM login via reconstructed PIN (called from Quorum phase) ───────────

    pub(crate) fn do_login_with_pin(&mut self, pin_hex: &str) -> Result<(), String> {
        let pin_bytes = match hex::decode(pin_hex) {
            Ok(b) => b,
            Err(e) => return Err(format!("Internal PIN decode error: {e}")),
        };
        let pin = SecretString::new(hex::encode(&pin_bytes));

        let cfg = match &self.profile {
            Some(p) => &p.hsm,
            None => return Err("No profile loaded".into()),
        };

        let backend = match create_backend(cfg.backend) {
            Ok(b) => b,
            Err(e) => return Err(format!("HSM backend error: {e}")),
        };

        let hsm = match backend.open_session(&cfg.token_label, &pin) {
            Ok(h) => h,
            Err(e) => return Err(format!("HSM open/login failed: {e}")),
        };
        let actor = HsmActor::spawn(hsm);
        self.hw.actor = Some(actor);
        self.hw.hsm_state = HwState::Ready("authenticated via SSS quorum".into());
        Ok(())
    }

    // ── Quorum phase: collect shares → reconstruct PIN → HSM login ─────────

    /// Enter the Quorum phase: create a ShareInput and switch to Quorum state.
    pub(crate) fn enter_quorum_phase(&mut self) {
        let sss_meta = match &self.disc.session_state {
            Some(state) => state.sss.clone(),
            None => {
                self.set_status("ERROR: no STATE.JSON loaded — cannot enter quorum.");
                self.ceremony.state = CeremonyPhase::OperationSelect;
                return;
            }
        };

        self.sss.share_input = Some(crate::components::share_input::ShareInput::new(
            sss_meta.clone(),
            32,
        ));
        self.ceremony.state = CeremonyPhase::Quorum;
        self.set_status(format!(
            "Quorum: collect {}-of-{} shares to unlock HSM.",
            sss_meta.threshold, sss_meta.total,
        ));

        tracing::info!(
            threshold = sss_meta.threshold,
            total = sss_meta.total,
            "Entering quorum phase for {:?}",
            self.current_op,
        );
    }

    /// Called when quorum ShareInput reaches threshold during the Quorum phase.
    pub(crate) fn do_quorum_complete(&mut self) {
        // Collect shares
        let shares: Vec<anodize_sss::Share> = self
            .sss
            .share_input
            .as_ref()
            .map(|si| si.collected.iter().map(|c| c.share.clone()).collect())
            .unwrap_or_default();
        self.sss.share_input = None;

        let threshold = self
            .disc
            .session_state
            .as_ref()
            .map(|s| s.sss.threshold)
            .unwrap_or(2);

        // Reconstruct PIN
        let pin_bytes = match anodize_sss::reconstruct(&shares, threshold) {
            Ok(b) => b,
            Err(e) => {
                self.set_status(format!("PIN reconstruction failed: {e}"));
                self.ceremony.state = CeremonyPhase::OperationSelect;
                self.current_op = None;
                return;
            }
        };

        // Verify against pin_verify_hash
        let pin_hash = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(&pin_bytes))
        };
        let expected = self
            .disc
            .session_state
            .as_ref()
            .map(|s| s.sss.pin_verify_hash.as_str())
            .unwrap_or("");

        if pin_hash != expected {
            self.set_status("PIN verify hash mismatch — shares may be corrupted.");
            self.ceremony.state = CeremonyPhase::OperationSelect;
            self.current_op = None;
            return;
        }

        // Login to HSM with reconstructed PIN
        let pin_hex = hex::encode(&pin_bytes);
        if let Err(e) = self.do_login_with_pin(&pin_hex) {
            self.set_status(format!("HSM login failed: {e}"));
            self.ceremony.state = CeremonyPhase::OperationSelect;
            self.current_op = None;
            return;
        }

        // Transition to clock re-confirm before signing
        self.ceremony.state = CeremonyPhase::ClockReconfirm;
        self.set_status("Confirm system clock is correct before signing.");
    }

    /// Dispatch to the pending crypto operation after the operator re-confirms
    /// the clock. Called from Action::ReconfirmClock.
    pub(crate) fn do_dispatch_after_clock_reconfirm(&mut self) {
        match self.current_op.clone() {
            Some(Operation::SignCsr) => self.do_sign_csr(),
            Some(Operation::RevokeCert) => self.do_sign_crl_for_revoke(),
            Some(Operation::IssueCrl) => self.do_sign_crl_refresh(),
            other => {
                self.set_status(format!("Unexpected operation after quorum: {other:?}"));
                self.ceremony.state = CeremonyPhase::OperationSelect;
            }
        }
    }

    // ── Operation selection ───────────────────────────────────────────────────

    pub(crate) fn do_select_operation(&mut self, op: Operation) {
        self.current_op = Some(op.clone());
        match op {
            Operation::InitRoot => {
                if self.disc.session_state.is_some() {
                    self.set_status(
                        "Root already initialized on this disc. Use RekeyShares to change PIN.",
                    );
                    self.current_op = None;
                    self.ceremony.state = CeremonyPhase::OperationSelect;
                    return;
                }
                self.sss.custodian_names.clear();
                self.sss.custodian_setup = Some(
                    crate::components::custodian_setup::CustodianSetup::new("Root Init"),
                );
                self.ceremony.state = CeremonyPhase::Planning(PlanningState::CustodianSetup);
                self.set_status("Enter custodian names one-by-one, then set threshold.");
            }
            Operation::SignCsr => {
                self.do_load_csr();
            }
            Operation::RevokeCert => {
                self.do_load_revocation();
                if self.ceremony.state == CeremonyPhase::Planning(PlanningState::RevokeInput) {
                    self.data.revoke_phase = 0;
                    self.data.revoke_serial_buf.clear();
                    self.data.revoke_reason_buf.clear();
                    self.set_status(
                        "Enter certificate serial number (digits). Press Enter to continue.",
                    );
                }
            }
            Operation::IssueCrl => {
                self.do_load_revocation();
                if self.ceremony.state == CeremonyPhase::Planning(PlanningState::CrlPreview) {
                    self.set_status("Review CRL details. [1] to proceed, [q] to cancel.");
                }
            }
            Operation::RekeyShares => {
                if self.disc.session_state.is_none() {
                    self.set_status("No STATE.JSON — run InitRoot first.");
                    self.current_op = None;
                    self.ceremony.state = CeremonyPhase::OperationSelect;
                    return;
                }
                // Enter quorum phase: custodians re-enter shares
                let sss = self.disc.session_state.as_ref().unwrap().sss.clone();
                self.sss.share_input =
                    Some(crate::components::share_input::ShareInput::new(sss, 32));
                self.ceremony.state = CeremonyPhase::Planning(PlanningState::RekeyQuorum);
                self.set_status("Enter threshold shares to reconstruct the PIN.");
            }
            Operation::MigrateDisc => {
                self.do_migrate_confirm();
            }
            Operation::KeyBackup => {
                if self.disc.session_state.is_none() {
                    self.set_status("No STATE.JSON \u{2014} run InitRoot first.");
                    self.current_op = None;
                    self.ceremony.state = CeremonyPhase::OperationSelect;
                    return;
                }
                // Enter backup quorum phase: custodians re-enter shares.
                let sss = self.disc.session_state.as_ref().unwrap().sss.clone();
                self.sss.share_input =
                    Some(crate::components::share_input::ShareInput::new(sss, 32));
                self.ceremony.state = CeremonyPhase::Planning(PlanningState::BackupQuorum);
                self.set_status("Enter threshold shares to reconstruct the HSM PIN for backup.");
            }
        }
    }

    // ── KeyBackup: quorum → reconstruct PIN → discover devices ─────────────

    pub(crate) fn do_backup_quorum_complete(&mut self) {
        // Collect shares from the input component.
        let shares: Vec<anodize_sss::Share> = self
            .sss
            .share_input
            .as_ref()
            .map(|si| si.collected.iter().map(|c| c.share.clone()).collect())
            .unwrap_or_default();
        self.sss.share_input = None;

        let threshold = self
            .disc
            .session_state
            .as_ref()
            .map(|s| s.sss.threshold)
            .unwrap_or(2);

        // Reconstruct PIN.
        let pin_bytes = match anodize_sss::reconstruct(&shares, threshold) {
            Ok(b) => b,
            Err(e) => {
                self.set_status(format!("PIN reconstruction failed: {e}"));
                self.ceremony.state = CeremonyPhase::OperationSelect;
                self.current_op = None;
                return;
            }
        };

        // Verify against pin_verify_hash.
        let pin_hash = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(&pin_bytes))
        };
        let expected = self
            .disc
            .session_state
            .as_ref()
            .map(|s| s.sss.pin_verify_hash.as_str())
            .unwrap_or("");

        if pin_hash != expected {
            self.set_status("PIN verify hash mismatch — shares may be corrupted.");
            self.ceremony.state = CeremonyPhase::OperationSelect;
            self.current_op = None;
            return;
        }

        // Store the reconstructed PIN for backup operations.
        self.pin_buf = hex::encode(&pin_bytes);

        // Discover backup-capable devices using the reconstructed PIN.
        self.utilities.backup.reset();
        if let Some(ref profile) = self.profile {
            match anodize_hsm::create_backup(profile.hsm.backend) {
                Ok(backup_impl) => {
                    let pin = secrecy::SecretString::new(self.pin_buf.clone());
                    self.utilities
                        .backup
                        .discover(backup_impl.as_ref(), Some(&pin));
                }
                Err(e) => {
                    self.utilities.backup.phase =
                        crate::modes::utilities::backup::BackupPhase::Error(format!(
                            "Backend init: {e}"
                        ));
                    self.utilities.backup.render_lines();
                }
            }
        }

        self.ceremony.state = CeremonyPhase::Planning(PlanningState::BackupDevices);
        self.set_status("PIN verified. Select source and destination devices.");

        tracing::info!("KeyBackup: quorum reached, PIN verified, entering device selection");
    }

    /// Execute the backup/pair HSM operation (no audit logging — that happens
    /// in build_burn_session when the record is written to disc).
    pub(crate) fn do_backup_execute(&mut self) {
        let pin = secrecy::SecretString::new(self.pin_buf.clone());
        if let Some(ref profile) = self.profile {
            match anodize_hsm::create_backup(profile.hsm.backend) {
                Ok(backup_impl) => {
                    self.utilities
                        .backup
                        .execute(backup_impl.as_ref(), &pin);
                }
                Err(e) => {
                    self.utilities.backup.phase =
                        crate::modes::utilities::backup::BackupPhase::Error(format!(
                            "Backend init: {e}"
                        ));
                    self.utilities.backup.render_lines();
                }
            }
        }
    }

    // ── InitRoot: confirm custodians → generate PIN → split → reveal ────────

    /// Called by the CustodianSetup component (names already collected).
    pub(crate) fn do_init_root_confirm_custodians_with_threshold(&mut self, threshold: u8) {
        let names = self.sss.custodian_names.clone();

        if names.len() < 2 {
            self.set_status("Need at least 2 custodians for SSS (threshold >= 2).");
            return;
        }
        if names.len() > 255 {
            self.set_status("Maximum 255 custodians.");
            return;
        }

        let total = names.len() as u8;

        // Generate random 32-byte PIN
        let mut pin_bytes = vec![0u8; 32];
        if let Err(e) = getrandom::getrandom(&mut pin_bytes) {
            self.set_status(format!("CSPRNG failure: {e}"));
            return;
        }

        // Split into shares
        let shares = match anodize_sss::split(&pin_bytes, threshold, total) {
            Ok(s) => s,
            Err(e) => {
                self.set_status(format!("SSS split failed: {e}"));
                return;
            }
        };

        // Compute commitments and PIN verify hash
        let mut share_commitments = Vec::with_capacity(shares.len());
        for (share, name) in shares.iter().zip(names.iter()) {
            let commitment = share.commitment(name);
            share_commitments.push(hex::encode(commitment));
        }

        let pin_verify_hash = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(&pin_bytes);
            hex::encode(h.finalize())
        };

        // Store the PIN hex for HSM init later (held in memory only)
        self.pin_buf = hex::encode(&pin_bytes);

        // Build custodian metadata
        let custodians: Vec<anodize_config::state::Custodian> = names
            .iter()
            .enumerate()
            .map(|(i, name)| anodize_config::state::Custodian {
                name: name.clone(),
                index: (i + 1) as u8,
            })
            .collect();

        // Prepare partial SessionState (root_cert fields filled after HSM keygen)
        use anodize_config::state::{SessionState, SssMetadata, STATE_VERSION};
        let state = SessionState {
            version: STATE_VERSION,
            root_cert_sha256: "0".repeat(64), // placeholder, updated after keygen
            root_cert_der_b64: String::new(), // placeholder
            sss: SssMetadata {
                threshold,
                total,
                custodians,
                pin_verify_hash,
                share_commitments,
            },
            revocation_list: vec![],
            crl_number: 0,
            last_audit_hash: String::new(),
        };

        self.disc.session_state = Some(state);
        self.sss.custodian_names = names.clone();
        self.sss.shares = Some(shares.clone());

        // Create ShareReveal component
        self.sss.share_reveal = Some(crate::components::share_reveal::ShareReveal::new(
            shares, &names,
        ));

        self.ceremony.state = CeremonyPhase::Planning(PlanningState::ShareReveal);
        self.set_status(format!(
            "PIN generated. Distributing {total} shares ({threshold}-of-{total}). Hand device to each custodian."
        ));

        tracing::info!(
            threshold,
            total,
            custodians = ?self.sss.custodian_names,
            "InitRoot: SSS split complete, entering share reveal"
        );
    }

    // ── RekeyShares: quorum → reconstruct PIN → new custodians → re-split ───

    pub(crate) fn do_rekey_quorum_complete(&mut self) {
        // Collect shares from the input component
        let shares: Vec<anodize_sss::Share> = self
            .sss
            .share_input
            .as_ref()
            .map(|si| si.collected.iter().map(|c| c.share.clone()).collect())
            .unwrap_or_default();
        self.sss.share_input = None;

        // Reconstruct PIN
        let threshold = self
            .disc
            .session_state
            .as_ref()
            .map(|s| s.sss.threshold)
            .unwrap_or(2);
        let pin_bytes = match anodize_sss::reconstruct(&shares, threshold) {
            Ok(b) => b,
            Err(e) => {
                self.set_status(format!("PIN reconstruction failed: {e}"));
                self.ceremony.state = CeremonyPhase::OperationSelect;
                self.current_op = None;
                return;
            }
        };

        // Verify against pin_verify_hash
        let pin_hash = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(&pin_bytes))
        };
        let expected = self
            .disc
            .session_state
            .as_ref()
            .map(|s| s.sss.pin_verify_hash.as_str())
            .unwrap_or("");

        if pin_hash != expected {
            self.set_status("PIN verify hash mismatch — shares may be corrupted.");
            self.ceremony.state = CeremonyPhase::OperationSelect;
            self.current_op = None;
            return;
        }

        // Store reconstructed PIN for re-splitting
        self.pin_buf = hex::encode(&pin_bytes);
        self.sss.custodian_names.clear();
        self.sss.custodian_setup = Some(crate::components::custodian_setup::CustodianSetup::new(
            "Re-key Shares",
        ));
        self.ceremony.state = CeremonyPhase::Planning(PlanningState::RekeyCustodianSetup);
        self.set_status("PIN verified. Enter new custodian names, then set threshold.");

        tracing::info!("RekeyShares: quorum reached, PIN verified, entering custodian setup");
    }

    pub(crate) fn do_rekey_confirm_custodians_with_threshold(&mut self, threshold: u8) {
        let names = self.sss.custodian_names.clone();

        if names.len() < 2 {
            self.set_status("Need at least 2 custodians for SSS (threshold >= 2).");
            return;
        }
        if names.len() > 255 {
            self.set_status("Maximum 255 custodians.");
            return;
        }

        let total = names.len() as u8;

        // PIN length: 32 bytes
        let pin_bytes = match hex::decode(&self.pin_buf) {
            Ok(b) => b,
            Err(e) => {
                self.set_status(format!("Internal error decoding PIN: {e}"));
                return;
            }
        };

        // Re-split with new custodians
        let shares = match anodize_sss::split(&pin_bytes, threshold, total) {
            Ok(s) => s,
            Err(e) => {
                self.set_status(format!("SSS split failed: {e}"));
                return;
            }
        };

        // Compute new commitments
        let mut share_commitments = Vec::with_capacity(shares.len());
        for (share, name) in shares.iter().zip(names.iter()) {
            let commitment = share.commitment(name);
            share_commitments.push(hex::encode(commitment));
        }

        // Update SessionState SSS metadata
        let custodians: Vec<anodize_config::state::Custodian> = names
            .iter()
            .enumerate()
            .map(|(i, name)| anodize_config::state::Custodian {
                name: name.clone(),
                index: (i + 1) as u8,
            })
            .collect();

        if let Some(ref mut state) = self.disc.session_state {
            state.sss.threshold = threshold;
            state.sss.total = total;
            state.sss.custodians = custodians;
            state.sss.share_commitments = share_commitments;
            // pin_verify_hash stays the same (same PIN)
        }

        self.sss.custodian_names = names.clone();
        self.sss.shares = Some(shares.clone());

        // Create ShareReveal component
        self.sss.share_reveal = Some(crate::components::share_reveal::ShareReveal::new(
            shares, &names,
        ));

        self.ceremony.state = CeremonyPhase::Planning(PlanningState::RekeyShareReveal);
        self.set_status(format!(
            "Distributing {total} new shares ({threshold}-of-{total}). Hand device to each custodian."
        ));

        tracing::info!(
            threshold,
            total,
            custodians = ?self.sss.custodian_names,
            "RekeyShares: re-split complete, entering share reveal"
        );
    }

    // ── Mode 2: Load CSR ──────────────────────────────────────────────────────

    fn do_load_csr(&mut self) {
        let csr_path = self.shuttle_mount.join("csr.der");
        let csr_bytes = match std::fs::read(&csr_path) {
            Ok(b) => b,
            Err(e) => {
                self.set_status(format!("Cannot read csr.der from USB: {e}"));
                self.current_op = None;
                return;
            }
        };

        let csr_subject = match x509_cert::request::CertReq::from_der(&csr_bytes) {
            Ok(csr) => csr.info.subject.to_string(),
            Err(e) => {
                self.set_status(format!("csr.der is not a valid DER-encoded CSR: {e}"));
                self.current_op = None;
                return;
            }
        };
        self.data.csr_subject_display = Some(csr_subject);

        let profiles_len = self
            .profile
            .as_ref()
            .map(|p| p.cert_profiles.len())
            .unwrap_or(0);
        if profiles_len == 0 {
            self.set_status(
                "No [[cert_profiles]] defined in profile.toml. Add at least one profile.",
            );
            self.current_op = None;
            return;
        }

        self.data.csr_der = Some(csr_bytes);
        self.ceremony.state = CeremonyPhase::Planning(PlanningState::LoadCsr);
        self.set_status(format!("CSR loaded. Select profile [1]–[{profiles_len}]."));
    }

    // ── Mode 3: Add revocation entry ─────────────────────────────────────────

    pub(crate) fn do_add_revocation_entry(&mut self) {
        let serial: u64 = match self.data.revoke_serial_buf.parse() {
            Ok(n) => n,
            Err(_) => {
                self.set_status(format!(
                    "Invalid serial number: {:?}. Must be a u64.",
                    self.data.revoke_serial_buf
                ));
                return;
            }
        };

        if self.data.revocation_list.iter().any(|e| e.serial == serial) {
            self.set_status(format!(
                "Serial {serial} is already in the revocation list — duplicate not added."
            ));
            return;
        }

        let reason = if self.data.revoke_reason_buf.is_empty() {
            None
        } else {
            Some(self.data.revoke_reason_buf.clone())
        };

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

        self.data.revocation_list.push(RevocationEntry {
            serial,
            revocation_time: rev_time,
            reason,
        });

        if self.data.crl_number.is_none() {
            self.data.crl_number = Some(next_crl_number_from_sessions(&self.disc.prior_sessions));
        }

        self.ceremony.state = CeremonyPhase::Planning(PlanningState::RevokePreview);
        self.set_status("Review revocation. [1] to commit to disc, [q] to cancel.");
    }

    // ── Modes 3+4: Load revocation list from disc ────────────────────────────

    fn do_load_revocation(&mut self) {
        self.data.root_cert_der = load_root_cert_der_from_sessions(&self.disc.prior_sessions);
        if self.data.root_cert_der.is_none() {
            self.set_status("No ROOT.CRT found on disc. Generate root CA first.");
            self.current_op = None;
            return;
        }

        self.data.revocation_list = load_revocation_from_sessions(&self.disc.prior_sessions);
        self.data.crl_number = Some(next_crl_number_from_sessions(&self.disc.prior_sessions));

        match self.current_op {
            Some(Operation::RevokeCert) => {
                self.ceremony.state = CeremonyPhase::Planning(PlanningState::RevokeInput);
            }
            Some(Operation::IssueCrl) => {
                self.ceremony.state = CeremonyPhase::Planning(PlanningState::CrlPreview);
            }
            _ => {}
        }
    }

    // ── Mode 5: Migrate confirm ──────────────────────────────────────────────

    fn do_migrate_confirm(&mut self) {
        let total_bytes: u64 = self
            .disc
            .prior_sessions
            .iter()
            .flat_map(|s| s.files.iter())
            .map(|f| f.data.len() as u64)
            .sum();
        self.data.migrate_total_bytes = total_bytes;

        const RAM_WARN_THRESHOLD: u64 = 512 * 1024 * 1024;
        if total_bytes > RAM_WARN_THRESHOLD {
            self.set_status(format!(
                "WARNING: disc data ({} MiB) exceeds 512 MiB RAM threshold. \
                 Proceed only if you have sufficient free memory.",
                total_bytes / (1024 * 1024)
            ));
        }

        self.data.migrate_chain_ok = verify_audit_chain(&self.disc.prior_sessions);
        self.ceremony.state = CeremonyPhase::Planning(PlanningState::MigrateConfirm);
        let chain_status = if self.data.migrate_chain_ok {
            "OK"
        } else {
            "FAIL"
        };
        self.set_status(format!(
            "Chain: {chain_status}  {} session(s)  {} bytes. [1] to proceed, [q] to abort.",
            self.disc.prior_sessions.len(),
            total_bytes
        ));
    }

    // ── Key operations (Mode 1) ───────────────────────────────────────────────

    fn do_generate_and_build(&mut self) -> Result<(), String> {
        let label = match &self.profile {
            Some(p) => p.hsm.key_label.clone(),
            None => return Err("No profile".into()),
        };
        let key = {
            let actor = match self.hw.actor.as_mut() {
                Some(a) => a,
                None => return Err("No HSM session".into()),
            };
            match actor.generate_keypair(&label, KeySpec::EcdsaP384) {
                Ok(k) => k,
                Err(e) => return Err(format!("Key generation failed: {e}")),
            }
        };
        self.hw.root_key = Some(key);
        self.set_status(format!("Generated P-384 keypair (label={label:?})"));
        self.do_build_cert()
    }

    fn do_find_and_build(&mut self) -> Result<(), String> {
        let label = match &self.profile {
            Some(p) => p.hsm.key_label.clone(),
            None => return Err("No profile".into()),
        };
        let key = {
            let actor = match self.hw.actor.as_ref() {
                Some(a) => a,
                None => return Err("No HSM session".into()),
            };
            match actor.find_key(&label) {
                Ok(k) => k,
                Err(e) => return Err(format!("Key not found: {e}")),
            }
        };
        self.hw.root_key = Some(key);
        self.set_status(format!("Found existing key (label={label:?})"));
        self.do_build_cert()
    }

    fn do_build_cert(&mut self) -> Result<(), String> {
        let actor = match self.hw.actor.clone() {
            Some(a) => a,
            None => return Err("No HSM session".into()),
        };
        let key = match self.hw.root_key {
            Some(k) => k,
            None => return Err("No key handle".into()),
        };
        let signer = match P384HsmSigner::new(actor, key) {
            Ok(s) => s,
            Err(e) => return Err(format!("Signer error: {e}")),
        };
        let ca = match &self.profile {
            Some(p) => &p.ca,
            None => return Err("No profile".into()),
        };
        let cert = match build_root_cert(
            &signer,
            &ca.common_name,
            &ca.organization,
            &ca.country,
            7305,
        ) {
            Ok(c) => c,
            Err(e) => return Err(mechanism_error_msg("Cert build failed", &e)),
        };
        let cert_der = match cert.to_der() {
            Ok(d) => d,
            Err(e) => return Err(format!("DER encode failed: {e}")),
        };

        // Issue initial CRL (#1, empty) alongside root cert
        let base_time = self.confirmed_time.unwrap_or_else(SystemTime::now);
        let next_update = base_time + std::time::Duration::from_secs(365 * 24 * 3600);
        let crl_der = match issue_crl(&signer, &cert, &[], next_update, 1) {
            Ok(d) => d,
            Err(e) => return Err(mechanism_error_msg("Initial CRL build failed", &e)),
        };

        let fp = sha256_fingerprint(&cert_der);
        self.data.fingerprint = Some(fp);

        // Update SessionState with root cert info (for InitRoot flow)
        if let Some(ref mut state) = self.disc.session_state {
            use base64::Engine;
            let cert_hash = {
                use sha2::{Digest, Sha256};
                hex::encode(Sha256::digest(&cert_der))
            };
            state.root_cert_sha256 = cert_hash;
            state.root_cert_der_b64 = base64::engine::general_purpose::STANDARD.encode(&cert_der);
        }

        self.data.cert_der = Some(cert_der);
        self.data.crl_der = Some(crl_der);
        self.ceremony.state = CeremonyPhase::Execute;
        self.set_status("Certificate built. Verify fingerprint before writing.");
        Ok(())
    }

    // ── Mode 2: Sign CSR ─────────────────────────────────────────────────────

    fn do_sign_csr(&mut self) {
        let label = match self.profile.as_ref().map(|p| p.hsm.key_label.clone()) {
            Some(l) => l,
            None => {
                self.set_status("No profile");
                return;
            }
        };
        let actor = match self.hw.actor.clone() {
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

        let root_cert_der = match &self.data.root_cert_der {
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

        let csr_der = match self.data.csr_der.as_ref() {
            Some(d) => d.clone(),
            None => {
                self.set_status("No CSR loaded");
                return;
            }
        };

        let (validity_days, path_len) = match self
            .profile
            .as_ref()
            .and_then(|p| self.data.selected_profile_idx.map(|i| &p.cert_profiles[i]))
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
            Err(anodize_ca::CaError::CsrSignatureInvalid) => {
                self.set_status("CSR signature verification failed — CSR may be corrupt");
                return;
            }
            Err(anodize_ca::CaError::CsrAlgorithmUnsupported(alg)) => {
                self.set_status(format!(
                    "CSR uses unsupported signature algorithm ({alg}). \
                     Accepted: ECDSA P-256/SHA-256 or P-384/SHA-384."
                ));
                return;
            }
            Err(anodize_ca::CaError::CsrExtensionRejected(oid)) => {
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
        self.data.fingerprint = Some(fp);
        self.data.cert_der = Some(cert_der);
        self.ceremony.state = CeremonyPhase::Execute;
        self.set_status("Intermediate cert signed. Verify fingerprint before writing.");
    }

    // ── Mode 3: Sign CRL for revocation ──────────────────────────────────────

    fn do_sign_crl_for_revoke(&mut self) {
        self.do_sign_crl_inner();
    }

    // ── Mode 4: Sign CRL refresh ─────────────────────────────────────────────

    fn do_sign_crl_refresh(&mut self) {
        self.do_sign_crl_inner();
    }

    fn do_sign_crl_inner(&mut self) {
        let label = match self.profile.as_ref().map(|p| p.hsm.key_label.clone()) {
            Some(l) => l,
            None => {
                self.set_status("No profile");
                return;
            }
        };
        let actor = match self.hw.actor.clone() {
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

        let root_cert_der = match &self.data.root_cert_der {
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

        let crl_number = match self.data.crl_number {
            Some(n) => n,
            None => {
                self.set_status("CRL number not determined");
                return;
            }
        };

        // Convert RevocationEntry list to (serial, SystemTime, reason) triples
        let revoked: Vec<(u64, SystemTime, Option<anodize_ca::CrlReason>)> = self
            .data
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

        self.data.crl_der = Some(crl_der);
        self.do_start_burn();
    }

    // ── WAL intent write ──────────────────────────────────────────────────────

    pub(crate) fn do_write_intent(&mut self) {
        // For Mode 2+, load root cert from disc before intent write
        if matches!(
            self.current_op,
            Some(Operation::SignCsr) | Some(Operation::RevokeCert) | Some(Operation::IssueCrl)
        ) && self.data.root_cert_der.is_none()
        {
            self.data.root_cert_der = load_root_cert_der_from_sessions(&self.disc.prior_sessions);
            if self.data.root_cert_der.is_none() {
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

        if !self.skip_disc && self.disc.sessions_remaining.map(|r| r < 2).unwrap_or(false) {
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
        let mut all_sessions = self.disc.prior_sessions.clone();
        all_sessions.push(intent_session.clone());

        let (tx, rx) = mpsc::channel();
        self.disc.burn_rx = Some(rx);
        self.disc.pending_intent_session = Some(intent_session);

        tracing::info!(
            skip_disc = self.skip_disc,
            optical_dev = ?self.disc.optical_dev,
            "do_write_intent: about to dispatch write"
        );

        {
            if self.skip_disc {
                let iso = media::iso9660::build_iso(&all_sessions);
                let iso_path = staging.join("ceremony.iso");
                match std::fs::write(&iso_path, &iso) {
                    Ok(()) => {
                        tracing::info!("do_write_intent: skip_disc ISO written, sending Ok");
                        tx.send(Ok(())).ok();
                    }
                    Err(e) => {
                        tracing::error!("do_write_intent: skip_disc ISO write failed: {e}");
                        tx.send(Err(anyhow::anyhow!("write intent ISO: {e}"))).ok();
                    }
                }
            } else if let Some(dev) = self.disc.optical_dev.clone() {
                tracing::info!(
                    "do_write_intent: spawning write_session to {}",
                    dev.display()
                );
                media::write_session(&dev, all_sessions, false, tx);
            } else {
                tracing::error!("do_write_intent: no optical device!");
                self.set_status("No optical device — cannot write intent");
                self.disc.burn_rx = None;
                self.disc.pending_intent_session = None;
                return;
            }
        }

        tracing::info!(
            burn_rx_is_some = self.disc.burn_rx.is_some(),
            "do_write_intent: setting Commit state"
        );
        self.ceremony.state = CeremonyPhase::Commit;
        self.set_status("Writing intent to disc. Operation will follow…");
    }

    /// Build the intent audit event (name, data) for the current operation.
    fn build_intent_audit_event(&self, genesis_hex: &str) -> Option<(String, serde_json::Value)> {
        match &self.current_op {
            Some(Operation::InitRoot) => {
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
                let action_str = match self.disc.pending_key_action {
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
                    .data
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
                        self.data
                            .selected_profile_idx
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
                let serial: u64 = self.data.revoke_serial_buf.parse().unwrap_or(0);
                let reason = if self.data.revoke_reason_buf.is_empty() {
                    serde_json::Value::Null
                } else {
                    serde_json::Value::String(self.data.revoke_reason_buf.clone())
                };
                Some((
                    "cert.revoke.intent".into(),
                    serde_json::json!({
                        "operation": "revoke-and-issue-crl",
                        "serial": serial,
                        "reason": reason,
                        "crl_number": self.data.crl_number.unwrap_or(0),
                        "revocation_count": self.data.revocation_list.len(),
                    }),
                ))
            }
            Some(Operation::IssueCrl) => Some((
                "crl.intent".into(),
                serde_json::json!({
                    "operation": "issue-crl",
                    "crl_number": self.data.crl_number.unwrap_or(0),
                    "revocation_count": self.data.revocation_list.len(),
                }),
            )),
            Some(Operation::KeyBackup) => {
                let src_id = self
                    .utilities
                    .backup
                    .source_idx
                    .and_then(|i| self.utilities.backup.targets.get(i))
                    .map(|t| t.identifier.clone())
                    .unwrap_or_default();
                let dst_id = self
                    .utilities
                    .backup
                    .dest_idx
                    .and_then(|i| self.utilities.backup.targets.get(i))
                    .map(|t| t.identifier.clone())
                    .unwrap_or_default();
                let action = if self.utilities.backup.action_is_pair {
                    "pair-devices"
                } else {
                    "backup-signing-key"
                };
                Some((
                    "hsm.backup.intent".into(),
                    serde_json::json!({
                        "operation": action,
                        "source": src_id,
                        "destination": dst_id,
                        "profile_toml_sha256": genesis_hex,
                    }),
                ))
            }
            _ => None,
        }
    }

    // ── Disc burn ─────────────────────────────────────────────────────────────

    pub(crate) fn do_start_burn(&mut self) {
        let staging = PathBuf::from("/run/anodize/staging");

        let new_session = match self.build_burn_session(&staging) {
            Some(s) => s,
            None => return,
        };

        let all_sessions = if self.current_op == Some(Operation::MigrateDisc) {
            self.data.migrate_sessions.clone()
        } else {
            let mut sessions = self.disc.prior_sessions.clone();
            sessions.push(new_session);
            sessions
        };

        let (tx, rx) = mpsc::channel();
        self.disc.burn_rx = Some(rx);

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
            } else if let Some(dev) = &self.disc.optical_dev {
                media::write_session(dev, all_sessions, false, tx);
            } else {
                self.set_status("No optical device — cannot burn");
                self.disc.burn_rx = None;
                return;
            }

            self.ceremony.state = CeremonyPhase::BurningDisc;
            self.set_status("Burning disc session… (this may take a few minutes)");
        }
    }

    /// Build a STATE.JSON IsoFile from the current session_state.
    /// Returns None if no session state is set.
    fn build_state_json_file(&self) -> Option<IsoFile> {
        self.disc.session_state.as_ref().map(|state| IsoFile {
            name: anodize_config::state::STATE_FILENAME.into(),
            data: state.to_json(),
        })
    }

    /// Update session_state to reflect the outcome of the current operation.
    /// Must be called before build_state_json_file in build_burn_session.
    fn update_session_state_for_record(&mut self, audit_bytes: &[u8]) {
        // Compute last audit hash from the final line
        let last_hash = audit_bytes
            .split(|&b| b == b'\n')
            .rev()
            .find(|line| !line.is_empty())
            .and_then(|line| serde_json::from_slice::<serde_json::Value>(line).ok())
            .and_then(|v| {
                v.get("entry_hash")
                    .and_then(|h| h.as_str().map(String::from))
            })
            .unwrap_or_default();

        if let Some(ref mut state) = self.disc.session_state {
            state.last_audit_hash = last_hash;

            // Update CRL number
            if let Some(n) = self.data.crl_number {
                state.crl_number = n;
            }

            // Update revocation list
            if !self.data.revocation_list.is_empty() {
                state.revocation_list = self.data.revocation_list.clone();
            }
        }
    }

    /// Build the SessionEntry for the current operation's disc burn.
    fn build_burn_session(&mut self, staging: &std::path::Path) -> Option<SessionEntry> {
        let ts = self.confirmed_time.unwrap_or_else(SystemTime::now);
        let dir_name = media::session_dir_name(ts) + "-record";

        match self.current_op.clone() {
            Some(Operation::RekeyShares) => {
                let log_path = staging.join("audit.log");
                let mut log = match AuditLog::open(&log_path) {
                    Ok(l) => l,
                    Err(e) => {
                        self.set_status(format!("Audit log reopen failed: {e}"));
                        return None;
                    }
                };
                let new_total = self
                    .disc
                    .session_state
                    .as_ref()
                    .map(|s| s.sss.total)
                    .unwrap_or(0);
                let new_threshold = self
                    .disc
                    .session_state
                    .as_ref()
                    .map(|s| s.sss.threshold)
                    .unwrap_or(0);
                if let Err(e) = log.append(
                    "sss.rekey",
                    serde_json::json!({
                        "operation": "rekey-shares",
                        "new_threshold": new_threshold,
                        "new_total": new_total,
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

                self.update_session_state_for_record(&audit_bytes);
                let mut files = vec![IsoFile {
                    name: "AUDIT.LOG".into(),
                    data: audit_bytes,
                }];
                if let Some(state_file) = self.build_state_json_file() {
                    files.push(state_file);
                }

                Some(SessionEntry {
                    dir_name,
                    timestamp: ts,
                    files,
                })
            }
            Some(Operation::InitRoot) => {
                let cert_der = self.data.cert_der.clone()?;
                let crl_der = self.data.crl_der.clone()?;

                let log_path = staging.join("audit.log");
                let mut log = match AuditLog::open(&log_path) {
                    Ok(l) => l,
                    Err(e) => {
                        self.set_status(format!("Audit log reopen failed: {e}"));
                        return None;
                    }
                };
                let fp = self.data.fingerprint.clone().unwrap_or_default();
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
                        "intent_session": self.disc.intent_session_dir_name.as_deref().unwrap_or(""),
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
                        "intent_session": self.disc.intent_session_dir_name.as_deref().unwrap_or(""),
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

                self.update_session_state_for_record(&audit_bytes);
                let mut files = vec![
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
                ];
                if let Some(state_file) = self.build_state_json_file() {
                    files.push(state_file);
                }

                Some(SessionEntry {
                    dir_name,
                    timestamp: ts,
                    files,
                })
            }

            Some(Operation::SignCsr) => {
                let cert_der = self.data.cert_der.clone()?;

                let log_path = staging.join("audit.log");
                let mut log = match AuditLog::open(&log_path) {
                    Ok(l) => l,
                    Err(e) => {
                        self.set_status(format!("Audit log reopen failed: {e}"));
                        return None;
                    }
                };
                let fp = self.data.fingerprint.clone().unwrap_or_default();
                let profile_name = self
                    .profile
                    .as_ref()
                    .and_then(|p| {
                        self.data
                            .selected_profile_idx
                            .map(|i| p.cert_profiles[i].name.clone())
                    })
                    .unwrap_or_default();
                if let Err(e) = log.append(
                    "cert.intermediate.issue",
                    serde_json::json!({
                        "fingerprint": fp,
                        "profile": profile_name,
                        "intent_session": self.disc.intent_session_dir_name.as_deref().unwrap_or(""),
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

                self.update_session_state_for_record(&audit_bytes);
                let mut files = vec![
                    IsoFile {
                        name: "INTERMEDIATE.CRT".into(),
                        data: cert_der,
                    },
                    IsoFile {
                        name: "AUDIT.LOG".into(),
                        data: audit_bytes,
                    },
                ];
                if let Some(state_file) = self.build_state_json_file() {
                    files.push(state_file);
                }

                Some(SessionEntry {
                    dir_name,
                    timestamp: ts,
                    files,
                })
            }

            Some(Operation::RevokeCert) => {
                let crl_der = self.data.crl_der.clone()?;
                let revoked_toml =
                    serialize_revocation_list(&self.data.revocation_list).into_bytes();
                let crl_number = self.data.crl_number.unwrap_or(0);

                let log_path = staging.join("audit.log");
                let mut log = match AuditLog::open(&log_path) {
                    Ok(l) => l,
                    Err(e) => {
                        self.set_status(format!("Audit log reopen failed: {e}"));
                        return None;
                    }
                };
                let serial: u64 = self.data.revoke_serial_buf.parse().unwrap_or(0);
                let reason = if self.data.revoke_reason_buf.is_empty() {
                    serde_json::Value::Null
                } else {
                    serde_json::Value::String(self.data.revoke_reason_buf.clone())
                };
                if let Err(e) = log.append(
                    "cert.revoke",
                    serde_json::json!({
                        "serial": serial,
                        "reason": reason,
                        "intent_session": self.disc.intent_session_dir_name.as_deref().unwrap_or(""),
                    }),
                ) {
                    self.set_status(format!("Audit log append failed: {e}"));
                    return None;
                }
                if let Err(e) = log.append(
                    "crl.issue",
                    serde_json::json!({
                        "crl_number": crl_number,
                        "revocation_count": self.data.revocation_list.len(),
                        "intent_session": self.disc.intent_session_dir_name.as_deref().unwrap_or(""),
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

                self.update_session_state_for_record(&audit_bytes);
                let mut files = vec![
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
                ];
                if let Some(state_file) = self.build_state_json_file() {
                    files.push(state_file);
                }

                Some(SessionEntry {
                    dir_name,
                    timestamp: ts,
                    files,
                })
            }

            Some(Operation::IssueCrl) => {
                let crl_der = self.data.crl_der.clone()?;
                let crl_number = self.data.crl_number.unwrap_or(0);

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
                        "revocation_count": self.data.revocation_list.len(),
                        "intent_session": self.disc.intent_session_dir_name.as_deref().unwrap_or(""),
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

                self.update_session_state_for_record(&audit_bytes);
                let mut files = vec![
                    IsoFile {
                        name: "ROOT.CRL".into(),
                        data: crl_der,
                    },
                    IsoFile {
                        name: "AUDIT.LOG".into(),
                        data: audit_bytes,
                    },
                ];
                if let Some(state_file) = self.build_state_json_file() {
                    files.push(state_file);
                }

                Some(SessionEntry {
                    dir_name,
                    timestamp: ts,
                    files,
                })
            }

            Some(Operation::MigrateDisc) => Some(SessionEntry {
                dir_name,
                timestamp: ts,
                files: vec![],
            }),

            Some(Operation::KeyBackup) => {
                let log_path = staging.join("audit.log");
                let mut log = match AuditLog::open(&log_path) {
                    Ok(l) => l,
                    Err(e) => {
                        self.set_status(format!("Audit log reopen failed: {e}"));
                        return None;
                    }
                };

                let src_id = self
                    .utilities
                    .backup
                    .source_idx
                    .and_then(|i| self.utilities.backup.targets.get(i))
                    .map(|t| t.identifier.clone())
                    .unwrap_or_default();
                let dst_id = self
                    .utilities
                    .backup
                    .dest_idx
                    .and_then(|i| self.utilities.backup.targets.get(i))
                    .map(|t| t.identifier.clone())
                    .unwrap_or_default();
                let is_pair = self.utilities.backup.action_is_pair;
                let succeeded = self.utilities.backup.phase
                    == crate::modes::utilities::backup::BackupPhase::Done;

                let event_name = if is_pair {
                    "hsm.backup.pair"
                } else {
                    "hsm.backup.key"
                };
                if let Err(e) = log.append(
                    event_name,
                    serde_json::json!({
                        "operation": if is_pair { "pair-devices" } else { "backup-signing-key" },
                        "source": src_id,
                        "destination": dst_id,
                        "success": succeeded,
                        "wrap_key": self.utilities.backup.wrap_key_desc.as_deref().unwrap_or(""),
                        "public_keys_match": self.utilities.backup.result
                            .as_ref().map(|r| r.public_keys_match),
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
                    files: vec![IsoFile {
                        name: "AUDIT.LOG".into(),
                        data: audit_bytes,
                    }],
                })
            }

            None => {
                self.set_status("No operation set");
                None
            }
        }
    }

    // ── Shuttle write ─────────────────────────────────────────────────────

    pub(crate) fn do_write_shuttle(&mut self) {
        let shuttle = self.shuttle_mount.clone();
        let staging_log = PathBuf::from("/run/anodize/staging/audit.log");

        match self.current_op.clone() {
            Some(Operation::InitRoot) => {
                if let Some(cert_der) = &self.data.cert_der {
                    if let Err(e) = std::fs::write(shuttle.join("root.crt"), cert_der) {
                        self.set_status(format!("Shuttle write failed (root.crt): {e}"));
                        return;
                    }
                }
                if let Some(crl_der) = &self.data.crl_der {
                    if let Err(e) = std::fs::write(shuttle.join("root.crl"), crl_der) {
                        self.set_status(format!("Shuttle write failed (root.crl): {e}"));
                        return;
                    }
                }
            }
            Some(Operation::SignCsr) => {
                if let Some(cert_der) = &self.data.cert_der {
                    if let Err(e) = std::fs::write(shuttle.join("intermediate.crt"), cert_der) {
                        self.set_status(format!("Shuttle write failed (intermediate.crt): {e}"));
                        return;
                    }
                }
            }
            Some(Operation::RevokeCert) => {
                let revoked_toml = serialize_revocation_list(&self.data.revocation_list);
                if let Err(e) = std::fs::write(shuttle.join("revoked.toml"), &revoked_toml) {
                    self.set_status(format!("Shuttle write failed (revoked.toml): {e}"));
                    return;
                }
                if let Some(crl_der) = &self.data.crl_der {
                    if let Err(e) = std::fs::write(shuttle.join("root.crl"), crl_der) {
                        self.set_status(format!("Shuttle write failed (root.crl): {e}"));
                        return;
                    }
                }
            }
            Some(Operation::IssueCrl) => {
                if let Some(crl_der) = &self.data.crl_der {
                    if let Err(e) = std::fs::write(shuttle.join("root.crl"), crl_der) {
                        self.set_status(format!("Shuttle write failed (root.crl): {e}"));
                        return;
                    }
                }
            }
            Some(Operation::RekeyShares) => {
                // No shuttle artifacts for re-key
                self.ceremony.state = CeremonyPhase::Done;
                self.set_status("Operation complete.");
                return;
            }
            Some(Operation::KeyBackup) => {
                // Key backup has no shuttle artifacts.
                self.ceremony.state = CeremonyPhase::Done;
                self.set_status("Key backup complete.");
                return;
            }
            Some(Operation::MigrateDisc) | None => {
                self.ceremony.state = CeremonyPhase::Done;
                self.set_status("Migration complete.");
                return;
            }
        }

        // Copy audit log to shuttle for all artifact-producing operations
        let shuttle_log = shuttle.join("audit.log");
        if let Err(e) = std::fs::copy(&staging_log, &shuttle_log) {
            self.set_status(format!("Audit log copy to shuttle failed: {e}"));
            return;
        }

        self.ceremony.state = CeremonyPhase::Done;
        self.set_status(format!("Shuttle write complete: {}", shuttle.display()));
    }

    // ── Content rendering (avoids borrow splitting) ──────────────────────────

    pub(crate) fn render_setup_content(&self, frame: &mut Frame, area: Rect) {
        self.setup.render_with_app(frame, area, self);
    }

    pub(crate) fn render_ceremony_content(&self, frame: &mut Frame, area: Rect) {
        // CustodianSetup overlay for InitRoot and Rekey custodian entry
        match self.ceremony.state {
            CeremonyPhase::Planning(PlanningState::CustodianSetup)
            | CeremonyPhase::Planning(PlanningState::RekeyCustodianSetup) => {
                if let Some(ref setup) = self.sss.custodian_setup {
                    setup.render(frame, area);
                    return;
                }
            }
            _ => {}
        }
        // ShareReveal / ShareInput overlay for InitRoot and Rekey states
        match self.ceremony.state {
            CeremonyPhase::Planning(PlanningState::ShareReveal)
            | CeremonyPhase::Planning(PlanningState::RekeyShareReveal) => {
                if let Some(ref reveal) = self.sss.share_reveal {
                    reveal.render(frame, area);
                    return;
                }
            }
            CeremonyPhase::Quorum
            | CeremonyPhase::Planning(PlanningState::ShareVerify)
            | CeremonyPhase::Planning(PlanningState::RekeyShareVerify)
            | CeremonyPhase::Planning(PlanningState::RekeyQuorum)
            | CeremonyPhase::Planning(PlanningState::BackupQuorum) => {
                if let Some(ref input) = self.sss.share_input {
                    input.render(frame, area);
                    return;
                }
            }
            _ => {}
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
        let mut app = crate::app::App::new(PathBuf::from("/tmp/test-shuttle"), true);
        app.current_op = Some(Operation::InitRoot);
        app.disc.pending_key_action = Some(1);
        app.pin_buf = hex::encode(vec![0u8; 32]);
        app
    }

    #[test]
    fn post_intent_init_root_fails_without_hsm() {
        let mut app = test_app();
        // No HSM backend configured → do_bootstrap_hsm should fail
        let result = app.post_intent_init_root();
        assert!(result.is_err(), "Expected error without profile/HSM");
    }

    #[test]
    fn tick_intent_burn_transitions_to_post_commit_error() {
        let mut app = test_app();
        app.ceremony.state = CeremonyPhase::Commit;

        // Set up a burn_rx channel that immediately yields Ok(())
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(Ok(())).unwrap();
        app.disc.burn_rx = Some(rx);

        app.tick_intent_burn();

        assert_eq!(
            app.ceremony.state,
            CeremonyPhase::PostCommitError,
            "Should transition to PostCommitError when HSM bootstrap fails"
        );
    }

    #[test]
    fn retry_post_commit_stays_in_error_without_hsm() {
        let mut app = test_app();
        app.ceremony.state = CeremonyPhase::PostCommitError;

        app.update(Action::RetryPostCommit);

        assert_eq!(
            app.ceremony.state,
            CeremonyPhase::PostCommitError,
            "Retry without HSM should stay in PostCommitError"
        );
    }

    #[test]
    fn abort_from_post_commit_error_resets_to_operation_select() {
        let mut app = test_app();
        app.ceremony.state = CeremonyPhase::PostCommitError;

        app.update(Action::InitRootAbort);

        assert_eq!(
            app.ceremony.state,
            CeremonyPhase::OperationSelect,
            "InitRootAbort should reset to OperationSelect"
        );
        assert!(app.current_op.is_none());
    }
}
