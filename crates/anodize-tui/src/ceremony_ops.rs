//! Ceremony operation methods on App.
//!
//! This is a separate `impl App` block to keep app.rs focused on dispatch/rendering
//! and this file focused on the ceremony business logic.

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::SystemTime;

use anodize_audit::{genesis_hash, AuditLog};
use anodize_ca::{build_root_cert, issue_crl, sign_intermediate_csr, P384HsmSigner};
use anodize_config::{
    load as load_profile, serialize_revocation_list, PinSource, RevocationEntry,
};
use anodize_hsm::{Hsm, HsmActor, KeySpec, Pkcs11Hsm};
use der::{Decode, Encode};
use ratatui::{layout::Rect, Frame};
use secrecy::SecretString;
use x509_cert::certificate::Certificate;

use crate::action::Operation;
use crate::app::App;
use crate::components::status_bar::HwState;
use crate::helpers::*;
use crate::media::{self, IsoFile, SessionEntry};
use crate::modes::ceremony::CeremonyState;
use crate::modes::setup::SetupPhase;

impl App {
    // ── USB scan tick ─────────────────────────────────────────────────────────

    pub(crate) fn tick_wait_usb(&mut self) {
        let diagnostics = media::usb_scan_diagnostics();
        let candidates = media::scan_usb_partitions();
        if candidates.is_empty() {
            self.set_status(format!("Scanning… {diagnostics}"));
            return;
        }
        match media::find_profile_usb(&candidates, &self.usb_mountpoint) {
            Ok(Some((profile_path, dev_path))) => {
                let _ = dev_path;
                #[cfg(feature = "dev-softhsm-usb")]
                if let Err(e) = configure_softhsm_from_usb(&self.usb_mountpoint) {
                    self.set_status(format!("SoftHSM2 USB setup failed: {e}"));
                    let _ = media::unmount(&self.usb_mountpoint);
                    return;
                }
                let raw_bytes = std::fs::read(&profile_path).unwrap_or_default();
                match load_profile(&profile_path) {
                    Ok(profile) => {
                        if profile.hsm.pin_source != PinSource::Prompt {
                            profile.hsm.pin_source.warn_if_unsafe();
                            self.set_status(
                                "ERROR: pin_source is not 'prompt' — unsuitable for \
                                 ceremony. Fix profile.toml and re-insert USB.",
                            );
                            let _ = media::unmount(&self.usb_mountpoint);
                            return;
                        }
                        if let Err(e) = profile.hsm.check_module_allowed() {
                            self.set_status(format!("PKCS#11 module not allowed: {e}"));
                            let _ = media::unmount(&self.usb_mountpoint);
                            return;
                        }
                        self.profile = Some(profile);
                        self.profile_toml_bytes = Some(raw_bytes);
                        self.setup.phase = SetupPhase::ProfileLoaded;
                        self.set_status("Profile loaded from USB.");
                    }
                    Err(e) => {
                        self.set_status(format!("Profile parse error: {e}"));
                        let _ = media::unmount(&self.usb_mountpoint);
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
            self.optical_dev = Some(PathBuf::from("/run/anodize/staging"));
            self.sessions_remaining = Some(100);
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
                    self.sessions_remaining = Some(remaining);
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
                    self.optical_dev = Some(dev.clone());
                    if !need_blank {
                        self.prior_sessions = scan.sessions;
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
        self.optical_dev = None;
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

    // ── Intent burn tick ──────────────────────────────────────────────────────

    pub(crate) fn tick_intent_burn(&mut self) {
        if let Some(rx) = &self.burn_rx {
            if let Ok(result) = rx.try_recv() {
                self.burn_rx = None;
                match result {
                    Err(e) => {
                        self.set_status(format!("Intent disc write failed: {e}"));
                        self.setup.phase = SetupPhase::WaitDisc;
                        self.optical_dev = None;
                    }
                    Ok(()) => {
                        if let Some(intent) = self.pending_intent_session.take() {
                            self.intent_session_dir_name = Some(intent.dir_name.clone());
                            self.prior_sessions.push(intent);
                        }
                        match self.current_op.clone() {
                            Some(Operation::GenerateRootCa) => {
                                match self.pending_key_action {
                                    Some(1) => self.do_generate_and_build(),
                                    Some(2) => self.do_find_and_build(),
                                    _ => {
                                        self.set_status("Unknown key action");
                                        self.ceremony.state = CeremonyState::OperationSelect;
                                    }
                                }
                            }
                            Some(Operation::SignCsr) => self.do_sign_csr(),
                            Some(Operation::RevokeCert) => self.do_sign_crl_for_revoke(),
                            Some(Operation::IssueCrl) => self.do_sign_crl_refresh(),
                            _ => {
                                self.set_status("Unknown operation after intent");
                                self.ceremony.state = CeremonyState::OperationSelect;
                            }
                        }
                    }
                }
            }
        }
    }

    // ── Record burn tick ──────────────────────────────────────────────────────

    pub(crate) fn tick_record_burn(&mut self) {
        if let Some(rx) = &self.burn_rx {
            if let Ok(result) = rx.try_recv() {
                self.burn_rx = None;
                match result {
                    Ok(()) => {
                        self.ceremony.state = CeremonyState::DiscDone;
                        let disc_label = self
                            .optical_dev
                            .as_deref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| "/run/anodize/staging".into());
                        let op_label = match self.current_op {
                            Some(Operation::GenerateRootCa) => "Root CA + CRL",
                            Some(Operation::SignCsr) => "Intermediate cert",
                            Some(Operation::RevokeCert) => "Revocation + CRL",
                            Some(Operation::IssueCrl) => "CRL refresh",
                            Some(Operation::MigrateDisc) => "Disc migration",
                            None => "session",
                        };
                        self.set_status(format!("{op_label} written to disc: {disc_label}"));
                    }
                    Err(e) => {
                        self.set_status(format!(
                            "Burn failed: {e} — reinsert disc and retry."
                        ));
                        self.ceremony.state = CeremonyState::OperationSelect;
                        self.optical_dev = None;
                    }
                }
            }
        }
    }

    // ── HSM login ─────────────────────────────────────────────────────────────

    pub(crate) fn do_login(&mut self) {
        let pin: String = self.pin_buf.drain(..).collect();
        let pin = SecretString::new(pin);
        let cfg = match &self.profile {
            Some(p) => &p.hsm,
            None => {
                self.set_status("No profile loaded");
                return;
            }
        };

        let hsm = match Pkcs11Hsm::new(&cfg.module_path, &cfg.token_label) {
            Ok(h) => h,
            Err(e) => {
                self.set_status(format!("HSM open failed: {e}"));
                return;
            }
        };
        let mut actor = HsmActor::spawn(hsm);
        if let Err(e) = actor.login(&pin) {
            self.set_status(format!("Login failed: {e}"));
            return;
        }
        self.actor = Some(actor);
        self.setup.phase = SetupPhase::WaitDisc;
        self.hsm_state = HwState::Ready("logged in".into());
        self.set_status(
            "Logged in. Insert write-once disc (BD-R, DVD-R, CD-R, or M-Disc) and press [1].",
        );
    }

    // ── Operation selection ───────────────────────────────────────────────────

    pub(crate) fn do_select_operation(&mut self, op: Operation) {
        self.current_op = Some(op.clone());
        match op {
            Operation::GenerateRootCa => {
                self.ceremony.state = CeremonyState::KeyAction;
                self.set_status(
                    "[1] Generate new P-384 keypair (fresh)  [2] Use existing key (resume)",
                );
            }
            Operation::SignCsr => {
                self.do_load_csr();
            }
            Operation::RevokeCert => {
                self.do_load_revocation();
                if self.ceremony.state == CeremonyState::RevokeInput {
                    self.revoke_phase = 0;
                    self.revoke_serial_buf.clear();
                    self.revoke_reason_buf.clear();
                    self.set_status(
                        "Enter certificate serial number (digits). Press Enter to continue.",
                    );
                }
            }
            Operation::IssueCrl => {
                self.do_load_revocation();
                if self.ceremony.state == CeremonyState::CrlPreview {
                    self.set_status("Review CRL details. [1] to proceed, [q] to cancel.");
                }
            }
            Operation::MigrateDisc => {
                self.do_migrate_confirm();
            }
        }
    }

    // ── Mode 2: Load CSR ──────────────────────────────────────────────────────

    fn do_load_csr(&mut self) {
        let csr_path = self.usb_mountpoint.join("csr.der");
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
        self.csr_subject_display = Some(csr_subject);

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

        self.csr_der = Some(csr_bytes);
        self.ceremony.state = CeremonyState::LoadCsr;
        self.set_status(format!("CSR loaded. Select profile [1]–[{profiles_len}]."));
    }

    // ── Mode 3: Add revocation entry ─────────────────────────────────────────

    pub(crate) fn do_add_revocation_entry(&mut self) {
        let serial: u64 = match self.revoke_serial_buf.parse() {
            Ok(n) => n,
            Err(_) => {
                self.set_status(format!(
                    "Invalid serial number: {:?}. Must be a u64.",
                    self.revoke_serial_buf
                ));
                return;
            }
        };

        if self.revocation_list.iter().any(|e| e.serial == serial) {
            self.set_status(format!(
                "Serial {serial} is already in the revocation list — duplicate not added."
            ));
            return;
        }

        let reason = if self.revoke_reason_buf.is_empty() {
            None
        } else {
            Some(self.revoke_reason_buf.clone())
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

        self.revocation_list.push(RevocationEntry {
            serial,
            revocation_time: rev_time,
            reason,
        });

        if self.crl_number.is_none() {
            self.crl_number = Some(next_crl_number_from_sessions(&self.prior_sessions));
        }

        self.ceremony.state = CeremonyState::RevokePreview;
        self.set_status("Review revocation. [1] to commit to disc, [q] to cancel.");
    }

    // ── Modes 3+4: Load revocation list from disc ────────────────────────────

    fn do_load_revocation(&mut self) {
        self.root_cert_der = load_root_cert_der_from_sessions(&self.prior_sessions);
        if self.root_cert_der.is_none() {
            self.set_status("No ROOT.CRT found on disc. Generate root CA first.");
            self.current_op = None;
            return;
        }

        self.revocation_list = load_revocation_from_sessions(&self.prior_sessions);
        self.crl_number = Some(next_crl_number_from_sessions(&self.prior_sessions));

        match self.current_op {
            Some(Operation::RevokeCert) => {
                self.ceremony.state = CeremonyState::RevokeInput;
            }
            Some(Operation::IssueCrl) => {
                self.ceremony.state = CeremonyState::CrlPreview;
            }
            _ => {}
        }
    }

    // ── Mode 5: Migrate confirm ──────────────────────────────────────────────

    fn do_migrate_confirm(&mut self) {
        let total_bytes: u64 = self
            .prior_sessions
            .iter()
            .flat_map(|s| s.files.iter())
            .map(|f| f.data.len() as u64)
            .sum();
        self.migrate_total_bytes = total_bytes;

        const RAM_WARN_THRESHOLD: u64 = 512 * 1024 * 1024;
        if total_bytes > RAM_WARN_THRESHOLD {
            self.set_status(format!(
                "WARNING: disc data ({} MiB) exceeds 512 MiB RAM threshold. \
                 Proceed only if you have sufficient free memory.",
                total_bytes / (1024 * 1024)
            ));
        }

        self.migrate_chain_ok = verify_audit_chain(&self.prior_sessions);
        self.ceremony.state = CeremonyState::MigrateConfirm;
        let chain_status = if self.migrate_chain_ok { "OK" } else { "FAIL" };
        self.set_status(format!(
            "Chain: {chain_status}  {} session(s)  {} bytes. [1] to proceed, [q] to abort.",
            self.prior_sessions.len(),
            total_bytes
        ));
    }

    // ── Key operations (Mode 1) ───────────────────────────────────────────────

    fn do_generate_and_build(&mut self) {
        let label = match &self.profile {
            Some(p) => p.hsm.key_label.clone(),
            None => {
                self.set_status("No profile");
                return;
            }
        };
        let key = {
            let actor = match self.actor.as_mut() {
                Some(a) => a,
                None => {
                    self.set_status("No HSM session");
                    return;
                }
            };
            match actor.generate_keypair(&label, KeySpec::EcdsaP384) {
                Ok(k) => k,
                Err(e) => {
                    self.set_status(format!("Key generation failed: {e}"));
                    return;
                }
            }
        };
        self.root_key = Some(key);
        self.set_status(format!("Generated P-384 keypair (label={label:?})"));
        self.do_build_cert();
    }

    fn do_find_and_build(&mut self) {
        let label = match &self.profile {
            Some(p) => p.hsm.key_label.clone(),
            None => {
                self.set_status("No profile");
                return;
            }
        };
        let key = {
            let actor = match self.actor.as_ref() {
                Some(a) => a,
                None => {
                    self.set_status("No HSM session");
                    return;
                }
            };
            match actor.find_key(&label) {
                Ok(k) => k,
                Err(e) => {
                    self.set_status(format!("Key not found: {e}"));
                    return;
                }
            }
        };
        self.root_key = Some(key);
        self.set_status(format!("Found existing key (label={label:?})"));
        self.do_build_cert();
    }

    fn do_build_cert(&mut self) {
        if let Some(ct) = self.confirmed_time {
            if !clock_drift_ok(ct) {
                self.set_status(
                    "Clock drift > 5 min since ClockCheck — restart ceremony to re-confirm clock.",
                );
                return;
            }
        }
        let actor = match self.actor.clone() {
            Some(a) => a,
            None => {
                self.set_status("No HSM session");
                return;
            }
        };
        let key = match self.root_key {
            Some(k) => k,
            None => {
                self.set_status("No key handle");
                return;
            }
        };
        let signer = match P384HsmSigner::new(actor, key) {
            Ok(s) => s,
            Err(e) => {
                self.set_status(format!("Signer error: {e}"));
                return;
            }
        };
        let ca = match &self.profile {
            Some(p) => &p.ca,
            None => {
                self.set_status("No profile");
                return;
            }
        };
        let cert = match build_root_cert(
            &signer,
            &ca.common_name,
            &ca.organization,
            &ca.country,
            7305,
        ) {
            Ok(c) => c,
            Err(e) => {
                self.set_status(mechanism_error_msg("Cert build failed", &e));
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

        // Issue initial CRL (#1, empty) alongside root cert
        let base_time = self.confirmed_time.unwrap_or_else(SystemTime::now);
        let next_update = base_time + std::time::Duration::from_secs(365 * 24 * 3600);
        let crl_der = match issue_crl(&signer, &cert, &[], next_update, 1) {
            Ok(d) => d,
            Err(e) => {
                self.set_status(mechanism_error_msg("Initial CRL build failed", &e));
                return;
            }
        };

        let fp = sha256_fingerprint(&cert_der);
        self.fingerprint = Some(fp);
        self.cert_der = Some(cert_der);
        self.crl_der = Some(crl_der);
        self.ceremony.state = CeremonyState::CertPreview;
        self.set_status("Certificate built. Verify fingerprint before writing.");
    }

    // ── Mode 2: Sign CSR ─────────────────────────────────────────────────────

    fn do_sign_csr(&mut self) {
        if let Some(ct) = self.confirmed_time {
            if !clock_drift_ok(ct) {
                self.set_status(
                    "Clock drift > 5 min since ClockCheck — restart ceremony to re-confirm clock.",
                );
                return;
            }
        }
        let label = match self.profile.as_ref().map(|p| p.hsm.key_label.clone()) {
            Some(l) => l,
            None => {
                self.set_status("No profile");
                return;
            }
        };
        let actor = match self.actor.clone() {
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

        let root_cert_der = match &self.root_cert_der {
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

        let csr_der = match self.csr_der.as_ref() {
            Some(d) => d.clone(),
            None => {
                self.set_status("No CSR loaded");
                return;
            }
        };

        let (validity_days, path_len) = match self
            .profile
            .as_ref()
            .and_then(|p| self.selected_profile_idx.map(|i| &p.cert_profiles[i]))
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
        self.fingerprint = Some(fp);
        self.cert_der = Some(cert_der);
        self.ceremony.state = CeremonyState::CertPreview;
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
        if let Some(ct) = self.confirmed_time {
            if !clock_drift_ok(ct) {
                self.set_status(
                    "Clock drift > 5 min since ClockCheck — restart ceremony to re-confirm clock.",
                );
                return;
            }
        }
        let label = match self.profile.as_ref().map(|p| p.hsm.key_label.clone()) {
            Some(l) => l,
            None => {
                self.set_status("No profile");
                return;
            }
        };
        let actor = match self.actor.clone() {
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

        let root_cert_der = match &self.root_cert_der {
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

        let crl_number = match self.crl_number {
            Some(n) => n,
            None => {
                self.set_status("CRL number not determined");
                return;
            }
        };

        // Convert RevocationEntry list to (serial, SystemTime, reason) triples
        let revoked: Vec<(u64, SystemTime, Option<anodize_ca::CrlReason>)> = self
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

        self.crl_der = Some(crl_der);
        self.do_start_burn();
    }

    // ── WAL intent write ──────────────────────────────────────────────────────

    pub(crate) fn do_write_intent(&mut self) {
        // For Mode 2+, load root cert from disc before intent write
        if matches!(
            self.current_op,
            Some(Operation::SignCsr) | Some(Operation::RevokeCert) | Some(Operation::IssueCrl)
        ) && self.root_cert_der.is_none()
        {
            self.root_cert_der = load_root_cert_der_from_sessions(&self.prior_sessions);
            if self.root_cert_der.is_none() {
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

        if !self.skip_disc && self.sessions_remaining.map(|r| r < 2).unwrap_or(false) {
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
        let mut all_sessions = self.prior_sessions.clone();
        all_sessions.push(intent_session.clone());

        let (tx, rx) = mpsc::channel();
        self.burn_rx = Some(rx);
        self.pending_intent_session = Some(intent_session);

        {
            if self.skip_disc {
                let iso = media::iso9660::build_iso(&all_sessions);
                let iso_path = staging.join("ceremony.iso");
                match std::fs::write(&iso_path, &iso) {
                    Ok(()) => {
                        tx.send(Ok(())).ok();
                    }
                    Err(e) => {
                        tx.send(Err(anyhow::anyhow!("write intent ISO: {e}"))).ok();
                    }
                }
            } else if let Some(dev) = self.optical_dev.clone() {
                media::write_session(&dev, all_sessions, false, tx);
            } else {
                self.set_status("No optical device — cannot write intent");
                self.burn_rx = None;
                self.pending_intent_session = None;
                return;
            }
        }

        self.ceremony.state = CeremonyState::WritingIntent;
        self.set_status("Writing intent to disc. Operation will follow…");
    }

    /// Build the intent audit event (name, data) for the current operation.
    fn build_intent_audit_event(
        &self,
        genesis_hex: &str,
    ) -> Option<(String, serde_json::Value)> {
        match &self.current_op {
            Some(Operation::GenerateRootCa) => {
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
                let action_str = match self.pending_key_action {
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
                        self.selected_profile_idx
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
                let serial: u64 = self.revoke_serial_buf.parse().unwrap_or(0);
                let reason = if self.revoke_reason_buf.is_empty() {
                    serde_json::Value::Null
                } else {
                    serde_json::Value::String(self.revoke_reason_buf.clone())
                };
                Some((
                    "cert.revoke.intent".into(),
                    serde_json::json!({
                        "operation": "revoke-and-issue-crl",
                        "serial": serial,
                        "reason": reason,
                        "crl_number": self.crl_number.unwrap_or(0),
                        "revocation_count": self.revocation_list.len(),
                    }),
                ))
            }
            Some(Operation::IssueCrl) => Some((
                "crl.intent".into(),
                serde_json::json!({
                    "operation": "issue-crl",
                    "crl_number": self.crl_number.unwrap_or(0),
                    "revocation_count": self.revocation_list.len(),
                }),
            )),
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
            self.migrate_sessions.clone()
        } else {
            let mut sessions = self.prior_sessions.clone();
            sessions.push(new_session);
            sessions
        };

        let (tx, rx) = mpsc::channel();
        self.burn_rx = Some(rx);

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
            } else if let Some(dev) = &self.optical_dev {
                media::write_session(dev, all_sessions, false, tx);
            } else {
                self.set_status("No optical device — cannot burn");
                self.burn_rx = None;
                return;
            }

            self.ceremony.state = CeremonyState::BurningDisc;
            self.set_status("Burning disc session… (this may take a few minutes)");
        }
    }

    /// Build the SessionEntry for the current operation's disc burn.
    fn build_burn_session(&mut self, staging: &std::path::Path) -> Option<SessionEntry> {
        let ts = self.confirmed_time.unwrap_or_else(SystemTime::now);
        let dir_name = media::session_dir_name(ts) + "-record";

        match self.current_op.clone() {
            Some(Operation::GenerateRootCa) => {
                let cert_der = self.cert_der.clone()?;
                let crl_der = self.crl_der.clone()?;

                let log_path = staging.join("audit.log");
                let mut log = match AuditLog::open(&log_path) {
                    Ok(l) => l,
                    Err(e) => {
                        self.set_status(format!("Audit log reopen failed: {e}"));
                        return None;
                    }
                };
                let fp = self.fingerprint.clone().unwrap_or_default();
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
                        "intent_session": self.intent_session_dir_name.as_deref().unwrap_or(""),
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
                        "intent_session": self.intent_session_dir_name.as_deref().unwrap_or(""),
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

                Some(SessionEntry {
                    dir_name,
                    timestamp: ts,
                    files: vec![
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
                    ],
                })
            }

            Some(Operation::SignCsr) => {
                let cert_der = self.cert_der.clone()?;

                let log_path = staging.join("audit.log");
                let mut log = match AuditLog::open(&log_path) {
                    Ok(l) => l,
                    Err(e) => {
                        self.set_status(format!("Audit log reopen failed: {e}"));
                        return None;
                    }
                };
                let fp = self.fingerprint.clone().unwrap_or_default();
                let profile_name = self
                    .profile
                    .as_ref()
                    .and_then(|p| {
                        self.selected_profile_idx
                            .map(|i| p.cert_profiles[i].name.clone())
                    })
                    .unwrap_or_default();
                if let Err(e) = log.append(
                    "cert.intermediate.issue",
                    serde_json::json!({
                        "fingerprint": fp,
                        "profile": profile_name,
                        "intent_session": self.intent_session_dir_name.as_deref().unwrap_or(""),
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
                    files: vec![
                        IsoFile {
                            name: "INTERMEDIATE.CRT".into(),
                            data: cert_der,
                        },
                        IsoFile {
                            name: "AUDIT.LOG".into(),
                            data: audit_bytes,
                        },
                    ],
                })
            }

            Some(Operation::RevokeCert) => {
                let crl_der = self.crl_der.clone()?;
                let revoked_toml = serialize_revocation_list(&self.revocation_list).into_bytes();
                let crl_number = self.crl_number.unwrap_or(0);

                let log_path = staging.join("audit.log");
                let mut log = match AuditLog::open(&log_path) {
                    Ok(l) => l,
                    Err(e) => {
                        self.set_status(format!("Audit log reopen failed: {e}"));
                        return None;
                    }
                };
                let serial: u64 = self.revoke_serial_buf.parse().unwrap_or(0);
                let reason = if self.revoke_reason_buf.is_empty() {
                    serde_json::Value::Null
                } else {
                    serde_json::Value::String(self.revoke_reason_buf.clone())
                };
                if let Err(e) = log.append(
                    "cert.revoke",
                    serde_json::json!({
                        "serial": serial,
                        "reason": reason,
                        "intent_session": self.intent_session_dir_name.as_deref().unwrap_or(""),
                    }),
                ) {
                    self.set_status(format!("Audit log append failed: {e}"));
                    return None;
                }
                if let Err(e) = log.append(
                    "crl.issue",
                    serde_json::json!({
                        "crl_number": crl_number,
                        "revocation_count": self.revocation_list.len(),
                        "intent_session": self.intent_session_dir_name.as_deref().unwrap_or(""),
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

                Some(SessionEntry {
                    dir_name,
                    timestamp: ts,
                    files: vec![
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
                    ],
                })
            }

            Some(Operation::IssueCrl) => {
                let crl_der = self.crl_der.clone()?;
                let crl_number = self.crl_number.unwrap_or(0);

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
                        "revocation_count": self.revocation_list.len(),
                        "intent_session": self.intent_session_dir_name.as_deref().unwrap_or(""),
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
                    files: vec![
                        IsoFile {
                            name: "ROOT.CRL".into(),
                            data: crl_der,
                        },
                        IsoFile {
                            name: "AUDIT.LOG".into(),
                            data: audit_bytes,
                        },
                    ],
                })
            }

            Some(Operation::MigrateDisc) => {
                Some(SessionEntry {
                    dir_name,
                    timestamp: ts,
                    files: vec![],
                })
            }

            None => {
                self.set_status("No operation set");
                None
            }
        }
    }

    // ── USB write ─────────────────────────────────────────────────────────────

    pub(crate) fn do_write_usb(&mut self) {
        let usb = self.usb_mountpoint.clone();
        let staging_log = PathBuf::from("/run/anodize/staging/audit.log");

        match self.current_op.clone() {
            Some(Operation::GenerateRootCa) => {
                if let Some(cert_der) = &self.cert_der {
                    if let Err(e) = std::fs::write(usb.join("root.crt"), cert_der) {
                        self.set_status(format!("USB write failed (root.crt): {e}"));
                        return;
                    }
                }
                if let Some(crl_der) = &self.crl_der {
                    if let Err(e) = std::fs::write(usb.join("root.crl"), crl_der) {
                        self.set_status(format!("USB write failed (root.crl): {e}"));
                        return;
                    }
                }
            }
            Some(Operation::SignCsr) => {
                if let Some(cert_der) = &self.cert_der {
                    if let Err(e) = std::fs::write(usb.join("intermediate.crt"), cert_der) {
                        self.set_status(format!("USB write failed (intermediate.crt): {e}"));
                        return;
                    }
                }
            }
            Some(Operation::RevokeCert) => {
                let revoked_toml = serialize_revocation_list(&self.revocation_list);
                if let Err(e) = std::fs::write(usb.join("revoked.toml"), &revoked_toml) {
                    self.set_status(format!("USB write failed (revoked.toml): {e}"));
                    return;
                }
                if let Some(crl_der) = &self.crl_der {
                    if let Err(e) = std::fs::write(usb.join("root.crl"), crl_der) {
                        self.set_status(format!("USB write failed (root.crl): {e}"));
                        return;
                    }
                }
            }
            Some(Operation::IssueCrl) => {
                if let Some(crl_der) = &self.crl_der {
                    if let Err(e) = std::fs::write(usb.join("root.crl"), crl_der) {
                        self.set_status(format!("USB write failed (root.crl): {e}"));
                        return;
                    }
                }
            }
            Some(Operation::MigrateDisc) | None => {
                self.ceremony.state = CeremonyState::Done;
                self.set_status("Migration complete.");
                return;
            }
        }

        // Copy audit log to USB for all non-migration operations
        let usb_log = usb.join("audit.log");
        if let Err(e) = std::fs::copy(&staging_log, &usb_log) {
            self.set_status(format!("Audit log copy to USB failed: {e}"));
            return;
        }

        self.ceremony.state = CeremonyState::Done;
        self.set_status(format!("USB write complete: {}", usb.display()));
    }

    // ── Content rendering (avoids borrow splitting) ──────────────────────────

    pub(crate) fn render_setup_content(&self, frame: &mut Frame, area: Rect) {
        self.setup.render_with_app(frame, area, self);
    }

    pub(crate) fn render_ceremony_content(&self, frame: &mut Frame, area: Rect) {
        self.ceremony.render_with_app(frame, area, self);
    }
}
