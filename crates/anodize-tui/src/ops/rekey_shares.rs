//! RekeyShares operation context.
//!
//! Phases: Quorum → CustodianSetup → ShareReveal → ShareVerify → (PIN change
//! + burn).  All SSS state, custodian components, and PIN rotation logic are
//! scoped to this context.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{layout::Rect, Frame};

use super::{AppShared, ConfirmTarget, OpAction, OpContext};
use crate::media::{IsoFile, SessionEntry};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RekeyPhase {
    Quorum,
    CustodianSetup,
    ShareReveal,
    ShareVerify,
    Done,
}

pub struct RekeyCtx {
    pub phase: RekeyPhase,
    pub custodian_setup: Option<crate::components::custodian_setup::CustodianSetup>,
    pub share_reveal: Option<crate::components::share_reveal::ShareReveal>,
    pub share_input: Option<crate::components::share_input::ShareInput>,
    pub shares: Option<Vec<anodize_sss::Share>>,
    pub custodian_names: Vec<String>,
    pub rekey_old_pin_hex: Option<String>,
    pub rekey_changed_backup_ids: Vec<String>,
}

impl RekeyCtx {
    pub fn new(sss: anodize_config::state::SssMetadata) -> Self {
        let share_input = Some(crate::components::share_input::ShareInput::new(sss, 32));
        Self {
            phase: RekeyPhase::Quorum,
            custodian_setup: None,
            share_reveal: None,
            share_input,
            shares: None,
            custodian_names: Vec::new(),
            rekey_old_pin_hex: None,
            rekey_changed_backup_ids: Vec::new(),
        }
    }

    // ── Quorum completion ─────────────────────────────────────────────

    fn try_quorum_complete(&mut self, shared: &mut AppShared<'_>) -> OpAction {
        let shares: Vec<anodize_sss::Share> = self
            .share_input
            .as_ref()
            .map(|si| si.collected.iter().map(|c| c.share.clone()).collect())
            .unwrap_or_default();
        self.share_input = None;

        match shared.quorum_complete(&shares) {
            Ok(()) => {
                // Store old PIN for change_pin later
                self.rekey_old_pin_hex = Some(shared.pin_buf.clone());
                self.custodian_setup = Some(
                    crate::components::custodian_setup::CustodianSetup::new("Re-key Shares"),
                );
                self.phase = RekeyPhase::CustodianSetup;
                shared.set_status(
                    "PIN verified, HSM authenticated. Enter new custodian names, then set threshold.",
                );
                tracing::info!("RekeyShares: quorum reached, PIN verified, HSM authenticated, entering custodian setup");
                OpAction::Noop
            }
            Err(e) => {
                shared.set_status(format!("{e}"));
                OpAction::Abort
            }
        }
    }

    // ── Custodian confirm → new PIN generation → SSS split ────────────

    fn on_custodian_confirm(&mut self, shared: &mut AppShared<'_>, threshold: u8) -> OpAction {
        let names = self.custodian_names.clone();

        if names.len() < 2 {
            shared.set_status("Need at least 2 custodians for SSS (threshold >= 2).");
            return OpAction::Noop;
        }
        if names.len() > 255 {
            shared.set_status("Maximum 255 custodians.");
            return OpAction::Noop;
        }

        let total = names.len() as u8;

        // Generate a new random 32-byte PIN (actual PIN rotation)
        let mut new_pin_bytes = vec![0u8; 32];
        if let Err(e) = getrandom::getrandom(&mut new_pin_bytes) {
            shared.set_status(format!("CSPRNG failure: {e}"));
            return OpAction::Noop;
        }

        // Split NEW PIN with new custodians
        let shares = match anodize_sss::split(&new_pin_bytes, threshold, total) {
            Ok(s) => s,
            Err(e) => {
                shared.set_status(format!("SSS split failed: {e}"));
                return OpAction::Noop;
            }
        };

        // Compute new commitments
        let mut share_commitments = Vec::with_capacity(shares.len());
        for (share, name) in shares.iter().zip(names.iter()) {
            let commitment = share.commitment(name);
            share_commitments.push(hex::encode(commitment));
        }

        // Compute new pin_verify_hash for the NEW PIN
        let new_pin_verify_hash = hex::encode(anodize_sss::pin_verify_hash(&new_pin_bytes));

        // Build custodian metadata
        let custodians: Vec<anodize_config::state::Custodian> = names
            .iter()
            .enumerate()
            .map(|(i, name)| anodize_config::state::Custodian {
                name: name.clone(),
                index: (i + 1) as u8,
            })
            .collect();

        // Update SessionState SSS metadata with new PIN hash
        if let Some(ref mut state) = shared.disc.session_state {
            state.sss.generation += 1;
            state.sss.threshold = threshold;
            state.sss.total = total;
            state.sss.custodians = custodians;
            state.sss.share_commitments = share_commitments;
            state.sss.pin_verify_hash = new_pin_verify_hash;
        }

        // Store NEW PIN hex in pin_buf (old PIN is in rekey_old_pin_hex)
        *shared.pin_buf = hex::encode(&new_pin_bytes);

        self.shares = Some(shares.clone());

        // Create ShareReveal component — use the newly incremented generation
        let generation = shared
            .disc
            .session_state
            .as_ref()
            .map(|s| s.sss.generation)
            .unwrap_or(1);
        self.share_reveal = Some(crate::components::share_reveal::ShareReveal::new(
            shares, &names, generation,
        ));

        self.phase = RekeyPhase::ShareReveal;
        shared.set_status(format!(
            "Distributing {total} new shares ({threshold}-of-{total}). Hand device to each custodian."
        ));

        tracing::info!(
            threshold,
            total,
            custodians = ?self.custodian_names,
            "RekeyShares: new PIN generated, shares split, entering share reveal"
        );
        OpAction::Noop
    }

    // ── Share verify complete → PIN change + backup propagation ───────

    fn on_share_verify_complete(&mut self, shared: &mut AppShared<'_>) -> OpAction {
        // Round-trip check: reconstruct new PIN from verified shares
        let shares: Vec<anodize_sss::Share> = self
            .share_input
            .as_ref()
            .map(|si| si.collected.iter().map(|c| c.share.clone()).collect())
            .unwrap_or_default();

        let threshold = shared
            .disc
            .session_state
            .as_ref()
            .map(|s| s.sss.threshold)
            .unwrap_or(2);

        let reconstructed = match anodize_sss::reconstruct(&shares, threshold) {
            Ok(b) => b,
            Err(e) => {
                shared.set_status(format!("Share round-trip reconstruction failed: {e}"));
                return OpAction::Abort;
            }
        };

        let expected_new_pin_hex = &*shared.pin_buf;
        let reconstructed_hex = hex::encode(&reconstructed);
        if reconstructed_hex != *expected_new_pin_hex {
            shared.set_status(
                "Share round-trip check FAILED: reconstructed PIN does not match generated PIN.",
            );
            return OpAction::Abort;
        }

        tracing::info!("RekeyShares: share round-trip check passed");

        // Change PIN on primary HSM
        let old_pin_hex = match self.rekey_old_pin_hex.take() {
            Some(h) => h,
            None => {
                shared.set_status("Internal error: old PIN not available for change_pin");
                return OpAction::Abort;
            }
        };

        {
            use anodize_hsm::Hsm;
            use secrecy::SecretString;
            let old_pin = SecretString::new(old_pin_hex.clone());
            let new_pin = SecretString::new(expected_new_pin_hex.to_string());

            let actor = match shared.hw.actor.as_mut() {
                Some(a) => a,
                None => {
                    shared.set_status("No HSM session for change_pin");
                    return OpAction::Abort;
                }
            };

            // Drain HSM audit log before change_pin — force-audit mode
            // blocks all operations once the 62-entry ring buffer is full.
            if let Ok(snapshot) = actor.get_audit_log() {
                if let Some(last) = snapshot.entries.last() {
                    let _ = actor.drain_audit_log(last.item);
                }
            }

            if let Err(e) = actor.change_pin(&old_pin, &new_pin) {
                shared.set_status(format!("HSM change_pin failed: {e}"));
                return OpAction::Abort;
            }
            tracing::info!("RekeyShares: HSM PIN changed successfully");
        }

        // Propagate PIN to backup HSMs
        let new_pin_hex = expected_new_pin_hex.to_string();
        match Self::change_pin_backups(shared, &old_pin_hex, &new_pin_hex) {
            Ok(ids) => {
                self.rekey_changed_backup_ids = ids;
            }
            Err(e) => {
                tracing::error!("RekeyShares: backup PIN propagation failed: {e}");
                shared.set_status(format!("Re-key failed: {e}"));
                return OpAction::Abort;
            }
        }

        // Verify old PIN is rejected on all fleet devices
        if let Err(e) = Self::verify_old_pin_rejected(shared, &old_pin_hex) {
            tracing::error!("RekeyShares: old-PIN rejection check failed: {e}");
            shared.set_status(format!("Re-key failed: {e}"));
            return OpAction::Abort;
        }

        self.share_input = None;
        self.shares = None;
        self.phase = RekeyPhase::Done;
        shared.set_status("PIN rotated on all fleet devices. Writing session to disc…");
        OpAction::StartRecordBurn
    }

    // ── PIN propagation to backup HSMs ───────────────────────────────

    fn change_pin_backups(
        shared: &mut AppShared<'_>,
        old_pin_hex: &str,
        new_pin_hex: &str,
    ) -> Result<Vec<String>, String> {
        use secrecy::SecretString;

        let profile = shared.profile.ok_or("No profile loaded")?;
        let backend_kind = profile.hsm.backend;

        let fleet = shared
            .disc
            .session_state
            .as_ref()
            .ok_or("No STATE.JSON loaded")?
            .fleet
            .clone();
        let active_ids = fleet.active_device_ids();

        let primary_device_id = shared
            .hw
            .device_id
            .as_ref()
            .ok_or("No primary device_id recorded")?
            .clone();

        let backup_impl = anodize_hsm::create_backup(backend_kind)
            .map_err(|e| format!("Backup backend init: {e}"))?;

        let old_pin = SecretString::new(old_pin_hex.to_string());
        let new_pin = SecretString::new(new_pin_hex.to_string());
        let mut changed: Vec<String> = Vec::new();

        for device_id in &active_ids {
            if *device_id == primary_device_id {
                continue;
            }
            tracing::info!(device = %device_id, "RekeyShares: changing PIN on fleet HSM");
            match backup_impl.change_pin_on_device(device_id, &old_pin, &new_pin) {
                Ok(()) => {
                    changed.push(device_id.to_string());
                    tracing::info!(device = %device_id, "RekeyShares: fleet HSM PIN changed");
                }
                Err(e) => {
                    tracing::error!(
                        device = %device_id,
                        "RekeyShares: fleet PIN change failed: {e}, initiating rollback"
                    );
                    // Roll back already-changed fleet devices to the old PIN.
                    Self::rollback_backup_pins(&*backup_impl, &changed, &new_pin, &old_pin);
                    // Roll back primary HSM to the old PIN.
                    Self::rollback_primary_pin(shared.hw.actor.as_mut(), &new_pin, &old_pin);
                    return Err(format!(
                        "PIN change failed on fleet device {}: {e}. \
                         All HSMs rolled back to old PIN.",
                        device_id
                    ));
                }
            }
        }

        if !changed.is_empty() {
            tracing::info!(
                count = changed.len(),
                devices = ?changed,
                "RekeyShares: fleet PIN propagation complete"
            );
        }

        Ok(changed)
    }

    fn rollback_backup_pins(
        backup_impl: &dyn anodize_hsm::HsmBackup,
        device_ids: &[String],
        current_pin: &secrecy::SecretString,
        target_pin: &secrecy::SecretString,
    ) {
        for id in device_ids {
            match backup_impl.change_pin_on_device(id, current_pin, target_pin) {
                Ok(()) => {
                    tracing::info!(device = %id, "RekeyShares: backup rolled back to old PIN");
                }
                Err(e) => {
                    tracing::error!(
                        device = %id,
                        "RekeyShares: CRITICAL — backup rollback failed: {e}"
                    );
                }
            }
        }
    }

    fn rollback_primary_pin(
        actor: Option<&mut anodize_hsm::HsmActor>,
        current_pin: &secrecy::SecretString,
        target_pin: &secrecy::SecretString,
    ) {
        use anodize_hsm::Hsm;
        if let Some(actor) = actor {
            match actor.change_pin(current_pin, target_pin) {
                Ok(()) => {
                    tracing::info!("RekeyShares: primary HSM rolled back to old PIN");
                }
                Err(e) => {
                    tracing::error!("RekeyShares: CRITICAL — primary rollback failed: {e}");
                }
            }
        } else {
            tracing::error!("RekeyShares: no HSM actor available for primary rollback");
        }
    }

    // ── Verify old PIN is rejected ───────────────────────────────────

    fn verify_old_pin_rejected(shared: &AppShared<'_>, old_pin_hex: &str) -> Result<(), String> {
        use secrecy::SecretString;

        let cfg = shared.profile.map(|p| &p.hsm).ok_or("No profile loaded")?;
        let backend = anodize_hsm::create_backend(cfg.backend)
            .map_err(|e| format!("HSM backend error during old-PIN check: {e}"))?;

        let fleet = shared
            .disc
            .session_state
            .as_ref()
            .ok_or("No STATE.JSON loaded")?
            .fleet
            .clone();
        let active_ids = fleet.active_device_ids();

        if active_ids.is_empty() {
            return Err("No active fleet devices in STATE.JSON".into());
        }

        let pin_bytes =
            hex::decode(old_pin_hex).map_err(|e| format!("Internal PIN decode error: {e}"))?;
        let pin = SecretString::new(hex::encode(&pin_bytes));

        for device_id in &active_ids {
            match backend.open_session_by_id(device_id, &pin) {
                Ok(_) => {
                    tracing::error!(
                        device = %device_id,
                        "RekeyShares: old PIN still accepted after change_pin!"
                    );
                    return Err(format!(
                        "CRITICAL: old PIN still accepted by fleet device {}. \
                         The PIN rotation may not have taken effect.",
                        device_id
                    ));
                }
                Err(_) => {
                    tracing::info!(
                        device = %device_id,
                        "RekeyShares: old PIN correctly rejected"
                    );
                }
            }
        }

        tracing::info!(
            count = active_ids.len(),
            "RekeyShares: old PIN rejected on all fleet devices"
        );
        Ok(())
    }
}

impl OpContext for RekeyCtx {
    fn phase_index(&self) -> usize {
        match self.phase {
            RekeyPhase::Quorum => 3,
            RekeyPhase::CustodianSetup | RekeyPhase::ShareReveal | RekeyPhase::ShareVerify => 1,
            RekeyPhase::Done => 5,
        }
    }

    fn title(&self) -> &str {
        match self.phase {
            RekeyPhase::Quorum => "Re-key Shares \u{2014} Quorum",
            RekeyPhase::CustodianSetup => "Re-key Shares \u{2014} New Custodians",
            RekeyPhase::ShareReveal => "Re-key Shares \u{2014} Distribute New Shares",
            RekeyPhase::ShareVerify => "Re-key Shares \u{2014} Verify New Shares",
            RekeyPhase::Done => "Re-key Complete",
        }
    }

    fn build_body(&self) -> Vec<String> {
        match self.phase {
            RekeyPhase::Quorum => {
                vec![
                    String::new(),
                    "  Enter threshold shares to reconstruct the current PIN.".into(),
                ]
            }
            RekeyPhase::CustodianSetup => {
                vec![
                    String::new(),
                    "  Enter new custodian names and threshold.".into(),
                ]
            }
            RekeyPhase::ShareReveal => {
                vec![
                    String::new(),
                    "  Hand device to each custodian to reveal their share.".into(),
                ]
            }
            RekeyPhase::ShareVerify => {
                vec![
                    String::new(),
                    "  Every custodian must re-enter their share to verify.".into(),
                ]
            }
            RekeyPhase::Done => {
                let mut lines = vec![String::new()];
                if !self.rekey_changed_backup_ids.is_empty() {
                    lines.push(format!(
                        "  Backup HSMs updated: {}",
                        self.rekey_changed_backup_ids.join(", ")
                    ));
                }
                lines.push("  PIN rotated on all fleet devices.".into());
                lines.push(String::new());
                lines.push("  Session will be written to disc.".into());
                lines
            }
        }
    }

    fn handle_key(&mut self, key: KeyEvent, shared: &mut AppShared<'_>) -> OpAction {
        match self.phase {
            RekeyPhase::Quorum => {
                if key.code == KeyCode::Esc {
                    return OpAction::ShowConfirm {
                        title: "Abort re-key?".into(),
                        body: vec![],
                        on_confirm: ConfirmTarget::Abort,
                    };
                }
                if let Some(ref mut si) = self.share_input {
                    si.handle_key(key);
                    if si.quorum_reached() {
                        return self.try_quorum_complete(shared);
                    }
                }
                OpAction::Noop
            }
            RekeyPhase::CustodianSetup => {
                if key.code == KeyCode::Esc {
                    return OpAction::ShowConfirm {
                        title: "Abort re-key?".into(),
                        body: vec![],
                        on_confirm: ConfirmTarget::Abort,
                    };
                }
                if let Some(ref mut setup) = self.custodian_setup {
                    setup.handle_key(key);
                    if setup.confirmed {
                        let names = setup.names.clone();
                        let threshold = setup.threshold;
                        self.custodian_setup = None;
                        self.custodian_names = names;
                        return self.on_custodian_confirm(shared, threshold);
                    }
                }
                OpAction::Noop
            }
            RekeyPhase::ShareReveal => {
                if key.code == KeyCode::Esc {
                    return OpAction::ShowConfirm {
                        title: "Abort re-key?".into(),
                        body: vec![],
                        on_confirm: ConfirmTarget::Abort,
                    };
                }
                if let Some(ref mut reveal) = self.share_reveal {
                    if reveal.handle_key(key) {
                        // All shares revealed → verification round
                        self.share_reveal = None;
                        if let Some(ref state) = shared.disc.session_state {
                            let mut si = crate::components::share_input::ShareInput::new(
                                state.sss.clone(),
                                32,
                            );
                            si.verify_all = true;
                            self.share_input = Some(si);
                        }
                        self.phase = RekeyPhase::ShareVerify;
                        shared.set_status(
                            "Verify new shares: every custodian must re-enter their share.",
                        );
                    }
                }
                OpAction::Noop
            }
            RekeyPhase::ShareVerify => {
                if key.code == KeyCode::Esc {
                    return OpAction::ShowConfirm {
                        title: "Abort re-key?".into(),
                        body: vec![],
                        on_confirm: ConfirmTarget::Abort,
                    };
                }
                if let Some(ref mut si) = self.share_input {
                    si.handle_key(key);
                    if si.is_complete() {
                        return self.on_share_verify_complete(shared);
                    }
                }
                OpAction::Noop
            }
            RekeyPhase::Done => OpAction::Noop,
        }
    }

    fn build_record_session(
        &mut self,
        dir_name: String,
        ts: std::time::SystemTime,
        staging: &std::path::Path,
        shared: &mut AppShared<'_>,
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
        let new_total = shared
            .disc
            .session_state
            .as_ref()
            .map(|s| s.sss.total)
            .unwrap_or(0);
        let new_threshold = shared
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
                "pin_rotated": true,
                "backup_devices_updated": self.rekey_changed_backup_ids,
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

        shared.update_session_state_for_record(&audit_bytes, None, &[]);
        let mut files = vec![IsoFile {
            name: "AUDIT.LOG".into(),
            data: audit_bytes,
        }];
        if let Some(state_file) = shared.build_state_json_file() {
            files.push(state_file);
        }

        Some(SessionEntry {
            dir_name,
            timestamp: ts,
            files,
        })
    }

    fn holds_ephemeral_state(&self) -> bool {
        !matches!(self.phase, RekeyPhase::Done)
    }

    fn needs_abort_confirmation(&self) -> bool {
        !matches!(self.phase, RekeyPhase::Done)
    }

    fn in_text_entry(&self) -> bool {
        matches!(
            self.phase,
            RekeyPhase::CustodianSetup | RekeyPhase::ShareVerify | RekeyPhase::Quorum
        )
    }

    fn render_overlay(&self, frame: &mut Frame, area: Rect) {
        match self.phase {
            RekeyPhase::CustodianSetup => {
                if let Some(ref setup) = self.custodian_setup {
                    setup.render(frame, area);
                }
            }
            RekeyPhase::ShareReveal => {
                if let Some(ref reveal) = self.share_reveal {
                    reveal.render(frame, area);
                }
            }
            RekeyPhase::Quorum | RekeyPhase::ShareVerify => {
                if let Some(ref si) = self.share_input {
                    si.render(frame, area);
                }
            }
            _ => {}
        }
    }
}
