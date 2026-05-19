//! InitRoot operation context.
//!
//! Owns all SSS state (CustodianSetup → ShareReveal → ShareVerify) plus the
//! post-intent HSM bootstrap, keygen, and cert build.  After intent burn the
//! ctx drives Execute (cert preview) → record burn → done.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use ratatui::Frame;

use super::{AppShared, ConfirmTarget, OpAction, OpContext};
use crate::media::{IsoFile, SessionEntry};

/// Phase FSM for the InitRoot ceremony.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitRootPhase {
    CustodianSetup,
    ShareReveal,
    ShareVerify,
    /// Cert preview — user records fingerprint then triggers record burn.
    Execute,
}

/// Operation context for InitRoot.
pub struct InitRootCtx {
    pub phase: InitRootPhase,
    // SSS components (scoped to this operation)
    pub custodian_setup: Option<crate::components::custodian_setup::CustodianSetup>,
    pub share_reveal: Option<crate::components::share_reveal::ShareReveal>,
    pub share_input: Option<crate::components::share_input::ShareInput>,
    pub custodian_names: Vec<String>,
    // Artifacts (populated after intent burn)
    pub cert_der: Option<Vec<u8>>,
    pub crl_der: Option<Vec<u8>>,
    pub fingerprint: Option<String>,
}

impl InitRootCtx {
    pub fn new() -> Self {
        let custodian_setup = Some(crate::components::custodian_setup::CustodianSetup::new(
            "Root Init",
        ));
        Self {
            phase: InitRootPhase::CustodianSetup,
            custodian_setup,
            share_reveal: None,
            share_input: None,
            custodian_names: Vec::new(),
            cert_der: None,
            crl_der: None,
            fingerprint: None,
        }
    }

    // ── CustodianSetup confirmed: generate PIN, split, build SessionState ──

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

        // Generate random 32-byte PIN
        let mut pin_bytes = vec![0u8; 32];
        if let Err(e) = getrandom::getrandom(&mut pin_bytes) {
            shared.set_status(format!("CSPRNG failure: {e}"));
            return OpAction::Noop;
        }

        // Split into shares
        let shares = match anodize_sss::split(&pin_bytes, threshold, total) {
            Ok(s) => s,
            Err(e) => {
                shared.set_status(format!("SSS split failed: {e}"));
                return OpAction::Noop;
            }
        };

        // Compute commitments and PIN verify hash
        let mut share_commitments = Vec::with_capacity(shares.len());
        for (share, name) in shares.iter().zip(names.iter()) {
            let commitment = share.commitment(name);
            share_commitments.push(hex::encode(commitment));
        }
        let pin_verify_hash = hex::encode(anodize_sss::pin_verify_hash(&pin_bytes));

        // Store PIN hex for HSM init later
        *shared.pin_buf = hex::encode(&pin_bytes);

        // Build custodian metadata
        let custodians: Vec<anodize_config::state::Custodian> = names
            .iter()
            .enumerate()
            .map(|(i, name)| anodize_config::state::Custodian {
                name: name.clone(),
                index: (i + 1) as u8,
            })
            .collect();

        // Build partial SessionState (root_cert fields filled after HSM keygen)
        use anodize_config::state::{SessionState, SssMetadata, STATE_VERSION};
        let state = SessionState {
            version: STATE_VERSION,
            root_cert_sha256: "0".repeat(64),
            root_cert_der_b64: String::new(),
            sss: SssMetadata {
                generation: 1,
                threshold,
                total,
                custodians,
                pin_verify_hash,
                share_commitments,
            },
            revocation_list: vec![],
            crl_number: 0,
            last_audit_hash: String::new(),
            last_hsm_log_seq: None,
            fleet: anodize_config::state::HsmFleet::default(),
        };
        shared.disc.session_state = Some(state);

        // Create ShareReveal component
        self.share_reveal = Some(crate::components::share_reveal::ShareReveal::new(
            shares, &names, 1,
        ));
        self.phase = InitRootPhase::ShareReveal;
        shared.set_status(format!(
            "PIN generated. Distributing {total} shares ({threshold}-of-{total}). Hand device to each custodian."
        ));
        tracing::info!(
            threshold,
            total,
            custodians = ?self.custodian_names,
            "InitRoot: SSS split complete, entering share reveal"
        );
        OpAction::Noop
    }

    // ── Post-intent HSM bootstrap + keygen + cert build ────────────────

    pub(crate) fn do_bootstrap_hsm(shared: &mut AppShared<'_>) -> Result<(), String> {
        use anodize_hsm::{create_backend, HsmActor};
        use secrecy::SecretString;

        let pin_bytes =
            hex::decode(&*shared.pin_buf).map_err(|e| format!("Internal PIN decode error: {e}"))?;
        let user_pin = SecretString::new(hex::encode(&pin_bytes));

        let cfg = shared
            .profile
            .map(|p| &p.hsm)
            .ok_or_else(|| "No profile loaded".to_string())?;

        let backend = create_backend(cfg.backend).map_err(|e| format!("HSM backend error: {e}"))?;

        let mut tokens = backend
            .list_tokens()
            .map_err(|e| format!("HSM enumerate failed: {e}"))?;

        if tokens.is_empty() {
            tokens = backend
                .list_all_slots()
                .map_err(|e| format!("HSM slot enumerate failed: {e}"))?;
        }
        if tokens.is_empty() {
            return Err("No HSM slots found. Insert a YubiHSM or HSM device.".into());
        }

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

        let so_pin = user_pin.clone();
        let hsm = backend
            .bootstrap(target.slot_id, &so_pin, &user_pin, &cfg.token_label)
            .map_err(|e| format!("HSM bootstrap failed: {e}"))?;

        // Determine device_id and model for fleet enrollment.
        //
        // NOTE: We intentionally avoid calling create_inventory() here.
        // For PKCS#11 backends (SoftHSM), enumerate_devices() creates a
        // temporary Pkcs11 context whose C_Finalize on drop is process-global
        // and would kill the session we just bootstrapped above.
        let (device_id, model) = {
            let id = if target.serial_number.is_empty() {
                cfg.token_label.clone()
            } else {
                target.serial_number.clone()
            };
            let model_name = if target.model.is_empty() {
                format!("{:?}", cfg.backend)
            } else {
                target.model.clone()
            };
            (id, model_name)
        };

        let now = {
            let d = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            format!("{}Z", d.as_secs())
        };

        use anodize_config::state::{HsmDevice, HsmDeviceStatus, HsmFleet};
        let fleet_device = HsmDevice {
            device_id: device_id.clone(),
            model,
            backend: cfg.backend,
            enrolled_at: now.clone(),
            last_seen_at: now,
            status: HsmDeviceStatus::Active,
        };
        if let Some(ref mut state) = shared.disc.session_state {
            state.fleet = HsmFleet {
                devices: vec![fleet_device],
            };
        }

        tracing::info!(device_id = %device_id, "do_bootstrap_hsm: enrolled device in fleet");

        let actor = HsmActor::spawn(hsm);
        shared.hw.actor = Some(actor);
        shared.hw.device_id = Some(device_id.clone());
        shared.hw.hsm_state = crate::components::status_bar::HwState::Ready(format!(
            "bootstrapped (id={device_id}, label={})",
            cfg.token_label
        ));
        tracing::info!(device_id, label = %cfg.token_label, "do_bootstrap_hsm: token ready");
        Ok(())
    }

    fn do_generate_and_build(&mut self, shared: &mut AppShared<'_>) -> Result<(), String> {
        use anodize_ca::{build_root_cert, issue_crl, P384HsmSigner};
        use anodize_hsm::{Hsm, KeySpec};
        use der::Encode;

        let label = shared
            .profile
            .map(|p| p.hsm.key_label.clone())
            .ok_or_else(|| "No profile".to_string())?;
        let key = {
            let actor = shared.hw.actor.as_mut().ok_or("No HSM session")?;
            actor
                .generate_keypair(&label, KeySpec::EcdsaP384)
                .map_err(|e| format!("Key generation failed: {e}"))?
        };
        shared.hw.root_key = Some(key);
        shared.set_status(format!("Generated P-384 keypair (label={label:?})"));

        let actor = shared.hw.actor.clone().ok_or("No HSM session")?;
        let signer = P384HsmSigner::new(actor, key).map_err(|e| format!("Signer error: {e}"))?;

        let ca = shared
            .profile
            .map(|p| &p.ca)
            .ok_or_else(|| "No profile".to_string())?;

        let cert = build_root_cert(
            &signer,
            &ca.common_name,
            &ca.organization,
            &ca.country,
            7305,
        )
        .map_err(|e| crate::helpers::mechanism_error_msg("Cert build failed", &e))?;

        let cert_der = cert
            .to_der()
            .map_err(|e| format!("DER encode failed: {e}"))?;

        // Issue initial CRL (#1, empty)
        let base_time = shared
            .confirmed_time
            .unwrap_or_else(std::time::SystemTime::now);
        let next_update = base_time + std::time::Duration::from_secs(365 * 24 * 3600);
        let crl_der = issue_crl(&signer, &cert, &[], next_update, 1)
            .map_err(|e| crate::helpers::mechanism_error_msg("Initial CRL build failed", &e))?;

        let fp = crate::helpers::sha256_fingerprint(&cert_der);

        // Update SessionState with root cert info
        if let Some(ref mut state) = shared.disc.session_state {
            use base64::Engine;
            let cert_hash = {
                use sha2::{Digest, Sha256};
                hex::encode(Sha256::digest(&cert_der))
            };
            state.root_cert_sha256 = cert_hash;
            state.root_cert_der_b64 = base64::engine::general_purpose::STANDARD.encode(&cert_der);
        }

        self.cert_der = Some(cert_der);
        self.crl_der = Some(crl_der);
        self.fingerprint = Some(fp);
        self.phase = InitRootPhase::Execute;
        shared.set_status("Certificate built. Record fingerprint before writing.");
        Ok(())
    }
}

impl OpContext for InitRootCtx {
    fn phase_index(&self) -> usize {
        match self.phase {
            InitRootPhase::CustodianSetup
            | InitRootPhase::ShareReveal
            | InitRootPhase::ShareVerify => 1,
            InitRootPhase::Execute => 4,
        }
    }

    fn title(&self) -> &str {
        match self.phase {
            InitRootPhase::CustodianSetup => "Root Init \u{2014} Custodian Setup",
            InitRootPhase::ShareReveal => "Root Init \u{2014} Distribute Shares",
            InitRootPhase::ShareVerify => "Root Init \u{2014} Verify Shares",
            InitRootPhase::Execute => "Certificate Preview \u{2014} RECORD FINGERPRINT",
        }
    }

    fn build_body(&self) -> Vec<String> {
        match self.phase {
            InitRootPhase::CustodianSetup | InitRootPhase::ShareReveal => {
                // Overlay component renders itself
                vec![]
            }
            InitRootPhase::ShareVerify => {
                // Overlay component renders itself
                vec![]
            }
            InitRootPhase::Execute => {
                let fp = self.fingerprint.as_deref().unwrap_or("(none)");
                let (subject, validity_label) = self
                    .cert_der
                    .as_deref()
                    .and_then(crate::helpers::cert_subject_and_validity_days)
                    .map(|(subj, days)| (subj, format!("{days} days")))
                    .unwrap_or_else(|| ("(unknown)".into(), "7305 days (20 years)".into()));
                let has_crl = self.crl_der.is_some();
                let mut lines = vec![
                    String::new(),
                    format!("  Subject  : {subject}"),
                    format!("  Validity : {validity_label}"),
                    String::new(),
                    "  SHA-256 Fingerprint:".into(),
                    format!("  {fp}"),
                ];
                if has_crl {
                    lines.push(String::new());
                    lines.push("  Initial CRL #1 (empty) will be included in this session.".into());
                }
                lines.push(String::new());
                lines.push(
                    "  RECORD the fingerprint above \u{2014} it will NOT be shown again.".into(),
                );
                lines.push(String::new());
                lines.push("  [1]  Proceed to disc write".into());
                lines.push("  [Esc]  Abort".into());
                lines
            }
        }
    }

    fn handle_key(&mut self, key: KeyEvent, shared: &mut AppShared<'_>) -> OpAction {
        match self.phase {
            InitRootPhase::CustodianSetup => {
                if key.code == KeyCode::Esc {
                    return OpAction::Abort;
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
            InitRootPhase::ShareReveal => {
                if key.code == KeyCode::Esc {
                    return OpAction::Abort;
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
                        self.phase = InitRootPhase::ShareVerify;
                        shared.set_status(
                            "Verification round: every custodian must re-enter their share.",
                        );
                    }
                }
                OpAction::Noop
            }
            InitRootPhase::ShareVerify => {
                if key.code == KeyCode::Esc {
                    return OpAction::Abort;
                }
                if let Some(ref mut input) = self.share_input {
                    input.handle_key(key);
                    if input.is_complete() {
                        self.share_input = None;
                        shared.set_status("All shares verified. Writing intent to disc\u{2026}");
                        return OpAction::WriteIntent;
                    }
                }
                OpAction::Noop
            }
            InitRootPhase::Execute => match key.code {
                KeyCode::Char('1') => OpAction::ShowConfirm {
                    title: "Write Record to Disc".into(),
                    body: vec![
                        format!(
                            "Fingerprint: {}",
                            self.fingerprint.as_deref().unwrap_or("?")
                        ),
                        "This will burn the root cert and CRL to disc.".into(),
                    ],
                    on_confirm: ConfirmTarget::StartRecordBurn,
                },
                KeyCode::Esc => OpAction::Abort,
                _ => OpAction::Noop,
            },
        }
    }

    fn holds_ephemeral_state(&self) -> bool {
        true
    }

    fn needs_abort_confirmation(&self) -> bool {
        true
    }

    fn in_text_entry(&self) -> bool {
        matches!(
            self.phase,
            InitRootPhase::CustodianSetup | InitRootPhase::ShareVerify
        )
    }

    fn render_overlay(&self, frame: &mut Frame, area: Rect) {
        if let Some(ref setup) = self.custodian_setup {
            setup.render(frame, area);
        } else if let Some(ref reveal) = self.share_reveal {
            reveal.render(frame, area);
        } else if let Some(ref input) = self.share_input {
            input.render(frame, area);
        }
    }

    fn build_intent_audit_event(
        &self,
        genesis_hex: &str,
        shared: &AppShared<'_>,
    ) -> Option<(String, serde_json::Value)> {
        let (cn, org, country) = shared
            .profile
            .map(|p| {
                (
                    p.ca.common_name.clone(),
                    p.ca.organization.clone(),
                    p.ca.country.clone(),
                )
            })
            .unwrap_or_default();
        Some((
            "cert.root.intent".into(),
            serde_json::json!({
                "operation": "sign-root-cert",
                "key_action": "generate",
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

    fn build_record_session(
        &mut self,
        dir_name: String,
        ts: std::time::SystemTime,
        staging: &std::path::Path,
        shared: &mut AppShared<'_>,
    ) -> Option<SessionEntry> {
        use anodize_audit::AuditLog;

        let cert_der = self.cert_der.clone()?;
        let crl_der = self.crl_der.clone()?;
        let fp = self.fingerprint.clone().unwrap_or_default();

        let log_path = staging.join("audit.log");
        let mut log = match AuditLog::open(&log_path) {
            Ok(l) => l,
            Err(e) => {
                shared.set_status(format!("Audit log reopen failed: {e}"));
                return None;
            }
        };
        let ca_name = shared
            .profile
            .map(|p| p.ca.common_name.clone())
            .unwrap_or_default();
        if let Err(e) = log.append(
            "cert.root.issue",
            serde_json::json!({
                "subject": ca_name,
                "fingerprint": fp,
                "intent_session": shared.disc.intent_session_dir_name.as_deref().unwrap_or(""),
            }),
        ) {
            shared.set_status(format!("Audit log append failed: {e}"));
            return None;
        }
        if let Err(e) = log.append(
            "crl.issue",
            serde_json::json!({
                "crl_number": 1,
                "revocation_count": 0,
                "intent_session": shared.disc.intent_session_dir_name.as_deref().unwrap_or(""),
            }),
        ) {
            shared.set_status(format!("CRL audit append failed: {e}"));
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
        if let Some(state_file) = shared.build_state_json_file() {
            files.push(state_file);
        }

        Some(SessionEntry {
            dir_name,
            timestamp: ts,
            files,
        })
    }

    fn has_shuttle_artifacts(&self) -> bool {
        true
    }

    fn write_shuttle_artifacts(&self, shuttle: &std::path::Path) -> Result<bool, String> {
        if let Some(ref cert_der) = self.cert_der {
            crate::media::write_and_sync(&shuttle.join("root.crt"), cert_der)
                .map_err(|e| format!("Shuttle write failed (root.crt): {e:#}"))?;
        }
        if let Some(ref crl_der) = self.crl_der {
            crate::media::write_and_sync(&shuttle.join("root.crl"), crl_der)
                .map_err(|e| format!("Shuttle write failed (root.crl): {e:#}"))?;
        }
        Ok(true)
    }

    fn advance_after_intent_burn(&mut self, shared: &mut AppShared<'_>) {
        // Bootstrap HSM, generate key, build cert + CRL.
        if let Err(e) = Self::do_bootstrap_hsm(shared) {
            tracing::error!("InitRoot: HSM bootstrap failed: {e}");
            shared.set_status(e);
            return;
        }
        if let Err(e) = self.do_generate_and_build(shared) {
            tracing::error!("InitRoot: keygen/cert build failed: {e}");
            shared.set_status(e);
        }
    }
}
