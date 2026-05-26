//! SignCsr operation context.
//!
//! Phases: LoadCsr → CertPreview → (intent burn) → Quorum → ClockReconfirm → ExecuteOp

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use ratatui::Frame;

use super::{ConfirmTarget, OpAction, OpContext, OpEnv};
use crate::media::{IsoFile, SessionEntry};
use anodize_hsm::Hsm as _;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignCsrPhase {
    /// Waiting for user to select a certificate profile.
    LoadCsr,
    /// Certificate preview — review before signing.
    CertPreview,
    /// Quorum phase — collecting SSS shares to reconstruct HSM PIN.
    Quorum,
    /// Clock re-confirm before signing.
    ClockReconfirm,
    /// Certificate preview — verify fingerprint before record burn.
    Execute,
}

pub struct SignCsrCtx {
    pub phase: SignCsrPhase,
    /// Raw CSR DER bytes (loaded from shuttle).
    pub csr_der: Vec<u8>,
    /// Root cert DER (for issuer preview).
    pub root_cert_der: Option<Vec<u8>>,
    /// Pre-formatted profile selection lines (one per profile).
    pub profile_lines: Vec<String>,
    /// Selected profile index (set when user picks [1]–[N]).
    pub selected_profile_idx: Option<usize>,
    /// Lines for the cert preview screen.
    pub cert_preview_lines: Vec<String>,
    pub share_input: Option<crate::components::share_input::ShareInput>,
    /// Signed certificate DER (populated by execute).
    pub cert_der: Option<Vec<u8>>,
    /// SHA-256 fingerprint of signed cert (populated by execute).
    pub fingerprint: Option<String>,
}

impl SignCsrCtx {
    /// Create from a validated CSR.  Called from `do_select_operation`.
    pub fn new(
        csr_der: Vec<u8>,
        root_cert_der: Option<Vec<u8>>,
        profile_lines: Vec<String>,
    ) -> Self {
        Self {
            phase: SignCsrPhase::LoadCsr,
            csr_der,
            root_cert_der,
            profile_lines,
            selected_profile_idx: None,
            cert_preview_lines: Vec::new(),
            share_input: None,
            cert_der: None,
            fingerprint: None,
        }
    }

    /// Select a cert profile, build the preview, and advance to CertPreview.
    fn select_profile(&mut self, idx: usize, shared: &mut OpEnv<'_>) -> OpAction {
        if idx >= self.profile_lines.len() {
            shared.set_status(format!(
                "Invalid profile number {}. Choose 1\u{2013}{}.",
                idx + 1,
                self.profile_lines.len(),
            ));
            return OpAction::Noop;
        }

        self.selected_profile_idx = Some(idx);

        if let Some(profile) = shared.profile {
            let prof = &profile.cert_profiles[idx];
            let cdp = profile.ca.cdp_url.as_deref();
            self.cert_preview_lines = crate::helpers::build_cert_preview(
                &self.csr_der,
                prof,
                &profile.ca.common_name,
                &profile.ca.organization,
                &profile.ca.country,
                cdp,
                self.root_cert_der.as_deref(),
            );
        }

        self.phase = SignCsrPhase::CertPreview;
        shared.set_status("Review certificate document. [1] to proceed, [Esc] to cancel.");
        OpAction::Noop
    }

    fn try_quorum_complete(&mut self, shared: &mut OpEnv<'_>) -> OpAction {
        let shares: Vec<anodize_sss::Share> = self
            .share_input
            .as_ref()
            .map(|si| si.collected.iter().map(|c| c.share.clone()).collect())
            .unwrap_or_default();
        self.share_input = None;
        match shared.quorum_complete(&shares) {
            Ok(()) => {
                self.phase = SignCsrPhase::ClockReconfirm;
                shared.set_status("Confirm system clock is correct before signing.");
                OpAction::Noop
            }
            Err(e) => {
                shared.set_status(e.to_string());
                OpAction::Abort
            }
        }
    }
}

impl OpContext for SignCsrCtx {
    fn phase_index(&self) -> usize {
        match self.phase {
            SignCsrPhase::LoadCsr | SignCsrPhase::CertPreview => 1,
            SignCsrPhase::Quorum | SignCsrPhase::ClockReconfirm => 3,
            SignCsrPhase::Execute => 4,
        }
    }

    fn title(&self) -> &str {
        match self.phase {
            SignCsrPhase::LoadCsr => "Select Certificate Profile",
            SignCsrPhase::CertPreview => "Certificate Review \u{2014} VERIFY BEFORE SIGNING",
            SignCsrPhase::Quorum => "Quorum \u{2014} Reconstruct PIN",
            SignCsrPhase::ClockReconfirm => "Clock Re-confirm \u{2014} Verify Before Signing",
            SignCsrPhase::Execute => "Certificate Preview \u{2014} VERIFY FINGERPRINT",
        }
    }

    fn build_body(&self) -> Vec<String> {
        match self.phase {
            SignCsrPhase::LoadCsr => {
                let mut lines = vec![
                    String::new(),
                    "  CSR loaded from USB (csr.der).".into(),
                    String::new(),
                    "  Select certificate profile:".into(),
                    String::new(),
                ];
                for line in &self.profile_lines {
                    lines.push(line.clone());
                }
                lines.push(String::new());
                lines.push("  [Esc]  Cancel".into());
                lines
            }
            SignCsrPhase::CertPreview => {
                let mut lines = self.cert_preview_lines.clone();
                lines.push("  The CSR DER bytes are recorded in the intent audit log.".into());
                lines.push(String::new());
                lines.push("  [1]  Sign CSR and write to disc".into());
                lines.push("  [Esc]  Cancel".into());
                lines
            }
            SignCsrPhase::Quorum => {
                vec![
                    String::new(),
                    "  Collecting threshold shares to reconstruct the HSM PIN.".into(),
                    String::new(),
                    "  The share input component is active.".into(),
                    "  [Esc]  Abort".into(),
                ]
            }
            SignCsrPhase::ClockReconfirm => {
                let now = time::OffsetDateTime::now_utc()
                    .replace_nanosecond(0)
                    .expect("0ns is always valid");
                let time_str = now
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_else(|_| "unknown".into());
                vec![
                    String::new(),
                    "  HSM unlocked. Before signing, confirm the system clock is correct.".into(),
                    String::new(),
                    format!("  Current time:  {time_str}"),
                    String::new(),
                    "  Certificates will be timestamped with this time.".into(),
                    "  If the clock is wrong, quit and correct it before proceeding.".into(),
                    String::new(),
                    "  [1]  Clock is correct \u{2014} proceed with signing".into(),
                    "  [Esc]  Abort".into(),
                ]
            }
            SignCsrPhase::Execute => {
                let fp = self.fingerprint.as_deref().unwrap_or("(none)");
                let (subject, validity_label) = self
                    .cert_der
                    .as_deref()
                    .and_then(crate::helpers::cert_subject_and_validity_days)
                    .map(|(subj, days)| (subj, format!("{days} days")))
                    .unwrap_or_else(|| ("(unknown)".into(), "unknown".into()));
                vec![
                    String::new(),
                    format!("  Subject  : {subject}"),
                    format!("  Validity : {validity_label}"),
                    String::new(),
                    "  SHA-256 Fingerprint:".into(),
                    format!("  {fp}"),
                    String::new(),
                    "  Compare this fingerprint against your paper checklist.".into(),
                    String::new(),
                    "  [1]  Proceed to disc write".into(),
                    "  [Esc]  Abort".into(),
                ]
            }
        }
    }

    fn handle_key(&mut self, key: KeyEvent, shared: &mut OpEnv<'_>) -> OpAction {
        match self.phase {
            SignCsrPhase::LoadCsr => match key.code {
                KeyCode::Esc => OpAction::Abort,
                KeyCode::Char(c) => {
                    if let Some(d) = c.to_digit(10) {
                        let idx = d as usize;
                        if idx >= 1 {
                            return self.select_profile(idx - 1, shared);
                        }
                    }
                    OpAction::Noop
                }
                _ => OpAction::Noop,
            },
            SignCsrPhase::CertPreview => match key.code {
                KeyCode::Char('1') => OpAction::ShowConfirm {
                    title: "Sign CSR".into(),
                    body: vec![
                        "This will sign the CSR using the HSM private key".into(),
                        "and write an intent+record session to disc.".into(),
                    ],
                    on_confirm: ConfirmTarget::WriteIntent,
                },
                KeyCode::Esc => OpAction::Abort,
                _ => OpAction::Noop,
            },
            SignCsrPhase::Quorum => {
                if let Some(ref mut si) = self.share_input {
                    si.handle_key(key);
                    if si.is_complete() {
                        return self.try_quorum_complete(shared);
                    }
                }
                OpAction::Noop
            }
            SignCsrPhase::ClockReconfirm => match key.code {
                KeyCode::Char('1') => {
                    *shared.confirmed_time = Some(std::time::SystemTime::now());
                    OpAction::ExecuteOp
                }
                KeyCode::Esc => OpAction::Abort,
                _ => OpAction::Noop,
            },
            SignCsrPhase::Execute => match key.code {
                KeyCode::Char('1') => OpAction::ShowConfirm {
                    title: "Write Record to Disc".into(),
                    body: vec![
                        format!(
                            "Fingerprint: {}",
                            self.fingerprint.as_deref().unwrap_or("?")
                        ),
                        "This will burn the intermediate cert to disc.".into(),
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
        !matches!(self.phase, SignCsrPhase::LoadCsr)
    }

    fn abort_confirm_body(&self) -> Vec<String> {
        match self.phase {
            SignCsrPhase::Execute => vec![
                "HSM session and partially-reconstructed PIN".into(),
                "will be discarded.".into(),
            ],
            _ => vec!["All ceremony progress will be lost.".into()],
        }
    }

    fn in_text_entry(&self) -> bool {
        matches!(self.phase, SignCsrPhase::Quorum | SignCsrPhase::Execute)
    }

    fn render_overlay(&self, frame: &mut Frame, area: Rect) {
        if let Some(ref input) = self.share_input {
            input.render(frame, area);
        }
    }

    fn execute(&mut self, shared: &mut OpEnv<'_>) -> OpAction {
        use crate::helpers::{
            collect_serial_numbers_from_sessions, mechanism_error_msg, sha256_fingerprint,
        };
        use anodize_ca::{sign_intermediate_csr, P384HsmSigner};
        use der::{Decode, Encode};
        use x509_cert::certificate::Certificate;

        let label = match shared.profile.map(|p| p.hsm.key_label.clone()) {
            Some(l) => l,
            None => return OpAction::SetStatus("No profile".into()),
        };
        let actor = match shared.hw.actor.clone() {
            Some(a) => a,
            None => return OpAction::SetStatus("No HSM session".into()),
        };
        let root_key = match actor.find_key(&label) {
            Ok(k) => k,
            Err(e) => return OpAction::SetStatus(format!("Root key not found: {e}")),
        };
        let signer = match P384HsmSigner::new(actor, root_key) {
            Ok(s) => s,
            Err(e) => return OpAction::SetStatus(format!("Signer error: {e}")),
        };

        let root_cert_der = match &self.root_cert_der {
            Some(d) => d.clone(),
            None => return OpAction::SetStatus("Root cert not loaded from disc".into()),
        };
        let root_cert = match Certificate::from_der(&root_cert_der) {
            Ok(c) => c,
            Err(e) => return OpAction::SetStatus(format!("Root cert DER decode failed: {e}")),
        };

        let csr_der = self.csr_der.clone();

        let (validity_days, path_len) = match shared
            .profile
            .and_then(|p| self.selected_profile_idx.map(|i| &p.cert_profiles[i]))
        {
            Some(prof) => (prof.validity_days, prof.path_len),
            None => return OpAction::SetStatus("No cert profile selected".into()),
        };

        let cdp_url = shared.profile.and_then(|p| p.ca.cdp_url.as_deref());
        let existing_serials = collect_serial_numbers_from_sessions(&shared.disc.prior_sessions);

        let cert = match sign_intermediate_csr(
            &signer,
            &root_cert,
            &csr_der,
            path_len,
            validity_days,
            cdp_url,
            &existing_serials,
        ) {
            Ok(c) => c,
            Err(anodize_ca::CaError::CsrSignatureInvalid) => {
                return OpAction::SetStatus(
                    "CSR signature verification failed \u{2014} CSR may be corrupt".into(),
                );
            }
            Err(anodize_ca::CaError::CsrAlgorithmUnsupported(alg)) => {
                return OpAction::SetStatus(format!(
                    "CSR uses unsupported signature algorithm ({alg}). \
                     Accepted: ECDSA P-256/SHA-256 or P-384/SHA-384."
                ));
            }
            Err(anodize_ca::CaError::CsrExtensionRejected(oid)) => {
                return OpAction::SetStatus(format!("CSR contains rejected extension OID: {oid}"));
            }
            Err(e) => {
                return OpAction::SetStatus(mechanism_error_msg("CSR signing failed", &e));
            }
        };

        let cert_der = match cert.to_der() {
            Ok(d) => d,
            Err(e) => return OpAction::SetStatus(format!("DER encode failed: {e}")),
        };

        let fp = sha256_fingerprint(&cert_der);
        self.fingerprint = Some(fp);
        self.cert_der = Some(cert_der);
        self.phase = SignCsrPhase::Execute;
        shared.set_status("Intermediate cert signed. Verify fingerprint before writing.");
        OpAction::Noop
    }

    fn build_intent_audit_event(
        &self,
        _genesis_hex: &str,
        shared: &OpEnv<'_>,
    ) -> Option<(String, serde_json::Value)> {
        let csr_hex = self
            .csr_der
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let profile_name = shared
            .profile
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

    fn build_record_session(
        &mut self,
        dir_name: String,
        ts: std::time::SystemTime,
        staging: &std::path::Path,
        shared: &mut OpEnv<'_>,
    ) -> Option<SessionEntry> {
        use anodize_audit::AuditLog;

        let cert_der = self.cert_der.clone()?;
        let log_path = staging.join("audit.log");
        let mut log = match AuditLog::open(&log_path) {
            Ok(l) => l,
            Err(e) => {
                shared.set_status(format!("Audit log reopen failed: {e}"));
                return None;
            }
        };
        let fp = self.fingerprint.clone().unwrap_or_default();
        let profile_name = shared
            .profile
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
                "intent_session": shared.disc.intent_session_dir_name.as_deref().unwrap_or(""),
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
            crate::media::write_and_sync(&shuttle.join("intermediate.crt"), cert_der)
                .map_err(|e| format!("Shuttle write failed (intermediate.crt): {e:#}"))?;
        }
        Ok(true)
    }

    fn advance_after_intent_burn(&mut self, shared: &mut OpEnv<'_>) {
        let sss_meta = match &shared.disc.session_state {
            Some(state) => state.sss.clone(),
            None => {
                shared.set_status("ERROR: no STATE.JSON loaded — cannot enter quorum.");
                return;
            }
        };
        self.share_input = Some(crate::components::share_input::ShareInput::new(
            sss_meta.clone(),
            32,
        ));
        self.phase = SignCsrPhase::Quorum;
        shared.set_status(format!(
            "Quorum: collect {}-of-{} shares to unlock HSM.",
            sss_meta.threshold, sss_meta.total,
        ));
    }
}
