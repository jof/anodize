//! IssueCrl operation context.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use ratatui::Frame;

use super::{ConfirmTarget, OpAction, OpContext, OpEnv};
use crate::media::{IsoFile, SessionEntry};
use anodize_hsm::Hsm as _;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssueCrlPhase {
    CrlPreview,
    Quorum,
    ClockReconfirm,
}

pub struct IssueCrlCtx {
    pub phase: IssueCrlPhase,
    pub revocation_list: Vec<anodize_config::RevocationEntry>,
    pub crl_number: Option<u64>,
    /// Root cert DER (for issuer when signing CRL).
    pub root_cert_der: Option<Vec<u8>>,
    /// Signed CRL DER (populated by execute).
    pub crl_der: Option<Vec<u8>>,
    pub share_input: Option<crate::components::share_input::ShareInput>,
}

impl IssueCrlCtx {
    pub fn new(
        revocation_list: Vec<anodize_config::RevocationEntry>,
        crl_number: Option<u64>,
        root_cert_der: Option<Vec<u8>>,
    ) -> Self {
        Self {
            phase: IssueCrlPhase::CrlPreview,
            revocation_list,
            crl_number,
            root_cert_der,
            crl_der: None,
            share_input: None,
        }
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
                self.phase = IssueCrlPhase::ClockReconfirm;
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

impl OpContext for IssueCrlCtx {
    fn phase_index(&self) -> usize {
        match self.phase {
            IssueCrlPhase::CrlPreview => 1,
            IssueCrlPhase::Quorum | IssueCrlPhase::ClockReconfirm => 3,
        }
    }

    fn title(&self) -> &str {
        match self.phase {
            IssueCrlPhase::CrlPreview => "CRL Issuance Preview",
            IssueCrlPhase::Quorum => "Quorum \u{2014} Reconstruct PIN",
            IssueCrlPhase::ClockReconfirm => "Clock Re-confirm \u{2014} Verify Before Signing",
        }
    }

    fn build_body(&self) -> Vec<String> {
        match self.phase {
            IssueCrlPhase::CrlPreview => {
                let crl_num = self.crl_number.unwrap_or(0);
                let count = self.revocation_list.len();
                let mut lines = vec![
                    String::new(),
                    format!("  CRL number      : {crl_num}"),
                    format!("  Revoked entries : {count}"),
                    String::new(),
                ];
                if count == 0 {
                    lines.push("  (No certificates have been revoked.)".into());
                } else {
                    for entry in &self.revocation_list {
                        let reason = entry.reason.as_deref().unwrap_or("(no reason)");
                        lines.push(format!(
                            "    serial={}  time={}  reason={}",
                            entry.serial, entry.revocation_time, reason
                        ));
                    }
                }
                lines.push(String::new());
                lines.push("  [1]  Sign CRL and write to disc".into());
                lines.push("  [Esc]  Cancel".into());
                lines
            }
            IssueCrlPhase::Quorum => {
                vec![
                    String::new(),
                    "  Collecting threshold shares to reconstruct the HSM PIN.".into(),
                    String::new(),
                    "  The share input component is active.".into(),
                    "  [Esc]  Abort".into(),
                ]
            }
            IssueCrlPhase::ClockReconfirm => {
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
        }
    }

    fn handle_key(&mut self, key: KeyEvent, shared: &mut OpEnv<'_>) -> OpAction {
        match self.phase {
            IssueCrlPhase::CrlPreview => match key.code {
                KeyCode::Char('1') => OpAction::ShowConfirm {
                    title: "Sign and Write CRL".into(),
                    body: vec![
                        "This will sign the CRL using the HSM private key".into(),
                        "and write an intent+record session to disc.".into(),
                    ],
                    on_confirm: ConfirmTarget::WriteIntent,
                },
                KeyCode::Esc => OpAction::Abort,
                _ => OpAction::Noop,
            },
            IssueCrlPhase::Quorum => {
                if let Some(ref mut si) = self.share_input {
                    si.handle_key(key);
                    if si.is_complete() {
                        return self.try_quorum_complete(shared);
                    }
                }
                OpAction::Noop
            }
            IssueCrlPhase::ClockReconfirm => match key.code {
                KeyCode::Char('1') => {
                    *shared.confirmed_time = Some(std::time::SystemTime::now());
                    OpAction::ExecuteOp
                }
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
        matches!(self.phase, IssueCrlPhase::Quorum)
    }

    fn render_overlay(&self, frame: &mut Frame, area: Rect) {
        if let Some(ref input) = self.share_input {
            input.render(frame, area);
        }
    }

    fn execute(&mut self, shared: &mut OpEnv<'_>) -> OpAction {
        use crate::helpers::{
            hex_serial_to_bytes, mechanism_error_msg, parse_rfc3339_to_system_time,
        };
        use anodize_ca::{issue_crl, P384HsmSigner};
        use der::Decode;
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
            None => return OpAction::SetStatus("Root cert not on disc".into()),
        };
        let root_cert = match Certificate::from_der(&root_cert_der) {
            Ok(c) => c,
            Err(e) => return OpAction::SetStatus(format!("Root cert DER decode: {e}")),
        };

        let crl_number = match self.crl_number {
            Some(n) => n,
            None => return OpAction::SetStatus("CRL number not determined".into()),
        };

        let revoked: Vec<(
            x509_cert::serial_number::SerialNumber,
            std::time::SystemTime,
            Option<anodize_ca::CrlReason>,
        )> = self
            .revocation_list
            .iter()
            .filter_map(|e| {
                let serial_bytes = hex_serial_to_bytes(&e.serial)?;
                let sn = x509_cert::serial_number::SerialNumber::new(&serial_bytes).ok()?;
                let t = parse_rfc3339_to_system_time(&e.revocation_time)
                    .unwrap_or_else(std::time::SystemTime::now);
                let reason = e
                    .reason
                    .as_deref()
                    .map(anodize_ca::reason_str_to_crl_reason);
                Some((sn, t, reason))
            })
            .collect();

        let base_time = shared
            .confirmed_time
            .unwrap_or_else(std::time::SystemTime::now);
        let next_update = base_time + std::time::Duration::from_secs(365 * 24 * 3600);

        let crl_der = match issue_crl(&signer, &root_cert, &revoked, next_update, crl_number) {
            Ok(d) => d,
            Err(e) => return OpAction::SetStatus(mechanism_error_msg("CRL signing failed", &e)),
        };

        self.crl_der = Some(crl_der);
        OpAction::StartRecordBurn
    }

    fn build_intent_audit_event(
        &self,
        _genesis_hex: &str,
        _shared: &OpEnv<'_>,
    ) -> Option<(String, serde_json::Value)> {
        Some((
            "crl.intent".into(),
            serde_json::json!({
                "operation": "issue-crl",
                "crl_number": self.crl_number.unwrap_or(0),
                "revocation_count": self.revocation_list.len(),
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

        let crl_der = self.crl_der.clone()?;
        let crl_number = self.crl_number.unwrap_or(0);

        let log_path = staging.join("audit.log");
        let mut log = match AuditLog::open(&log_path) {
            Ok(l) => l,
            Err(e) => {
                shared.set_status(format!("Audit log reopen failed: {e}"));
                return None;
            }
        };
        if let Err(e) = log.append(
            "crl.issue",
            serde_json::json!({
                "crl_number": crl_number,
                "revocation_count": self.revocation_list.len(),
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

        shared.update_session_state_for_record(
            &audit_bytes,
            self.crl_number,
            &self.revocation_list,
        );
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
        if let Some(ref crl_der) = self.crl_der {
            crate::media::write_and_sync(&shuttle.join("root.crl"), crl_der)
                .map_err(|e| format!("Shuttle write failed (root.crl): {e:#}"))?;
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
        self.phase = IssueCrlPhase::Quorum;
        shared.set_status(format!(
            "Quorum: collect {}-of-{} shares to unlock HSM.",
            sss_meta.threshold, sss_meta.total,
        ));
    }
}
