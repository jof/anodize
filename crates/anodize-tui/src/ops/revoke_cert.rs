//! RevokeCert operation context.
//!
//! Phases: RevokeSelect → RevokeInput → RevokePreview → (intent burn) →
//!         Quorum → ClockReconfirm → ExecuteOp

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use ratatui::Frame;

use super::{ConfirmTarget, OpAction, OpContext, OpEnv};
use crate::disc::CertSummary;
use crate::media::{IsoFile, SessionEntry};
use anodize_hsm::Hsm as _;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokeCertPhase {
    /// Certificate picker — choose which cert to revoke.
    RevokeSelect,
    /// Serial / reason text input.
    RevokeInput,
    /// Review revocation list before committing.
    RevokePreview,
    /// Quorum phase — collecting SSS shares to reconstruct HSM PIN.
    Quorum,
    /// Clock re-confirm before signing.
    ClockReconfirm,
}

pub struct RevokeCertCtx {
    pub phase: RevokeCertPhase,
    pub revocation_list: Vec<anodize_config::RevocationEntry>,
    pub crl_number: Option<u64>,
    /// Root cert DER (for issuer when signing CRL).
    pub root_cert_der: Option<Vec<u8>>,
    /// Signed CRL DER (populated by execute).
    pub crl_der: Option<Vec<u8>>,
    // RevokeSelect state
    pub cert_list: Vec<CertSummary>,
    pub cursor: usize,
    // RevokeInput state (0 = serial entry, 1 = reason entry)
    pub input_phase: u8,
    pub serial_buf: String,
    pub reason_buf: String,
    pub share_input: Option<crate::components::share_input::ShareInput>,
}

impl RevokeCertCtx {
    /// Create from loaded disc data.  Called from `do_select_operation`.
    pub fn new(
        revocation_list: Vec<anodize_config::RevocationEntry>,
        crl_number: Option<u64>,
        cert_list: Vec<CertSummary>,
        root_cert_der: Option<Vec<u8>>,
    ) -> Self {
        Self {
            phase: RevokeCertPhase::RevokeSelect,
            revocation_list,
            crl_number,
            root_cert_der,
            crl_der: None,
            cert_list,
            cursor: 0,
            input_phase: 0,
            serial_buf: String::new(),
            reason_buf: String::new(),
            share_input: None,
        }
    }

    /// Validate and add the revocation entry, then advance to RevokePreview.
    fn add_revocation_entry(&mut self, shared: &mut OpEnv<'_>) -> OpAction {
        let serial = self.serial_buf.to_uppercase();
        if serial.is_empty() || !serial.chars().all(|c| c.is_ascii_hexdigit()) {
            shared.set_status(format!(
                "Invalid serial number: {:?}. Must be hex digits.",
                self.serial_buf,
            ));
            return OpAction::Noop;
        }

        if self.revocation_list.iter().any(|e| e.serial == serial) {
            shared.set_status(format!(
                "Serial {serial} is already in the revocation list — duplicate not added."
            ));
            return OpAction::Noop;
        }

        let reason = if self.reason_buf.is_empty() {
            None
        } else {
            Some(self.reason_buf.clone())
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

        self.revocation_list.push(anodize_config::RevocationEntry {
            serial,
            revocation_time: rev_time,
            reason,
        });

        self.phase = RevokeCertPhase::RevokePreview;
        shared.set_status("Review revocation. [1] to commit to disc, [Esc] to cancel.");
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
                self.phase = RevokeCertPhase::ClockReconfirm;
                shared.set_status("Confirm system clock is correct before signing.");
                OpAction::Noop
            }
            Err(e) => {
                shared.set_status(format!("{e}"));
                OpAction::Abort
            }
        }
    }
}

impl OpContext for RevokeCertCtx {
    fn phase_index(&self) -> usize {
        match self.phase {
            RevokeCertPhase::RevokeSelect
            | RevokeCertPhase::RevokeInput
            | RevokeCertPhase::RevokePreview => 1,
            RevokeCertPhase::Quorum | RevokeCertPhase::ClockReconfirm => 3,
        }
    }

    fn title(&self) -> &str {
        match self.phase {
            RevokeCertPhase::RevokeSelect => "Revoke Certificate \u{2014} Select Certificate",
            RevokeCertPhase::RevokeInput => "Revoke Certificate",
            RevokeCertPhase::RevokePreview => {
                "Revocation Preview \u{2014} VERIFY BEFORE COMMITTING"
            }
            RevokeCertPhase::Quorum => "Quorum \u{2014} Reconstruct PIN",
            RevokeCertPhase::ClockReconfirm => "Clock Re-confirm \u{2014} Verify Before Signing",
        }
    }

    fn build_body(&self) -> Vec<String> {
        match self.phase {
            RevokeCertPhase::RevokeSelect => {
                let rev_count = self.revocation_list.len();
                let mut lines = vec![
                    String::new(),
                    format!(
                        "  {} certificate(s) on disc, {} revoked.",
                        self.cert_list.len(),
                        rev_count,
                    ),
                    String::new(),
                    "  Select a certificate to revoke:".into(),
                    String::new(),
                ];
                for (i, c) in self.cert_list.iter().enumerate() {
                    let selected = i == self.cursor;
                    let marker = if selected { ">" } else { " " };
                    let status = if c.already_revoked {
                        "(revoked)"
                    } else if c.is_root {
                        "root"
                    } else {
                        "active"
                    };
                    lines.push(format!(
                        " {marker} [{:>2}] Serial: {}  Status: {}",
                        i + 1,
                        c.serial,
                        status,
                    ));
                    for part in c.subject.split(", ") {
                        lines.push(format!("        {part}"));
                    }
                    lines.push(format!("        Expires: {}", c.not_after));
                    lines.push(String::new());
                }
                if self.cert_list.is_empty() {
                    lines.push("  (No certificates found on disc.)".into());
                }
                lines.push(
                    "  [j/k] navigate  [Enter] select  [m] manual serial  [Esc] cancel".into(),
                );
                lines
            }

            RevokeCertPhase::RevokeInput => {
                let phase_hint = if self.input_phase == 0 {
                    "Enter serial number (hex):"
                } else {
                    "Enter reason (optional, press Enter to skip):"
                };
                vec![
                    String::new(),
                    format!(
                        "  {} revoked cert(s) on record.",
                        self.revocation_list.len(),
                    ),
                    String::new(),
                    format!("  {phase_hint}"),
                    String::new(),
                    format!("  Serial : {}", self.serial_buf),
                    format!("  Reason : {}", self.reason_buf),
                    String::new(),
                    "  Enter to confirm each field. Esc to go back.".into(),
                ]
            }

            RevokeCertPhase::RevokePreview => {
                let crl_num = self.crl_number.unwrap_or(0);
                let mut lines = vec![
                    String::new(),
                    format!("  New CRL number: {crl_num}"),
                    String::new(),
                    "  Updated revocation list:".into(),
                    String::new(),
                ];
                for entry in &self.revocation_list {
                    let reason = entry.reason.as_deref().unwrap_or("(no reason)");
                    lines.push(format!(
                        "    serial={}  time={}  reason={}",
                        entry.serial, entry.revocation_time, reason
                    ));
                }
                lines.push(String::new());
                lines.push("  [1]  Sign CRL and write to disc".into());
                lines.push("  [Esc]  Cancel".into());
                lines
            }

            RevokeCertPhase::Quorum => {
                vec![
                    String::new(),
                    "  Collecting threshold shares to reconstruct the HSM PIN.".into(),
                    String::new(),
                    "  The share input component is active.".into(),
                    "  [Esc]  Abort".into(),
                ]
            }

            RevokeCertPhase::ClockReconfirm => {
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
                    "  [1]  Clock is correct \u{2014} proceed with signing".into(),
                    "  [Esc]  Abort".into(),
                ]
            }
        }
    }

    fn handle_key(&mut self, key: KeyEvent, shared: &mut OpEnv<'_>) -> OpAction {
        match self.phase {
            RevokeCertPhase::RevokeSelect => match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    if self.cursor > 0 {
                        self.cursor -= 1;
                    }
                    OpAction::Noop
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if !self.cert_list.is_empty() && self.cursor < self.cert_list.len() - 1 {
                        self.cursor += 1;
                    }
                    OpAction::Noop
                }
                KeyCode::Enter => {
                    if let Some(cert) = self.cert_list.get(self.cursor) {
                        if cert.already_revoked {
                            shared
                                .set_status(format!("Serial {} is already revoked.", cert.serial,));
                            return OpAction::Noop;
                        }
                        self.serial_buf = cert.serial.clone();
                        self.reason_buf.clear();
                        self.input_phase = 1;
                        self.phase = RevokeCertPhase::RevokeInput;
                        shared.set_status(
                            "Serial pre-filled. Enter reason (optional, Enter to skip).",
                        );
                    }
                    OpAction::Noop
                }
                KeyCode::Char('m') => {
                    self.serial_buf.clear();
                    self.reason_buf.clear();
                    self.input_phase = 0;
                    self.phase = RevokeCertPhase::RevokeInput;
                    shared.set_status(
                        "Enter certificate serial number (hex). Press Enter to continue.",
                    );
                    OpAction::Noop
                }
                KeyCode::Esc => OpAction::Abort,
                _ => OpAction::Noop,
            },

            RevokeCertPhase::RevokeInput => match key.code {
                KeyCode::Char(c) => {
                    if self.input_phase == 0 && c.is_ascii_hexdigit() {
                        self.serial_buf.push(c);
                    } else if self.input_phase == 1 {
                        self.reason_buf.push(c);
                    }
                    OpAction::Noop
                }
                KeyCode::Backspace => {
                    if self.input_phase == 0 {
                        self.serial_buf.pop();
                    } else {
                        self.reason_buf.pop();
                    }
                    OpAction::Noop
                }
                KeyCode::Enter => {
                    if self.input_phase == 0 && !self.serial_buf.is_empty() {
                        self.input_phase = 1;
                        shared.set_status("Reason (optional, Enter to skip): e.g. key-compromise");
                        OpAction::Noop
                    } else {
                        self.add_revocation_entry(shared)
                    }
                }
                KeyCode::Esc => {
                    if self.input_phase == 0 {
                        self.phase = RevokeCertPhase::RevokeSelect;
                        shared.set_status("Revocation cancelled.");
                    } else {
                        self.input_phase = 0;
                        shared.set_status("Enter certificate serial number (digits). Press Enter.");
                    }
                    OpAction::Noop
                }
                _ => OpAction::Noop,
            },

            RevokeCertPhase::RevokePreview => match key.code {
                KeyCode::Char('1') => OpAction::ShowConfirm {
                    title: "Revoke and Sign CRL".into(),
                    body: vec![
                        "This will sign a new CRL using the HSM private key".into(),
                        "and write an intent+record session to disc.".into(),
                    ],
                    on_confirm: ConfirmTarget::WriteIntent,
                },
                KeyCode::Esc => OpAction::Abort,
                _ => OpAction::Noop,
            },

            RevokeCertPhase::Quorum => {
                if let Some(ref mut si) = self.share_input {
                    si.handle_key(key);
                    if si.is_complete() {
                        return self.try_quorum_complete(shared);
                    }
                }
                OpAction::Noop
            }

            RevokeCertPhase::ClockReconfirm => match key.code {
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
        !matches!(self.phase, RevokeCertPhase::RevokeSelect)
    }

    fn in_text_entry(&self) -> bool {
        matches!(
            self.phase,
            RevokeCertPhase::RevokeInput | RevokeCertPhase::Quorum
        )
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
        let serial_hex = self.serial_buf.to_uppercase();
        let reason = if self.reason_buf.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::Value::String(self.reason_buf.clone())
        };
        Some((
            "cert.revoke.intent".into(),
            serde_json::json!({
                "operation": "revoke-and-issue-crl",
                "serial_hex": serial_hex,
                "reason": reason,
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
        use anodize_config::serialize_revocation_list;

        let crl_der = self.crl_der.clone()?;
        let revoked_toml = serialize_revocation_list(&self.revocation_list).into_bytes();
        let crl_number = self.crl_number.unwrap_or(0);

        let log_path = staging.join("audit.log");
        let mut log = match AuditLog::open(&log_path) {
            Ok(l) => l,
            Err(e) => {
                shared.set_status(format!("Audit log reopen failed: {e}"));
                return None;
            }
        };
        let serial: u64 = self.serial_buf.parse().unwrap_or(0);
        let reason = if self.reason_buf.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::Value::String(self.reason_buf.clone())
        };
        if let Err(e) = log.append(
            "cert.revoke",
            serde_json::json!({
                "serial": serial,
                "reason": reason,
                "intent_session": shared.disc.intent_session_dir_name.as_deref().unwrap_or(""),
            }),
        ) {
            shared.set_status(format!("Audit log append failed: {e}"));
            return None;
        }
        if let Err(e) = log.append(
            "crl.issue",
            serde_json::json!({
                "crl_number": crl_number,
                "revocation_count": self.revocation_list.len(),
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

        shared.update_session_state_for_record(
            &audit_bytes,
            self.crl_number,
            &self.revocation_list,
        );
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
        let revoked_toml = anodize_config::serialize_revocation_list(&self.revocation_list);
        crate::media::write_and_sync(&shuttle.join("revoked.toml"), revoked_toml.as_bytes())
            .map_err(|e| format!("Shuttle write failed (revoked.toml): {e:#}"))?;
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
        self.phase = RevokeCertPhase::Quorum;
        shared.set_status(format!(
            "Quorum: collect {}-of-{} shares to unlock HSM.",
            sss_meta.threshold, sss_meta.total,
        ));
    }
}
