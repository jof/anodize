//! ValidateDisc operation context.
//!
//! Validates the audit chain and session continuity of a ceremony disc,
//! optionally cross-checks the HSM audit log, and exports a report.

use std::collections::BTreeMap;

use anodize_audit::validate::{
    cross_check_hsm_log, format_report, validate_disc_status, validate_session_continuity,
    DiscStatus, Finding, HsmLogEntry, HsmLogSnapshot, SessionSnapshot, Severity, StateFields,
};
use anodize_hsm::Hsm;
use crossterm::event::{KeyCode, KeyEvent};
use sha2::{Digest, Sha256};

use super::{OpAction, OpContext, OpEnv};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidatePhase {
    Report,
    HsmResult,
}

pub struct ValidateCtx {
    pub phase: ValidatePhase,
    pub report_lines: Vec<String>,
    pub has_hsm: bool,
    pub findings: Vec<Finding>,
}

impl ValidateCtx {
    /// Run disc validation and return a populated context.
    pub fn run(shared: &OpEnv<'_>) -> Self {
        let mut findings: Vec<Finding> = Vec::new();

        // Build snapshots from prior sessions.
        let mut snapshots: Vec<SessionSnapshot> = Vec::new();
        for (i, sess) in shared.disc.prior_sessions.iter().enumerate() {
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
            let state = if let Some(ref s) = shared.disc.session_state {
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

        // Disc status check.
        let disc_status = if shared.disc.optical_dev.is_some() {
            DiscStatus::Incomplete
        } else {
            DiscStatus::Blank
        };
        findings.extend(validate_disc_status(disc_status));

        // Session continuity.
        findings.extend(validate_session_continuity(&snapshots));

        // Audit chain check (uses staging audit log if available).
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
        } else if !shared.skip_disc {
            findings.push(Finding {
                severity: Severity::Warn,
                check: "audit_chain".into(),
                message: "No staging audit log found".into(),
            });
        }

        let has_hsm = shared.hw.actor.is_some();
        let report = format_report(&findings);
        let report_lines = report.lines().map(String::from).collect();

        Self {
            phase: ValidatePhase::Report,
            report_lines,
            has_hsm,
            findings,
        }
    }

    fn do_hsm_check(&mut self, shared: &mut OpEnv<'_>) {
        let actor = match shared.hw.actor.as_ref() {
            Some(a) => a,
            None => {
                shared.set_status("No HSM session \u{2014} run quorum first.");
                return;
            }
        };

        match actor.get_audit_log() {
            Ok(snapshot) => {
                let hsm_snapshot = HsmLogSnapshot {
                    unlogged_boot_events: snapshot.unlogged_boot_events,
                    unlogged_auth_events: snapshot.unlogged_auth_events,
                    entries: snapshot
                        .entries
                        .iter()
                        .map(|e| HsmLogEntry {
                            item: e.item,
                            command: e.command,
                            session_key: e.session_key,
                            target_key: e.target_key,
                            second_key: e.second_key,
                            result: e.result,
                            tick: e.tick,
                            digest: e.digest,
                        })
                        .collect(),
                };

                let staging_log = std::path::PathBuf::from("/run/anodize/staging/audit.log");
                let disc_records: Vec<anodize_audit::Record> = if staging_log.exists() {
                    std::fs::read_to_string(&staging_log)
                        .unwrap_or_default()
                        .lines()
                        .filter_map(|line| serde_json::from_str(line).ok())
                        .collect()
                } else {
                    Vec::new()
                };

                let last_seq = shared
                    .disc
                    .session_state
                    .as_ref()
                    .and_then(|s| s.last_hsm_log_seq);

                let hsm_findings = cross_check_hsm_log(
                    &hsm_snapshot,
                    &disc_records,
                    0x0002, // ANODIZE_AUTH_KEY_ID
                    0x0100, // SIGNING_KEY_ID
                    last_seq,
                );
                self.findings.extend(hsm_findings);

                let report = format_report(&self.findings);
                self.report_lines = report.lines().map(String::from).collect();
                self.phase = ValidatePhase::HsmResult;
                shared.set_status("HSM audit log cross-check complete.");
            }
            Err(e) => {
                shared.set_status(format!("HSM audit log fetch failed: {e}"));
            }
        }
    }

    fn do_export_report(&self, shared: &mut OpEnv<'_>) -> bool {
        let validate_log = shared.shuttle_mount.join("VALIDATE.LOG");
        let report = format_report(&self.findings);

        match std::fs::write(&validate_log, report.as_bytes()) {
            Ok(()) => {
                shared.set_status(format!(
                    "VALIDATE.LOG written to {}",
                    validate_log.display()
                ));
                true
            }
            Err(e) => {
                shared.set_status(format!("Failed to write VALIDATE.LOG: {e}"));
                false
            }
        }
    }
}

impl OpContext for ValidateCtx {
    fn phase_index(&self) -> usize {
        1
    }

    fn title(&self) -> &str {
        match self.phase {
            ValidatePhase::Report => "Disc Validation Report",
            ValidatePhase::HsmResult => "HSM Audit Log Cross-Check",
        }
    }

    fn build_body(&self) -> Vec<String> {
        let mut lines = Vec::new();
        lines.push(String::new());
        for line in &self.report_lines {
            lines.push(format!("  {line}"));
        }
        lines.push(String::new());
        if self.phase == ValidatePhase::Report {
            if self.has_hsm {
                lines.push("  [1]  Run HSM audit log cross-check (requires quorum)".into());
            }
            lines.push("  [2]  Export VALIDATE.LOG to shuttle".into());
            lines.push("  [Esc]  Done".into());
        } else {
            lines.push("  [2]  Export VALIDATE.LOG to shuttle".into());
            lines.push("  [Esc]  Done".into());
        }
        lines
    }

    fn handle_key(&mut self, key: KeyEvent, shared: &mut OpEnv<'_>) -> OpAction {
        match key.code {
            KeyCode::Char('1') if self.phase == ValidatePhase::Report => {
                self.do_hsm_check(shared);
                OpAction::Noop
            }
            KeyCode::Char('2') => {
                if self.do_export_report(shared) {
                    OpAction::Done
                } else {
                    OpAction::Noop
                }
            }
            KeyCode::Esc => OpAction::Abort,
            _ => OpAction::Noop,
        }
    }

    fn holds_ephemeral_state(&self) -> bool {
        false
    }

    fn needs_abort_confirmation(&self) -> bool {
        false
    }

    fn in_text_entry(&self) -> bool {
        false
    }
}
