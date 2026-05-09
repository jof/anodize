//! Disc validation logic for the Disc Validator ceremony phase.
//!
//! Pure functions that take parsed session data and return findings.
//! No HSM dependency — HSM cross-checks live in [`cross_check_hsm_log`].

use std::collections::BTreeMap;
use std::fmt;

use crate::{compute_entry_hash, Record};

// ── Finding types ──────────────────────────────────────────────────────────

/// Severity level for a validation finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Pass,
    Warn,
    Error,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Pass => write!(f, "PASS"),
            Severity::Warn => write!(f, "WARN"),
            Severity::Error => write!(f, "ERROR"),
        }
    }
}

/// A single validation finding.
#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: Severity,
    pub check: String,
    pub message: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.severity, self.check, self.message)
    }
}

// ── Input types ────────────────────────────────────────────────────────────

/// Parsed snapshot of a single disc session's contents.
#[derive(Debug, Clone)]
pub struct SessionSnapshot {
    /// 0-indexed session number on disc.
    pub index: usize,
    /// File names → SHA-256 content hashes for this session's directory.
    pub file_hashes: BTreeMap<String, String>,
    /// Parsed audit log records from this session's `AUDIT.LOG`.
    pub audit_records: Vec<Record>,
    /// Fields extracted from this session's `STATE.JSON`.
    pub state: StateFields,
}

/// Subset of `SessionState` fields needed for validation.
/// Avoids a dependency on `anodize-config`.
#[derive(Debug, Clone)]
pub struct StateFields {
    pub root_cert_sha256: String,
    pub crl_number: u64,
    pub last_audit_hash: String,
    pub last_hsm_log_seq: Option<u64>,
    /// True if this session contains a `MIGRATION.JSON` marker.
    pub is_migration: bool,
}

/// Disc-level status, mirroring `media::DiscStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscStatus {
    Blank,
    Incomplete,
    Complete,
    Other(u8),
}

// ── HSM audit log types (backend-agnostic) ─────────────────────────────────

/// A single entry from the HSM's internal audit log.
#[derive(Debug, Clone)]
pub struct HsmLogEntry {
    /// Monotonic command sequence number.
    pub item: u16,
    /// Command code (e.g. 0x56 = SignEcdsa).
    pub command: u8,
    /// Auth key ID used for the session that issued this command.
    pub session_key: u16,
    /// Target object ID affected by the command.
    pub target_key: u16,
    /// Secondary key ID (e.g. wrap key for export/import).
    pub second_key: u16,
    /// Result code (success or error).
    pub result: u8,
    /// HSM systick at command execution.
    pub tick: u32,
    /// 16-byte truncated SHA-256 digest chain.
    pub digest: [u8; 16],
}

/// Snapshot of the HSM audit log as returned by `get_log_entries`.
#[derive(Debug, Clone)]
pub struct HsmLogSnapshot {
    pub unlogged_boot_events: u16,
    pub unlogged_auth_events: u16,
    pub entries: Vec<HsmLogEntry>,
}

/// Well-known YubiHSM command codes used by anodize.
pub mod hsm_commands {
    pub const CREATE_SESSION: u8 = 0x03;
    pub const AUTHENTICATE_SESSION: u8 = 0x04;
    pub const DEVICE_INFO: u8 = 0x06;
    pub const PUT_AUTHENTICATION_KEY: u8 = 0x44;
    pub const GENERATE_ASYMMETRIC_KEY: u8 = 0x46;
    pub const EXPORT_WRAPPED: u8 = 0x4a;
    pub const IMPORT_WRAPPED: u8 = 0x4b;
    pub const PUT_WRAP_KEY: u8 = 0x4c;
    pub const GET_LOG_ENTRIES: u8 = 0x4d;
    pub const GET_OBJECT_INFO: u8 = 0x4e;
    pub const SET_OPTION: u8 = 0x4f;
    pub const GET_PSEUDO_RANDOM: u8 = 0x51;
    pub const GET_PUBLIC_KEY: u8 = 0x54;
    pub const SIGN_ECDSA: u8 = 0x56;
    pub const DELETE_OBJECT: u8 = 0x58;
    pub const CHANGE_AUTHENTICATION_KEY: u8 = 0x6c;

    /// Commands that anodize is expected to issue.
    pub const EXPECTED: &[u8] = &[
        CREATE_SESSION,
        AUTHENTICATE_SESSION,
        DEVICE_INFO,
        PUT_AUTHENTICATION_KEY,
        GENERATE_ASYMMETRIC_KEY,
        EXPORT_WRAPPED,
        IMPORT_WRAPPED,
        PUT_WRAP_KEY,
        GET_LOG_ENTRIES,
        GET_OBJECT_INFO,
        SET_OPTION,
        GET_PSEUDO_RANDOM,
        GET_PUBLIC_KEY,
        SIGN_ECDSA,
        DELETE_OBJECT,
        CHANGE_AUTHENTICATION_KEY,
    ];
}

// ── Validation functions ───────────────────────────────────────────────────

/// Check that the disc is not finalized (must remain appendable).
pub fn validate_disc_status(status: DiscStatus) -> Vec<Finding> {
    let mut findings = Vec::new();
    match status {
        DiscStatus::Incomplete => {
            findings.push(Finding {
                severity: Severity::Pass,
                check: "disc.finalization".into(),
                message: "Disc is appendable (not finalized)".into(),
            });
        }
        DiscStatus::Complete => {
            findings.push(Finding {
                severity: Severity::Error,
                check: "disc.finalization".into(),
                message: "Disc has been finalized — no further sessions can be appended".into(),
            });
        }
        DiscStatus::Blank => {
            findings.push(Finding {
                severity: Severity::Error,
                check: "disc.finalization".into(),
                message: "Disc is blank — no sessions present".into(),
            });
        }
        DiscStatus::Other(v) => {
            findings.push(Finding {
                severity: Severity::Warn,
                check: "disc.finalization".into(),
                message: format!("Unexpected disc status byte: 0x{v:02x}"),
            });
        }
    }
    findings
}

/// Verify that each session builds upon the prior without hiding information.
pub fn validate_session_continuity(sessions: &[SessionSnapshot]) -> Vec<Finding> {
    let mut findings = Vec::new();

    if sessions.is_empty() {
        findings.push(Finding {
            severity: Severity::Error,
            check: "session.count".into(),
            message: "No sessions found on disc".into(),
        });
        return findings;
    }

    findings.push(Finding {
        severity: Severity::Pass,
        check: "session.count".into(),
        message: format!("{} session(s) found", sessions.len()),
    });

    for i in 1..sessions.len() {
        let prev = &sessions[i - 1];
        let curr = &sessions[i];
        let check = format!("session.continuity[{}→{}]", i - 1, i);

        // Every file from the prior session must exist in the current session
        // with identical content.  AUDIT.LOG and STATE.JSON are exempt from
        // the content check — they legitimately grow/change between session
        // directories and are verified separately by validate_audit_chain
        // and the state-field checks above.
        const MUTABLE_FILES: &[&str] = &["AUDIT.LOG", "STATE.JSON"];
        let mut missing: Vec<String> = Vec::new();
        let mut changed: Vec<String> = Vec::new();
        for (name, prev_hash) in &prev.file_hashes {
            match curr.file_hashes.get(name) {
                None => missing.push(name.clone()),
                Some(curr_hash)
                    if curr_hash != prev_hash
                        && !MUTABLE_FILES.iter().any(|m| name.eq_ignore_ascii_case(m)) =>
                {
                    changed.push(name.clone())
                }
                _ => {}
            }
        }

        if missing.is_empty() && changed.is_empty() {
            findings.push(Finding {
                severity: Severity::Pass,
                check: check.clone(),
                message: format!(
                    "Session {i} is a superset of session {} ({} files → {} files, content verified)",
                    i - 1,
                    prev.file_hashes.len(),
                    curr.file_hashes.len()
                ),
            });
        } else {
            if !missing.is_empty() {
                findings.push(Finding {
                    severity: Severity::Error,
                    check: check.clone(),
                    message: format!(
                        "Session {i} is missing {} file(s) from session {}: {:?}",
                        missing.len(),
                        i - 1,
                        missing
                    ),
                });
            }
            if !changed.is_empty() {
                findings.push(Finding {
                    severity: Severity::Error,
                    check: check.clone(),
                    message: format!(
                        "Session {i} has {} file(s) with changed content vs session {}: {:?}",
                        changed.len(),
                        i - 1,
                        changed
                    ),
                });
            }
        }

        // root_cert_sha256 must not change across sessions.
        if prev.state.root_cert_sha256 != curr.state.root_cert_sha256 {
            findings.push(Finding {
                severity: Severity::Error,
                check: format!("session.root_cert[{}→{}]", i - 1, i),
                message: format!(
                    "root_cert_sha256 changed between sessions {} and {}",
                    i - 1,
                    i
                ),
            });
        }

        // CRL number must not go backwards.
        if curr.state.crl_number < prev.state.crl_number {
            findings.push(Finding {
                severity: Severity::Error,
                check: format!("session.crl_number[{}→{}]", i - 1, i),
                message: format!(
                    "CRL number decreased from {} to {} between sessions {} and {}",
                    prev.state.crl_number,
                    curr.state.crl_number,
                    i - 1,
                    i
                ),
            });
        }
    }

    // Handle migration: session 0 may be a migration from a prior disc.
    if sessions[0].state.is_migration {
        findings.push(Finding {
            severity: Severity::Pass,
            check: "session.migration".into(),
            message: "Session 0 is a migration from a prior disc".into(),
        });
    }

    findings
}

/// Verify the audit log hash chain across all sessions.
pub fn validate_audit_chain(sessions: &[SessionSnapshot]) -> Vec<Finding> {
    let mut findings = Vec::new();

    if sessions.is_empty() {
        return findings;
    }

    // Check each session's audit log individually.
    for session in sessions {
        let check = format!("audit.chain[session {}]", session.index);

        if session.audit_records.is_empty() {
            findings.push(Finding {
                severity: Severity::Error,
                check,
                message: "Audit log is empty".into(),
            });
            continue;
        }

        let mut ok = true;
        for (j, record) in session.audit_records.iter().enumerate() {
            if record.seq != j as u64 {
                findings.push(Finding {
                    severity: Severity::Error,
                    check: check.clone(),
                    message: format!(
                        "Sequence mismatch at position {j}: expected seq {j}, got {}",
                        record.seq
                    ),
                });
                ok = false;
                break;
            }

            let expected = compute_entry_hash(
                record.seq,
                &record.timestamp,
                &record.event,
                &record.op_data,
                &record.prev_hash,
            );
            if expected != record.entry_hash {
                findings.push(Finding {
                    severity: Severity::Error,
                    check: check.clone(),
                    message: format!(
                        "Hash chain broken at seq {}: expected {}, got {}",
                        record.seq, expected, record.entry_hash
                    ),
                });
                ok = false;
                break;
            }
        }

        if ok {
            findings.push(Finding {
                severity: Severity::Pass,
                check: check.clone(),
                message: format!("Hash chain valid ({} records)", session.audit_records.len()),
            });
        }

        // Cross-check last_audit_hash in STATE.JSON.
        if let Some(last) = session.audit_records.last() {
            if last.entry_hash == session.state.last_audit_hash {
                findings.push(Finding {
                    severity: Severity::Pass,
                    check: format!("audit.state_hash[session {}]", session.index),
                    message: "STATE.JSON last_audit_hash matches log tail".into(),
                });
            } else {
                findings.push(Finding {
                    severity: Severity::Error,
                    check: format!("audit.state_hash[session {}]", session.index),
                    message: format!(
                        "STATE.JSON last_audit_hash ({}) != log tail ({})",
                        session.state.last_audit_hash, last.entry_hash
                    ),
                });
            }
        }
    }

    // Verify that each later session's audit log is a strict superset of the prior.
    for i in 1..sessions.len() {
        let prev = &sessions[i - 1];
        let curr = &sessions[i];
        let check = format!("audit.superset[{}→{}]", i - 1, i);

        if curr.audit_records.len() < prev.audit_records.len() {
            findings.push(Finding {
                severity: Severity::Error,
                check,
                message: format!(
                    "Session {i} has fewer audit records ({}) than session {} ({})",
                    curr.audit_records.len(),
                    i - 1,
                    prev.audit_records.len()
                ),
            });
            continue;
        }

        // The first N records of `curr` must be identical to `prev`.
        let mut prefix_ok = true;
        for (j, (p, c)) in prev
            .audit_records
            .iter()
            .zip(curr.audit_records.iter())
            .enumerate()
        {
            if p != c {
                findings.push(Finding {
                    severity: Severity::Error,
                    check: check.clone(),
                    message: format!(
                        "Session {i} audit record {j} differs from session {}",
                        i - 1
                    ),
                });
                prefix_ok = false;
                break;
            }
        }

        if prefix_ok {
            let new_count = curr.audit_records.len() - prev.audit_records.len();
            findings.push(Finding {
                severity: Severity::Pass,
                check,
                message: format!(
                    "Session {i} audit log is a superset of session {} ({new_count} new record(s))",
                    i - 1
                ),
            });
        }
    }

    findings
}

/// Cross-check the YubiHSM internal audit log against the disc audit log.
///
/// `anodize_auth_key_id` is the auth key ID used by anodize (typically 2).
/// `signing_key_id` is the object ID of the ceremony signing key (typically 0x0100).
pub fn cross_check_hsm_log(
    hsm_log: &HsmLogSnapshot,
    disc_records: &[Record],
    anodize_auth_key_id: u16,
    signing_key_id: u16,
    last_known_seq: Option<u64>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for unlogged events (ring buffer overflow).
    if hsm_log.unlogged_boot_events > 0 {
        findings.push(Finding {
            severity: Severity::Error,
            check: "hsm.unlogged_boots".into(),
            message: format!(
                "{} boot event(s) were not logged — potential unaudited operations",
                hsm_log.unlogged_boot_events
            ),
        });
    } else {
        findings.push(Finding {
            severity: Severity::Pass,
            check: "hsm.unlogged_boots".into(),
            message: "No unlogged boot events".into(),
        });
    }

    if hsm_log.unlogged_auth_events > 0 {
        findings.push(Finding {
            severity: Severity::Error,
            check: "hsm.unlogged_auths".into(),
            message: format!(
                "{} authentication event(s) were not logged — potential unaudited operations",
                hsm_log.unlogged_auth_events
            ),
        });
    } else {
        findings.push(Finding {
            severity: Severity::Pass,
            check: "hsm.unlogged_auths".into(),
            message: "No unlogged authentication events".into(),
        });
    }

    // Check continuity with last known sequence number from STATE.JSON.
    if let Some(last_seq) = last_known_seq {
        if let Some(first) = hsm_log.entries.first() {
            if (first.item as u64) > last_seq + 1 {
                findings.push(Finding {
                    severity: Severity::Error,
                    check: "hsm.continuity".into(),
                    message: format!(
                        "Gap detected: STATE.JSON last_hsm_log_seq={last_seq}, \
                         but oldest HSM entry is item={}. {} entries may have been lost.",
                        first.item,
                        first.item as u64 - last_seq - 1
                    ),
                });
            } else {
                findings.push(Finding {
                    severity: Severity::Pass,
                    check: "hsm.continuity".into(),
                    message: format!(
                        "HSM log continuous from last known seq {last_seq} (oldest entry: {})",
                        first.item
                    ),
                });
            }
        }
    }

    // Check auth key usage — flag any operation not using anodize's auth key.
    // Skip boot/init entries (session_key = 0xffff).
    let foreign_ops: Vec<_> = hsm_log
        .entries
        .iter()
        .filter(|e| e.session_key != 0xffff && e.session_key != anodize_auth_key_id)
        .collect();

    if foreign_ops.is_empty() {
        findings.push(Finding {
            severity: Severity::Pass,
            check: "hsm.auth_key".into(),
            message: format!("All operations used anodize auth key (0x{anodize_auth_key_id:04x})"),
        });
    } else {
        for op in &foreign_ops {
            findings.push(Finding {
                severity: Severity::Error,
                check: "hsm.auth_key".into(),
                message: format!(
                    "Item {}: command 0x{:02x} used auth key 0x{:04x} (expected 0x{:04x})",
                    op.item, op.command, op.session_key, anodize_auth_key_id
                ),
            });
        }
    }

    // Check for unexpected commands.
    for entry in &hsm_log.entries {
        // Skip boot/init entries.
        if entry.session_key == 0xffff {
            continue;
        }
        if !hsm_commands::EXPECTED.contains(&entry.command) {
            findings.push(Finding {
                severity: Severity::Warn,
                check: "hsm.command_set".into(),
                message: format!(
                    "Item {}: unexpected command 0x{:02x} (not in anodize's expected set)",
                    entry.item, entry.command
                ),
            });
        }
    }

    // Count signing operations on the signing key and compare with disc audit log.
    let hsm_sign_count = hsm_log
        .entries
        .iter()
        .filter(|e| {
            e.command == hsm_commands::SIGN_ECDSA
                && e.target_key == signing_key_id
                && e.session_key == anodize_auth_key_id
        })
        .count();

    let disc_sign_count = disc_records
        .iter()
        .filter(|r| r.event == "cert.issue" || r.event == "crl.issue")
        .count();

    // Only compare if we have continuity (no gaps).
    let has_gaps = last_known_seq.is_some_and(|seq| {
        hsm_log
            .entries
            .first()
            .is_some_and(|e| (e.item as u64) > seq + 1)
    });

    if !has_gaps {
        if hsm_sign_count == disc_sign_count {
            findings.push(Finding {
                severity: Severity::Pass,
                check: "hsm.sign_count".into(),
                message: format!(
                    "HSM signing operations ({hsm_sign_count}) match disc audit log \
                     cert.issue+crl.issue events ({disc_sign_count})"
                ),
            });
        } else {
            findings.push(Finding {
                severity: Severity::Error,
                check: "hsm.sign_count".into(),
                message: format!(
                    "HSM has {hsm_sign_count} signing operations on key 0x{signing_key_id:04x}, \
                     but disc audit log has {disc_sign_count} cert.issue+crl.issue events"
                ),
            });
        }
    } else {
        findings.push(Finding {
            severity: Severity::Warn,
            check: "hsm.sign_count".into(),
            message: "Skipping sign count comparison — HSM log has gaps".into(),
        });
    }

    findings
}

// ── Report formatting ──────────────────────────────────────────────────────

/// Format findings as a human-readable report.
pub fn format_report(findings: &[Finding]) -> String {
    let mut out = String::new();
    let errors = findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .count();
    let warns = findings
        .iter()
        .filter(|f| f.severity == Severity::Warn)
        .count();
    let passes = findings
        .iter()
        .filter(|f| f.severity == Severity::Pass)
        .count();

    out.push_str(&format!(
        "=== Disc Validation Report ===\n{passes} PASS, {warns} WARN, {errors} ERROR\n\n"
    ));

    for f in findings {
        out.push_str(&format!("{f}\n"));
    }

    if errors > 0 {
        out.push_str("\n*** VALIDATION FAILED ***\n");
    } else if warns > 0 {
        out.push_str("\n--- VALIDATION PASSED (with warnings) ---\n");
    } else {
        out.push_str("\n--- VALIDATION PASSED ---\n");
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(seq: u64, event: &str, prev_hash: &str) -> Record {
        let timestamp = "2026-01-01T00:00:00Z";
        let op_data = serde_json::json!({});
        let entry_hash = compute_entry_hash(seq, timestamp, event, &op_data, prev_hash);
        Record {
            seq,
            timestamp: timestamp.to_string(),
            event: event.to_string(),
            op_data,
            prev_hash: prev_hash.to_string(),
            entry_hash,
        }
    }

    fn make_chain(events: &[&str]) -> Vec<Record> {
        let mut records = Vec::new();
        let mut prev = "0".repeat(64);
        for (i, event) in events.iter().enumerate() {
            let r = make_record(i as u64, event, &prev);
            prev = r.entry_hash.clone();
            records.push(r);
        }
        records
    }

    /// Build a test session. `files` maps name → content (hashed via SHA-256).
    fn make_session_with_files(
        index: usize,
        files: &[(&str, &str)],
        events: &[&str],
        crl: u64,
    ) -> SessionSnapshot {
        use sha2::{Digest, Sha256};
        let records = make_chain(events);
        let last_hash = records
            .last()
            .map(|r| r.entry_hash.clone())
            .unwrap_or_default();
        let file_hashes = files
            .iter()
            .map(|(name, content)| {
                let hash = format!("{:x}", Sha256::digest(content.as_bytes()));
                (name.to_string(), hash)
            })
            .collect();
        SessionSnapshot {
            index,
            file_hashes,
            audit_records: records,
            state: StateFields {
                root_cert_sha256: "a".repeat(64),
                crl_number: crl,
                last_audit_hash: last_hash,
                last_hsm_log_seq: None,
                is_migration: false,
            },
        }
    }

    /// Convenience: build a session with dummy file content (each name hashes uniquely).
    fn make_session(index: usize, dirs: &[&str], events: &[&str], crl: u64) -> SessionSnapshot {
        let files: Vec<(&str, &str)> = dirs.iter().map(|d| (*d, *d)).collect();
        make_session_with_files(index, &files, events, crl)
    }

    #[test]
    fn disc_status_incomplete_passes() {
        let f = validate_disc_status(DiscStatus::Incomplete);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Pass);
    }

    #[test]
    fn disc_status_complete_errors() {
        let f = validate_disc_status(DiscStatus::Complete);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Error);
    }

    #[test]
    fn session_continuity_superset() {
        let s0 = make_session_with_files(0, &[("AUDIT.LOG", "log-v1")], &["key.generate"], 0);
        let s1 = make_session_with_files(
            1,
            &[
                ("AUDIT.LOG", "log-v1"),
                ("STATE.JSON", "state-v1"),
                ("ROOT.CRT", "cert-data"),
                ("ROOT.CRL", "crl-data"),
            ],
            &["key.generate", "cert.issue"],
            0,
        );
        let findings = validate_session_continuity(&[s0, s1]);
        assert!(
            findings.iter().all(|f| f.severity != Severity::Error),
            "unexpected error: {findings:?}"
        );
    }

    #[test]
    fn session_continuity_missing_file() {
        let s0 = make_session_with_files(
            0,
            &[("AUDIT.LOG", "log"), ("STATE.JSON", "state")],
            &["key.generate"],
            0,
        );
        // Session 1 is missing STATE.JSON.
        let s1 = make_session_with_files(
            1,
            &[("AUDIT.LOG", "log"), ("ROOT.CRT", "cert")],
            &["key.generate", "cert.issue"],
            0,
        );
        let findings = validate_session_continuity(&[s0, s1]);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Error && f.message.contains("missing")));
    }

    #[test]
    fn session_continuity_changed_content() {
        let s0 = make_session_with_files(0, &[("ROOT.CRT", "original-cert")], &["key.generate"], 0);
        // Session 1 has ROOT.CRT but with different content.
        let s1 = make_session_with_files(
            1,
            &[("ROOT.CRT", "tampered-cert"), ("STATE.JSON", "state")],
            &["key.generate", "cert.issue"],
            0,
        );
        let findings = validate_session_continuity(&[s0, s1]);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Error && f.message.contains("changed content")));
    }

    #[test]
    fn session_continuity_crl_regression() {
        let s0 = make_session_with_files(0, &[("a", "x")], &["key.generate"], 5);
        let s1 = make_session_with_files(
            1,
            &[("a", "x"), ("b", "y")],
            &["key.generate", "crl.issue"],
            3,
        );
        let findings = validate_session_continuity(&[s0, s1]);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Error && f.check.contains("crl_number")));
    }

    #[test]
    fn audit_chain_valid() {
        let s0 = make_session(0, &["a"], &["key.generate", "cert.issue"], 0);
        let findings = validate_audit_chain(&[s0]);
        let errors: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .collect();
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn audit_chain_hash_mismatch_in_state() {
        let mut s0 = make_session(0, &["a"], &["key.generate"], 0);
        s0.state.last_audit_hash = "wrong".into();
        let findings = validate_audit_chain(&[s0]);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Error && f.check.contains("state_hash")));
    }

    #[test]
    fn audit_superset_check() {
        let chain = make_chain(&["key.generate", "cert.issue", "crl.issue"]);
        let s0 = SessionSnapshot {
            index: 0,
            file_hashes: [("a".to_string(), "h1".to_string())].into_iter().collect(),
            audit_records: chain[..2].to_vec(),
            state: StateFields {
                root_cert_sha256: "a".repeat(64),
                crl_number: 0,
                last_audit_hash: chain[1].entry_hash.clone(),
                last_hsm_log_seq: None,
                is_migration: false,
            },
        };
        let s1 = SessionSnapshot {
            index: 1,
            file_hashes: [
                ("a".to_string(), "h1".to_string()),
                ("b".to_string(), "h2".to_string()),
            ]
            .into_iter()
            .collect(),
            audit_records: chain.clone(),
            state: StateFields {
                root_cert_sha256: "a".repeat(64),
                crl_number: 1,
                last_audit_hash: chain[2].entry_hash.clone(),
                last_hsm_log_seq: None,
                is_migration: false,
            },
        };
        let findings = validate_audit_chain(&[s0, s1]);
        let errors: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .collect();
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn hsm_unlogged_events_error() {
        let snap = HsmLogSnapshot {
            unlogged_boot_events: 1,
            unlogged_auth_events: 0,
            entries: vec![],
        };
        let findings = cross_check_hsm_log(&snap, &[], 2, 0x0100, None);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Error && f.check == "hsm.unlogged_boots"));
    }

    #[test]
    fn hsm_foreign_auth_key_error() {
        let snap = HsmLogSnapshot {
            unlogged_boot_events: 0,
            unlogged_auth_events: 0,
            entries: vec![HsmLogEntry {
                item: 10,
                command: hsm_commands::SIGN_ECDSA,
                session_key: 99, // not anodize's key
                target_key: 0x0100,
                second_key: 0xffff,
                result: 0,
                tick: 1000,
                digest: [0; 16],
            }],
        };
        let findings = cross_check_hsm_log(&snap, &[], 2, 0x0100, None);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Error && f.check == "hsm.auth_key"));
    }

    #[test]
    fn hsm_sign_count_match() {
        let snap = HsmLogSnapshot {
            unlogged_boot_events: 0,
            unlogged_auth_events: 0,
            entries: vec![HsmLogEntry {
                item: 5,
                command: hsm_commands::SIGN_ECDSA,
                session_key: 2,
                target_key: 0x0100,
                second_key: 0xffff,
                result: 0,
                tick: 1000,
                digest: [0; 16],
            }],
        };
        let disc_records = make_chain(&["cert.issue"]);
        let findings = cross_check_hsm_log(&snap, &disc_records, 2, 0x0100, None);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Pass && f.check == "hsm.sign_count"));
    }

    #[test]
    fn hsm_sign_count_mismatch() {
        let snap = HsmLogSnapshot {
            unlogged_boot_events: 0,
            unlogged_auth_events: 0,
            entries: vec![
                HsmLogEntry {
                    item: 5,
                    command: hsm_commands::SIGN_ECDSA,
                    session_key: 2,
                    target_key: 0x0100,
                    second_key: 0xffff,
                    result: 0,
                    tick: 1000,
                    digest: [0; 16],
                },
                HsmLogEntry {
                    item: 6,
                    command: hsm_commands::SIGN_ECDSA,
                    session_key: 2,
                    target_key: 0x0100,
                    second_key: 0xffff,
                    result: 0,
                    tick: 2000,
                    digest: [0; 16],
                },
            ],
        };
        // Disc only has one signing event.
        let disc_records = make_chain(&["cert.issue"]);
        let findings = cross_check_hsm_log(&snap, &disc_records, 2, 0x0100, None);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Error && f.check == "hsm.sign_count"));
    }

    #[test]
    fn audit_chain_corrupt_hash() {
        let mut s0 = make_session(0, &["a"], &["key.generate", "cert.issue"], 0);
        // Corrupt a record hash in the chain.
        s0.audit_records[1].entry_hash = "deadbeef".repeat(8);
        let findings = validate_audit_chain(&[s0]);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Error && f.check.contains("chain")));
    }

    #[test]
    fn session_continuity_root_cert_change() {
        let mut s0 = make_session_with_files(0, &[("a", "x")], &["key.generate"], 0);
        let mut s1 = make_session_with_files(
            1,
            &[("a", "x"), ("b", "y")],
            &["key.generate", "cert.issue"],
            0,
        );
        s0.state.root_cert_sha256 = "a".repeat(64);
        s1.state.root_cert_sha256 = "b".repeat(64);
        let findings = validate_session_continuity(&[s0, s1]);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Error && f.check.contains("root_cert")));
    }

    #[test]
    fn session_continuity_migration_flag() {
        let mut s0 = make_session_with_files(0, &[("a", "x")], &["migrate"], 3);
        s0.state.is_migration = true;
        let findings = validate_session_continuity(&[s0]);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Pass && f.check.contains("migration")));
    }

    #[test]
    fn multi_session_with_gap_in_audit_records() {
        let chain = make_chain(&["key.generate", "cert.issue", "crl.issue"]);
        let s0 = SessionSnapshot {
            index: 0,
            file_hashes: [("a".to_string(), "h1".to_string())].into_iter().collect(),
            audit_records: chain[..2].to_vec(),
            state: StateFields {
                root_cert_sha256: "a".repeat(64),
                crl_number: 0,
                last_audit_hash: chain[1].entry_hash.clone(),
                last_hsm_log_seq: None,
                is_migration: false,
            },
        };
        // Session 1 starts with a record whose prev_hash doesn't match session 0's
        // last hash — simulates a gap between sessions.
        let bad_record = make_record(
            0,
            "orphan.event",
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        let s1 = SessionSnapshot {
            index: 1,
            file_hashes: [
                ("a".to_string(), "h1".to_string()),
                ("b".to_string(), "h2".to_string()),
            ]
            .into_iter()
            .collect(),
            audit_records: vec![bad_record],
            state: StateFields {
                root_cert_sha256: "a".repeat(64),
                crl_number: 1,
                last_audit_hash: "x".repeat(64),
                last_hsm_log_seq: None,
                is_migration: false,
            },
        };
        let findings = validate_audit_chain(&[s0, s1]);
        // Should detect the cross-session gap.
        assert!(findings.iter().any(|f| f.severity == Severity::Error));
    }

    #[test]
    fn hsm_unexpected_command() {
        let snap = HsmLogSnapshot {
            unlogged_boot_events: 0,
            unlogged_auth_events: 0,
            entries: vec![HsmLogEntry {
                item: 1,
                command: 0xFE, // unknown command
                session_key: 2,
                target_key: 0xffff,
                second_key: 0xffff,
                result: 0,
                tick: 100,
                digest: [0; 16],
            }],
        };
        let findings = cross_check_hsm_log(&snap, &[], 2, 0x0100, None);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Warn && f.check == "hsm.command_set"));
    }

    #[test]
    fn hsm_ring_buffer_wrap() {
        // Simulate unlogged auth events (ring buffer overflow).
        let snap = HsmLogSnapshot {
            unlogged_boot_events: 0,
            unlogged_auth_events: 3,
            entries: vec![],
        };
        let findings = cross_check_hsm_log(&snap, &[], 2, 0x0100, None);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Error && f.check == "hsm.unlogged_auths"));
    }

    #[test]
    fn format_report_summary() {
        let findings = vec![
            Finding {
                severity: Severity::Pass,
                check: "a".into(),
                message: "ok".into(),
            },
            Finding {
                severity: Severity::Error,
                check: "b".into(),
                message: "fail".into(),
            },
        ];
        let report = format_report(&findings);
        assert!(report.contains("1 PASS"));
        assert!(report.contains("1 ERROR"));
        assert!(report.contains("VALIDATION FAILED"));
    }

    #[test]
    fn format_report_all_pass() {
        let findings = vec![Finding {
            severity: Severity::Pass,
            check: "a".into(),
            message: "ok".into(),
        }];
        let report = format_report(&findings);
        assert!(report.contains("VALIDATION PASSED"));
        assert!(!report.contains("FAILED"));
    }

    #[test]
    fn disc_status_blank_errors() {
        let f = validate_disc_status(DiscStatus::Blank);
        assert_eq!(f[0].severity, Severity::Error);
    }

    #[test]
    fn disc_status_other_warns() {
        let f = validate_disc_status(DiscStatus::Other(0x42));
        assert_eq!(f[0].severity, Severity::Warn);
    }

    #[test]
    fn empty_sessions_errors() {
        let findings = validate_session_continuity(&[]);
        assert!(findings.iter().any(|f| f.severity == Severity::Error));
    }

    #[test]
    fn hsm_continuity_gap_detected() {
        let snap = HsmLogSnapshot {
            unlogged_boot_events: 0,
            unlogged_auth_events: 0,
            entries: vec![HsmLogEntry {
                item: 50, // gap: last known was 10
                command: hsm_commands::GET_LOG_ENTRIES,
                session_key: 2,
                target_key: 0xffff,
                second_key: 0xffff,
                result: 0,
                tick: 5000,
                digest: [0; 16],
            }],
        };
        let findings = cross_check_hsm_log(&snap, &[], 2, 0x0100, Some(10));
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Error && f.check == "hsm.continuity"));
    }
}
