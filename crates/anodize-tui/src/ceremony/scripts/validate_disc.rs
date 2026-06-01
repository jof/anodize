//! The ValidateDisc ceremony, as a script.
//!
//! Read-only audit and integrity check of a ceremony disc. No HSM signing,
//! no disc mutation — this ceremony only reads disc state, optionally
//! cross-checks the HSM audit log, and exports a report to the shuttle.
//!
//! 1. show pre-computed validation report (confirm gate),
//! 2. if an HSM is available, offer an audit-log cross-check,
//!    a. if accepted: collect quorum → login → fetch HSM log → cross-check,
//!    b. show combined report (confirm gate),
//! 3. export VALIDATE.LOG to shuttle.

use anodize_audit::validate::{cross_check_hsm_log, format_report, HsmLogEntry, HsmLogSnapshot};

use crate::ceremony::io::*;

/// Convert the io-layer `HsmAuditLog` to the `anodize_audit::validate` type.
fn to_validate_snapshot(log: &HsmAuditLog) -> HsmLogSnapshot {
    HsmLogSnapshot {
        unlogged_boot_events: log.unlogged_boot_events,
        unlogged_auth_events: log.unlogged_auth_events,
        entries: log
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
    }
}

/// Parse the raw staging AUDIT.LOG bytes into `anodize_audit::Record`s.
fn parse_disc_records(bytes: &[u8]) -> Vec<anodize_audit::Record> {
    std::str::from_utf8(bytes)
        .unwrap_or("")
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

/// Run the ValidateDisc ceremony.
pub fn validate_disc(
    op: &mut dyn Operator,
    vault: &mut dyn Vault,
    arc: &mut dyn Archive,
    env: &Env<ValidateDiscPlan>,
) -> Result<Outcome, Abort> {
    let plan = &env.plan;

    // 1. Show the pre-computed validation report.
    let report_lines: Vec<String> = plan.initial_report.lines().map(String::from).collect();
    op.review("Disc Validation Report", &report_lines);

    // 2. Optionally run the HSM audit-log cross-check.
    let mut final_report = plan.initial_report.clone();

    if plan.has_hsm {
        let options = vec![
            Choice {
                key: '1',
                label: "Run HSM audit log cross-check (requires quorum)".into(),
            },
            Choice {
                key: '2',
                label: "Skip HSM check".into(),
            },
        ];
        let idx = op.choose(
            "HSM Audit Cross-Check",
            &["An HSM device is available for cross-checking.".into()],
            &options,
        )?;

        if idx == 0 {
            let pin = op.collect_quorum(&env.sss)?;

            let hsm_log = {
                let mut sess = vault.login(pin)?;
                sess.get_hsm_audit_log()?
            };

            let disc_records = plan
                .staging_audit_bytes
                .as_deref()
                .map(parse_disc_records)
                .unwrap_or_default();

            let hsm_snapshot = to_validate_snapshot(&hsm_log);
            let hsm_findings = cross_check_hsm_log(
                &hsm_snapshot,
                &disc_records,
                0x0002, // ANODIZE_AUTH_KEY_ID
                0x0100, // SIGNING_KEY_ID
                plan.last_hsm_log_seq,
            );

            // Build combined report: initial + HSM section.
            let hsm_section = format_report(&hsm_findings);
            final_report = format!(
                "{}\n\n=== HSM Audit Log Cross-Check ===\n{}",
                plan.initial_report, hsm_section
            );

            let combined_lines: Vec<String> = final_report.lines().map(String::from).collect();
            op.review("Combined Validation Report", &combined_lines);
        }
    }

    // 3. Export VALIDATE.LOG to shuttle.
    arc.write_shuttle_direct(&[("VALIDATE.LOG", final_report.as_bytes())])?;

    let has_errors = final_report.contains("*** VALIDATION FAILED ***");
    let status = if has_errors {
        "FAILED"
    } else if final_report.contains("with warnings") {
        "PASSED (with warnings)"
    } else {
        "PASSED"
    };

    Ok(Outcome {
        headline: format!("Disc validation {status}"),
        detail: vec!["VALIDATE.LOG exported to shuttle.".into()],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony::scripts::init_root::tests::{FakeArchive, FakeOperator};
    use anodize_audit::validate::{Finding, Severity};
    use anodize_config::state::SssMetadata;

    fn sample_sss() -> SssMetadata {
        SssMetadata {
            generation: 1,
            threshold: 2,
            total: 2,
            custodians: vec![],
            pin_verify_hash: String::new(),
            share_commitments: vec![],
        }
    }

    fn sample_env(has_hsm: bool) -> Env<ValidateDiscPlan> {
        Env {
            sss: sample_sss(),
            plan: ValidateDiscPlan {
                initial_report: format_report(&[Finding {
                    severity: Severity::Pass,
                    check: "disc_status".into(),
                    message: "Disc is appendable".into(),
                }]),
                has_hsm,
                staging_audit_bytes: None,
                last_hsm_log_seq: None,
            },
        }
    }

    struct FakeVault {
        login_count: usize,
    }

    impl FakeVault {
        fn new() -> Self {
            Self { login_count: 0 }
        }
    }

    struct FakeSession;

    impl Vault for FakeVault {
        fn login<'a>(&'a mut self, _pin: Pin) -> Result<Box<dyn Session + 'a>, Abort> {
            self.login_count += 1;
            Ok(Box::new(FakeSession))
        }
    }

    impl Session for FakeSession {
        fn get_hsm_audit_log(&mut self) -> Result<HsmAuditLog, Abort> {
            Ok(HsmAuditLog {
                unlogged_boot_events: 0,
                unlogged_auth_events: 0,
                entries: vec![],
            })
        }
    }

    #[test]
    fn happy_path_no_hsm() {
        let env = sample_env(false);
        let mut op = FakeOperator::new();
        let mut vault = FakeVault::new();
        let mut arc = FakeArchive::new();

        let result = validate_disc(&mut op, &mut vault, &mut arc, &env);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");

        let out = result.unwrap();
        assert!(out.headline.contains("PASSED"), "got: {}", out.headline);
        assert!(out.detail[0].contains("VALIDATE.LOG"));

        // Verify: no intent/record/shuttle, one direct shuttle write.
        assert_eq!(arc.intents, 0);
        assert_eq!(arc.records, 0);
        assert_eq!(arc.shuttles, 0);
        assert_eq!(arc.shuttle_directs, 1);

        // No vault interaction.
        assert_eq!(vault.login_count, 0);

        // Transcript: review (report) then done.
        assert!(op.transcript.contains(&"review".to_string()));
    }

    #[test]
    fn happy_path_with_hsm_crosscheck() {
        let env = sample_env(true);
        let mut op = FakeOperator::new();
        // FakeOperator.choose returns 0 → "Run HSM cross-check"
        let mut vault = FakeVault::new();
        let mut arc = FakeArchive::new();

        let result = validate_disc(&mut op, &mut vault, &mut arc, &env);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");

        // Should have logged in to the HSM.
        assert_eq!(vault.login_count, 1);

        // Two reviews: initial report + combined report.
        let review_count = op.transcript.iter().filter(|e| *e == "review").count();
        assert_eq!(review_count, 2, "expected two review prompts");

        assert_eq!(arc.shuttle_directs, 1);
    }

    #[test]
    fn skip_hsm_crosscheck() {
        let env = sample_env(true);
        let mut op = FakeOperator::new();
        // Make choose return 1 → "Skip HSM check"
        op.choose_index = Some(1);
        let mut vault = FakeVault::new();
        let mut arc = FakeArchive::new();

        let result = validate_disc(&mut op, &mut vault, &mut arc, &env);
        assert!(result.is_ok());

        // No vault login.
        assert_eq!(vault.login_count, 0);

        // Only one review (initial report), no second.
        let review_count = op.transcript.iter().filter(|e| *e == "review").count();
        assert_eq!(review_count, 1);

        assert_eq!(arc.shuttle_directs, 1);
    }

    #[test]
    fn review_cannot_abort_so_shuttle_always_written() {
        let env = sample_env(false);
        let mut op = FakeOperator::new();
        let mut vault = FakeVault::new();
        let mut arc = FakeArchive::new();

        let result = validate_disc(&mut op, &mut vault, &mut arc, &env);
        assert!(result.is_ok());
        assert_eq!(arc.shuttle_directs, 1, "VALIDATE.LOG always exported");
    }
}
