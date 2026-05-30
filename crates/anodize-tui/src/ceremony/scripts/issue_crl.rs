//! The IssueCrl ceremony, as a script.
//!
//! Re-sign the current revocation list and write a fresh CRL. Read it top to
//! bottom — the order of the lines *is* the order of operations, and that
//! ordering is the security property:
//!
//! 1. operator confirms the plan,
//! 2. the intent WAL is committed to disc (crash-safe record of what we attempt),
//! 3. the quorum reconstructs the PIN,
//! 4. the clock is re-confirmed,
//! 5. the HSM signs,
//! 6. the record session is burned to disc,
//! 7. artifacts are exported to the shuttle.
//!
//! An [`Abort`] at any step short-circuits via `?`: nothing below it runs, and
//! the HSM session (if any) logs out as it drops. The disc-before-shuttle and
//! intent-before-record invariants are additionally enforced by the typestate
//! tokens threaded through [`Archive`].

use crate::ceremony::io::*;

/// Build the operator-facing preview of the CRL about to be signed.
fn crl_preview(plan: &CrlPlan) -> Vec<String> {
    let mut lines = vec![
        format!("CRL number      : {}", plan.crl_number),
        format!("Revoked entries : {}", plan.revocation_list.len()),
        String::new(),
    ];
    if plan.revocation_list.is_empty() {
        lines.push("(No certificates have been revoked.)".into());
    } else {
        for entry in &plan.revocation_list {
            let reason = entry.reason.as_deref().unwrap_or("(no reason)");
            lines.push(format!(
                "  serial={}  time={}  reason={}",
                entry.serial, entry.revocation_time, reason
            ));
        }
    }
    lines
}

/// Run the IssueCrl ceremony. Generic over the effect traits, so the live TUI
/// and the transcript test drive the exact same code.
pub fn issue_crl(
    op: &mut dyn Operator,
    vault: &mut dyn Vault,
    arc: &mut dyn Archive,
    env: &Env,
) -> Result<Outcome, Abort> {
    let plan = &env.crl_plan;

    op.confirm("Sign and write CRL", &crl_preview(plan))?;

    let intent = arc.commit_intent(IntentEvent {
        name: "crl.intent".into(),
        data: serde_json::json!({
            "operation": "issue-crl",
            "crl_number": plan.crl_number,
            "revocation_count": plan.revocation_list.len(),
        }),
    })?;

    let pin = op.collect_quorum(&env.sss)?;
    let when = op.reconfirm_clock()?;

    // The signing key is unlocked only for the duration of this block; the
    // session logs out + zeroizes when `sess` drops, including on early return.
    let (crl, hsm_log_seq) = {
        let mut sess = vault.login(pin)?;
        let crl = sess.issue_crl(plan, when)?;
        let seq = sess.record_audit_seq();
        (crl, seq)
    };

    op.note("CRL signed. Writing record session to disc\u{2026}");

    let record = arc.commit_record(
        intent,
        RecordSession {
            audit_event: (
                "crl.issue".into(),
                serde_json::json!({
                    "crl_number": plan.crl_number,
                    "revocation_count": plan.revocation_list.len(),
                }),
            ),
            artifacts: vec![Artifact {
                name: "ROOT.CRL".into(),
                bytes: crl.der().to_vec(),
            }],
            state: Some(StateDelta {
                crl_number: Some(plan.crl_number),
                revocation_list: plan.revocation_list.clone(),
                hsm_log_seq,
            }),
        },
    )?;

    arc.export_shuttle(&record, &[("root.crl", crl.der())])?;

    Ok(Outcome {
        headline: format!("CRL #{} written to disc", plan.crl_number),
        detail: vec![format!("Revoked entries: {}", plan.revocation_list.len())],
    })
}

// ── transcript tests ────────────────────────────────────────────────────────
//
// The fakes share a single ordered effect log. Because each fake records its
// effect only on success, an `Abort` leaves the log showing exactly which
// effects completed before the abort — which is how we assert that an aborted
// quorum never reaches the HSM or the disc record.

#[cfg(test)]
mod tests {
    use super::*;
    use anodize_config::state::{Custodian, SssMetadata};
    use secrecy::SecretString;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Effect {
        Confirm,
        CommitIntent,
        CollectQuorum,
        ReconfirmClock,
        Login,
        IssueCrl,
        CommitRecord,
        ExportShuttle,
    }

    type Log = Rc<RefCell<Vec<Effect>>>;

    /// Which effect, if any, the operator/HSM should fail at.
    #[derive(Default, Clone, Copy)]
    struct FailAt {
        confirm: bool,
        quorum: bool,
        sign: bool,
    }

    struct FakeOperator {
        log: Log,
        fail: FailAt,
    }

    impl Operator for FakeOperator {
        fn choose(&mut self, _: &str, _: &[String], _: &[Choice]) -> Result<usize, Abort> {
            Ok(0)
        }
        fn confirm(&mut self, _: &str, _: &[String]) -> Result<(), Abort> {
            if self.fail.confirm {
                return Err(Abort::new("operator declined"));
            }
            self.log.borrow_mut().push(Effect::Confirm);
            Ok(())
        }
        fn collect_quorum(&mut self, _: &SssMetadata) -> Result<Pin, Abort> {
            if self.fail.quorum {
                return Err(Abort::new("quorum aborted"));
            }
            self.log.borrow_mut().push(Effect::CollectQuorum);
            Ok(SecretString::new("00ff".into()))
        }
        fn reconfirm_clock(&mut self) -> Result<Timestamp, Abort> {
            self.log.borrow_mut().push(Effect::ReconfirmClock);
            Ok(std::time::SystemTime::UNIX_EPOCH)
        }
        fn note(&mut self, _: &str) {}
    }

    struct FakeVault {
        log: Log,
        fail_sign: bool,
    }
    struct FakeSession {
        log: Log,
        fail_sign: bool,
    }

    impl Vault for FakeVault {
        fn login<'a>(&'a mut self, _pin: Pin) -> Result<Box<dyn Session + 'a>, Abort> {
            self.log.borrow_mut().push(Effect::Login);
            Ok(Box::new(FakeSession {
                log: self.log.clone(),
                fail_sign: self.fail_sign,
            }))
        }
    }

    impl Session for FakeSession {
        fn issue_crl(&mut self, _: &CrlPlan, _: Timestamp) -> Result<SignedCrl, Abort> {
            if self.fail_sign {
                return Err(Abort::new("HSM signing failed"));
            }
            self.log.borrow_mut().push(Effect::IssueCrl);
            Ok(SignedCrl::new(vec![0xDE, 0xAD, 0xBE, 0xEF]))
        }
    }

    struct FakeArchive {
        log: Log,
    }

    impl Archive for FakeArchive {
        fn commit_intent(&mut self, _: IntentEvent) -> Result<IntentCommitted, Abort> {
            self.log.borrow_mut().push(Effect::CommitIntent);
            Ok(IntentCommitted::new("2026-intent"))
        }
        fn commit_record(
            &mut self,
            _intent: IntentCommitted,
            _session: RecordSession,
        ) -> Result<RecordCommitted, Abort> {
            self.log.borrow_mut().push(Effect::CommitRecord);
            Ok(RecordCommitted::new("2026-record"))
        }
        fn export_shuttle(
            &mut self,
            _record: &RecordCommitted,
            _files: &[(&str, &[u8])],
        ) -> Result<(), Abort> {
            self.log.borrow_mut().push(Effect::ExportShuttle);
            Ok(())
        }
    }

    fn test_env() -> Env {
        Env {
            sss: SssMetadata {
                generation: 1,
                threshold: 2,
                total: 2,
                custodians: vec![
                    Custodian {
                        name: "Alice".into(),
                        index: 1,
                    },
                    Custodian {
                        name: "Bob".into(),
                        index: 2,
                    },
                ],
                pin_verify_hash: "deadbeef".into(),
                share_commitments: vec![],
            },
            crl_plan: CrlPlan {
                crl_number: 7,
                revocation_list: vec![],
                root_cert_der: vec![0x30, 0x00],
            },
        }
    }

    fn run(fail: FailAt) -> (Result<Outcome, Abort>, Vec<Effect>) {
        let log: Log = Rc::new(RefCell::new(Vec::new()));
        let mut op = FakeOperator {
            log: log.clone(),
            fail,
        };
        let mut vault = FakeVault {
            log: log.clone(),
            fail_sign: fail.sign,
        };
        let mut arc = FakeArchive { log: log.clone() };
        let env = test_env();
        let result = issue_crl(&mut op, &mut vault, &mut arc, &env);
        let effects = log.borrow().clone();
        (result, effects)
    }

    #[test]
    fn happy_path_runs_effects_in_order() {
        let (result, effects) = run(FailAt::default());
        assert!(result.is_ok());
        assert_eq!(
            effects,
            vec![
                Effect::Confirm,
                Effect::CommitIntent,
                Effect::CollectQuorum,
                Effect::ReconfirmClock,
                Effect::Login,
                Effect::IssueCrl,
                Effect::CommitRecord,
                Effect::ExportShuttle,
            ]
        );
    }

    #[test]
    fn disc_before_shuttle() {
        // The typestate tokens make this a compile-time guarantee; assert it at
        // runtime too as a belt-and-suspenders check on the happy path.
        let (_r, effects) = run(FailAt::default());
        let record = effects.iter().position(|e| *e == Effect::CommitRecord);
        let shuttle = effects.iter().position(|e| *e == Effect::ExportShuttle);
        assert!(
            record < shuttle,
            "record must be committed before shuttle export"
        );
    }

    #[test]
    fn abort_at_quorum_never_touches_hsm_or_record() {
        // This is the rekey-class bug, made impossible by construction: aborting
        // the quorum must leave the intent on disc but perform NO HSM login,
        // NO signing, NO record burn, and NO shuttle export.
        let (result, effects) = run(FailAt {
            quorum: true,
            ..Default::default()
        });
        assert!(result.is_err());
        assert_eq!(effects, vec![Effect::Confirm, Effect::CommitIntent]);
        assert!(!effects.contains(&Effect::Login));
        assert!(!effects.contains(&Effect::IssueCrl));
        assert!(!effects.contains(&Effect::CommitRecord));
        assert!(!effects.contains(&Effect::ExportShuttle));
    }

    #[test]
    fn abort_at_confirm_commits_nothing() {
        let (result, effects) = run(FailAt {
            confirm: true,
            ..Default::default()
        });
        assert!(result.is_err());
        assert!(effects.is_empty(), "declining the plan must commit nothing");
    }

    #[test]
    fn signing_failure_writes_no_record_or_shuttle() {
        // A failed HSM signature aborts before any record/shuttle write, so a
        // failure can never be masked by a "written successfully" screen.
        let (result, effects) = run(FailAt {
            sign: true,
            ..Default::default()
        });
        assert!(result.is_err());
        assert!(effects.contains(&Effect::Login));
        assert!(!effects.contains(&Effect::IssueCrl));
        assert!(!effects.contains(&Effect::CommitRecord));
        assert!(!effects.contains(&Effect::ExportShuttle));
    }
}
