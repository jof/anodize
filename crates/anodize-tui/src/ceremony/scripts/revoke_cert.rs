//! The RevokeCert ceremony, as a script.
//!
//! Add a certificate to the revocation list and re-sign the CRL. Reads
//! top to bottom:
//!
//! 1. operator picks a certificate from disc (or types a serial) + a reason,
//! 2. confirms the updated revocation list,
//! 3. the intent WAL is committed to disc,
//! 4. the quorum reconstructs the PIN,
//! 5. the clock is re-confirmed,
//! 6. the HSM signs the new CRL,
//! 7. the record session (REVOKED.TOML + ROOT.CRL + STATE.JSON) is burned,
//! 8. artifacts are exported to the shuttle.
//!
//! Same `Abort`-on-`?` and typestate guarantees as `issue_crl`.

use anodize_config::RevocationEntry;

use crate::ceremony::io::*;

/// RFC 3339 (`YYYY-MM-DDTHH:MM:SSZ`) timestamp for the revocation entry.
fn now_rfc3339() -> String {
    let odt = time::OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        odt.year(),
        odt.month() as u8,
        odt.day(),
        odt.hour(),
        odt.minute(),
        odt.second()
    )
}

fn revoke_preview(list: &[RevocationEntry], crl_number: u64) -> Vec<String> {
    let mut lines = vec![
        format!("New CRL number  : {crl_number}"),
        format!("Revoked entries : {}", list.len()),
        String::new(),
    ];
    for entry in list {
        let reason = entry.reason.as_deref().unwrap_or("(no reason)");
        lines.push(format!(
            "  serial={}  time={}  reason={}",
            entry.serial, entry.revocation_time, reason
        ));
    }
    lines
}

/// Choose the certificate to revoke (from the on-disc list or a typed serial)
/// plus an optional reason. Loops until a valid, non-duplicate serial is given.
fn select_target(
    op: &mut dyn Operator,
    plan: &RevokePlan,
) -> Result<(String, Option<String>), Abort> {
    loop {
        let mut options: Vec<Choice> = plan
            .cert_list
            .iter()
            .map(|c| {
                let status = if c.already_revoked {
                    "revoked"
                } else if c.is_root {
                    "root"
                } else {
                    "active"
                };
                let subject = c.subject.split(", ").next().unwrap_or(&c.subject);
                Choice {
                    key: ' ',
                    label: format!("{} [{}]  {}", c.serial, status, subject),
                }
            })
            .collect();
        options.push(Choice {
            key: 'm',
            label: "Enter a serial number manually".into(),
        });

        let body = vec![format!(
            "{} certificate(s) on disc, {} already revoked.",
            plan.cert_list.len(),
            plan.revocation_list.len()
        )];
        let idx = op.choose("Revoke Certificate \u{2014} select", &body, &options)?;

        let serial = if idx < plan.cert_list.len() {
            let cert = &plan.cert_list[idx];
            if cert.already_revoked {
                op.note("That certificate is already revoked. Choose another.");
                continue;
            }
            cert.serial.clone()
        } else {
            let typed = op
                .prompt_text("Revoke \u{2014} manual entry", "Serial number (hex)")?
                .trim()
                .to_uppercase();
            if typed.is_empty() || !typed.chars().all(|c| c.is_ascii_hexdigit()) {
                op.note("Serial must be non-empty hex digits.");
                continue;
            }
            typed
        };

        if plan.revocation_list.iter().any(|e| e.serial == serial) {
            op.note(&format!(
                "Serial {serial} is already in the revocation list."
            ));
            continue;
        }

        let reason_raw =
            op.prompt_text("Revoke \u{2014} reason", "Reason (optional, Enter to skip)")?;
        let reason = {
            let trimmed = reason_raw.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        };
        return Ok((serial, reason));
    }
}

/// Run the RevokeCert ceremony.
pub fn revoke_cert(
    op: &mut dyn Operator,
    vault: &mut dyn Vault,
    arc: &mut dyn Archive,
    env: &Env<RevokePlan>,
) -> Result<Outcome, Abort> {
    let plan = &env.plan;

    let (serial, reason) = select_target(op, plan)?;

    let mut revocation_list = plan.revocation_list.clone();
    revocation_list.push(RevocationEntry {
        serial: serial.clone(),
        revocation_time: now_rfc3339(),
        reason: reason.clone(),
    });

    op.confirm(
        "Revoke and sign CRL",
        &revoke_preview(&revocation_list, plan.crl_number),
    )?;

    let intent = arc.commit_intent(IntentEvent {
        name: "cert.revoke.intent".into(),
        data: serde_json::json!({
            "operation": "revoke-and-issue-crl",
            "serial_hex": serial,
            "reason": reason,
            "crl_number": plan.crl_number,
            "revocation_count": revocation_list.len(),
        }),
    })?;

    let pin = op.collect_quorum(&env.sss)?;
    let when = op.reconfirm_clock()?;

    // Sign a CRL over the updated revocation list, reusing the CRL plan shape.
    let crl_plan = CrlPlan {
        crl_number: plan.crl_number,
        revocation_list: revocation_list.clone(),
        root_cert_der: plan.root_cert_der.clone(),
    };
    let (crl, hsm_log_seq) = {
        let mut sess = vault.login(pin)?;
        let crl = sess.issue_crl(&crl_plan, when)?;
        let seq = sess.record_audit_seq();
        (crl, seq)
    };

    op.note("CRL signed. Writing record session to disc\u{2026}");

    let revoked_toml = anodize_config::serialize_revocation_list(&revocation_list).into_bytes();
    let record = arc.commit_record(
        intent,
        RecordSession {
            audit_events: vec![
                (
                    "cert.revoke".into(),
                    serde_json::json!({ "serial_hex": serial, "reason": reason }),
                ),
                (
                    "crl.issue".into(),
                    serde_json::json!({
                        "crl_number": plan.crl_number,
                        "revocation_count": revocation_list.len(),
                    }),
                ),
            ],
            artifacts: vec![
                Artifact {
                    name: "REVOKED.TOML".into(),
                    bytes: revoked_toml.clone(),
                },
                Artifact {
                    name: "ROOT.CRL".into(),
                    bytes: crl.der().to_vec(),
                },
            ],
            state: Some(StateDelta {
                crl_number: Some(plan.crl_number),
                revocation_list: revocation_list.clone(),
                hsm_log_seq,
                fresh_state: None,
                sss: None,
                fleet: None,
            }),
        },
    )?;

    arc.export_shuttle(
        &record,
        &[("revoked.toml", &revoked_toml), ("root.crl", crl.der())],
    )?;

    Ok(Outcome {
        headline: format!("Revoked {serial}; CRL #{} written to disc", plan.crl_number),
        detail: vec![format!("Revoked entries: {}", revocation_list.len())],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disc::CertSummary;
    use anodize_config::state::{Custodian, SssMetadata};
    use secrecy::SecretString;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Effect {
        Choose,
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

    struct FakeOperator {
        log: Log,
        abort_quorum: bool,
    }
    impl Operator for FakeOperator {
        fn choose(&mut self, _: &str, _: &[String], _: &[Choice]) -> Result<usize, Abort> {
            self.log.borrow_mut().push(Effect::Choose);
            Ok(0) // pick the first (active) certificate
        }
        fn confirm(&mut self, _: &str, _: &[String]) -> Result<(), Abort> {
            self.log.borrow_mut().push(Effect::Confirm);
            Ok(())
        }
        fn collect_quorum(&mut self, _: &SssMetadata) -> Result<Pin, Abort> {
            if self.abort_quorum {
                return Err(Abort::new("quorum aborted"));
            }
            self.log.borrow_mut().push(Effect::CollectQuorum);
            Ok(SecretString::new("00ff".into()))
        }
        fn reconfirm_clock(&mut self) -> Result<Timestamp, Abort> {
            self.log.borrow_mut().push(Effect::ReconfirmClock);
            Ok(std::time::SystemTime::UNIX_EPOCH)
        }
        fn prompt_text(&mut self, _: &str, _: &str) -> Result<String, Abort> {
            Ok(String::new()) // reason skipped
        }
        fn note(&mut self, _: &str) {}
    }

    struct FakeVault {
        log: Log,
    }
    struct FakeSession {
        log: Log,
    }
    impl Vault for FakeVault {
        fn login<'a>(&'a mut self, _: Pin) -> Result<Box<dyn Session + 'a>, Abort> {
            self.log.borrow_mut().push(Effect::Login);
            Ok(Box::new(FakeSession {
                log: self.log.clone(),
            }))
        }
    }
    impl Session for FakeSession {
        fn issue_crl(&mut self, _: &CrlPlan, _: Timestamp) -> Result<SignedCrl, Abort> {
            self.log.borrow_mut().push(Effect::IssueCrl);
            Ok(SignedCrl::new(vec![0xCA, 0xFE]))
        }
    }

    struct FakeArchive {
        log: Log,
    }
    impl Archive for FakeArchive {
        fn commit_intent(&mut self, _: IntentEvent) -> Result<IntentCommitted, Abort> {
            self.log.borrow_mut().push(Effect::CommitIntent);
            Ok(IntentCommitted::new("intent"))
        }
        fn commit_record(
            &mut self,
            _: IntentCommitted,
            _: RecordSession,
        ) -> Result<RecordCommitted, Abort> {
            self.log.borrow_mut().push(Effect::CommitRecord);
            Ok(RecordCommitted::new("record"))
        }
        fn export_shuttle(
            &mut self,
            _: &RecordCommitted,
            _: &[(&str, &[u8])],
        ) -> Result<(), Abort> {
            self.log.borrow_mut().push(Effect::ExportShuttle);
            Ok(())
        }
    }

    fn env() -> Env<RevokePlan> {
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
            plan: RevokePlan {
                cert_list: vec![CertSummary {
                    serial: "ABCD".into(),
                    subject: "CN=leaf".into(),
                    is_root: false,
                    already_revoked: false,
                }],
                revocation_list: vec![],
                crl_number: 3,
                root_cert_der: vec![0x30, 0x00],
            },
        }
    }

    fn run(abort_quorum: bool) -> (Result<Outcome, Abort>, Vec<Effect>) {
        let log: Log = Rc::new(RefCell::new(Vec::new()));
        let mut op = FakeOperator {
            log: log.clone(),
            abort_quorum,
        };
        let mut vault = FakeVault { log: log.clone() };
        let mut arc = FakeArchive { log: log.clone() };
        let result = revoke_cert(&mut op, &mut vault, &mut arc, &env());
        let effects = log.borrow().clone();
        (result, effects)
    }

    #[test]
    fn happy_path_runs_effects_in_order() {
        let (result, effects) = run(false);
        assert!(result.is_ok());
        assert_eq!(
            effects,
            vec![
                Effect::Choose,
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
    fn abort_at_quorum_never_touches_hsm_or_record() {
        let (result, effects) = run(true);
        assert!(result.is_err());
        assert_eq!(
            effects,
            vec![Effect::Choose, Effect::Confirm, Effect::CommitIntent]
        );
        assert!(!effects.contains(&Effect::Login));
        assert!(!effects.contains(&Effect::IssueCrl));
        assert!(!effects.contains(&Effect::CommitRecord));
        assert!(!effects.contains(&Effect::ExportShuttle));
    }
}
