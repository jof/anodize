//! The SignCsr ceremony, as a script.
//!
//! Sign an intermediate-CA CSR (loaded from the shuttle) under a chosen
//! profile. Reads top to bottom:
//!
//! 1. operator selects a certificate profile,
//! 2. confirms the rendered certificate document,
//! 3. the intent WAL (recording the CSR bytes) is committed to disc,
//! 4. the quorum reconstructs the PIN,
//! 5. the clock is re-confirmed,
//! 6. the HSM signs the intermediate certificate,
//! 7. the operator verifies the fingerprint against their paper checklist,
//! 8. the record session (INTERMEDIATE.CRT + STATE.JSON) is burned,
//! 9. the certificate is exported to the shuttle.

use crate::ceremony::io::*;

/// Run the SignCsr ceremony.
pub fn sign_csr(
    op: &mut dyn Operator,
    vault: &mut dyn Vault,
    arc: &mut dyn Archive,
    env: &Env<SignCsrPlan>,
) -> Result<Outcome, Abort> {
    let plan = &env.plan;
    if plan.profiles.is_empty() {
        return Err(Abort::new("No [[cert_profiles]] defined in profile.toml."));
    }

    // 1. Select the certificate profile.
    let options: Vec<Choice> = plan
        .profiles
        .iter()
        .map(|p| Choice {
            key: ' ',
            label: p.label.clone(),
        })
        .collect();
    let idx = op.choose(
        "Select certificate profile",
        &["CSR loaded from shuttle (csr.der).".into()],
        &options,
    )?;
    let profile = &plan.profiles[idx];

    // 2. Review the rendered certificate document.
    op.confirm("Sign CSR", &profile.preview)?;

    // 3. Commit intent (records the CSR bytes for the audit trail).
    let intent = arc.commit_intent(IntentEvent {
        name: "cert.csr.intent".into(),
        data: serde_json::json!({
            "operation": "sign-csr",
            "csr_der_hex": hex::encode(&plan.csr_der),
            "profile_name": profile.name,
        }),
    })?;

    // 4-5. Unlock + re-confirm clock.
    let pin = op.collect_quorum(&env.sss)?;
    let when = op.reconfirm_clock()?;

    // 6. Sign the intermediate certificate.
    let req = IntermediateReq {
        csr_der: plan.csr_der.clone(),
        root_cert_der: plan.root_cert_der.clone(),
        path_len: profile.path_len,
        validity_days: profile.validity_days,
        cdp_url: plan.cdp_url.clone(),
        existing_serials: plan.existing_serials.clone(),
    };
    let (cert, hsm_log_seq) = {
        let mut sess = vault.login(pin)?;
        let cert = sess.sign_intermediate(&req, when)?;
        let seq = sess.record_audit_seq();
        (cert, seq)
    };

    // 7. Operator verifies the fingerprint before anything touches the disc.
    let fingerprint = crate::helpers::sha256_fingerprint(cert.der());
    let (subject, validity_days) = crate::helpers::cert_subject_and_validity_days(cert.der())
        .unwrap_or_else(|| ("(unknown)".into(), 0));
    op.confirm(
        "Verify fingerprint before writing",
        &[
            format!("Subject  : {subject}"),
            format!("Validity : {validity_days} days"),
            String::new(),
            "SHA-256 fingerprint:".into(),
            format!("  {fingerprint}"),
            String::new(),
            "Compare against your paper checklist.".into(),
        ],
    )?;

    op.note("Fingerprint confirmed. Writing record session to disc\u{2026}");

    // 8. Burn the record session.
    let record = arc.commit_record(
        intent,
        RecordSession {
            audit_events: vec![(
                "cert.intermediate.issue".into(),
                serde_json::json!({
                    "fingerprint": fingerprint,
                    "profile": profile.name,
                }),
            )],
            artifacts: vec![Artifact {
                name: "INTERMEDIATE.CRT".into(),
                bytes: cert.der().to_vec(),
            }],
            // Intermediate issuance does not change crl_number/revocation_list;
            // only the audit-chain head (and HSM seq) advance.
            state: Some(StateDelta {
                crl_number: None,
                revocation_list: Vec::new(),
                hsm_log_seq,
            }),
        },
    )?;

    // 9. Export to shuttle.
    arc.export_shuttle(&record, &[("intermediate.crt", cert.der())])?;

    Ok(Outcome {
        headline: format!("Intermediate certificate written ({})", profile.name),
        detail: vec![format!("Fingerprint: {fingerprint}")],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
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
        SignIntermediate,
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
            Ok(0)
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
            Ok(String::new())
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
        fn sign_intermediate(
            &mut self,
            _: &IntermediateReq,
            _: Timestamp,
        ) -> Result<SignedCert, Abort> {
            self.log.borrow_mut().push(Effect::SignIntermediate);
            // A tiny but real DER cert is not needed; the fingerprint/preview
            // helpers tolerate undecodable DER (fall back to "(unknown)").
            Ok(SignedCert::new(vec![0x30, 0x00]))
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

    fn env() -> Env<SignCsrPlan> {
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
            plan: SignCsrPlan {
                csr_der: vec![0x30, 0x00],
                root_cert_der: vec![0x30, 0x00],
                cdp_url: None,
                profiles: vec![CsrProfileChoice {
                    name: "tls-server".into(),
                    label: "[1] tls-server (validity=365 days)".into(),
                    validity_days: 365,
                    path_len: None,
                    preview: vec!["Subject: CN=example".into()],
                }],
                existing_serials: vec![],
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
        let result = sign_csr(&mut op, &mut vault, &mut arc, &env());
        let effects = log.borrow().clone();
        (result, effects)
    }

    #[test]
    fn happy_path_runs_effects_in_order() {
        let (result, effects) = run(false);
        assert!(result.is_ok(), "{:?}", result.err());
        assert_eq!(
            effects,
            vec![
                Effect::Choose,
                Effect::Confirm, // profile/document review
                Effect::CommitIntent,
                Effect::CollectQuorum,
                Effect::ReconfirmClock,
                Effect::Login,
                Effect::SignIntermediate,
                Effect::Confirm, // fingerprint verification
                Effect::CommitRecord,
                Effect::ExportShuttle,
            ]
        );
    }

    #[test]
    fn abort_at_quorum_never_signs_or_records() {
        let (result, effects) = run(true);
        assert!(result.is_err());
        assert_eq!(
            effects,
            vec![Effect::Choose, Effect::Confirm, Effect::CommitIntent]
        );
        assert!(!effects.contains(&Effect::Login));
        assert!(!effects.contains(&Effect::SignIntermediate));
        assert!(!effects.contains(&Effect::CommitRecord));
        assert!(!effects.contains(&Effect::ExportShuttle));
    }
}
