//! The SignCsr ceremony, as a script.
//!
//! Sign an intermediate-CA CSR (selected from shuttle candidates) under a
//! chosen profile. Reads top to bottom:
//!
//! 0. operator selects a CSR file (if multiple candidates on shuttle),
//! 1. operator selects a certificate profile,
//! 2. confirms the rendered certificate document,
//! 3. the intent WAL (recording the CSR bytes) is committed to disc,
//! 4. the quorum reconstructs the PIN,
//! 5. the clock is re-confirmed,
//! 6. the HSM signs the intermediate certificate,
//! 7. the operator verifies the public key fingerprint and records the cert fingerprint,
//! 8. the record session (cert + STATE.JSON) is burned,
//! 9. the certificate is exported to the shuttle (dynamic filename, never overwrites).

use crate::ceremony::io::*;

/// Derive the output `.crt` filename from the input CSR filename.
/// Strips the extension and appends `.crt`.
fn output_filename(csr_filename: &str) -> String {
    let stem = csr_filename
        .rsplit_once('.')
        .map(|(s, _)| s)
        .unwrap_or(csr_filename);
    format!("{stem}.crt")
}

/// Run the SignCsr ceremony.
pub fn sign_csr(
    op: &mut dyn Operator,
    vault: &mut dyn Vault,
    arc: &mut dyn Archive,
    env: &Env<SignCsrPlan>,
) -> Result<Outcome, Abort> {
    let plan = &env.plan;
    if plan.candidates.is_empty() {
        return Err(Abort::new("No CSR candidates found on shuttle."));
    }

    // 0. Select the CSR file (auto-select if only one).
    let csr = if plan.candidates.len() == 1 {
        op.note(&format!("CSR: {}", plan.candidates[0].filename));
        &plan.candidates[0]
    } else {
        let csr_options: Vec<Choice> = plan
            .candidates
            .iter()
            .enumerate()
            .map(|(i, c)| Choice {
                key: char::from_digit((i + 1) as u32, 10).unwrap_or('?'),
                label: c.label.clone(),
            })
            .collect();
        let idx = op.choose(
            "Select CSR file",
            &["Multiple CSR files found on shuttle.".into()],
            &csr_options,
        )?;
        &plan.candidates[idx]
    };

    if csr.profiles.is_empty() {
        return Err(Abort::new("No [[cert_profiles]] defined in profile.toml."));
    }

    // 1. Select the certificate profile.
    let options: Vec<Choice> = csr
        .profiles
        .iter()
        .enumerate()
        .map(|(i, p)| Choice {
            key: char::from_digit((i + 1) as u32, 10).unwrap_or('?'),
            label: p.label.clone(),
        })
        .collect();
    let idx = op.choose(
        "Select certificate profile",
        &[format!("CSR: {}", csr.filename)],
        &options,
    )?;
    let profile = &csr.profiles[idx];

    // 2. Review the rendered certificate document.
    op.confirm("Sign CSR", &profile.preview)?;

    // 3. Commit intent (records the CSR bytes for the audit trail).
    let intent = arc.commit_intent(IntentEvent {
        name: "cert.csr.intent".into(),
        data: serde_json::json!({
            "operation": "sign-csr",
            "csr_filename": csr.filename,
            "csr_der_hex": hex::encode(&csr.csr_der),
            "profile_name": profile.name,
        }),
    })?;

    // 4-5. Unlock + re-confirm clock.
    let pin = op.collect_quorum(&env.sss)?;
    let when = op.reconfirm_clock()?;

    // 6. Sign the intermediate certificate.
    op.note("Signing intermediate certificate\u{2026}");
    let req = IntermediateReq {
        csr_der: csr.csr_der.clone(),
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

    // 7. Operator verifies the public key fingerprint (known from the CSR
    //    requester) and records the certificate fingerprint (new).
    let cert_fingerprint = crate::helpers::sha256_fingerprint(cert.der());
    let spki_fingerprint = crate::helpers::csr_spki_fingerprint(&csr.csr_der)
        .unwrap_or_else(|| "(CSR decode error)".into());
    let (subject, validity_days) = crate::helpers::cert_subject_and_validity_days(cert.der())
        .unwrap_or_else(|| ("(unknown)".into(), 0));
    op.confirm(
        "Verify public key & record certificate fingerprint",
        &[
            format!("Subject  : {subject}"),
            format!("Validity : {validity_days} days"),
            String::new(),
            "Public key fingerprint (SHA-256 of SPKI from CSR):".into(),
            format!("  {spki_fingerprint}"),
            "↑ Verify against the CSR requester's key fingerprint.".into(),
            "  To compute beforehand:".into(),
            "  openssl req -in csr.der -inform DER -noout -pubkey \\".into(),
            "    | openssl pkey -pubin -outform DER \\".into(),
            "    | openssl dgst -sha256 -c | tr 'a-f' 'A-F'".into(),
            String::new(),
            "Certificate fingerprint (SHA-256 of signed cert):".into(),
            format!("  {cert_fingerprint}"),
            "↑ Record this on your checklist — it is new.".into(),
        ],
    )?;

    let out_filename = output_filename(&csr.filename);
    op.note("Fingerprint confirmed. Writing record session to disc\u{2026}");

    // 8. Burn the record session.
    let record = arc.commit_record(
        intent,
        RecordSession {
            audit_events: vec![(
                "cert.intermediate.issue".into(),
                serde_json::json!({
                    "fingerprint": cert_fingerprint,
                    "profile": profile.name,
                    "output_filename": out_filename,
                }),
            )],
            artifacts: vec![Artifact {
                name: out_filename.to_ascii_uppercase(),
                bytes: cert.der().to_vec(),
            }],
            // Intermediate issuance does not change crl_number/revocation_list;
            // only the audit-chain head (and HSM seq) advance.
            state: Some(StateDelta {
                crl_number: None,
                revocation_list: Vec::new(),
                hsm_log_seq,
                fresh_state: None,
                sss: None,
                fleet: None,
            }),
        },
    )?;

    // 9. Export to shuttle.
    op.note("Exporting certificate to shuttle\u{2026}");
    arc.export_shuttle(&record, &[(&out_filename, cert.der())])?;

    Ok(Outcome {
        headline: format!("Certificate written as {out_filename} ({})", profile.name),
        detail: vec![format!("Fingerprint: {cert_fingerprint}")],
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

    fn test_sss() -> SssMetadata {
        SssMetadata {
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
        }
    }

    fn one_candidate() -> CsrCandidate {
        CsrCandidate {
            filename: "test.csr".into(),
            csr_der: vec![0x30, 0x00],
            label: "test.csr (CN=example)".into(),
            profiles: vec![CsrProfileChoice {
                name: "tls-server".into(),
                label: "[1] tls-server (validity=365 days)".into(),
                validity_days: 365,
                path_len: None,
                preview: vec!["Subject: CN=example".into()],
            }],
        }
    }

    fn env_single() -> Env<SignCsrPlan> {
        Env {
            sss: test_sss(),
            plan: SignCsrPlan {
                candidates: vec![one_candidate()],
                root_cert_der: vec![0x30, 0x00],
                cdp_url: None,
                existing_serials: vec![],
            },
        }
    }

    fn env_multi() -> Env<SignCsrPlan> {
        let mut c2 = one_candidate();
        c2.filename = "other.pem".into();
        c2.label = "other.pem (CN=other)".into();
        Env {
            sss: test_sss(),
            plan: SignCsrPlan {
                candidates: vec![one_candidate(), c2],
                root_cert_der: vec![0x30, 0x00],
                cdp_url: None,
                existing_serials: vec![],
            },
        }
    }

    fn run(env: &Env<SignCsrPlan>, abort_quorum: bool) -> (Result<Outcome, Abort>, Vec<Effect>) {
        let log: Log = Rc::new(RefCell::new(Vec::new()));
        let mut op = FakeOperator {
            log: log.clone(),
            abort_quorum,
        };
        let mut vault = FakeVault { log: log.clone() };
        let mut arc = FakeArchive { log: log.clone() };
        let result = sign_csr(&mut op, &mut vault, &mut arc, env);
        let effects = log.borrow().clone();
        (result, effects)
    }

    #[test]
    fn happy_path_single_csr_runs_effects_in_order() {
        let env = env_single();
        let (result, effects) = run(&env, false);
        assert!(result.is_ok(), "{:?}", result.err());
        // Single CSR → auto-selected (no Choose for CSR), one Choose for profile
        assert_eq!(
            effects,
            vec![
                Effect::Choose,  // profile selection
                Effect::Confirm, // document review
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
        let outcome = result.unwrap();
        assert!(
            outcome.headline.contains("test.crt"),
            "{}",
            outcome.headline
        );
    }

    #[test]
    fn multi_csr_shows_picker() {
        let env = env_multi();
        let (result, effects) = run(&env, false);
        assert!(result.is_ok(), "{:?}", result.err());
        // Multiple CSRs → Choose for CSR + Choose for profile
        assert_eq!(
            effects,
            vec![
                Effect::Choose,  // CSR file selection
                Effect::Choose,  // profile selection
                Effect::Confirm, // document review
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
        let env = env_single();
        let (result, effects) = run(&env, true);
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

    #[test]
    fn output_filename_strips_extension() {
        assert_eq!(output_filename("foo.csr"), "foo.crt");
        assert_eq!(
            output_filename("my-intermediate.der"),
            "my-intermediate.crt"
        );
        assert_eq!(output_filename("bar.pem"), "bar.crt");
        assert_eq!(output_filename("no-ext"), "no-ext.crt");
        assert_eq!(output_filename("multi.dots.csr"), "multi.dots.crt");
    }
}
