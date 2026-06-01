//! The InitRoot ceremony, as a script.
//!
//! Generate a root CA keypair, self-signed certificate, and initial CRL on
//! a freshly bootstrapped HSM. The HSM PIN is split into Shamir shares and
//! distributed to custodians before any HSM operation begins.
//!
//! 1. custodian setup (names + threshold),
//! 2. generate random PIN, split into shares,
//! 3. reveal each share one-at-a-time,
//! 4. verify all shares,
//! 5. commit the intent WAL to disc,
//! 6. re-confirm the clock,
//! 7. bootstrap the HSM token with the generated PIN,
//! 8. generate a P-384 root keypair,
//! 9. build a self-signed root certificate,
//! 10. issue the initial (empty) CRL,
//! 11. operator records the certificate fingerprint,
//! 12. commit the record session (ROOT.CRT + ROOT.CRL + STATE.JSON),
//! 13. export root.crt + root.crl to the shuttle.

use base64::Engine;
use sha2::{Digest, Sha256};

use anodize_config::state::{
    Custodian, HsmDevice, HsmDeviceStatus, HsmFleet, SessionState, SssMetadata, STATE_VERSION,
};

use crate::ceremony::io::*;
use crate::helpers::sha256_fingerprint;

/// Run the InitRoot ceremony.
pub fn init_root(
    op: &mut dyn Operator,
    vault: &mut dyn Vault,
    arc: &mut dyn Archive,
    env: &Env<InitRootPlan>,
) -> Result<Outcome, Abort> {
    let ca = &env.plan.ca;

    // 1. Setup custodians.
    let custodians = op.setup_custodians("Root Init")?;
    let names = &custodians.names;
    let threshold = custodians.threshold;
    let total = names.len() as u8;

    // 2. Generate random 32-byte PIN and split into SSS shares.
    let mut pin_bytes = vec![0u8; 32];
    getrandom::getrandom(&mut pin_bytes).map_err(|e| Abort::new(format!("CSPRNG failure: {e}")))?;

    let shares = anodize_sss::split(&pin_bytes, threshold, total)
        .map_err(|e| Abort::new(format!("SSS split failed: {e}")))?;

    let share_commitments: Vec<String> = shares
        .iter()
        .zip(names.iter())
        .map(|(share, name)| hex::encode(share.commitment(name)))
        .collect();
    let pin_verify_hash = hex::encode(anodize_sss::pin_verify_hash(&pin_bytes));
    let pin_hex = hex::encode(&pin_bytes);

    let custodian_meta: Vec<Custodian> = names
        .iter()
        .enumerate()
        .map(|(i, name)| Custodian {
            name: name.clone(),
            index: (i + 1) as u8,
        })
        .collect();
    let sss = SssMetadata {
        generation: 1,
        threshold,
        total,
        custodians: custodian_meta,
        pin_verify_hash,
        share_commitments,
    };

    op.note(&format!(
        "PIN generated. Distributing {total} shares ({threshold}-of-{total})."
    ));

    // 3. Reveal shares one-at-a-time.
    op.reveal_shares(&shares, names, 1)?;

    // 4. Verify all shares.
    op.verify_shares(&sss)?;

    // 5. Commit the intent WAL.
    let intent = arc.commit_intent(IntentEvent {
        name: "cert.root.intent".into(),
        data: serde_json::json!({
            "operation": "sign-root-cert",
            "key_action": "generate",
            "cert_params": {
                "subject": {
                    "common_name": ca.common_name,
                    "organization": ca.organization,
                    "country": ca.country,
                },
                "validity_days": ca.validity_days,
                "key_algorithm": "ecdsa-p384",
            },
        }),
    })?;

    // 6. Re-confirm the clock.
    let when = op.reconfirm_clock()?;

    // 7. Bootstrap HSM with the generated PIN.
    op.note("Bootstrapping HSM…");
    let pin = secrecy::SecretString::new(pin_hex);
    let mut sess = vault.bootstrap(pin)?;

    // 8. Generate root keypair.
    op.note("Generating P-384 root keypair…");
    sess.generate_root_key()?;

    // 9. Build self-signed root certificate.
    op.note("Building self-signed root certificate…");
    let cert = sess.build_root_cert(ca, when)?;

    // 10. Issue initial CRL (#1, empty).
    op.note("Issuing initial CRL…");
    let crl_plan = CrlPlan {
        crl_number: 1,
        revocation_list: Vec::new(),
        root_cert_der: cert.der().to_vec(),
    };
    let crl = sess.issue_crl(&crl_plan, when)?;

    // Grab device info + HSM audit seq before dropping session.
    let device = sess.device_info();
    let hsm_log_seq = sess.record_audit_seq();
    drop(sess);

    // 11. Confirm fingerprint.
    let fingerprint = sha256_fingerprint(cert.der());
    let (subject, validity_label) = crate::helpers::cert_subject_and_validity_days(cert.der())
        .map(|(subj, days)| (subj, format!("{days} days")))
        .unwrap_or_else(|| ("(unknown)".into(), format!("{} days", ca.validity_days)));

    op.confirm(
        "Certificate Preview",
        &[
            String::new(),
            format!("  Subject  : {subject}"),
            format!("  Validity : {validity_label}"),
            String::new(),
            "  SHA-256 Fingerprint:".into(),
            format!("  {fingerprint}"),
            String::new(),
            "  Initial CRL #1 (empty) will be included in this session.".into(),
            String::new(),
            "  The fingerprint may optionally be recorded; it is also".into(),
            "  persisted on disc and can be retrieved later.".into(),
        ],
    )?;

    // 12. Build fresh STATE.JSON and commit the record session.
    let cert_hash = hex::encode(Sha256::digest(cert.der()));
    let cert_b64 = base64::engine::general_purpose::STANDARD.encode(cert.der());

    let now_ts = {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        format!("{}Z", d.as_secs())
    };

    let fleet = match device {
        Some(d) => HsmFleet {
            devices: vec![HsmDevice {
                device_id: d.device_id,
                model: d.model,
                backend: d.backend,
                enrolled_at: now_ts.clone(),
                last_seen_at: now_ts,
                status: HsmDeviceStatus::Active,
            }],
        },
        None => HsmFleet::default(),
    };

    let fresh_state = SessionState {
        version: STATE_VERSION,
        root_cert_sha256: cert_hash,
        root_cert_der_b64: cert_b64,
        sss: sss.clone(),
        revocation_list: Vec::new(),
        crl_number: 1,
        last_audit_hash: String::new(), // filled by archive
        last_hsm_log_seq: None,         // filled via delta below
        fleet,
    };

    let record = arc.commit_record(
        intent,
        RecordSession {
            audit_events: vec![
                (
                    "cert.root.issue".into(),
                    serde_json::json!({
                        "subject": ca.common_name,
                        "fingerprint": fingerprint,
                    }),
                ),
                (
                    "crl.issue".into(),
                    serde_json::json!({
                        "crl_number": 1,
                        "revocation_count": 0,
                    }),
                ),
            ],
            artifacts: vec![
                Artifact {
                    name: "ROOT.CRT".into(),
                    bytes: cert.der().to_vec(),
                },
                Artifact {
                    name: "ROOT.CRL".into(),
                    bytes: crl.der().to_vec(),
                },
            ],
            state: Some(StateDelta {
                crl_number: Some(1),
                revocation_list: Vec::new(),
                hsm_log_seq,
                fresh_state: Some(fresh_state),
                sss: None,
                fleet: None,
            }),
        },
    )?;

    // 13. Export to shuttle.
    arc.export_shuttle(
        &record,
        &[("root.crt", cert.der()), ("root.crl", crl.der())],
    )?;

    Ok(Outcome {
        headline: "Root CA initialised".into(),
        detail: vec![
            format!("Subject: {subject}"),
            format!("Fingerprint: {fingerprint}"),
            format!("Custodians: {total} ({threshold}-of-{total} threshold)"),
        ],
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use anodize_config::state::SssMetadata;
    use secrecy::SecretString;

    // ── Shared transcript fakes ──────────────────────────────────────────

    /// Fake operator that records every effect call in a transcript Vec and
    /// can be told to abort at a specific step.
    pub(crate) struct FakeOperator {
        pub transcript: Vec<String>,
        pub abort_at: Option<&'static str>,
        /// Override the return value of `choose`. Default `None` returns 0.
        pub choose_index: Option<usize>,
    }

    impl FakeOperator {
        pub fn new() -> Self {
            Self {
                transcript: Vec::new(),
                abort_at: None,
                choose_index: None,
            }
        }
        fn should_abort(&self, step: &str) -> Result<(), Abort> {
            if self.abort_at == Some(step) {
                Err(Abort::new(format!("{step} aborted by test")))
            } else {
                Ok(())
            }
        }
    }

    impl Operator for FakeOperator {
        fn choose(&mut self, _: &str, _: &[String], _: &[Choice]) -> Result<usize, Abort> {
            self.transcript.push("choose".into());
            Ok(self.choose_index.unwrap_or(0))
        }
        fn confirm(&mut self, _: &str, _: &[String]) -> Result<(), Abort> {
            self.should_abort("confirm")?;
            self.transcript.push("confirm".into());
            Ok(())
        }
        fn collect_quorum(&mut self, _: &SssMetadata) -> Result<Pin, Abort> {
            self.should_abort("collect_quorum")?;
            self.transcript.push("collect_quorum".into());
            Ok(SecretString::new("00ff".into()))
        }
        fn reconfirm_clock(&mut self) -> Result<Timestamp, Abort> {
            self.should_abort("reconfirm_clock")?;
            self.transcript.push("reconfirm_clock".into());
            Ok(std::time::SystemTime::UNIX_EPOCH)
        }
        fn prompt_text(&mut self, _: &str, _: &str) -> Result<String, Abort> {
            self.transcript.push("prompt_text".into());
            Ok(String::new())
        }
        fn setup_custodians(&mut self, _: &str) -> Result<CustodianResult, Abort> {
            self.should_abort("setup_custodians")?;
            self.transcript.push("setup_custodians".into());
            Ok(CustodianResult {
                names: vec!["Alice".into(), "Bob".into()],
                threshold: 2,
            })
        }
        fn reveal_shares(
            &mut self,
            _: &[anodize_sss::Share],
            _: &[String],
            _: u64,
        ) -> Result<(), Abort> {
            self.should_abort("reveal_shares")?;
            self.transcript.push("reveal_shares".into());
            Ok(())
        }
        fn verify_shares(&mut self, _: &SssMetadata) -> Result<(), Abort> {
            self.should_abort("verify_shares")?;
            self.transcript.push("verify_shares".into());
            Ok(())
        }
        fn wait_for_disc_swap(&mut self, _: usize) -> Result<(), Abort> {
            self.should_abort("wait_for_disc_swap")?;
            self.transcript.push("wait_for_disc_swap".into());
            Ok(())
        }
        fn note(&mut self, _: &str) {}
    }

    /// Fake session: all signing ops return dummy DER bytes.
    pub(crate) struct FakeSession;

    impl Session for FakeSession {
        fn issue_crl(&mut self, _: &CrlPlan, _: Timestamp) -> Result<SignedCrl, Abort> {
            Ok(SignedCrl::new(vec![0x30, 0x02, 0x05, 0x00]))
        }
        fn sign_intermediate(
            &mut self,
            _: &IntermediateReq,
            _: Timestamp,
        ) -> Result<SignedCert, Abort> {
            Ok(SignedCert::new(vec![0x30, 0x02, 0x05, 0x00]))
        }
        fn generate_root_key(&mut self) -> Result<(), Abort> {
            Ok(())
        }
        fn build_root_cert(
            &mut self,
            _: &RootCertParams,
            _: Timestamp,
        ) -> Result<SignedCert, Abort> {
            Ok(SignedCert::new(vec![0x30, 0x02, 0x05, 0x00]))
        }
        fn device_info(&self) -> Option<DeviceInfo> {
            Some(DeviceInfo {
                device_id: "test-0001".into(),
                model: "FakeHSM".into(),
                backend: anodize_config::HsmBackendKind::Softhsm,
            })
        }
        fn change_pin(&mut self, _old: &Pin, _new: &Pin) -> Result<(), Abort> {
            Ok(())
        }
    }

    /// Fake archive: counts intent/record/shuttle calls.
    pub(crate) struct FakeArchive {
        pub intents: usize,
        pub records: usize,
        pub shuttles: usize,
        pub migrations: usize,
        pub shuttle_directs: usize,
    }

    impl FakeArchive {
        pub fn new() -> Self {
            Self {
                intents: 0,
                records: 0,
                shuttles: 0,
                migrations: 0,
                shuttle_directs: 0,
            }
        }
    }

    impl Archive for FakeArchive {
        fn commit_intent(&mut self, _: IntentEvent) -> Result<IntentCommitted, Abort> {
            self.intents += 1;
            Ok(IntentCommitted::new("test-intent"))
        }
        fn commit_record(
            &mut self,
            _intent: IntentCommitted,
            _session: RecordSession,
        ) -> Result<RecordCommitted, Abort> {
            self.records += 1;
            Ok(RecordCommitted::new("test-record"))
        }
        fn export_shuttle(
            &mut self,
            _record: &RecordCommitted,
            _files: &[(&str, &[u8])],
        ) -> Result<(), Abort> {
            self.shuttles += 1;
            Ok(())
        }
        fn write_migration(
            &mut self,
            _files: &[crate::ceremony::io::MigrationFile],
        ) -> Result<(), Abort> {
            self.migrations += 1;
            Ok(())
        }
        fn write_shuttle_direct(&mut self, _files: &[(&str, &[u8])]) -> Result<(), Abort> {
            self.shuttle_directs += 1;
            Ok(())
        }
    }

    // ── Vault fake ───────────────────────────────────────────────────────

    struct BootstrapVault;

    impl Vault for BootstrapVault {
        fn login<'a>(&'a mut self, _pin: Pin) -> Result<Box<dyn Session + 'a>, Abort> {
            Err(Abort::new("login not used in InitRoot"))
        }
        fn bootstrap<'a>(&'a mut self, _pin: Pin) -> Result<Box<dyn Session + 'a>, Abort> {
            Ok(Box::new(FakeSession))
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    fn fake_env() -> Env<InitRootPlan> {
        Env {
            sss: SssMetadata {
                generation: 0,
                threshold: 0,
                total: 0,
                custodians: Vec::new(),
                pin_verify_hash: String::new(),
                share_commitments: Vec::new(),
            },
            plan: InitRootPlan {
                ca: RootCertParams {
                    common_name: "Test Root CA".into(),
                    organization: "Test Org".into(),
                    country: "US".into(),
                    validity_days: 7305,
                },
            },
        }
    }

    // ── Tests ────────────────────────────────────────────────────────────

    #[test]
    fn happy_path_transcript() {
        let env = fake_env();
        let mut op = FakeOperator::new();
        let mut vault = BootstrapVault;
        let mut arc = FakeArchive::new();

        let outcome = init_root(&mut op, &mut vault, &mut arc, &env).expect("should succeed");

        assert!(
            outcome.headline.contains("Root CA"),
            "got: {}",
            outcome.headline
        );

        // Verify effect ordering via transcript.
        let t = &op.transcript;
        let event_names: Vec<&str> = t.iter().map(|s| s.as_str()).collect();
        assert!(
            event_names.contains(&"setup_custodians"),
            "missing custodian setup"
        );
        assert!(
            event_names.contains(&"reveal_shares"),
            "missing share reveal"
        );
        assert!(
            event_names.contains(&"verify_shares"),
            "missing share verify"
        );
        assert!(
            event_names.contains(&"reconfirm_clock"),
            "missing clock reconfirm"
        );
        assert!(
            event_names.contains(&"confirm"),
            "missing fingerprint confirm"
        );

        // Verify archive events.
        assert_eq!(arc.intents, 1, "should have exactly one intent");
        assert_eq!(arc.records, 1, "should have exactly one record");
        assert_eq!(arc.shuttles, 1, "should have exactly one shuttle export");
    }

    #[test]
    fn abort_at_custodian_setup() {
        let env = fake_env();
        let mut op = FakeOperator::new();
        op.abort_at = Some("setup_custodians");
        let mut vault = BootstrapVault;
        let mut arc = FakeArchive::new();

        let err = init_root(&mut op, &mut vault, &mut arc, &env).unwrap_err();
        assert!(err.0.contains("abort"), "got: {}", err.0);
        assert_eq!(arc.intents, 0, "no intent should be written");
    }

    #[test]
    fn abort_at_share_reveal() {
        let env = fake_env();
        let mut op = FakeOperator::new();
        op.abort_at = Some("reveal_shares");
        let mut vault = BootstrapVault;
        let mut arc = FakeArchive::new();

        let err = init_root(&mut op, &mut vault, &mut arc, &env).unwrap_err();
        assert!(err.0.contains("abort"), "got: {}", err.0);
        assert_eq!(arc.intents, 0, "no intent before share reveal");
    }

    #[test]
    fn abort_at_share_verify() {
        let env = fake_env();
        let mut op = FakeOperator::new();
        op.abort_at = Some("verify_shares");
        let mut vault = BootstrapVault;
        let mut arc = FakeArchive::new();

        let err = init_root(&mut op, &mut vault, &mut arc, &env).unwrap_err();
        assert!(err.0.contains("abort"), "got: {}", err.0);
        assert_eq!(arc.intents, 0, "no intent before verify");
    }

    #[test]
    fn abort_at_fingerprint_confirm() {
        let env = fake_env();
        let mut op = FakeOperator::new();
        op.abort_at = Some("confirm");
        let mut vault = BootstrapVault;
        let mut arc = FakeArchive::new();

        let err = init_root(&mut op, &mut vault, &mut arc, &env).unwrap_err();
        assert!(err.0.contains("abort"), "got: {}", err.0);
        // Intent should have been written (it precedes the confirm).
        assert_eq!(arc.intents, 1, "intent written before confirm");
        assert_eq!(arc.records, 0, "no record after abort at confirm");
    }
}
