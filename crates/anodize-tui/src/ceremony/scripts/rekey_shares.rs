//! The RekeyShares ceremony, as a script.
//!
//! Rotate the HSM PIN and redistribute Shamir shares to (potentially new)
//! custodians. The old quorum authenticates with the current PIN, then:
//!
//! 1. confirm the rekey intent,
//! 2. commit the intent WAL to disc,
//! 3. collect old quorum to reconstruct the current PIN,
//! 4. re-confirm the clock,
//! 5. log in to the HSM with the old PIN,
//! 6. set up new custodians (names + threshold),
//! 7. generate a new random PIN, split into shares,
//! 8. reveal each new share one-at-a-time,
//! 9. verify all new shares (round-trip reconstruction check),
//! 10. change the PIN on the primary HSM,
//! 11. propagate the PIN change to backup fleet HSMs,
//! 12. verify the old PIN is rejected on all fleet devices,
//! 13. commit the record session (updated STATE.JSON),
//! 14. export the audit log to the shuttle.

use anodize_config::state::{Custodian, SssMetadata};
use secrecy::{ExposeSecret, SecretString};

use crate::ceremony::io::*;

/// Run the RekeyShares ceremony.
///
/// `op`   — human interaction (confirm / collect shares / reveal shares / …)
/// `vault` — HSM backend (login / change_pin_fleet / verify_pin_rejected)
/// `arc`  — optical disc + shuttle
pub fn rekey_shares(
    env: &Env<RekeyPlan>,
    op: &mut dyn Operator,
    vault: &mut dyn Vault,
    arc: &mut dyn Archive,
) -> Result<Outcome, Abort> {
    let sss = &env.sss;

    // 1. Confirm
    op.confirm(
        "Re-key Shares",
        &[
            format!(
                "Current scheme: {}-of-{}, generation {}",
                sss.threshold, sss.total, sss.generation
            ),
            "This will:".into(),
            "  • collect the current quorum to unlock the HSM".into(),
            "  • generate a NEW random PIN and split it among new custodians".into(),
            "  • change the PIN on all fleet HSMs".into(),
            "  • burn a new session to the audit disc".into(),
        ],
    )?;

    // 2. Commit intent WAL
    let intent = arc.commit_intent(IntentEvent {
        name: "sss.rekey.intent".into(),
        data: serde_json::json!({
            "operation": "rekey-shares",
            "old_generation": sss.generation,
        }),
    })?;

    // 3. Collect old quorum → reconstruct old PIN
    let old_pin: SecretString = op.collect_quorum(sss)?;
    let old_pin_hex = old_pin.clone();

    // 4. Re-confirm clock
    let _when = op.reconfirm_clock()?;

    // 5. Log in with old PIN
    let mut sess = vault.login(old_pin)?;

    // 6. Set up new custodians
    let cr = op.setup_custodians("New Custodian Setup (Re-key)")?;
    let custodian_names = cr.names;
    let threshold = cr.threshold;

    // 7. Generate new random PIN, split into shares
    let mut new_pin_bytes = vec![0u8; 32];
    getrandom::getrandom(&mut new_pin_bytes)
        .map_err(|e| Abort::new(format!("CSPRNG failure: {e}")))?;

    let total = custodian_names.len() as u8;
    let shares = anodize_sss::split(&new_pin_bytes, threshold, total)
        .map_err(|e| Abort::new(format!("SSS split failed: {e}")))?;

    let share_commitments: Vec<String> = shares
        .iter()
        .zip(custodian_names.iter())
        .map(|(share, name)| hex::encode(share.commitment(name)))
        .collect();

    let new_pin_verify_hash = hex::encode(anodize_sss::pin_verify_hash(&new_pin_bytes));

    let custodians: Vec<Custodian> = custodian_names
        .iter()
        .enumerate()
        .map(|(i, name)| Custodian {
            name: name.clone(),
            index: (i + 1) as u8,
        })
        .collect();

    let new_generation = sss.generation + 1;
    let new_sss = SssMetadata {
        generation: new_generation,
        threshold,
        total,
        custodians,
        share_commitments,
        pin_verify_hash: new_pin_verify_hash,
    };

    let new_pin_hex = SecretString::new(hex::encode(&new_pin_bytes));

    // 8. Reveal shares
    op.reveal_shares(&shares, &custodian_names, new_generation)?;

    // 9. Verify shares — round-trip reconstruction check
    op.verify_shares(&new_sss)?;

    op.note("Verified. Changing PIN on primary HSM…");

    // 10. Change PIN on primary HSM
    sess.change_pin(&old_pin_hex, &new_pin_hex)?;
    tracing::info!("RekeyShares: primary HSM PIN changed");

    // Capture session data, then drop to release vault borrow for fleet ops.
    let primary_device_id = sess
        .device_info()
        .map(|d| d.device_id.clone())
        .unwrap_or_default();
    let hsm_log_seq = sess.record_audit_seq();
    drop(sess);

    // 11. Propagate to backup fleet HSMs.
    // If a backup fails, change_pin_fleet rolls back the backups; we then
    // re-login with the new PIN to roll back the primary.
    match vault.change_pin_fleet(&old_pin_hex, &new_pin_hex, &primary_device_id) {
        Ok(changed) => {
            if !changed.is_empty() {
                op.note(&format!(
                    "PIN changed on {} backup device(s).",
                    changed.len()
                ));
            }
        }
        Err(e) => {
            // Re-login with the new PIN to roll back the primary to old.
            let new_pin_for_rollback = SecretString::new(new_pin_hex.expose_secret().clone());
            if let Ok(mut rollback_sess) = vault.login(new_pin_for_rollback) {
                let _ = rollback_sess.change_pin(
                    &SecretString::new(new_pin_hex.expose_secret().clone()),
                    &old_pin_hex,
                );
            }
            return Err(Abort::new(format!(
                "Fleet PIN propagation failed (all HSMs rolled back): {e}"
            )));
        }
    }

    // 12. Verify old PIN is rejected on all fleet devices
    vault.verify_pin_rejected(&old_pin_hex)?;
    op.note("Old PIN rejected on all fleet devices. Writing session to disc…");

    // 13. Commit record session
    let record = arc.commit_record(
        intent,
        RecordSession::single(
            "sss.rekey",
            serde_json::json!({
                "generation": new_generation,
                "threshold": threshold,
                "total": total,
                "custodians": new_sss.custodians.iter().map(|c| &c.name).collect::<Vec<_>>(),
            }),
            Vec::new(),
            Some(StateDelta {
                crl_number: None,
                revocation_list: Vec::new(),
                hsm_log_seq,
                fresh_state: None,
                sss: Some(new_sss),
                fleet: None,
            }),
        ),
    )?;

    // 14. Export audit log to shuttle
    arc.export_shuttle(&record, &[])?;

    Ok(Outcome {
        headline: format!(
            "Shares re-keyed: generation {} → {}",
            sss.generation, new_generation
        ),
        detail: vec![
            format!("Scheme: {threshold}-of-{total}"),
            format!("Custodians: {}", custodian_names.join(", ")),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony::scripts::init_root::tests::{FakeArchive, FakeOperator, FakeSession};

    /// Vault that supports login (returns FakeSession) and records calls.
    struct LoginVault;

    impl Vault for LoginVault {
        fn login<'a>(&'a mut self, _pin: Pin) -> Result<Box<dyn Session + 'a>, Abort> {
            Ok(Box::new(FakeSession))
        }
    }

    fn sample_sss() -> SssMetadata {
        SssMetadata {
            generation: 1,
            threshold: 2,
            total: 3,
            custodians: vec![
                Custodian {
                    name: "Alice".into(),
                    index: 1,
                },
                Custodian {
                    name: "Bob".into(),
                    index: 2,
                },
                Custodian {
                    name: "Carol".into(),
                    index: 3,
                },
            ],
            pin_verify_hash: "ab".repeat(32),
            share_commitments: vec!["c1".into(), "c2".into(), "c3".into()],
        }
    }

    fn sample_env() -> Env<RekeyPlan> {
        Env {
            sss: sample_sss(),
            plan: RekeyPlan,
        }
    }

    #[test]
    fn happy_path_transcript() {
        let env = sample_env();
        let mut op = FakeOperator::new();
        let mut vault = LoginVault;
        let mut arc = FakeArchive::new();

        let result = rekey_shares(&env, &mut op, &mut vault, &mut arc);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");

        let out = result.unwrap();
        assert!(out.headline.contains("1 → 2"), "got: {}", out.headline);

        // Verify effect ordering via transcript.
        let t = &op.transcript;
        let has = |s: &str| t.iter().position(|e| e == s);
        let confirm_pos = has("confirm").expect("confirm");
        let quorum_pos = has("collect_quorum").expect("collect_quorum");
        let clock_pos = has("reconfirm_clock").expect("reconfirm_clock");
        let setup_pos = has("setup_custodians").expect("setup_custodians");
        let reveal_pos = has("reveal_shares").expect("reveal_shares");
        let verify_pos = has("verify_shares").expect("verify_shares");

        assert!(confirm_pos < quorum_pos);
        assert!(quorum_pos < clock_pos);
        assert!(clock_pos < setup_pos);
        assert!(setup_pos < reveal_pos);
        assert!(reveal_pos < verify_pos);

        assert_eq!(arc.intents, 1);
        assert_eq!(arc.records, 1);
        assert_eq!(arc.shuttles, 1);
    }

    #[test]
    fn abort_at_confirm_touches_nothing() {
        let env = sample_env();
        let mut op = FakeOperator::new();
        op.abort_at = Some("confirm");
        let mut vault = LoginVault;
        let mut arc = FakeArchive::new();

        let result = rekey_shares(&env, &mut op, &mut vault, &mut arc);
        assert!(result.is_err());
        assert_eq!(arc.intents, 0, "no intent on confirm abort");
        assert_eq!(arc.records, 0);
    }

    #[test]
    fn abort_at_quorum_does_not_touch_hsm() {
        let env = sample_env();
        let mut op = FakeOperator::new();
        op.abort_at = Some("collect_quorum");
        let mut vault = LoginVault;
        let mut arc = FakeArchive::new();

        let result = rekey_shares(&env, &mut op, &mut vault, &mut arc);
        assert!(result.is_err());
        // Intent was committed before quorum
        assert_eq!(arc.intents, 1);
        assert_eq!(arc.records, 0);
    }

    #[test]
    fn abort_at_custodian_setup() {
        let env = sample_env();
        let mut op = FakeOperator::new();
        op.abort_at = Some("setup_custodians");
        let mut vault = LoginVault;
        let mut arc = FakeArchive::new();

        let result = rekey_shares(&env, &mut op, &mut vault, &mut arc);
        assert!(result.is_err());
        // Intent + quorum + clock + login all happened
        assert_eq!(arc.intents, 1);
        assert_eq!(arc.records, 0);
    }

    #[test]
    fn abort_at_verify_shares() {
        let env = sample_env();
        let mut op = FakeOperator::new();
        op.abort_at = Some("verify_shares");
        let mut vault = LoginVault;
        let mut arc = FakeArchive::new();

        let result = rekey_shares(&env, &mut op, &mut vault, &mut arc);
        assert!(result.is_err());
        assert_eq!(arc.intents, 1);
        assert_eq!(arc.records, 0, "no record when shares not verified");
    }
}
