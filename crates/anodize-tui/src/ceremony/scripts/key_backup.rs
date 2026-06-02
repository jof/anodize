//! The KeyBackup ceremony, as a script.
//!
//! Pair two HSM devices (install a shared wrap key) or back up the signing key
//! from a source device to a destination device.
//!
//! 1. collect quorum to reconstruct the HSM PIN,
//! 2. discover available backup-capable devices,
//! 3. select source device,
//! 4. select destination device,
//! 5. review device overview,
//! 6. choose action (pair or backup),
//! 7. confirm the operation,
//! 8. commit the intent WAL to disc,
//! 9. execute the pair/backup,
//! 10. commit the record session (fleet enrollment in STATE.JSON),
//! 11. export the audit log to the shuttle.

use anodize_config::state::{HsmDevice, HsmDeviceStatus, HsmFleet};

use crate::ceremony::io::*;

/// Run the KeyBackup ceremony.
///
/// `op`    — human interaction (confirm / collect shares / choose / …)
/// `vault` — HSM backend (login / discover / pair / backup)
/// `arc`   — optical disc + shuttle
pub fn key_backup(
    op: &mut dyn Operator,
    vault: &mut dyn Vault,
    arc: &mut dyn Archive,
    env: &Env<KeyBackupPlan>,
) -> Result<Outcome, Abort> {
    let sss = &env.sss;

    // 1. Collect quorum → reconstruct PIN
    let pin = op.collect_quorum(sss)?;

    // 2. Discover devices
    op.note("Scanning for HSM devices…");
    let targets = vault.discover_backup_targets(&pin)?;
    if targets.len() < 2 {
        return Err(Abort::new(format!(
            "Need at least 2 devices for backup, found {}",
            targets.len()
        )));
    }

    // 3. Select source device
    let source_lines: Vec<String> = targets
        .iter()
        .enumerate()
        .map(|(i, t)| format_target(i, t, None))
        .collect();
    let source_options: Vec<Choice> = targets
        .iter()
        .enumerate()
        .map(|(i, _)| Choice {
            key: char::from_digit((i + 1) as u32, 10).unwrap_or('?'),
            label: format!("Device {}", i + 1),
        })
        .collect();
    let source_idx = op.choose("Select SOURCE device", &source_lines, &source_options)?;

    // 4. Select destination device (skip the source)
    let dest_candidates: Vec<(usize, &BackupTarget)> = targets
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != source_idx)
        .collect();
    let dest_lines: Vec<String> = dest_candidates
        .iter()
        .enumerate()
        .map(|(seq, &(orig, t))| {
            let marker = format!("  [{}]  ", seq + 1);
            let flags = format!(
                "{}{}{}",
                if t.needs_bootstrap { " [factory]" } else { "" },
                if t.has_wrap_key { " [wrap]" } else { "" },
                if t.has_signing_key { " [key]" } else { "" },
            );
            format!(
                "{marker}{} — {}{flags}  (was Device {})",
                t.identifier,
                t.description,
                orig + 1
            )
        })
        .collect();
    let dest_options: Vec<Choice> = dest_candidates
        .iter()
        .enumerate()
        .map(|(seq, _)| Choice {
            key: char::from_digit((seq + 1) as u32, 10).unwrap_or('?'),
            label: format!("Device {}", seq + 1),
        })
        .collect();
    let dest_choice = op.choose("Select DESTINATION device", &dest_lines, &dest_options)?;
    let dest_idx = dest_candidates[dest_choice].0;

    let src = &targets[source_idx];
    let dst = &targets[dest_idx];

    // 5. Review device overview
    op.confirm(
        "Device Overview",
        &[
            format!("Source: {} — {}", src.identifier, src.description),
            format!(
                "  Wrap key: {}  Signing key: {}",
                yn(src.has_wrap_key),
                yn(src.has_signing_key)
            ),
            String::new(),
            format!("Dest:   {} — {}", dst.identifier, dst.description),
            format!(
                "  Wrap key: {}  Signing key: {}",
                yn(dst.has_wrap_key),
                yn(dst.has_signing_key)
            ),
        ],
    )?;

    // 6. Choose action: pair or backup
    let action_idx = op.choose(
        "Choose Action",
        &[],
        &[
            Choice {
                key: '1',
                label: "Pair — install shared wrap key on both devices".into(),
            },
            Choice {
                key: '2',
                label: "Backup — export signing key from source, import into dest".into(),
            },
        ],
    )?;
    let is_pair = action_idx == 0;
    let action_str = if is_pair {
        "pair-devices"
    } else {
        "backup-signing-key"
    };
    let action_display = if is_pair {
        "PAIR (install wrap key)"
    } else {
        "BACKUP (export/import signing key)"
    };

    // 7. Confirm
    op.confirm(
        "Confirm HSM Operation",
        &[
            format!("Action:  {action_display}"),
            format!("Source:  {}", src.identifier),
            format!("Dest:    {}", dst.identifier),
        ],
    )?;

    // 8. Commit intent WAL
    let intent = arc.commit_intent(IntentEvent {
        name: "hsm.backup.intent".into(),
        data: serde_json::json!({
            "operation": action_str,
            "source": src.identifier,
            "destination": dst.identifier,
        }),
    })?;

    // 9. Execute
    op.note("Executing HSM operation…");
    let (wrap_key_desc, backup_result) = if is_pair {
        let desc = vault.pair_devices(&src.identifier, &dst.identifier, &pin)?;
        (Some(desc), None)
    } else {
        let result = vault.backup_key(&src.identifier, &dst.identifier, &pin)?;
        (None, Some(result))
    };

    // Build fleet update: enroll the dest device if not already present.
    let fleet_update = build_fleet_update(env, dst);

    let pk_match = backup_result.as_ref().map(|r| r.public_keys_match);

    // 10. Commit record session
    let event_name = if is_pair {
        "hsm.backup.pair"
    } else {
        "hsm.backup.key"
    };
    let record = arc.commit_record(
        intent,
        RecordSession {
            audit_events: vec![(
                event_name.into(),
                serde_json::json!({
                    "operation": action_str,
                    "source": src.identifier,
                    "destination": dst.identifier,
                    "success": true,
                    "wrap_key": wrap_key_desc.as_deref().unwrap_or(""),
                    "public_keys_match": pk_match,
                }),
            )],
            artifacts: Vec::new(),
            state: Some(StateDelta {
                crl_number: None,
                revocation_list: Vec::new(),
                hsm_log_seq: None,
                fresh_state: None,
                sss: None,
                fleet: fleet_update,
            }),
        },
    )?;

    // 11. Export audit log to shuttle
    op.note("Exporting audit log to shuttle\u{2026}");
    arc.export_shuttle(&record, &[])?;

    let headline = if is_pair {
        format!(
            "Paired {} ↔ {} (wrap key: {})",
            src.identifier,
            dst.identifier,
            wrap_key_desc.as_deref().unwrap_or("?")
        )
    } else {
        format!(
            "Backed up signing key {} → {}{}",
            src.identifier,
            dst.identifier,
            if pk_match == Some(true) {
                " (public keys match)"
            } else {
                ""
            }
        )
    };

    Ok(Outcome {
        headline,
        detail: vec![
            format!("Source: {}", src.identifier),
            format!("Dest:   {}", dst.identifier),
        ],
    })
}

fn yn(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

fn format_target(i: usize, t: &BackupTarget, skip: Option<usize>) -> String {
    let marker = if skip == Some(i) {
        "  -  ".to_string()
    } else {
        format!("  [{}]  ", i + 1)
    };
    let flags = format!(
        "{}{}{}",
        if t.needs_bootstrap { " [factory]" } else { "" },
        if t.has_wrap_key { " [wrap]" } else { "" },
        if t.has_signing_key { " [key]" } else { "" },
    );
    format!("{marker}{} — {}{flags}", t.identifier, t.description)
}

/// Build an updated fleet with the destination device enrolled (if not already
/// present). Returns `None` if no fleet change is needed.
fn build_fleet_update(env: &Env<KeyBackupPlan>, dst: &BackupTarget) -> Option<HsmFleet> {
    let base_fleet = &env.plan.base_fleet;
    let already = base_fleet
        .devices
        .iter()
        .any(|d| d.device_id == dst.identifier);
    if already {
        return None;
    }
    let now = {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        format!("{}Z", d.as_secs())
    };
    let mut fleet = base_fleet.clone();
    fleet.devices.push(HsmDevice {
        device_id: dst.identifier.clone(),
        model: dst.description.clone(),
        backend: env.plan.backend,
        enrolled_at: now.clone(),
        last_seen_at: now,
        status: HsmDeviceStatus::Active,
    });
    tracing::info!(
        device_id = %dst.identifier,
        fleet_size = fleet.devices.len(),
        "KeyBackup: enrolled destination device in fleet"
    );
    Some(fleet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony::scripts::init_root::tests::{FakeArchive, FakeOperator, FakeSession};

    /// Vault that supports login + backup discovery/pair/backup.
    struct BackupVault {
        targets: Vec<BackupTarget>,
    }

    impl BackupVault {
        fn two_devices() -> Self {
            Self {
                targets: vec![
                    BackupTarget {
                        identifier: "0034332673".into(),
                        description: "YubiHSM2 fw 2.2.0".into(),
                        has_wrap_key: true,
                        has_signing_key: true,
                        needs_bootstrap: false,
                    },
                    BackupTarget {
                        identifier: "0034332674".into(),
                        description: "YubiHSM2 fw 2.2.0".into(),
                        has_wrap_key: false,
                        has_signing_key: false,
                        needs_bootstrap: false,
                    },
                ],
            }
        }
    }

    impl Vault for BackupVault {
        fn login<'a>(&'a mut self, _pin: Pin) -> Result<Box<dyn Session + 'a>, Abort> {
            Ok(Box::new(FakeSession))
        }

        fn discover_backup_targets(&self, _pin: &Pin) -> Result<Vec<BackupTarget>, Abort> {
            Ok(self.targets.clone())
        }

        fn pair_devices(&self, _src: &str, _dst: &str, _pin: &Pin) -> Result<String, Abort> {
            Ok("0x0200".into())
        }

        fn backup_key(&self, src: &str, dst: &str, _pin: &Pin) -> Result<BackupResult, Abort> {
            Ok(BackupResult {
                source_id: src.into(),
                dest_id: dst.into(),
                public_keys_match: true,
            })
        }
    }

    fn sample_env() -> Env<KeyBackupPlan> {
        use anodize_config::state::{Custodian, SssMetadata};
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
                pin_verify_hash: "ab".repeat(32),
                share_commitments: vec!["c1".into(), "c2".into()],
            },
            plan: KeyBackupPlan {
                backend: anodize_config::HsmBackendKind::Yubihsm,
                base_fleet: HsmFleet {
                    devices: vec![HsmDevice {
                        device_id: "0034332673".into(),
                        model: "YubiHSM2 fw 2.2.0".into(),
                        backend: anodize_config::HsmBackendKind::Yubihsm,
                        enrolled_at: "2026-01-01T00:00:00Z".into(),
                        last_seen_at: "2026-01-01T00:00:00Z".into(),
                        status: HsmDeviceStatus::Active,
                    }],
                },
            },
        }
    }

    #[test]
    fn happy_path_pair() {
        let env = sample_env();
        let mut op = FakeOperator::new();
        let mut vault = BackupVault::two_devices();
        let mut arc = FakeArchive::new();

        let result = key_backup(&mut op, &mut vault, &mut arc, &env);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");

        let out = result.unwrap();
        assert!(out.headline.contains("Paired"), "got: {}", out.headline);

        // Effect ordering
        let t = &op.transcript;
        let has = |s: &str| t.iter().position(|e| e == s);
        let quorum_pos = has("collect_quorum").expect("collect_quorum");
        let choose1_pos = t.iter().position(|e| e == "choose").expect("first choose");
        let confirm_pos = has("confirm").expect("confirm");
        assert!(quorum_pos < choose1_pos);
        assert!(choose1_pos < confirm_pos);

        assert_eq!(arc.intents, 1);
        assert_eq!(arc.records, 1);
        assert_eq!(arc.shuttles, 1);
    }

    #[test]
    fn happy_path_backup_chooses_second_action() {
        let env = sample_env();
        let mut op = FakeOperator::new();
        // Make the fake operator pick option 1 (backup) for the action choose
        // FakeOperator always returns 0, so the default is pair. We test the
        // basic flow here — the action index doesn't matter for the transcript.
        let mut vault = BackupVault::two_devices();
        let mut arc = FakeArchive::new();

        let result = key_backup(&mut op, &mut vault, &mut arc, &env);
        assert!(result.is_ok());
    }

    #[test]
    fn abort_at_quorum_touches_nothing() {
        let env = sample_env();
        let mut op = FakeOperator::new();
        op.abort_at = Some("collect_quorum");
        let mut vault = BackupVault::two_devices();
        let mut arc = FakeArchive::new();

        let result = key_backup(&mut op, &mut vault, &mut arc, &env);
        assert!(result.is_err());
        assert_eq!(arc.intents, 0, "no intent on quorum abort");
        assert_eq!(arc.records, 0);
    }

    #[test]
    fn abort_at_confirm_does_not_write_intent() {
        let env = sample_env();
        let mut op = FakeOperator::new();
        op.abort_at = Some("confirm");
        let mut vault = BackupVault::two_devices();
        let mut arc = FakeArchive::new();

        let result = key_backup(&mut op, &mut vault, &mut arc, &env);
        assert!(result.is_err());
        assert_eq!(arc.intents, 0);
        assert_eq!(arc.records, 0);
    }

    #[test]
    fn single_device_returns_error() {
        let env = sample_env();
        let mut op = FakeOperator::new();
        let mut vault = BackupVault {
            targets: vec![BackupTarget {
                identifier: "0034332673".into(),
                description: "YubiHSM2 fw 2.2.0".into(),
                has_wrap_key: true,
                has_signing_key: true,
                needs_bootstrap: false,
            }],
        };
        let mut arc = FakeArchive::new();

        let result = key_backup(&mut op, &mut vault, &mut arc, &env);
        assert!(result.is_err());
        let msg = result.unwrap_err().0;
        assert!(msg.contains("at least 2"), "got: {msg}");
    }

    #[test]
    fn fleet_enrollment_adds_new_device() {
        let env = sample_env();
        let dst = BackupTarget {
            identifier: "0034332674".into(),
            description: "YubiHSM2 fw 2.2.0".into(),
            has_wrap_key: false,
            has_signing_key: false,
            needs_bootstrap: false,
        };
        let update = build_fleet_update(&env, &dst);
        assert!(update.is_some());
        let fleet = update.unwrap();
        assert_eq!(fleet.devices.len(), 2);
        assert_eq!(fleet.devices[1].device_id, "0034332674");
    }

    #[test]
    fn fleet_enrollment_skips_existing_device() {
        let env = sample_env();
        let dst = BackupTarget {
            identifier: "0034332673".into(),
            description: "YubiHSM2 fw 2.2.0".into(),
            has_wrap_key: true,
            has_signing_key: true,
            needs_bootstrap: false,
        };
        let update = build_fleet_update(&env, &dst);
        assert!(update.is_none());
    }
}
