//! The MigrateDisc ceremony, as a script.
//!
//! Copy the latest session from a source optical disc to a new blank disc.
//! No HSM interaction — this is a pure disc-management operation:
//!
//! 1. verify the audit chain on the source disc,
//! 2. confirm the source disc summary with the operator,
//! 3. operator ejects the source disc and inserts a blank target,
//! 4. write the migrated session files to the target disc.
//!
//! Because MigrateDisc is a copy (not a state mutation), it bypasses the
//! intent/record typestate — no WAL is needed.

use crate::ceremony::io::*;

fn migration_preview(plan: &MigrateDiscPlan) -> Vec<String> {
    let chain_str = if plan.chain_ok { "OK" } else { "FAIL" };
    let fp_str = plan.source_fingerprint.as_deref().unwrap_or("(none)");
    vec![
        format!("Sessions    : {}", plan.session_count),
        format!("Audit chain : {chain_str}"),
        format!("Source hash : {fp_str}"),
        format!("Last session: {} bytes", plan.total_bytes),
        String::new(),
        "Verify the chain status before proceeding.".into(),
    ]
}

/// Run the MigrateDisc ceremony.
///
/// `op`  — human interaction (confirm / wait for disc swap)
/// `arc` — optical disc (write migrated session)
pub fn migrate_disc(
    op: &mut dyn Operator,
    arc: &mut dyn Archive,
    env: &Env<MigrateDiscPlan>,
) -> Result<Outcome, Abort> {
    let plan = &env.plan;

    if plan.files.is_empty() {
        return Err(Abort::new("No sessions on source disc to migrate."));
    }

    // 1. Confirm source disc summary.
    op.confirm(
        "Disc Migration \u{2014} Verify Chain",
        &migration_preview(plan),
    )?;

    // 2. Operator ejects old disc, inserts blank target.
    op.wait_for_disc_swap(plan.session_count)?;

    // 3. Write session files to new disc.
    op.note("Writing session files to target disc\u{2026}");
    arc.write_migration(&plan.files)?;

    Ok(Outcome {
        headline: format!(
            "Disc migrated: {} session(s), {} bytes",
            plan.session_count, plan.total_bytes
        ),
        detail: vec![format!(
            "Audit chain: {}",
            if plan.chain_ok { "OK" } else { "FAIL" }
        )],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony::scripts::init_root::tests::{FakeArchive, FakeOperator};
    use anodize_config::state::SssMetadata;

    fn sample_plan() -> MigrateDiscPlan {
        MigrateDiscPlan {
            session_count: 3,
            chain_ok: true,
            source_fingerprint: Some("abc123".into()),
            total_bytes: 4096,
            files: vec![
                MigrationFile {
                    name: "AUDIT.LOG".into(),
                    data: b"audit-data".to_vec(),
                },
                MigrationFile {
                    name: "STATE.JSON".into(),
                    data: b"state-data".to_vec(),
                },
                MigrationFile {
                    name: "ROOT.CRT".into(),
                    data: b"cert-data".to_vec(),
                },
            ],
        }
    }

    fn sample_env() -> Env<MigrateDiscPlan> {
        Env {
            sss: SssMetadata {
                generation: 1,
                threshold: 2,
                total: 2,
                custodians: vec![],
                pin_verify_hash: String::new(),
                share_commitments: vec![],
            },
            plan: sample_plan(),
        }
    }

    #[test]
    fn happy_path_transcript() {
        let env = sample_env();
        let mut op = FakeOperator::new();
        let mut arc = FakeArchive::new();

        let result = migrate_disc(&mut op, &mut arc, &env);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");

        let out = result.unwrap();
        assert!(
            out.headline.contains("3 session(s)"),
            "got: {}",
            out.headline
        );
        assert!(out.headline.contains("4096 bytes"), "got: {}", out.headline);

        // Verify effect ordering.
        let t = &op.transcript;
        let confirm_pos = t.iter().position(|e| e == "confirm").expect("confirm");
        let swap_pos = t
            .iter()
            .position(|e| e == "wait_for_disc_swap")
            .expect("wait_for_disc_swap");
        assert!(confirm_pos < swap_pos);

        // Archive: no intent/record/shuttle, one migration.
        assert_eq!(arc.intents, 0);
        assert_eq!(arc.records, 0);
        assert_eq!(arc.shuttles, 0);
        assert_eq!(arc.migrations, 1);
    }

    #[test]
    fn abort_at_confirm_touches_nothing() {
        let env = sample_env();
        let mut op = FakeOperator::new();
        op.abort_at = Some("confirm");
        let mut arc = FakeArchive::new();

        let result = migrate_disc(&mut op, &mut arc, &env);
        assert!(result.is_err());
        assert_eq!(arc.migrations, 0, "no migration on confirm abort");
    }

    #[test]
    fn abort_at_disc_swap_does_not_write() {
        let env = sample_env();
        let mut op = FakeOperator::new();
        op.abort_at = Some("wait_for_disc_swap");
        let mut arc = FakeArchive::new();

        let result = migrate_disc(&mut op, &mut arc, &env);
        assert!(result.is_err());
        assert_eq!(arc.migrations, 0, "no migration when swap aborted");
    }

    #[test]
    fn empty_files_returns_error() {
        let mut env = sample_env();
        env.plan.files.clear();
        let mut op = FakeOperator::new();
        let mut arc = FakeArchive::new();

        let result = migrate_disc(&mut op, &mut arc, &env);
        assert!(result.is_err());
        assert!(result.unwrap_err().0.contains("No sessions"));
        assert_eq!(arc.migrations, 0);
        assert!(
            op.transcript.is_empty(),
            "no operator interaction on empty files"
        );
    }
}
