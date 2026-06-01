//! RefreshDisc ceremony (dev-burn only).
//!
//! Writes a single seed session to the optical disc. Used during development
//! to initialise a blank disc so that subsequent ceremonies can append sessions.

use crate::ceremony::io::*;

/// Run the RefreshDisc ceremony.
///
/// `op`  — human interaction (confirm)
/// `arc` — optical disc (write seed session via migration path)
pub fn refresh_disc(
    op: &mut dyn Operator,
    arc: &mut dyn Archive,
    env: &Env<RefreshDiscPlan>,
) -> Result<Outcome, Abort> {
    let dir_name = &env.plan.dir_name;
    let body = vec![
        format!("Session name: {dir_name}"),
        String::new(),
        "This will write a seed session to the disc.".into(),
    ];
    op.confirm("Disc Refresh (dev)", &body)?;

    let seed_text = format!("anodize disc refresh\ncreated: {dir_name}\n");
    arc.write_migration(&[MigrationFile {
        name: "SEED.TXT".into(),
        data: seed_text.into_bytes(),
    }])?;

    Ok(Outcome {
        headline: "Disc refreshed".into(),
        detail: vec![format!("Seed session: {dir_name}")],
    })
}
