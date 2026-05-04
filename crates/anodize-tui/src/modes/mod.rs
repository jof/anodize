pub mod setup;
pub mod ceremony;
pub mod utilities;

use crate::components::phase_bar::{PhaseStatus, PhaseStep};

/// Phase steps for the Setup mode.
pub fn setup_phases(current: usize) -> Vec<PhaseStep> {
    let labels = &["Clock", "USB", "Profile", "PIN", "Disc"];
    labels
        .iter()
        .enumerate()
        .map(|(i, &label)| PhaseStep {
            label,
            status: if i < current {
                PhaseStatus::Completed
            } else if i == current {
                PhaseStatus::Active
            } else {
                PhaseStatus::Pending
            },
        })
        .collect()
}

/// Phase steps for the Utilities mode (shows active sub-screen).
pub fn utility_phases(screen: &utilities::UtilScreen) -> Vec<PhaseStep> {
    use utilities::UtilScreen;
    let items: &[(&str, UtilScreen)] = &[
        ("System", UtilScreen::SystemInfo),
        ("Audit", UtilScreen::AuditLog),
        ("HSM", UtilScreen::HsmBrowser),
    ];
    items
        .iter()
        .map(|(label, s)| PhaseStep {
            label,
            status: if screen == s {
                PhaseStatus::Active
            } else {
                PhaseStatus::Pending
            },
        })
        .collect()
}

/// Phase steps for a ceremony operation.
pub fn ceremony_phases(op_label: &'static str, current: usize) -> Vec<PhaseStep> {
    let labels: &[&str] = &["Select", op_label, "Intent", "HSM Op", "Preview", "Burn", "USB", "Done"];
    labels
        .iter()
        .enumerate()
        .map(|(i, &label)| PhaseStep {
            label,
            status: if i < current {
                PhaseStatus::Completed
            } else if i == current {
                PhaseStatus::Active
            } else {
                PhaseStatus::Pending
            },
        })
        .collect()
}
