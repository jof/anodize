//! Hardware manager — extracted from `HwContext` in `app.rs`.
//!
//! Owns HSM, disc, and shuttle peripheral state plus polling logic.

use std::path::Path;

use anodize_hsm::{HsmActor, KeyHandle};

use crate::components::status_bar::HwState;

/// Hardware / peripheral polling state.
pub struct HardwareManager {
    pub hsm_state: HwState,
    pub disc_state: HwState,
    pub shuttle_state: HwState,
    pub actor: Option<HsmActor>,
    pub root_key: Option<KeyHandle>,
    /// Backend-specific device ID of the currently authenticated HSM
    /// (USB serial for YubiHSM, token label for SoftHSM).
    pub device_id: Option<String>,
}

impl HardwareManager {
    pub fn new() -> Self {
        Self {
            hsm_state: HwState::Absent,
            disc_state: HwState::Absent,
            shuttle_state: HwState::Absent,
            actor: None,
            root_key: None,
            device_id: None,
        }
    }

    /// Poll shuttle mount point presence.
    pub fn tick_shuttle(&mut self, shuttle_mount: &Path) {
        let shuttle_present = shuttle_mount.join("profile.toml").is_file();
        if shuttle_present {
            if self.shuttle_state == HwState::Absent {
                self.shuttle_state = HwState::Ready("mounted".into());
            }
        } else {
            self.shuttle_state = HwState::Absent;
        }
    }
}
