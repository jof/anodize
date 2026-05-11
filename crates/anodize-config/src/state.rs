//! Ceremony state persisted as `STATE.JSON` in each disc session directory.
//!
//! This file is the accumulated CA state, written alongside `AUDIT.LOG` in
//! every disc session. It is loaded and verified at preflight before any
//! ceremony operation begins.

use serde::{Deserialize, Serialize};

use crate::{HsmBackendKind, RevocationEntry};

/// Current schema version. Increment on breaking changes.
pub const STATE_VERSION: u32 = 1;

/// Well-known filename on the audit disc.
pub const STATE_FILENAME: &str = "STATE.JSON";

/// Well-known volume label for the shuttle USB stick.
pub const SHUTTLE_VOLUME_LABEL: &str = "ANODIZE-SHUTTLE";

// ── Ceremony state ──────────────────────────────────────────────────────────

/// Accumulated CA state, loaded from the latest disc session.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionState {
    /// Schema version for forward compatibility.
    pub version: u32,
    /// SHA-256 hex of the root certificate DER.
    pub root_cert_sha256: String,
    /// Root certificate DER, base64-encoded.
    pub root_cert_der_b64: String,
    /// Shamir's Secret Sharing metadata (absent before root-init).
    pub sss: SssMetadata,
    /// Current revocation list (empty before any revocations).
    #[serde(default)]
    pub revocation_list: Vec<RevocationEntry>,
    /// Next CRL number to issue.
    #[serde(default)]
    pub crl_number: u64,
    /// Entry hash of the last audit log record, for chain verification.
    pub last_audit_hash: String,
    /// Sequence number of the last consumed YubiHSM audit log entry.
    /// `None` when using a backend that has no internal audit log (e.g. SoftHSM).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_hsm_log_seq: Option<u64>,
    /// Fleet of enrolled HSM devices.
    pub fleet: HsmFleet,
}

/// SSS metadata stored on the audit disc.
/// The actual shares are held on paper by the custodians.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SssMetadata {
    /// Share generation counter. Starts at 1, incremented on every RekeyShares.
    pub generation: u64,
    /// Minimum shares needed to reconstruct (k).
    pub threshold: u8,
    /// Total shares distributed (n).
    pub total: u8,
    /// Named custodians with their share indices.
    pub custodians: Vec<Custodian>,
    /// SHA-256 hex of the HSM PIN bytes, for pre-login verification.
    pub pin_verify_hash: String,
    /// Per-share commitment hashes: SHA-256(index || custodian_name || y_bytes).
    /// One entry per custodian, in custodian order.
    pub share_commitments: Vec<String>,
}

/// A named custodian holding a share.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Custodian {
    /// Human-readable name for audit log attribution.
    pub name: String,
    /// Share index (x-coordinate), 1-indexed.
    pub index: u8,
}

// ── HSM Fleet ───────────────────────────────────────────────────────────────

/// Fleet of enrolled HSM devices tracked in STATE.JSON.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HsmFleet {
    pub devices: Vec<HsmDevice>,
}

/// A single HSM device enrolled in the fleet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmDevice {
    /// Backend-specific unique ID (USB serial for YubiHSM, token label for
    /// PKCS#11, ARN for CloudHSM, etc.).
    pub device_id: String,
    /// Human-readable model description, e.g. "YubiHSM2 fw 2.2.0".
    pub model: String,
    /// Which backend type this device uses. All fleet devices must share the
    /// same backend for now.
    pub backend: HsmBackendKind,
    /// ISO 8601 timestamp when this device was first enrolled.
    pub enrolled_at: String,
    /// ISO 8601 timestamp of the last ceremony session that used this device.
    pub last_seen_at: String,
    /// Current device status.
    pub status: HsmDeviceStatus,
}

/// Lifecycle status of an HSM device in the fleet.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state")]
pub enum HsmDeviceStatus {
    /// Device is active and available for ceremony operations.
    Active,
    /// Device has been removed from the fleet (kept for audit trail).
    Removed {
        /// ISO 8601 timestamp when removed.
        at: String,
        /// Human-readable reason for removal.
        reason: String,
    },
}

impl HsmFleet {
    /// Return device IDs of all active fleet members.
    pub fn active_device_ids(&self) -> Vec<&str> {
        self.devices
            .iter()
            .filter(|d| matches!(d.status, HsmDeviceStatus::Active))
            .map(|d| d.device_id.as_str())
            .collect()
    }
}

// ── Validation ──────────────────────────────────────────────────────────────

impl SessionState {
    /// Validate internal consistency of the state.
    pub fn validate(&self) -> Result<(), StateValidationError> {
        if self.version != STATE_VERSION {
            return Err(StateValidationError::VersionMismatch {
                expected: STATE_VERSION,
                got: self.version,
            });
        }

        // SHA-256 hex should be 64 chars
        if self.root_cert_sha256.len() != 64 {
            return Err(StateValidationError::InvalidHash("root_cert_sha256".into()));
        }

        // SSS consistency
        let sss = &self.sss;
        if sss.threshold < 2 {
            return Err(StateValidationError::SssInvalid(
                "threshold must be >= 2".into(),
            ));
        }
        if sss.total < sss.threshold {
            return Err(StateValidationError::SssInvalid(
                "total must be >= threshold".into(),
            ));
        }
        if sss.custodians.len() != sss.total as usize {
            return Err(StateValidationError::SssInvalid(format!(
                "custodian count {} != total {}",
                sss.custodians.len(),
                sss.total
            )));
        }
        if sss.share_commitments.len() != sss.total as usize {
            return Err(StateValidationError::SssInvalid(format!(
                "commitment count {} != total {}",
                sss.share_commitments.len(),
                sss.total
            )));
        }

        // Custodian indices should be 1..=total, unique
        let mut seen = vec![false; 256];
        for c in &sss.custodians {
            if c.index == 0 || c.index > sss.total {
                return Err(StateValidationError::SssInvalid(format!(
                    "custodian {:?} index {} out of range 1..={}",
                    c.name, c.index, sss.total
                )));
            }
            if seen[c.index as usize] {
                return Err(StateValidationError::SssInvalid(format!(
                    "duplicate custodian index {}",
                    c.index
                )));
            }
            seen[c.index as usize] = true;
        }

        Ok(())
    }

    /// Serialize to JSON bytes for disc writing.
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec_pretty(self).expect("SessionState is always serializable")
    }

    /// Parse from JSON bytes read from disc.
    pub fn from_json(data: &[u8]) -> Result<Self, StateValidationError> {
        let state: SessionState =
            serde_json::from_slice(data).map_err(StateValidationError::JsonParse)?;
        state.validate()?;
        Ok(state)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StateValidationError {
    #[error("STATE.JSON version mismatch: expected {expected}, got {got}")]
    VersionMismatch { expected: u32, got: u32 },
    #[error("invalid hash field: {0}")]
    InvalidHash(String),
    #[error("SSS metadata invalid: {0}")]
    SssInvalid(String),
    #[error("JSON parse error: {0}")]
    JsonParse(serde_json::Error),
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn example_state() -> SessionState {
        SessionState {
            version: STATE_VERSION,
            root_cert_sha256: "a".repeat(64),
            root_cert_der_b64: "MIIB...".into(),
            sss: SssMetadata {
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
                pin_verify_hash: "b".repeat(64),
                share_commitments: vec!["c".repeat(64), "d".repeat(64), "e".repeat(64)],
            },
            revocation_list: vec![],
            crl_number: 0,
            last_audit_hash: "f".repeat(64),
            last_hsm_log_seq: None,
            fleet: HsmFleet {
                devices: vec![HsmDevice {
                    device_id: "0034332673".into(),
                    model: "YubiHSM2 fw 2.2.0".into(),
                    backend: crate::HsmBackendKind::Yubihsm,
                    enrolled_at: "2026-01-01T00:00:00Z".into(),
                    last_seen_at: "2026-01-01T00:00:00Z".into(),
                    status: HsmDeviceStatus::Active,
                }],
            },
        }
    }

    #[test]
    fn valid_state_roundtrip() {
        let state = example_state();
        let json = state.to_json();
        let parsed = SessionState::from_json(&json).unwrap();
        assert_eq!(parsed.version, STATE_VERSION);
        assert_eq!(parsed.sss.custodians.len(), 3);
        assert_eq!(parsed.sss.custodians[0].name, "Alice");
    }

    #[test]
    fn wrong_version_rejected() {
        let mut state = example_state();
        state.version = 99;
        let json = serde_json::to_vec(&state).unwrap();
        let err = SessionState::from_json(&json).unwrap_err();
        assert!(matches!(err, StateValidationError::VersionMismatch { .. }));
    }

    #[test]
    fn threshold_too_low_rejected() {
        let mut state = example_state();
        state.sss.threshold = 1;
        let json = serde_json::to_vec(&state).unwrap();
        let err = SessionState::from_json(&json).unwrap_err();
        assert!(matches!(err, StateValidationError::SssInvalid(_)));
    }

    #[test]
    fn custodian_count_mismatch_rejected() {
        let mut state = example_state();
        state.sss.custodians.pop();
        let json = serde_json::to_vec(&state).unwrap();
        let err = SessionState::from_json(&json).unwrap_err();
        assert!(matches!(err, StateValidationError::SssInvalid(_)));
    }

    #[test]
    fn duplicate_index_rejected() {
        let mut state = example_state();
        state.sss.custodians[1].index = 1; // duplicate of Alice
        let json = serde_json::to_vec(&state).unwrap();
        let err = SessionState::from_json(&json).unwrap_err();
        assert!(matches!(err, StateValidationError::SssInvalid(_)));
    }

    #[test]
    fn fleet_active_device_ids_filters_removed() {
        let mut state = example_state();
        state.fleet.devices.push(HsmDevice {
            device_id: "0034332674".into(),
            model: "YubiHSM2 fw 2.2.0".into(),
            backend: crate::HsmBackendKind::Yubihsm,
            enrolled_at: "2026-02-01T00:00:00Z".into(),
            last_seen_at: "2026-02-01T00:00:00Z".into(),
            status: HsmDeviceStatus::Removed {
                at: "2026-03-01T00:00:00Z".into(),
                reason: "decommissioned".into(),
            },
        });
        let active = state.fleet.active_device_ids();
        assert_eq!(active, vec!["0034332673"]);
    }

    #[test]
    fn fleet_empty_roundtrip() {
        let mut state = example_state();
        state.fleet = HsmFleet::default();
        let json = state.to_json();
        let parsed = SessionState::from_json(&json).unwrap();
        assert!(parsed.fleet.devices.is_empty());
        assert!(parsed.fleet.active_device_ids().is_empty());
    }

    #[test]
    fn fleet_multi_device_roundtrip() {
        let mut state = example_state();
        state.fleet.devices.push(HsmDevice {
            device_id: "0034332674".into(),
            model: "YubiHSM2 fw 2.3.0".into(),
            backend: crate::HsmBackendKind::Yubihsm,
            enrolled_at: "2026-02-01T00:00:00Z".into(),
            last_seen_at: "2026-02-15T00:00:00Z".into(),
            status: HsmDeviceStatus::Active,
        });
        let json = state.to_json();
        let parsed = SessionState::from_json(&json).unwrap();
        assert_eq!(parsed.fleet.devices.len(), 2);
        assert_eq!(parsed.fleet.active_device_ids().len(), 2);
    }

    #[test]
    fn generation_roundtrip() {
        let mut state = example_state();
        state.sss.generation = 42;
        let json = state.to_json();
        let parsed = SessionState::from_json(&json).unwrap();
        assert_eq!(parsed.sss.generation, 42);
    }

    #[test]
    fn removed_device_preserves_reason() {
        let mut state = example_state();
        state.fleet.devices[0].status = HsmDeviceStatus::Removed {
            at: "2026-06-01T00:00:00Z".into(),
            reason: "tamper suspected".into(),
        };
        let json = state.to_json();
        let parsed = SessionState::from_json(&json).unwrap();
        match &parsed.fleet.devices[0].status {
            HsmDeviceStatus::Removed { at, reason } => {
                assert_eq!(at, "2026-06-01T00:00:00Z");
                assert_eq!(reason, "tamper suspected");
            }
            _ => panic!("expected Removed status"),
        }
    }
}
