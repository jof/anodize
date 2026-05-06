//! Audit log event name constants.
//!
//! Every event recorded in the audit log uses one of these names. The
//! hierarchical `phase.action` naming makes logs grep-friendly and maps
//! directly to the ceremony pipeline phases.

// ── Preflight ───────────────────────────────────────────────────────────────
pub const PREFLIGHT_CLOCK_CONFIRMED: &str = "ceremony.preflight.clock_confirmed";
pub const PREFLIGHT_SHUTTLE_MOUNTED: &str = "ceremony.preflight.shuttle_mounted";
pub const PREFLIGHT_SHUTTLE_VALIDATED: &str = "ceremony.preflight.shuttle_validated";
pub const PREFLIGHT_STATE_LOADED: &str = "ceremony.preflight.state_loaded";
pub const PREFLIGHT_RECOVERY_DETECTED: &str = "ceremony.preflight.recovery_detected";

// ── Planning ────────────────────────────────────────────────────────────────
pub const PLANNING_OPERATION_SELECTED: &str = "ceremony.planning.operation_selected";
pub const PLANNING_PARAMETERS_CONFIRMED: &str = "ceremony.planning.parameters_confirmed";

// ── Commit ──────────────────────────────────────────────────────────────────
pub const COMMIT_INTENT_WRITTEN: &str = "ceremony.commit.intent_written";
pub const COMMIT_INTENT_VERIFIED: &str = "ceremony.commit.intent_verified";

// ── Quorum ──────────────────────────────────────────────────────────────────
pub const QUORUM_SHARE_PROVIDED: &str = "ceremony.quorum.share_provided";
pub const QUORUM_SHARE_REJECTED: &str = "ceremony.quorum.share_rejected";
pub const QUORUM_PIN_RECONSTRUCTED: &str = "ceremony.quorum.pin_reconstructed";
pub const QUORUM_PIN_VERIFY_FAILED: &str = "ceremony.quorum.pin_verify_failed";

// ── Execute ─────────────────────────────────────────────────────────────────
pub const EXECUTE_HSM_LOGIN: &str = "ceremony.execute.hsm_login";
pub const EXECUTE_KEY_GENERATED: &str = "ceremony.execute.key_generated";
pub const EXECUTE_CERT_SIGNED: &str = "ceremony.execute.cert_signed";
pub const EXECUTE_CRL_SIGNED: &str = "ceremony.execute.crl_signed";
pub const EXECUTE_PIN_CHANGED: &str = "ceremony.execute.pin_changed";
pub const EXECUTE_HSM_LOGOUT: &str = "ceremony.execute.hsm_logout";
pub const EXECUTE_RECORD_WRITTEN: &str = "ceremony.execute.record_written";

// ── Export ───────────────────────────────────────────────────────────────────
pub const EXPORT_SHUTTLE_WRITTEN: &str = "ceremony.export.shuttle_written";

// ── Init (root ceremony only) ───────────────────────────────────────────────
pub const INIT_PIN_GENERATED: &str = "ceremony.init.pin_generated";
pub const INIT_SHARES_DISTRIBUTED: &str = "ceremony.init.shares_distributed";
pub const INIT_SHARES_VERIFIED: &str = "ceremony.init.shares_verified";

// ── Re-key ──────────────────────────────────────────────────────────────────
pub const REKEY_STARTED: &str = "ceremony.rekey.started";
pub const REKEY_NEW_SHARES_VERIFIED: &str = "ceremony.rekey.new_shares_verified";
pub const REKEY_COMPLETED: &str = "ceremony.rekey.completed";
