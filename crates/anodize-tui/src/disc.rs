//! Disc / session management types extracted from `app.rs`.

use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::time::Instant;

use anodize_config::state::SessionState;

use crate::media::{BurnProgress, SessionEntry};

/// Disc / session management state.
pub struct DiscContext {
    pub optical_dev: Option<PathBuf>,
    pub prior_sessions: Vec<SessionEntry>,
    pub burn_rx: Option<Receiver<BurnProgress>>,
    pub burn_log: Vec<String>,
    pub burn_started: Option<Instant>,
    pub sessions_remaining: Option<u16>,
    pub intent_session_dir_name: Option<String>,
    pub pending_intent_session: Option<SessionEntry>,
    pub session_state: Option<SessionState>,
    /// Background disc scan result channel.  `Some` while a scan thread is
    /// running; the tick handler polls `try_recv` so the TUI stays responsive.
    pub disc_scan_rx: Option<Receiver<DiscScanBatch>>,
}

/// Result bundle from a background disc-scan thread.
pub struct DiscScanBatch {
    pub drives: Vec<PathBuf>,
    pub scans: Vec<(PathBuf, Result<crate::media::DiscScan, String>)>,
}

impl DiscContext {
    pub fn new() -> Self {
        Self {
            optical_dev: None,
            prior_sessions: Vec::new(),
            burn_rx: None,
            burn_log: Vec::new(),
            burn_started: None,
            sessions_remaining: None,
            intent_session_dir_name: None,
            pending_intent_session: None,
            session_state: None,
            disc_scan_rx: None,
        }
    }
}

/// Summary of a certificate found on disc, for the revocation picker.
#[derive(Debug, Clone)]
pub struct CertSummary {
    /// Uppercase hex string of the full certificate serial number.
    pub serial: String,
    pub subject: String,
    pub not_after: String,
    pub is_root: bool,
    pub already_revoked: bool,
}
