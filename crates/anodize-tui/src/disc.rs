//! Disc / session management types extracted from `app.rs`.

use std::path::PathBuf;
use std::sync::mpsc::Receiver;

use anodize_config::state::SessionState;

use crate::media::SessionEntry;

/// Disc / session management state.
pub struct DiscContext {
    pub optical_dev: Option<PathBuf>,
    pub prior_sessions: Vec<SessionEntry>,
    pub sessions_remaining: Option<u16>,
    pub session_state: Option<SessionState>,
    /// Background disc scan result channel.  `Some` while a scan thread is
    /// running; the tick handler polls `try_recv` so the TUI stays responsive.
    pub disc_scan_rx: Option<Receiver<DiscScanBatch>>,
    /// Persistent error about the inserted disc (e.g. missing landing pad).
    /// Displayed prominently in the WaitDisc panel so the operator doesn't
    /// miss it.  Cleared when a valid disc is detected or the disc changes.
    pub disc_error: Option<String>,
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
            sessions_remaining: None,
            session_state: None,
            disc_scan_rx: None,
            disc_error: None,
        }
    }
}

/// Summary of a certificate found on disc, for the revocation picker.
#[derive(Debug, Clone)]
pub struct CertSummary {
    /// Uppercase hex string of the full certificate serial number.
    pub serial: String,
    pub subject: String,
    pub is_root: bool,
    pub already_revoked: bool,
}
