//! App-level orchestration: setup ticks, HSM detection, and rendering helpers.
//!
//! All ceremony operations now use the script engine in `ceremony/scripts/`.

use std::sync::mpsc;

use anodize_config::load as load_profile;
use anodize_hsm::create_backend;
use ratatui::{layout::Rect, Frame};

use crate::app::App;
use crate::components::status_bar::HwState;
use crate::helpers::*;
use crate::media;
use crate::modes::setup::SetupPhase;

impl App {
    // ── Shuttle scan tick ─────────────────────────────────────────────────────

    pub(crate) fn tick_wait_shuttle(&mut self) {
        // The shuttle USB is mounted/unmounted by systemd
        // (mount-anodize-shuttle.service + BindsTo= the udev device).
        // We just check whether profile.toml is readable at the known path.
        let profile_path = self.shuttle_mount.join("profile.toml");
        if !profile_path.is_file() {
            self.hw.shuttle_state = HwState::Absent;
            let diagnostics = media::usb_scan_diagnostics();
            self.set_status(format!(
                "Waiting for shuttle USB… ({diagnostics}) — insert USB with profile.toml."
            ));
            return;
        }

        #[cfg(feature = "dev-softhsm-usb")]
        if let Err(e) = configure_softhsm_from_shuttle(&self.shuttle_mount) {
            self.hw.shuttle_state = HwState::Error(format!("SoftHSM2: {e}"));
            self.set_status(format!("SoftHSM2 USB setup failed: {e}"));
            return;
        }

        let raw_bytes = std::fs::read(&profile_path).unwrap_or_default();
        match load_profile(&profile_path) {
            Ok(profile) => {
                self.hw.shuttle_state = HwState::Ready("mounted".into());
                self.profile = Some(profile);
                self.profile_toml_bytes = Some(raw_bytes);
                self.setup.phase = SetupPhase::ProfileLoaded;
                self.set_status("Profile loaded from USB.");
            }
            Err(e) => {
                self.hw.shuttle_state = HwState::Error(format!("parse: {e}"));
                self.set_status(format!("Profile parse error: {e}"));
            }
        }
    }

    // ── Disc scan tick ────────────────────────────────────────────────────────

    pub(crate) fn tick_wait_disc(&mut self, need_blank: bool) {
        // Check for a pending background scan result.
        if let Some(ref rx) = self.disc.disc_scan_rx {
            match rx.try_recv() {
                Ok(batch) => {
                    self.disc.disc_scan_rx = None;
                    self.process_disc_scan(batch, need_blank);
                    return;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    return; // scan still running — TUI stays responsive
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    tracing::error!("disc scan thread panicked or dropped sender");
                    self.disc.disc_scan_rx = None;
                    // fall through to spawn a new scan
                }
            }
        }

        // No scan in flight — spawn one in a background thread.
        let (tx, rx) = mpsc::channel();
        self.disc.disc_scan_rx = Some(rx);
        self.set_status("Scanning optical drive…");
        std::thread::spawn(move || {
            let drives = media::scan_optical_drives();
            let scans: Vec<_> = drives
                .iter()
                .map(|dev| (dev.clone(), media::scan_disc(dev)))
                .collect();
            let _ = tx.send(crate::disc::DiscScanBatch { drives, scans });
        });
    }

    /// Process results from a completed background disc scan.
    fn process_disc_scan(&mut self, batch: crate::disc::DiscScanBatch, need_blank: bool) {
        let mut rw_rejection: Option<String> = None;
        for (dev, result) in batch.scans {
            match result {
                Ok(scan) => {
                    let n = scan.sessions.len();
                    let cap_summary = &scan.capacity_summary;
                    let remaining = scan.sessions_remaining;
                    self.disc.sessions_remaining = Some(remaining);
                    if need_blank && n > 0 {
                        self.set_status(format!(
                            "Disc in {} has {n} session(s) — need a blank disc for migration.",
                            dev.display()
                        ));
                        continue;
                    }
                    if !need_blank && remaining < 2 {
                        self.set_status(format!(
                            "Disc in {} is full ({cap_summary}). \
                             Need 2 sessions for WAL. Insert a new disc.",
                            dev.display()
                        ));
                        continue;
                    }
                    self.disc.optical_dev = Some(dev.clone());
                    self.hw.disc_state =
                        HwState::Present(format!("{} ({cap_summary})", dev.display()));
                    if !need_blank {
                        self.disc.prior_sessions = scan.sessions;
                        self.disc.session_state =
                            load_session_state_from_sessions(&self.disc.prior_sessions);
                        if let Some(ref state) = self.disc.session_state {
                            tracing::info!(
                                version = state.version,
                                crl_number = state.crl_number,
                                custodians = state.sss.custodians.len(),
                                "STATE.JSON loaded from disc"
                            );
                        }
                    }
                    self.set_status(if need_blank {
                        format!(
                            "Blank disc in {} ({cap_summary}). Press [1] to write.",
                            dev.display()
                        )
                    } else if n == 0 {
                        format!(
                            "Blank disc in {} ({cap_summary}). Press [1] to continue.",
                            dev.display()
                        )
                    } else {
                        format!(
                            "Disc in {} — {n} prior session(s), {cap_summary}. \
                             Press [1] to continue.",
                            dev.display()
                        )
                    });
                    return;
                }
                Err(ref e) if e.contains("rewritable") => {
                    rw_rejection = Some(e.clone());
                }
                Err(_) => {}
            }
        }
        self.disc.optical_dev = None;
        self.hw.disc_state = HwState::Absent;
        if let Some(msg) = rw_rejection {
            self.set_status(msg);
        } else if batch.drives.is_empty() {
            self.set_status("No optical drive detected. Insert drive and disc.");
        } else {
            self.set_status(
                "No blank/appendable disc found. Insert write-once disc \
                 (BD-R, DVD-R, CD-R, or M-Disc).",
            );
        }
    }

    // ── HSM detection (no login — authentication deferred to Quorum phase) ──

    pub(crate) fn do_detect_hsm(&mut self) {
        let cfg = match &self.profile {
            Some(p) => &p.hsm,
            None => {
                self.set_status("No profile loaded");
                self.setup.phase = SetupPhase::ProfileLoaded;
                return;
            }
        };

        let backend = match create_backend(cfg.backend) {
            Ok(b) => b,
            Err(e) => {
                self.hw.hsm_state = HwState::Error(format!("{e}"));
                self.set_status(format!("HSM detection failed: {e}"));
                self.setup.phase = SetupPhase::ProfileLoaded;
                return;
            }
        };

        match backend.probe_token(&cfg.token_label) {
            Ok(true) => {
                let label = &cfg.token_label;
                self.hw.hsm_state = HwState::Present(format!("token={label}"));
                self.setup.phase = SetupPhase::WaitDisc;
                self.set_status(
                    "HSM detected. Insert write-once disc (BD-R, DVD-R, CD-R, or M-Disc) and press [1].",
                );
            }
            Ok(false) => {
                let label = &cfg.token_label;
                // Fresh HSM — the token slot is created during InitRoot.
                // Warn the operator but allow proceeding.
                self.hw.hsm_state =
                    HwState::Present(format!("backend OK, token '{label}' not yet initialized"));
                self.setup.phase = SetupPhase::HsmWarnTokenMissing;
                self.set_status(format!(
                    "WARNING: HSM token '{label}' does not exist yet. \
                     This is expected for a first-time InitRoot ceremony. \
                     Press [1] to continue or [Ctrl+C] to quit.",
                ));
            }
            Err(e) => {
                self.hw.hsm_state = HwState::Error(format!("{e}"));
                self.set_status(format!("HSM detection failed: {e}"));
                self.setup.phase = SetupPhase::ProfileLoaded;
            }
        }
    }

    // ── Content rendering (avoids borrow splitting) ──────────────────────────

    pub(crate) fn render_setup_content(&self, frame: &mut Frame, area: Rect) {
        self.setup.render_with_app(frame, area, self);
    }

    pub(crate) fn render_ceremony_content(&self, frame: &mut Frame, area: Rect) {
        // Script engine: render the current prompt when a run is active.
        if let Some(run) = self.ceremony_run.as_ref() {
            run.render(frame, area);
            return;
        }
        self.ceremony.render_with_app(frame, area, self);
    }
}
