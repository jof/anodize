//! The App-facing driver for a running ceremony.
//!
//! [`CeremonyRun`] owns the [`CeremonyHandle`] plus the small bit of UI state
//! the renderer needs (the current prompt, the share-input component, a spinner
//! counter). The App calls [`CeremonyRun::on_tick`] / [`CeremonyRun::on_key`]
//! and renders via [`CeremonyRun::render`] — it never touches threads or
//! channels directly.

use crossterm::event::KeyEvent;
use ratatui::{layout::Rect, Frame};
use std::path::PathBuf;
use std::time::SystemTime;

use anodize_config::HsmBackendKind;

use crate::components::share_input::ShareInput;
use crate::media::SessionEntry;

use super::adapters::{DiscArchive, HsmVault};
use super::harness::{CeremonyHandle, ChannelOperator};
use super::io::Env;
use super::prompt::Prompt;
use super::scripts::issue_crl::issue_crl;
use super::ui;

/// HSM login configuration, captured from profile + fleet state before spawn.
pub struct VaultConfig {
    pub backend: HsmBackendKind,
    pub token_label: String,
    pub key_label: String,
    pub fleet_ids: Vec<String>,
}

/// Disc/shuttle configuration, captured from the live disc context before spawn.
pub struct ArchiveConfig {
    pub dev: Option<PathBuf>,
    pub prior_sessions: Vec<SessionEntry>,
    pub shuttle_mount: PathBuf,
    pub staging: PathBuf,
    pub profile_bytes: Vec<u8>,
    pub timestamp: SystemTime,
    pub sessions_remaining: Option<u16>,
}

/// A live ceremony, driven by the App's event loop.
pub struct CeremonyRun {
    handle: CeremonyHandle,
    prompt: Prompt,
    share_input: Option<ShareInput>,
    spinner: usize,
    finished: bool,
}

impl CeremonyRun {
    /// Spawn the IssueCrl ceremony. All configuration is moved into the worker
    /// thread, which builds the real adapters from it and runs the script.
    pub fn spawn_issue_crl(env: Env, vault: VaultConfig, archive: ArchiveConfig) -> Self {
        let share_input = Some(ShareInput::new(env.sss.clone(), 32));

        let handle = CeremonyHandle::spawn(move |bridge| {
            let mut op = ChannelOperator::new(&bridge);
            let mut hsm = HsmVault::new(
                vault.backend,
                vault.token_label,
                vault.key_label,
                vault.fleet_ids,
            );
            let mut arc = DiscArchive::new(
                &bridge,
                archive.dev,
                archive.prior_sessions,
                archive.shuttle_mount,
                archive.staging,
                archive.profile_bytes,
                archive.timestamp,
                archive.sessions_remaining,
            );
            match issue_crl(&mut op, &mut hsm, &mut arc, &env) {
                Ok(outcome) => Prompt::Done(outcome),
                Err(abort) => Prompt::Aborted(abort.0),
            }
        });

        // Block briefly for the first prompt (the script emits it immediately).
        let prompt = handle
            .recv()
            .unwrap_or_else(|| Prompt::Aborted("ceremony failed to start".into()));
        let finished = matches!(prompt, Prompt::Done(_) | Prompt::Aborted(_));

        Self {
            handle,
            prompt,
            share_input,
            spinner: 0,
            finished,
        }
    }

    /// True once a terminal prompt (Done/Aborted) has been reached.
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// True when the current prompt is collecting typed input (share words),
    /// so the App suppresses global single-key shortcuts (e.g. the `l` log
    /// toggle) while the operator types.
    pub fn wants_text_input(&self) -> bool {
        matches!(self.prompt, Prompt::CollectShares { .. })
    }

    /// Advance the spinner and drain any prompts the worker has produced.
    pub fn on_tick(&mut self) {
        self.spinner = self.spinner.wrapping_add(1);
        while let Some(p) = self.handle.poll() {
            if matches!(p, Prompt::Done(_) | Prompt::Aborted(_)) {
                self.finished = true;
            }
            self.prompt = p;
        }
    }

    /// Feed a key to the current prompt, answering the worker if it maps to a
    /// response. Returns `true` if the key was consumed by the ceremony.
    pub fn on_key(&mut self, key: KeyEvent) -> bool {
        if self.finished {
            return false;
        }
        if let Some(response) = ui::key_to_response(&self.prompt, key, &mut self.share_input) {
            self.handle.answer(response);
            true
        } else {
            false
        }
    }

    /// Render the current prompt into the content area.
    pub fn render(&self, frame: &mut Frame, area: Rect) {
        ui::render_prompt(
            frame,
            area,
            &self.prompt,
            self.share_input.as_ref(),
            self.spinner,
        );
    }

    /// Join the worker thread (call after a terminal prompt).
    pub fn join(self) {
        self.handle.join();
    }
}
