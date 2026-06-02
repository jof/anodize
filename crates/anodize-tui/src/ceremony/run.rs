//! The App-facing driver for a running ceremony.
//!
//! [`CeremonyRun`] owns the [`CeremonyHandle`] plus the small bit of UI state
//! the renderer needs (the current prompt, the share-input component, a spinner
//! counter). The App calls [`CeremonyRun::on_tick`] / [`CeremonyRun::on_key`]
//! and renders via [`CeremonyRun::render`] — it never touches threads or
//! channels directly.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{layout::Rect, Frame};
use std::path::PathBuf;
use std::time::SystemTime;

use anodize_config::state::SessionState;
use anodize_config::HsmBackendKind;

use crate::components::custodian_setup::CustodianSetup;
use crate::components::share_input::ShareInput;
use crate::components::share_reveal::ShareReveal;
use crate::media::SessionEntry;

use super::adapters::{DiscArchive, HsmVault};
use super::harness::{CeremonyHandle, ChannelOperator};
use super::io::{
    CrlPlan, Env, InitRootPlan, KeyBackupPlan, MigrateDiscPlan, RekeyPlan, RevokePlan, SignCsrPlan,
    ValidateDiscPlan,
};
use super::prompt::Prompt;
use super::scripts::init_root::init_root;
use super::scripts::issue_crl::issue_crl;
use super::scripts::key_backup::key_backup;
use super::scripts::migrate_disc::migrate_disc;
use super::scripts::rekey_shares::rekey_shares;
use super::scripts::revoke_cert::revoke_cert;
use super::scripts::sign_csr::sign_csr;
use super::scripts::validate_disc::validate_disc;
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
    pub base_state: Option<SessionState>,
}

/// A live ceremony, driven by the App's event loop.
pub struct CeremonyRun {
    handle: CeremonyHandle,
    prompt: Prompt,
    share_input: Option<ShareInput>,
    custodian_setup: Option<CustodianSetup>,
    share_reveal: Option<ShareReveal>,
    text_buf: String,
    spinner: usize,
    review_scroll: u16,
    finished: bool,
}

impl CeremonyRun {
    /// Spawn the IssueCrl ceremony. All configuration is moved into the worker
    /// thread, which builds the real adapters from it and runs the script.
    pub fn spawn_issue_crl(env: Env<CrlPlan>, vault: VaultConfig, archive: ArchiveConfig) -> Self {
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
                archive.base_state,
            );
            match issue_crl(&mut op, &mut hsm, &mut arc, &env) {
                Ok(outcome) => Prompt::Done(outcome),
                Err(abort) => Prompt::Aborted(abort.0),
            }
        });

        Self::from_handle(handle, share_input)
    }

    /// Spawn the RevokeCert ceremony.
    pub fn spawn_revoke_cert(
        env: Env<RevokePlan>,
        vault: VaultConfig,
        archive: ArchiveConfig,
    ) -> Self {
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
                archive.base_state,
            );
            match revoke_cert(&mut op, &mut hsm, &mut arc, &env) {
                Ok(outcome) => Prompt::Done(outcome),
                Err(abort) => Prompt::Aborted(abort.0),
            }
        });

        Self::from_handle(handle, share_input)
    }

    /// Spawn the InitRoot ceremony (no pre-existing SSS or state).
    pub fn spawn_init_root(
        env: Env<InitRootPlan>,
        vault: VaultConfig,
        archive: ArchiveConfig,
    ) -> Self {
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
                archive.base_state,
            );
            match init_root(&mut op, &mut hsm, &mut arc, &env) {
                Ok(outcome) => Prompt::Done(outcome),
                Err(abort) => Prompt::Aborted(abort.0),
            }
        });

        // No pre-existing ShareInput — components created lazily from prompts.
        Self::from_handle(handle, None)
    }

    /// Spawn the SignCsr ceremony.
    pub fn spawn_sign_csr(
        env: Env<SignCsrPlan>,
        vault: VaultConfig,
        archive: ArchiveConfig,
    ) -> Self {
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
                archive.base_state,
            );
            match sign_csr(&mut op, &mut hsm, &mut arc, &env) {
                Ok(outcome) => Prompt::Done(outcome),
                Err(abort) => Prompt::Aborted(abort.0),
            }
        });

        Self::from_handle(handle, share_input)
    }

    /// Spawn the RekeyShares ceremony.
    pub fn spawn_rekey_shares(
        env: Env<RekeyPlan>,
        vault: VaultConfig,
        archive: ArchiveConfig,
    ) -> Self {
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
                archive.base_state,
            );
            match rekey_shares(&env, &mut op, &mut hsm, &mut arc) {
                Ok(outcome) => Prompt::Done(outcome),
                Err(abort) => Prompt::Aborted(abort.0),
            }
        });

        Self::from_handle(handle, share_input)
    }

    /// Spawn the KeyBackup ceremony.
    pub fn spawn_key_backup(
        env: Env<KeyBackupPlan>,
        vault: VaultConfig,
        archive: ArchiveConfig,
    ) -> Self {
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
                archive.base_state,
            );
            match key_backup(&mut op, &mut hsm, &mut arc, &env) {
                Ok(outcome) => Prompt::Done(outcome),
                Err(abort) => Prompt::Aborted(abort.0),
            }
        });

        Self::from_handle(handle, share_input)
    }

    /// Spawn the RefreshDisc ceremony (dev-burn only). Writes a seed session.
    #[cfg(feature = "dev-burn")]
    pub fn spawn_refresh_disc(
        env: Env<super::io::RefreshDiscPlan>,
        archive: ArchiveConfig,
    ) -> Self {
        use super::scripts::refresh_disc::refresh_disc;
        let handle = CeremonyHandle::spawn(move |bridge| {
            let mut op = ChannelOperator::new(&bridge);
            let mut arc = DiscArchive::new(
                &bridge,
                archive.dev,
                archive.prior_sessions,
                archive.shuttle_mount,
                archive.staging,
                archive.profile_bytes,
                archive.timestamp,
                archive.sessions_remaining,
                archive.base_state,
            );
            match refresh_disc(&mut op, &mut arc, &env) {
                Ok(outcome) => Prompt::Done(outcome),
                Err(abort) => Prompt::Aborted(abort.0),
            }
        });

        Self::from_handle(handle, None)
    }

    /// Spawn the MigrateDisc ceremony. No HSM interaction — pure disc copy.
    pub fn spawn_migrate_disc(env: Env<MigrateDiscPlan>, archive: ArchiveConfig) -> Self {
        let handle = CeremonyHandle::spawn(move |bridge| {
            let mut op = ChannelOperator::new(&bridge);
            let mut arc = DiscArchive::new(
                &bridge,
                archive.dev,
                archive.prior_sessions,
                archive.shuttle_mount,
                archive.staging,
                archive.profile_bytes,
                archive.timestamp,
                archive.sessions_remaining,
                archive.base_state,
            );
            match migrate_disc(&mut op, &mut arc, &env) {
                Ok(outcome) => Prompt::Done(outcome),
                Err(abort) => Prompt::Aborted(abort.0),
            }
        });

        Self::from_handle(handle, None)
    }

    /// Spawn the ValidateDisc ceremony (read-only audit check, optional HSM
    /// cross-check with conditional quorum).
    pub fn spawn_validate_disc(
        env: Env<ValidateDiscPlan>,
        vault: VaultConfig,
        archive: ArchiveConfig,
    ) -> Self {
        // No pre-built ShareInput — quorum is conditional on the operator
        // choosing the HSM cross-check path.
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
                archive.base_state,
            );
            match validate_disc(&mut op, &mut hsm, &mut arc, &env) {
                Ok(outcome) => Prompt::Done(outcome),
                Err(abort) => Prompt::Aborted(abort.0),
            }
        });

        Self::from_handle(handle, None)
    }

    /// Block briefly for the first prompt (the script emits it immediately) and
    /// assemble the run state.
    fn from_handle(handle: CeremonyHandle, share_input: Option<ShareInput>) -> Self {
        let prompt = handle
            .recv()
            .unwrap_or_else(|| Prompt::Aborted("ceremony failed to start".into()));
        let finished = matches!(prompt, Prompt::Done(_) | Prompt::Aborted(_));

        // Lazily create interactive components from the initial prompt, matching
        // the logic in on_tick. Without this, prompts that need a component
        // (e.g. CustodianSetup for InitRoot) render blank.
        let mut custodian_setup = None;
        let mut share_reveal = None;
        let mut share_input = share_input;
        match &prompt {
            Prompt::CustodianSetup { title } => {
                custodian_setup = Some(CustodianSetup::new(title));
            }
            Prompt::RevealShares {
                shares,
                names,
                generation,
            } => {
                share_reveal = Some(ShareReveal::new(shares.clone(), names, *generation));
            }
            Prompt::VerifyShares { sss } => {
                let mut si = ShareInput::new(sss.clone(), 32);
                si.verify_all = true;
                share_input = Some(si);
            }
            Prompt::CollectShares { sss } if share_input.is_none() => {
                share_input = Some(ShareInput::new(sss.clone(), 32));
            }
            _ => {}
        }

        Self {
            handle,
            prompt,
            share_input,
            custodian_setup,
            share_reveal,
            text_buf: String::new(),
            spinner: 0,
            review_scroll: 0,
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
        matches!(
            self.prompt,
            Prompt::CollectShares { .. }
                | Prompt::TextInput { .. }
                | Prompt::CustodianSetup { .. }
                | Prompt::VerifyShares { .. }
        )
    }

    /// Advance the spinner and drain any prompts the worker has produced.
    /// Returns any informational messages (Note / Burning) that were consumed
    /// so the caller can forward them to the persistent log buffer.
    pub fn on_tick(&mut self) -> Vec<String> {
        self.spinner = self.spinner.wrapping_add(1);
        let mut notes = Vec::new();
        while let Some(p) = self.handle.poll() {
            if matches!(p, Prompt::Done(_) | Prompt::Aborted(_)) {
                self.finished = true;
            }
            // Capture informational prompts for the log buffer.
            match &p {
                Prompt::Note(msg) => notes.push(msg.clone()),
                Prompt::Burning { what, log } => {
                    if let Some(last) = log.last() {
                        notes.push(format!("[burn {what}] {last}"));
                    } else {
                        notes.push(format!("Burning {what}…"));
                    }
                }
                _ => {}
            }
            // Lazily create interactive components from prompt data.
            match &p {
                Prompt::CustodianSetup { title } => {
                    self.custodian_setup = Some(CustodianSetup::new(title));
                }
                Prompt::RevealShares {
                    shares,
                    names,
                    generation,
                } => {
                    self.share_reveal = Some(ShareReveal::new(shares.clone(), names, *generation));
                }
                Prompt::VerifyShares { sss } => {
                    let mut si = ShareInput::new(sss.clone(), 32);
                    si.verify_all = true;
                    self.share_input = Some(si);
                }
                Prompt::CollectShares { sss } if self.share_input.is_none() => {
                    self.share_input = Some(ShareInput::new(sss.clone(), 32));
                }
                _ => {}
            }
            self.prompt = p;
            self.text_buf.clear();
            self.review_scroll = 0;
        }
        notes
    }

    /// Feed a key to the current prompt, answering the worker if it maps to a
    /// response. Returns `true` if the key was consumed by the ceremony.
    pub fn on_key(&mut self, key: KeyEvent) -> bool {
        if self.finished {
            return false;
        }
        // Handle scroll keys for Review prompts before the response mapper.
        if matches!(self.prompt, Prompt::Review { .. }) {
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    self.review_scroll = self.review_scroll.saturating_sub(1);
                    return true;
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.review_scroll = self.review_scroll.saturating_add(1);
                    return true;
                }
                KeyCode::PageUp => {
                    self.review_scroll = self.review_scroll.saturating_sub(10);
                    return true;
                }
                KeyCode::PageDown => {
                    self.review_scroll = self.review_scroll.saturating_add(10);
                    return true;
                }
                _ => {}
            }
        }
        if let Some(response) = ui::key_to_response(
            &self.prompt,
            key,
            &mut self.share_input,
            &mut self.custodian_setup,
            &mut self.share_reveal,
            &mut self.text_buf,
        ) {
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
            self.custodian_setup.as_ref(),
            self.share_reveal.as_ref(),
            &self.text_buf,
            self.spinner,
            self.review_scroll,
        );
    }

    /// Join the worker thread (call after a terminal prompt).
    pub fn join(self) {
        self.handle.join();
    }
}
