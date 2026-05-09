use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::Rect,
    text::Text,
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

use crate::action::{Action, Operation};
use crate::components::Component;

/// Operation-specific sub-states within the Planning phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanningState {
    // InitRoot
    CustodianSetup,
    ShareReveal,
    ShareVerify,
    KeyAction,
    // SignCsr
    LoadCsr,
    CsrPreview,
    // RevokeCert
    RevokeSelect,
    RevokeInput,
    RevokePreview,
    // IssueCrl
    CrlPreview,
    // RekeyShares
    RekeyQuorum,
    RekeyCustodianSetup,
    RekeyShareReveal,
    RekeyShareVerify,
    // MigrateDisc
    MigrateConfirm,
    WaitMigrateTarget,
    // KeyBackup
    BackupQuorum,
    BackupDevices,
    // ValidateDisc
    ValidateReport,
    ValidateHsmResult,
}

/// Pipeline phase for the ceremony state machine.
///
/// Phases: Select → Plan → Commit → Quorum → Execute → Export → Done
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CeremonyPhase {
    /// Pre-pipeline: choose an operation.
    OperationSelect,
    /// Phase 2: operation-specific configuration.
    Planning(PlanningState),
    /// Phase 3: write intent WAL to disc.
    Commit,
    /// Phase 4: collect SSS shares, reconstruct PIN.
    Quorum,
    /// Phase 4b: re-confirm clock before signing.
    ClockReconfirm,
    /// Phase 5: HSM crypto operation complete, verify result.
    Execute,
    /// Post-commit error: HSM/keygen/cert-build failed after intent write.
    /// Operator can [1] retry or [Esc] abort.
    PostCommitError,
    /// Phase 6a: writing record session to disc.
    BurningDisc,
    /// Phase 6b: disc written, shuttle copy pending.
    DiscDone,
    /// Terminal.
    Done,
}

pub struct CeremonyMode {
    pub state: CeremonyPhase,
}

impl CeremonyMode {
    pub fn new() -> Self {
        Self {
            state: CeremonyPhase::OperationSelect,
        }
    }

    /// Whether the user is entering text (affects 'q' quit and 'L' log toggle).
    pub fn in_text_entry(&self) -> bool {
        matches!(
            self.state,
            CeremonyPhase::Planning(PlanningState::RevokeInput)
                | CeremonyPhase::Planning(PlanningState::CustodianSetup)
                | CeremonyPhase::Planning(PlanningState::RekeyCustodianSetup)
                | CeremonyPhase::Planning(PlanningState::ShareVerify)
                | CeremonyPhase::Planning(PlanningState::RekeyShareVerify)
                | CeremonyPhase::Planning(PlanningState::RekeyQuorum)
                | CeremonyPhase::Planning(PlanningState::BackupQuorum)
                | CeremonyPhase::Quorum
        )
    }

    pub fn is_waiting_migrate_target(&self) -> bool {
        self.state == CeremonyPhase::Planning(PlanningState::WaitMigrateTarget)
    }

    pub fn is_writing_intent(&self) -> bool {
        self.state == CeremonyPhase::Commit
    }

    pub fn is_burning_disc(&self) -> bool {
        self.state == CeremonyPhase::BurningDisc
    }

    /// Whether the current phase holds ephemeral/unrecoverable state in RAM.
    /// Quit is blocked entirely during these phases.
    pub fn holds_ephemeral_state(&self) -> bool {
        !matches!(
            self.state,
            CeremonyPhase::OperationSelect | CeremonyPhase::Done | CeremonyPhase::DiscDone
        )
    }

    pub fn set_state_csr_preview(&mut self) {
        self.state = CeremonyPhase::Planning(PlanningState::CsrPreview);
    }

    pub fn set_state_wait_migrate_target(&mut self) {
        self.state = CeremonyPhase::Planning(PlanningState::WaitMigrateTarget);
    }

    /// Phase index for the phase bar.
    ///
    /// Maps to: 0=Select, 1=Plan, 2=Commit, 3=Quorum, 4=Execute, 5=Export
    pub fn phase_index(&self) -> usize {
        match self.state {
            // 0 — Select
            CeremonyPhase::OperationSelect => 0,
            // 1 — Plan (operation-specific configuration)
            CeremonyPhase::Planning(PlanningState::KeyAction)
            | CeremonyPhase::Planning(PlanningState::LoadCsr)
            | CeremonyPhase::Planning(PlanningState::CsrPreview)
            | CeremonyPhase::Planning(PlanningState::RevokeSelect)
            | CeremonyPhase::Planning(PlanningState::RevokeInput)
            | CeremonyPhase::Planning(PlanningState::RevokePreview)
            | CeremonyPhase::Planning(PlanningState::CrlPreview)
            | CeremonyPhase::Planning(PlanningState::CustodianSetup)
            | CeremonyPhase::Planning(PlanningState::ShareReveal)
            | CeremonyPhase::Planning(PlanningState::ShareVerify)
            | CeremonyPhase::Planning(PlanningState::RekeyCustodianSetup)
            | CeremonyPhase::Planning(PlanningState::RekeyShareReveal)
            | CeremonyPhase::Planning(PlanningState::RekeyShareVerify)
            | CeremonyPhase::Planning(PlanningState::MigrateConfirm)
            | CeremonyPhase::Planning(PlanningState::WaitMigrateTarget)
            | CeremonyPhase::Planning(PlanningState::BackupDevices)
            | CeremonyPhase::Planning(PlanningState::ValidateReport)
            | CeremonyPhase::Planning(PlanningState::ValidateHsmResult) => 1,
            // 2 — Commit (write intent WAL to disc)
            CeremonyPhase::Commit | CeremonyPhase::PostCommitError => 2,
            // 3 — Quorum (SSS share collection + PIN reconstruction)
            CeremonyPhase::Quorum
            | CeremonyPhase::Planning(PlanningState::RekeyQuorum)
            | CeremonyPhase::Planning(PlanningState::BackupQuorum) => 3,
            // 3→4 — Clock re-confirm before signing (shown as part of Quorum phase)
            CeremonyPhase::ClockReconfirm => 3,
            // 4 — Execute (HSM crypto operation, cert preview/verify)
            CeremonyPhase::Execute => 4,
            // 5 — Export (write record to disc + shuttle copy)
            CeremonyPhase::BurningDisc | CeremonyPhase::DiscDone | CeremonyPhase::Done => 5,
        }
    }

    /// Render with access to parent App state.
    pub fn render_with_app(&self, frame: &mut Frame, area: Rect, app: &crate::app::App) {
        let title = match self.state {
            CeremonyPhase::OperationSelect => "Select Operation",
            CeremonyPhase::Planning(PlanningState::KeyAction) => "Key Management",
            CeremonyPhase::Commit => "Committing Intent to Disc\u{2026}",
            CeremonyPhase::PostCommitError => "Post-Commit Error",
            CeremonyPhase::Execute => "Certificate Preview \u{2014} VERIFY FINGERPRINT",
            CeremonyPhase::BurningDisc => "Writing Session\u{2026}",
            CeremonyPhase::DiscDone => "Disc Session Written",
            CeremonyPhase::Planning(PlanningState::LoadCsr) => "Select Certificate Profile",
            CeremonyPhase::Planning(PlanningState::CsrPreview) => {
                "Certificate Review \u{2014} VERIFY BEFORE SIGNING"
            }
            CeremonyPhase::Planning(PlanningState::RevokeSelect) => {
                "Revoke Certificate \u{2014} Select Certificate"
            }
            CeremonyPhase::Planning(PlanningState::RevokeInput) => "Revoke Certificate",
            CeremonyPhase::Planning(PlanningState::RevokePreview) => {
                "Revocation Preview \u{2014} VERIFY BEFORE COMMITTING"
            }
            CeremonyPhase::Planning(PlanningState::CrlPreview) => "CRL Issuance Preview",
            CeremonyPhase::Planning(PlanningState::CustodianSetup) => {
                "Root Init \u{2014} Custodian Setup"
            }
            CeremonyPhase::Planning(PlanningState::ShareReveal) => {
                "Root Init \u{2014} Distribute Shares"
            }
            CeremonyPhase::Planning(PlanningState::ShareVerify) => {
                "Root Init \u{2014} Verify Shares"
            }
            CeremonyPhase::Planning(PlanningState::RekeyQuorum) => "Re-key Shares \u{2014} Quorum",
            CeremonyPhase::Planning(PlanningState::RekeyCustodianSetup) => {
                "Re-key Shares \u{2014} New Custodians"
            }
            CeremonyPhase::Planning(PlanningState::RekeyShareReveal) => {
                "Re-key Shares \u{2014} Distribute New Shares"
            }
            CeremonyPhase::Planning(PlanningState::RekeyShareVerify) => {
                "Re-key Shares \u{2014} Verify New Shares"
            }
            CeremonyPhase::Planning(PlanningState::MigrateConfirm) => {
                "Disc Migration \u{2014} Verify Chain"
            }
            CeremonyPhase::Planning(PlanningState::WaitMigrateTarget) => "Insert Blank Target Disc",
            CeremonyPhase::Planning(PlanningState::BackupQuorum) => {
                "Key Backup \u{2014} Reconstruct PIN"
            }
            CeremonyPhase::Planning(PlanningState::BackupDevices) => {
                "Key Backup \u{2014} Device Selection"
            }
            CeremonyPhase::Planning(PlanningState::ValidateReport) => "Disc Validation Report",
            CeremonyPhase::Planning(PlanningState::ValidateHsmResult) => {
                "HSM Audit Log Cross-Check"
            }
            CeremonyPhase::Quorum => "Quorum \u{2014} Reconstruct PIN",
            CeremonyPhase::ClockReconfirm => "Clock Re-confirm \u{2014} Verify Before Signing",
            CeremonyPhase::Done => "Ceremony Complete",
        };

        let content = self.build_body(app);

        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .style(crate::theme::BLOCK)
            .border_style(crate::theme::BORDER)
            .title_style(crate::theme::TITLE);
        let para = Paragraph::new(Text::from(content.join("\n")))
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((app.content_scroll, 0));
        frame.render_widget(para, area);
    }

    fn build_body(&self, app: &crate::app::App) -> Vec<String> {
        match &self.state {
            CeremonyPhase::OperationSelect => {
                let n_sessions = app.disc.prior_sessions.len();
                let disc_label = if n_sessions == 0 {
                    "  Blank disc \u{2014} no prior sessions.".into()
                } else {
                    format!("  Disc: {n_sessions} prior session(s).")
                };
                let state_label = if let Some(ref state) = app.disc.session_state {
                    let names: Vec<&str> = state
                        .sss
                        .custodians
                        .iter()
                        .map(|c| c.name.as_str())
                        .collect();
                    format!(
                        "  STATE.JSON: v{}, {}/{} SSS, custodians: {}",
                        state.version,
                        state.sss.threshold,
                        state.sss.total,
                        names.join(", ")
                    )
                } else if n_sessions > 0 {
                    "  STATE.JSON: not found (legacy disc)".into()
                } else {
                    "  STATE.JSON: (blank disc)".into()
                };
                vec![
                    String::new(),
                    disc_label,
                    state_label,
                    String::new(),
                    "  [1]  Init root CA           (SSS PIN split + key generation)".into(),
                    "  [2]  Sign intermediate CSR  (requires csr.der on shuttle)".into(),
                    "  [3]  Revoke a certificate   (adds entry + issues new CRL)".into(),
                    "  [4]  Issue CRL refresh      (re-signs current revocation list)".into(),
                    "  [5]  Re-key shares          (change custodians, keep same PIN)".into(),
                    "  [6]  Migrate disc           (copy all sessions to new disc)".into(),
                    "  [7]  Key backup             (pair HSMs + backup signing key)".into(),
                    "  [8]  Validate disc           (verify integrity + HSM audit)".into(),
                ]
            }

            CeremonyPhase::Planning(PlanningState::KeyAction) => {
                let label = app
                    .profile
                    .as_ref()
                    .map(|p| p.hsm.key_label.as_str())
                    .unwrap_or("?");
                vec![
                    String::new(),
                    format!("  Key label: {label:?}"),
                    String::new(),
                    "  [1]  Generate new P-384 keypair (fresh ceremony)".into(),
                    "  [2]  Use existing key by label  (resume)".into(),
                    String::new(),
                    "  Selecting either option writes an intent record to disc".into(),
                    "  before using the HSM. Do not remove the disc.".into(),
                ]
            }

            CeremonyPhase::Commit => vec![
                String::new(),
                "  Writing intent session to disc.".into(),
                "  HSM signing will begin after disc commit completes.".into(),
                "  Do not remove the disc or power off.".into(),
            ],

            CeremonyPhase::PostCommitError => {
                vec![
                    String::new(),
                    "  The intent session was written to disc, but the post-commit".into(),
                    "  operation (HSM bootstrap / key generation / cert build) failed.".into(),
                    String::new(),
                    format!("  Error: {}", app.status),
                    String::new(),
                    "  The disc is safe — only the intent WAL was written.".into(),
                    "  You may retry without re-burning the intent session.".into(),
                    String::new(),
                    "  [1]   Retry HSM + key operation".into(),
                    "  [Esc] Abort to operation select".into(),
                ]
            }

            CeremonyPhase::Planning(PlanningState::LoadCsr) => {
                let profiles = app
                    .profile
                    .as_ref()
                    .map(|p| p.cert_profiles.as_slice())
                    .unwrap_or(&[]);
                let mut lines = vec![
                    String::new(),
                    "  CSR loaded from USB (csr.der).".into(),
                    String::new(),
                    "  Select certificate profile:".into(),
                    String::new(),
                ];
                for (i, prof) in profiles.iter().enumerate() {
                    let path_str = prof
                        .path_len
                        .map(|n| format!("  path_len={n}"))
                        .unwrap_or_default();
                    lines.push(format!(
                        "  [{}]  {}  (validity={} days{})",
                        i + 1,
                        prof.name,
                        prof.validity_days,
                        path_str
                    ));
                }
                lines.push(String::new());
                lines.push("  [Esc]  Cancel".into());
                lines
            }

            CeremonyPhase::Planning(PlanningState::CsrPreview) => {
                let mut lines = if app.data.cert_preview_lines.is_empty() {
                    // Fallback if preview wasn't built (shouldn't happen).
                    let subject = app
                        .data
                        .csr_subject_display
                        .as_deref()
                        .unwrap_or("(unknown)");
                    let profile_name = app
                        .profile
                        .as_ref()
                        .and_then(|p| {
                            app.data
                                .selected_profile_idx
                                .map(|i| p.cert_profiles[i].name.as_str())
                        })
                        .unwrap_or("?");
                    vec![
                        String::new(),
                        format!("  CSR Subject : {subject}"),
                        format!("  Profile     : {profile_name}"),
                        String::new(),
                    ]
                } else {
                    app.data.cert_preview_lines.clone()
                };
                lines.push("  The CSR DER bytes are recorded in the intent audit log.".into());
                lines.push(String::new());
                lines.push("  [1]  Sign CSR and write to disc".into());
                lines.push("  [Esc]  Cancel".into());
                lines
            }

            CeremonyPhase::Execute => {
                let fp = app.data.fingerprint.as_deref().unwrap_or("(none)");
                let ca = app.profile.as_ref().map(|p| &p.ca);
                let (cn, org, country) = ca
                    .map(|c| {
                        (
                            c.common_name.as_str(),
                            c.organization.as_str(),
                            c.country.as_str(),
                        )
                    })
                    .unwrap_or(("?", "?", "?"));
                let has_crl = app.data.crl_der.is_some();
                let mut lines = vec![
                    String::new(),
                    format!("  Subject  : CN={cn}, O={org}, C={country}"),
                    "  Validity : 7305 days (20 years)".into(),
                    String::new(),
                    "  SHA-256 Fingerprint:".into(),
                    format!("  {fp}"),
                ];
                if has_crl {
                    lines.push(String::new());
                    lines.push("  Initial CRL #1 (empty) will be included in this session.".into());
                }
                lines.push(String::new());
                lines.push("  Compare this fingerprint against your paper checklist.".into());
                lines.push(String::new());
                lines.push("  [1]  Proceed to disc write".into());
                lines.push("  [Esc]  Abort".into());
                lines
            }

            CeremonyPhase::Planning(PlanningState::RevokeSelect) => {
                let certs = &app.data.cert_list;
                let cursor = app.data.cert_list_cursor;
                let rev_count = app.data.revocation_list.len();
                let mut lines = vec![
                    String::new(),
                    format!(
                        "  {} certificate(s) on disc, {} revoked.",
                        certs.len(),
                        rev_count
                    ),
                    String::new(),
                    "  Select a certificate to revoke:".into(),
                    String::new(),
                    format!(
                        "  {:<3} {:<12} {:<40} {:<14} {}",
                        "#", "Serial", "Subject", "Expires", "Status"
                    ),
                ];
                for (i, c) in certs.iter().enumerate() {
                    let marker = if i == cursor { ">" } else { " " };
                    let status = if c.already_revoked {
                        "(revoked)"
                    } else if c.is_root {
                        "root"
                    } else {
                        "active"
                    };
                    let subject = if c.subject.len() > 38 {
                        format!("{}...", &c.subject[..35])
                    } else {
                        c.subject.clone()
                    };
                    lines.push(format!(
                        " {marker}{:<3} {:<12} {:<40} {:<14} {}",
                        i + 1,
                        c.serial,
                        subject,
                        c.not_after,
                        status
                    ));
                }
                if certs.is_empty() {
                    lines.push("  (No certificates found on disc.)".into());
                }
                lines.push(String::new());
                lines.push(
                    "  [j/k] navigate  [Enter] select  [m] manual serial  [Esc] cancel".into(),
                );
                lines
            }

            CeremonyPhase::Planning(PlanningState::RevokeInput) => {
                let phase_hint = if app.data.revoke_phase == 0 {
                    "Enter serial number (digits only):"
                } else {
                    "Enter reason (optional, press Enter to skip):"
                };
                vec![
                    String::new(),
                    format!(
                        "  {} revoked cert(s) on record.",
                        app.data.revocation_list.len()
                    ),
                    String::new(),
                    format!("  {phase_hint}"),
                    String::new(),
                    format!("  Serial : {}", app.data.revoke_serial_buf),
                    format!("  Reason : {}", app.data.revoke_reason_buf),
                    String::new(),
                    "  Enter to confirm each field. Esc to go back.".into(),
                ]
            }

            CeremonyPhase::Planning(PlanningState::RevokePreview) => {
                let crl_num = app.data.crl_number.unwrap_or(0);
                let mut lines = vec![
                    String::new(),
                    format!("  New CRL number: {crl_num}"),
                    String::new(),
                    "  Updated revocation list:".into(),
                    String::new(),
                ];
                for entry in &app.data.revocation_list {
                    let reason = entry.reason.as_deref().unwrap_or("(no reason)");
                    lines.push(format!(
                        "    serial={}  time={}  reason={}",
                        entry.serial, entry.revocation_time, reason
                    ));
                }
                lines.push(String::new());
                lines.push("  [1]  Sign CRL and write to disc".into());
                lines.push("  [Esc]  Cancel".into());
                lines
            }

            CeremonyPhase::Planning(PlanningState::CrlPreview) => {
                let crl_num = app.data.crl_number.unwrap_or(0);
                let count = app.data.revocation_list.len();
                let mut lines = vec![
                    String::new(),
                    format!("  CRL number      : {crl_num}"),
                    format!("  Revoked entries : {count}"),
                    String::new(),
                ];
                if count == 0 {
                    lines.push("  (No certificates have been revoked.)".into());
                } else {
                    for entry in &app.data.revocation_list {
                        let reason = entry.reason.as_deref().unwrap_or("(no reason)");
                        lines.push(format!(
                            "    serial={}  time={}  reason={}",
                            entry.serial, entry.revocation_time, reason
                        ));
                    }
                }
                lines.push(String::new());
                lines.push("  [1]  Sign CRL and write to disc".into());
                lines.push("  [Esc]  Cancel".into());
                lines
            }

            CeremonyPhase::BurningDisc => vec![
                String::new(),
                "  Writing ISO 9660 session to optical disc\u{2026}".into(),
                String::new(),
                "  Please wait. Do not remove the disc or USB.".into(),
            ],

            CeremonyPhase::DiscDone => {
                let op_label = match app.current_op {
                    Some(Operation::InitRoot) => "Root init",
                    Some(Operation::SignCsr) => "Intermediate certificate",
                    Some(Operation::RevokeCert) => "Revocation record + CRL",
                    Some(Operation::IssueCrl) => "CRL refresh",
                    Some(Operation::RekeyShares) => "Re-key shares",
                    Some(Operation::MigrateDisc) => "Disc migration",
                    Some(Operation::KeyBackup) => "Key backup",
                    Some(Operation::ValidateDisc) => "Disc validation",
                    None => "Session",
                };
                let fp = app.data.fingerprint.as_deref().unwrap_or("(none)");
                let mut lines = vec![
                    String::new(),
                    format!("  {op_label} written to disc successfully."),
                ];
                if app.data.fingerprint.is_some() {
                    lines.push(String::new());
                    lines.push(format!("  Fingerprint: {fp}"));
                }
                lines.push(String::new());
                match app.current_op {
                    Some(Operation::MigrateDisc) => {
                        lines.push("  [Ctrl+C]  Quit (migration complete; no USB export)".into());
                    }
                    _ => {
                        lines.push("  [1]  Copy artifacts to shuttle".into());
                        lines.push(
                            "  [Ctrl+C]  Quit without shuttle copy (disc is the primary record)"
                                .into(),
                        );
                    }
                }
                lines
            }

            CeremonyPhase::Planning(PlanningState::CustodianSetup) => {
                vec![
                    String::new(),
                    "  Configure Shamir Secret Sharing for the HSM PIN.".into(),
                    "  The custodian setup component is active.".into(),
                    "  [Esc]  Abort".into(),
                ]
            }

            CeremonyPhase::Planning(PlanningState::ShareReveal) => {
                vec![
                    String::new(),
                    "  Shares are being distributed to custodians.".into(),
                    "  The share reveal component is active.".into(),
                    String::new(),
                    "  Hand the device to each custodian in turn.".into(),
                    "  Press [S] to reveal the share (one-way), [Enter] to confirm transcription."
                        .into(),
                ]
            }

            CeremonyPhase::Planning(PlanningState::ShareVerify) => {
                vec![
                    String::new(),
                    "  Verification round: EVERY custodian re-enters their share.".into(),
                    "  All shares must verify — not just a quorum.".into(),
                    "  This confirms transcription accuracy before HSM initialization.".into(),
                    String::new(),
                    "  The share input component is active.".into(),
                ]
            }

            CeremonyPhase::Planning(PlanningState::RekeyQuorum) => {
                let info = if let Some(ref state) = app.disc.session_state {
                    format!(
                        "  Current scheme: {}-of-{}.  Need {} shares to proceed.",
                        state.sss.threshold, state.sss.total, state.sss.threshold
                    )
                } else {
                    "  ERROR: no STATE.JSON loaded.".into()
                };
                vec![
                    String::new(),
                    "  Custodians: enter your shares to reconstruct the PIN.".into(),
                    info,
                    String::new(),
                    "  The share input component is active.".into(),
                    "  [Esc]  Abort".into(),
                ]
            }

            CeremonyPhase::Planning(PlanningState::RekeyCustodianSetup) => {
                vec![
                    String::new(),
                    "  Enter new custodian names for re-keyed shares.".into(),
                    "  The custodian setup component is active.".into(),
                    "  [Esc]  Abort".into(),
                ]
            }

            CeremonyPhase::Planning(PlanningState::RekeyShareReveal) => {
                vec![
                    String::new(),
                    "  New shares are being distributed to custodians.".into(),
                    String::new(),
                    "  Hand the device to each custodian in turn.".into(),
                    "  Press [S] to reveal the share (one-way), [Enter] to confirm transcription."
                        .into(),
                ]
            }

            CeremonyPhase::Planning(PlanningState::RekeyShareVerify) => {
                vec![
                    String::new(),
                    "  Verification round: EVERY new custodian re-enters their share.".into(),
                    "  All shares must verify — not just a quorum.".into(),
                    String::new(),
                    "  The share input component is active.".into(),
                ]
            }

            CeremonyPhase::Planning(PlanningState::MigrateConfirm) => {
                let chain_str = if app.data.migrate_chain_ok {
                    "OK \u{2714}"
                } else {
                    "FAIL \u{2718}"
                };
                let fp_str = app
                    .data
                    .migrate_source_fingerprint
                    .as_deref()
                    .unwrap_or("(none)");
                let mb = app.data.migrate_total_bytes / (1024 * 1024);
                vec![
                    String::new(),
                    format!("  Sessions  : {}", app.disc.prior_sessions.len()),
                    format!("  Audit chain: {chain_str}"),
                    format!("  Source hash: {fp_str}"),
                    format!(
                        "  Last session: {} MiB ({} bytes)",
                        mb, app.data.migrate_total_bytes
                    ),
                    String::new(),
                    "  Verify chain is OK before proceeding.".into(),
                    String::new(),
                    "  [1]  Eject old disc, insert blank new disc".into(),
                    "  [Esc]  Abort".into(),
                ]
            }

            CeremonyPhase::Quorum => {
                vec![
                    String::new(),
                    "  Collecting threshold shares to reconstruct the HSM PIN.".into(),
                    String::new(),
                    "  The share input component is active.".into(),
                    "  [Esc]  Abort".into(),
                ]
            }

            CeremonyPhase::ClockReconfirm => {
                let now = time::OffsetDateTime::now_utc()
                    .replace_nanosecond(0)
                    .expect("0ns is always valid");
                let time_str = now
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_else(|_| "unknown".into());
                vec![
                    String::new(),
                    "  HSM unlocked. Before signing, confirm the system clock is correct.".into(),
                    String::new(),
                    format!("  Current time:  {time_str}"),
                    String::new(),
                    "  Certificates will be timestamped with this time.".into(),
                    "  If the clock is wrong, quit and correct it before proceeding.".into(),
                    String::new(),
                    "  [1]  Clock is correct \u{2014} proceed with signing".into(),
                    "  [Esc]  Abort".into(),
                ]
            }

            CeremonyPhase::Planning(PlanningState::WaitMigrateTarget) => {
                let session_count = app.data.migrate_sessions.len();
                let disc_info = match &app.disc.optical_dev {
                    Some(dev) => format!("  Blank disc in {}. Press [1].", dev.display()),
                    None => "  Waiting for blank write-once disc\u{2026}".into(),
                };
                vec![
                    String::new(),
                    format!("  Ready to copy {session_count} session(s) to new disc."),
                    String::new(),
                    disc_info,
                    String::new(),
                    "  [1]  Write all sessions to new disc".into(),
                    "  [Esc]  Abort".into(),
                ]
            }

            CeremonyPhase::Planning(PlanningState::BackupQuorum) => {
                let info = if let Some(ref state) = app.disc.session_state {
                    format!(
                        "  Current scheme: {}-of-{}.  Need {} shares to proceed.",
                        state.sss.threshold, state.sss.total, state.sss.threshold
                    )
                } else {
                    "  ERROR: no STATE.JSON loaded.".into()
                };
                vec![
                    String::new(),
                    "  Custodians: enter your shares to reconstruct the HSM PIN.".into(),
                    "  The PIN is needed to authenticate to the HSMs for backup.".into(),
                    info,
                    String::new(),
                    "  The share input component is active.".into(),
                    "  [Esc]  Abort".into(),
                ]
            }

            CeremonyPhase::Planning(PlanningState::BackupDevices) => {
                // Delegate to the backup FSM's rendered lines.
                app.utilities.backup.lines.clone()
            }

            CeremonyPhase::Planning(PlanningState::ValidateReport)
            | CeremonyPhase::Planning(PlanningState::ValidateHsmResult) => {
                let mut lines = Vec::new();
                lines.push(String::new());
                for line in &app.data.validate_report_lines {
                    lines.push(format!("  {line}"));
                }
                lines.push(String::new());
                if matches!(
                    self.state,
                    CeremonyPhase::Planning(PlanningState::ValidateReport)
                ) {
                    if app.data.validate_has_hsm {
                        lines.push("  [1]  Run HSM audit log cross-check (requires quorum)".into());
                    }
                    lines.push("  [2]  Export VALIDATE.LOG to shuttle".into());
                    lines.push("  [Esc]  Done".into());
                } else {
                    lines.push("  [2]  Export VALIDATE.LOG to shuttle".into());
                    lines.push("  [Esc]  Done".into());
                }
                lines
            }

            CeremonyPhase::Done => {
                vec![
                    String::new(),
                    "  Ceremony complete.".into(),
                    String::new(),
                    match app.current_op {
                        Some(Operation::MigrateDisc) => {
                            "  Disc migration finished. Store new disc and archive old disc.".into()
                        }
                        _ => format!("  Shuttle : {}  \u{2713}", app.shuttle_mount.display()),
                    },
                    String::new(),
                    "  Remove and store both disc and USB separately.".into(),
                    "  The HSM holds the private key; no key material was written to disk.".into(),
                    String::new(),
                    "  [Ctrl+C]  Quit".into(),
                ]
            }
        }
    }
}

impl Component for CeremonyMode {
    fn handle_key_event(&mut self, key: KeyEvent) -> Action {
        match &self.state {
            CeremonyPhase::OperationSelect => match key.code {
                KeyCode::Char('1') => Action::SelectOperation(Operation::InitRoot),
                KeyCode::Char('2') => Action::SelectOperation(Operation::SignCsr),
                KeyCode::Char('3') => Action::SelectOperation(Operation::RevokeCert),
                KeyCode::Char('4') => Action::SelectOperation(Operation::IssueCrl),
                KeyCode::Char('5') => Action::SelectOperation(Operation::RekeyShares),
                KeyCode::Char('6') => Action::SelectOperation(Operation::MigrateDisc),
                KeyCode::Char('7') => Action::SelectOperation(Operation::KeyBackup),
                KeyCode::Char('8') => Action::SelectOperation(Operation::ValidateDisc),
                _ => Action::Noop,
            },

            CeremonyPhase::Planning(PlanningState::KeyAction) => match key.code {
                KeyCode::Char('1') => Action::SelectKeyAction(1),
                KeyCode::Char('2') => Action::SelectKeyAction(2),
                _ => Action::Noop,
            },

            CeremonyPhase::Commit => Action::Noop, // auto-advance on burn

            CeremonyPhase::PostCommitError => match key.code {
                KeyCode::Char('1') => Action::RetryPostCommit,
                KeyCode::Esc => Action::InitRootAbort,
                _ => Action::Noop,
            },

            CeremonyPhase::Planning(PlanningState::LoadCsr) => match key.code {
                KeyCode::Esc => Action::CeremonyCancel,
                KeyCode::Char(c) => {
                    if let Some(d) = c.to_digit(10) {
                        let idx = d as usize;
                        if idx >= 1 {
                            return Action::SelectCertProfile(idx - 1);
                        }
                    }
                    Action::Noop
                }
                _ => Action::Noop,
            },

            CeremonyPhase::Planning(PlanningState::CsrPreview) => match key.code {
                KeyCode::Char('1') => Action::ConfirmCsrSign,
                KeyCode::Esc => Action::CeremonyCancel,
                _ => Action::Noop,
            },

            CeremonyPhase::Execute => match key.code {
                KeyCode::Char('1') => Action::ConfirmCertBurn,
                KeyCode::Esc => Action::CeremonyCancel,
                _ => Action::Noop,
            },

            CeremonyPhase::Planning(PlanningState::RevokeSelect) => match key.code {
                KeyCode::Up | KeyCode::Char('k') => Action::RevokeSelectUp,
                KeyCode::Down | KeyCode::Char('j') => Action::RevokeSelectDown,
                KeyCode::Enter => Action::RevokeSelectConfirm,
                KeyCode::Char('m') => Action::RevokeSelectManual,
                KeyCode::Esc => Action::RevokeSelectCancel,
                _ => Action::Noop,
            },

            CeremonyPhase::Planning(PlanningState::RevokeInput) => match key.code {
                KeyCode::Char(c) => Action::RevokeInputChar(c),
                KeyCode::Backspace => Action::RevokeInputBackspace,
                KeyCode::Enter => Action::RevokeInputNextPhase,
                KeyCode::Esc => Action::RevokeInputCancel,
                _ => Action::Noop,
            },

            CeremonyPhase::Planning(PlanningState::RevokePreview) => match key.code {
                KeyCode::Char('1') => Action::ConfirmCrlSign,
                KeyCode::Esc => Action::CeremonyCancel,
                _ => Action::Noop,
            },

            CeremonyPhase::Planning(PlanningState::CrlPreview) => match key.code {
                KeyCode::Char('1') => Action::ConfirmCrlSign,
                KeyCode::Esc => Action::CeremonyCancel,
                _ => Action::Noop,
            },

            CeremonyPhase::BurningDisc => Action::Noop, // auto-advance on burn

            CeremonyPhase::DiscDone => {
                if key.code == KeyCode::Char('1') {
                    Action::DoWriteShuttle
                } else {
                    Action::Noop
                }
            }

            CeremonyPhase::Planning(PlanningState::MigrateConfirm) => match key.code {
                KeyCode::Char('1') => Action::ConfirmMigrate,
                KeyCode::Esc => Action::CeremonyCancel,
                _ => Action::Noop,
            },

            CeremonyPhase::Planning(PlanningState::WaitMigrateTarget) => match key.code {
                KeyCode::Char('1') => Action::ConfirmMigrateTarget,
                KeyCode::Esc => Action::CeremonyCancel,
                _ => Action::Noop,
            },

            CeremonyPhase::Planning(PlanningState::CustodianSetup) => Action::Noop, // handled by CustodianSetup component

            CeremonyPhase::Planning(PlanningState::ShareReveal) => Action::Noop, // handled by ShareReveal component
            CeremonyPhase::Planning(PlanningState::ShareVerify) => Action::Noop, // handled by ShareInput component

            CeremonyPhase::Planning(PlanningState::RekeyQuorum) => Action::Noop, // handled by ShareInput component
            CeremonyPhase::Planning(PlanningState::RekeyCustodianSetup) => Action::Noop, // handled by CustodianSetup component
            CeremonyPhase::Planning(PlanningState::RekeyShareReveal) => Action::Noop, // handled by ShareReveal component
            CeremonyPhase::Planning(PlanningState::RekeyShareVerify) => Action::Noop, // handled by ShareInput component

            CeremonyPhase::Planning(PlanningState::BackupQuorum) => Action::Noop, // handled by ShareInput component
            CeremonyPhase::Planning(PlanningState::BackupDevices) => {
                // Forward keys to the backup FSM via BackupExecute or Noop.
                // The backup FSM handles its own key dispatch in app.rs.
                Action::Noop
            }

            CeremonyPhase::Planning(PlanningState::ValidateReport) => match key.code {
                KeyCode::Char('1') => Action::ValidateRunHsmCheck,
                KeyCode::Char('2') => Action::ValidateExportReport,
                KeyCode::Esc => Action::CeremonyCancel,
                _ => Action::Noop,
            },

            CeremonyPhase::Planning(PlanningState::ValidateHsmResult) => match key.code {
                KeyCode::Char('2') => Action::ValidateExportReport,
                KeyCode::Esc => Action::CeremonyCancel,
                _ => Action::Noop,
            },

            CeremonyPhase::Quorum => Action::Noop, // handled by ShareInput component

            CeremonyPhase::ClockReconfirm => match key.code {
                KeyCode::Char('1') => Action::ReconfirmClock,
                KeyCode::Esc => Action::CeremonyCancel,
                _ => Action::Noop,
            },

            CeremonyPhase::Done => Action::Noop,
        }
    }

    fn render(&self, frame: &mut Frame, area: Rect) {
        // Fallback render without app context
        let block = Block::default()
            .borders(Borders::ALL)
            .title("Ceremony")
            .style(crate::theme::BLOCK)
            .border_style(crate::theme::BORDER)
            .title_style(crate::theme::TITLE);
        let para = Paragraph::new("  (Ceremony mode)").block(block);
        frame.render_widget(para, area);
    }
}
