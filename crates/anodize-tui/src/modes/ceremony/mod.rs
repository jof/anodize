use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::Rect,
    text::Text,
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

use crate::action::{Action, Operation};
use crate::components::Component;

/// Ceremony sub-state — mirrors the old AppState but only for ceremony operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CeremonyState {
    OperationSelect,
    // Mode 1: Generate Root CA
    KeyAction,
    WritingIntent,
    CertPreview,
    BurningDisc,
    DiscDone,
    // Mode 2: Sign CSR
    LoadCsr,
    CsrPreview,
    // Mode 3: Revoke Cert + Issue CRL
    RevokeInput,
    RevokePreview,
    // Mode 4: Issue CRL refresh
    CrlPreview,
    // InitRoot flow
    InitRootCustodianSetup,
    InitRootShareReveal,
    InitRootShareVerify,
    // RekeyShares flow
    RekeyQuorum,
    RekeyCustodianSetup,
    RekeyShareReveal,
    RekeyShareVerify,
    // Mode 5: Migrate
    MigrateConfirm,
    WaitMigrateTarget,
    // Terminal
    Done,
}

pub struct CeremonyMode {
    pub state: CeremonyState,
}

impl CeremonyMode {
    pub fn new() -> Self {
        Self {
            state: CeremonyState::OperationSelect,
        }
    }

    /// Whether the user is entering text (affects 'q' quit and 'L' log toggle).
    pub fn in_text_entry(&self) -> bool {
        matches!(
            self.state,
            CeremonyState::RevokeInput
                | CeremonyState::InitRootCustodianSetup
                | CeremonyState::RekeyCustodianSetup
        )
    }

    pub fn is_waiting_migrate_target(&self) -> bool {
        self.state == CeremonyState::WaitMigrateTarget
    }

    pub fn is_writing_intent(&self) -> bool {
        self.state == CeremonyState::WritingIntent
    }

    pub fn is_burning_disc(&self) -> bool {
        self.state == CeremonyState::BurningDisc
    }

    pub fn set_state_csr_preview(&mut self) {
        self.state = CeremonyState::CsrPreview;
    }

    pub fn set_state_wait_migrate_target(&mut self) {
        self.state = CeremonyState::WaitMigrateTarget;
    }

    /// Human-readable label for the phase bar.
    pub fn op_label(&self) -> &'static str {
        match self.state {
            CeremonyState::OperationSelect => "Select",
            CeremonyState::KeyAction => "Key",
            CeremonyState::WritingIntent => "Intent",
            CeremonyState::CertPreview => "Preview",
            CeremonyState::BurningDisc => "Burn",
            CeremonyState::DiscDone => "Done",
            CeremonyState::LoadCsr => "CSR",
            CeremonyState::CsrPreview => "Preview",
            CeremonyState::RevokeInput => "Revoke",
            CeremonyState::RevokePreview => "Preview",
            CeremonyState::CrlPreview => "CRL",
            CeremonyState::InitRootCustodianSetup
            | CeremonyState::RekeyCustodianSetup => "Custodians",
            CeremonyState::InitRootShareReveal
            | CeremonyState::RekeyShareReveal => "Distribute",
            CeremonyState::InitRootShareVerify
            | CeremonyState::RekeyShareVerify => "Verify",
            CeremonyState::RekeyQuorum => "Quorum",
            CeremonyState::MigrateConfirm => "Verify",
            CeremonyState::WaitMigrateTarget => "Wait",
            CeremonyState::Done => "Done",
        }
    }

    /// Phase index for the phase bar.
    pub fn phase_index(&self) -> usize {
        match self.state {
            CeremonyState::OperationSelect => 0,
            CeremonyState::KeyAction
            | CeremonyState::LoadCsr
            | CeremonyState::RevokeInput
            | CeremonyState::InitRootCustodianSetup
            | CeremonyState::RekeyCustodianSetup => 1,
            CeremonyState::WritingIntent
            | CeremonyState::CsrPreview
            | CeremonyState::RevokePreview
            | CeremonyState::CrlPreview
            | CeremonyState::MigrateConfirm
            | CeremonyState::InitRootShareReveal
            | CeremonyState::RekeyQuorum => 2,
            CeremonyState::CertPreview
            | CeremonyState::WaitMigrateTarget
            | CeremonyState::InitRootShareVerify
            | CeremonyState::RekeyShareReveal
            | CeremonyState::RekeyShareVerify => 3,
            CeremonyState::BurningDisc => 4,
            CeremonyState::DiscDone | CeremonyState::Done => 5,
        }
    }

    /// Render with access to parent App state.
    pub fn render_with_app(
        &self,
        frame: &mut Frame,
        area: Rect,
        app: &crate::app::App,
    ) {
        let title = match self.state {
            CeremonyState::OperationSelect => "Select Operation",
            CeremonyState::KeyAction => "Key Management",
            CeremonyState::WritingIntent => "Committing Intent to Disc\u{2026}",
            CeremonyState::CertPreview => "Certificate Preview \u{2014} VERIFY FINGERPRINT",
            CeremonyState::BurningDisc => "Writing Session\u{2026}",
            CeremonyState::DiscDone => "Disc Session Written",
            CeremonyState::LoadCsr => "Select Certificate Profile",
            CeremonyState::CsrPreview => "CSR Review \u{2014} VERIFY BEFORE SIGNING",
            CeremonyState::RevokeInput => "Revoke Certificate",
            CeremonyState::RevokePreview => "Revocation Preview \u{2014} VERIFY BEFORE COMMITTING",
            CeremonyState::CrlPreview => "CRL Issuance Preview",
            CeremonyState::InitRootCustodianSetup => "Root Init \u{2014} Custodian Setup",
            CeremonyState::InitRootShareReveal => "Root Init \u{2014} Distribute Shares",
            CeremonyState::InitRootShareVerify => "Root Init \u{2014} Verify Shares",
            CeremonyState::RekeyQuorum => "Re-key Shares \u{2014} Quorum",
            CeremonyState::RekeyCustodianSetup => "Re-key Shares \u{2014} New Custodians",
            CeremonyState::RekeyShareReveal => "Re-key Shares \u{2014} Distribute New Shares",
            CeremonyState::RekeyShareVerify => "Re-key Shares \u{2014} Verify New Shares",
            CeremonyState::MigrateConfirm => "Disc Migration \u{2014} Verify Chain",
            CeremonyState::WaitMigrateTarget => "Insert Blank Target Disc",
            CeremonyState::Done => "Ceremony Complete",
        };

        let content = self.build_body(app);

        let block = Block::default().borders(Borders::ALL).title(title);
        let para = Paragraph::new(Text::from(content.join("\n")))
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((app.content_scroll, 0));
        frame.render_widget(para, area);
    }

    fn build_body(&self, app: &crate::app::App) -> Vec<String> {
        match &self.state {
            CeremonyState::OperationSelect => {
                let n_sessions = app.prior_sessions.len();
                let disc_label = if n_sessions == 0 {
                    "  Blank disc \u{2014} no prior sessions.".into()
                } else {
                    format!("  Disc: {n_sessions} prior session(s).")
                };
                let state_label = if let Some(ref state) = app.session_state {
                    let names: Vec<&str> = state.sss.custodians.iter().map(|c| c.name.as_str()).collect();
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
                    "  [1]  Generate new root CA (fresh or resume key)".into(),
                    "  [2]  Sign intermediate CSR  (requires csr.der on shuttle)".into(),
                    "  [3]  Revoke a certificate   (adds entry + issues new CRL)".into(),
                    "  [4]  Issue CRL refresh      (re-signs current revocation list)".into(),
                    "  [5]  Migrate disc           (copy all sessions to new disc)".into(),
                    "  [6]  Init root              (SSS PIN split + fresh root CA)".into(),
                    "  [7]  Re-key shares          (change custodians, keep same PIN)".into(),
                ]
            }

            CeremonyState::KeyAction => {
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

            CeremonyState::WritingIntent => vec![
                String::new(),
                "  Writing intent session to disc.".into(),
                "  HSM signing will begin after disc commit completes.".into(),
                "  Do not remove the disc or power off.".into(),
            ],

            CeremonyState::LoadCsr => {
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
                lines.push("  [q]  Cancel".into());
                lines
            }

            CeremonyState::CsrPreview => {
                let subject = app.csr_subject_display.as_deref().unwrap_or("(unknown)");
                let profile_name = app
                    .profile
                    .as_ref()
                    .and_then(|p| {
                        app.selected_profile_idx
                            .map(|i| p.cert_profiles[i].name.as_str())
                    })
                    .unwrap_or("?");
                vec![
                    String::new(),
                    format!("  CSR Subject : {subject}"),
                    format!("  Profile     : {profile_name}"),
                    String::new(),
                    "  The CSR DER bytes are recorded in the intent audit log.".into(),
                    String::new(),
                    "  [1]  Sign CSR and write to disc".into(),
                    "  [q]  Cancel".into(),
                ]
            }

            CeremonyState::CertPreview => {
                let fp = app.fingerprint.as_deref().unwrap_or("(none)");
                let ca = app.profile.as_ref().map(|p| &p.ca);
                let (cn, org, country) = ca
                    .map(|c| (
                        c.common_name.as_str(),
                        c.organization.as_str(),
                        c.country.as_str(),
                    ))
                    .unwrap_or(("?", "?", "?"));
                let has_crl = app.crl_der.is_some();
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
                lines.push("  [q]  Abort".into());
                lines
            }

            CeremonyState::RevokeInput => {
                let phase_hint = if app.revoke_phase == 0 {
                    "Enter serial number (digits only):"
                } else {
                    "Enter reason (optional, press Enter to skip):"
                };
                vec![
                    String::new(),
                    format!("  {} revoked cert(s) on record.", app.revocation_list.len()),
                    String::new(),
                    format!("  {phase_hint}"),
                    String::new(),
                    format!("  Serial : {}", app.revoke_serial_buf),
                    format!("  Reason : {}", app.revoke_reason_buf),
                    String::new(),
                    "  Enter to confirm each field. Esc (on reason) to go back.".into(),
                ]
            }

            CeremonyState::RevokePreview => {
                let crl_num = app.crl_number.unwrap_or(0);
                let mut lines = vec![
                    String::new(),
                    format!("  New CRL number: {crl_num}"),
                    String::new(),
                    "  Updated revocation list:".into(),
                    String::new(),
                ];
                for entry in &app.revocation_list {
                    let reason = entry.reason.as_deref().unwrap_or("(no reason)");
                    lines.push(format!(
                        "    serial={:>20}  time={}  reason={}",
                        entry.serial, entry.revocation_time, reason
                    ));
                }
                lines.push(String::new());
                lines.push("  [1]  Sign CRL and write to disc".into());
                lines.push("  [q]  Cancel".into());
                lines
            }

            CeremonyState::CrlPreview => {
                let crl_num = app.crl_number.unwrap_or(0);
                let count = app.revocation_list.len();
                let mut lines = vec![
                    String::new(),
                    format!("  CRL number      : {crl_num}"),
                    format!("  Revoked entries : {count}"),
                    String::new(),
                ];
                if count == 0 {
                    lines.push("  (No certificates have been revoked.)".into());
                } else {
                    for entry in &app.revocation_list {
                        let reason = entry.reason.as_deref().unwrap_or("(no reason)");
                        lines.push(format!(
                            "    serial={:>20}  time={}  reason={}",
                            entry.serial, entry.revocation_time, reason
                        ));
                    }
                }
                lines.push(String::new());
                lines.push("  [1]  Sign CRL and write to disc".into());
                lines.push("  [q]  Cancel".into());
                lines
            }

            CeremonyState::BurningDisc => vec![
                String::new(),
                "  Writing ISO 9660 session to optical disc\u{2026}".into(),
                String::new(),
                "  Please wait. Do not remove the disc or USB.".into(),
            ],

            CeremonyState::DiscDone => {
                let op_label = match app.current_op {
                    Some(Operation::InitRoot) => "Root init",
                    Some(Operation::GenerateRootCa) => "Root CA cert + initial CRL",
                    Some(Operation::SignCsr) => "Intermediate certificate",
                    Some(Operation::RevokeCert) => "Revocation record + CRL",
                    Some(Operation::IssueCrl) => "CRL refresh",
                    Some(Operation::RekeyShares) => "Re-key shares",
                    Some(Operation::MigrateDisc) => "Disc migration",
                    None => "Session",
                };
                let fp = app.fingerprint.as_deref().unwrap_or("(none)");
                let mut lines = vec![
                    String::new(),
                    format!("  {op_label} written to disc successfully."),
                ];
                if app.fingerprint.is_some() {
                    lines.push(String::new());
                    lines.push(format!("  Fingerprint: {fp}"));
                }
                lines.push(String::new());
                match app.current_op {
                    Some(Operation::MigrateDisc) => {
                        lines.push("  [q]  Quit (migration complete; no USB export)".into());
                    }
                    _ => {
                        lines.push("  [1]  Copy artifacts to shuttle".into());
                        lines.push("  [q]  Quit without shuttle copy (disc is the primary record)".into());
                    }
                }
                lines
            }

            CeremonyState::InitRootCustodianSetup => {
                vec![
                    String::new(),
                    "  Configure Shamir Secret Sharing for the HSM PIN.".into(),
                    String::new(),
                    "  Custodian names (comma-separated):".into(),
                    format!("  > {}|", app.init_root_custodian_buf),
                    String::new(),
                    "  After entering names, press [Enter] to set threshold.".into(),
                    "  Default threshold: 2-of-N (minimum for SSS).".into(),
                    String::new(),
                    "  [Enter]  Confirm    [Esc]  Abort".into(),
                ]
            }

            CeremonyState::InitRootShareReveal => {
                vec![
                    String::new(),
                    "  Shares are being distributed to custodians.".into(),
                    "  The share reveal component is active.".into(),
                    String::new(),
                    "  Hand the device to each custodian in turn.".into(),
                    "  Press [S] to show/hide the share, [Enter] to confirm transcription.".into(),
                ]
            }

            CeremonyState::InitRootShareVerify => {
                vec![
                    String::new(),
                    "  Verification round: each custodian re-enters their share.".into(),
                    "  This confirms transcription accuracy before HSM initialization.".into(),
                    String::new(),
                    "  The share input component is active.".into(),
                ]
            }

            CeremonyState::RekeyQuorum => {
                let info = if let Some(ref state) = app.session_state {
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

            CeremonyState::RekeyCustodianSetup => {
                vec![
                    String::new(),
                    "  Enter new custodian names for re-keyed shares.".into(),
                    String::new(),
                    "  Custodian names (comma-separated):".into(),
                    format!("  > {}|", app.init_root_custodian_buf),
                    String::new(),
                    "  [Enter]  Confirm    [Esc]  Abort".into(),
                ]
            }

            CeremonyState::RekeyShareReveal => {
                vec![
                    String::new(),
                    "  New shares are being distributed to custodians.".into(),
                    String::new(),
                    "  Hand the device to each custodian in turn.".into(),
                    "  Press [S] to show/hide the share, [Enter] to confirm transcription.".into(),
                ]
            }

            CeremonyState::RekeyShareVerify => {
                vec![
                    String::new(),
                    "  Verification round: each new custodian re-enters their share.".into(),
                    String::new(),
                    "  The share input component is active.".into(),
                ]
            }

            CeremonyState::MigrateConfirm => {
                let chain_str = if app.migrate_chain_ok {
                    "OK \u{2714}"
                } else {
                    "FAIL \u{2718}"
                };
                let mb = app.migrate_total_bytes / (1024 * 1024);
                vec![
                    String::new(),
                    format!("  Sessions  : {}", app.prior_sessions.len()),
                    format!("  Audit chain: {chain_str}"),
                    format!(
                        "  Total data: {} MiB ({} bytes)",
                        mb, app.migrate_total_bytes
                    ),
                    String::new(),
                    "  Verify chain is OK before proceeding.".into(),
                    String::new(),
                    "  [1]  Eject old disc, insert blank new disc".into(),
                    "  [q]  Abort".into(),
                ]
            }

            CeremonyState::WaitMigrateTarget => {
                let session_count = app.migrate_sessions.len();
                let disc_info = match &app.optical_dev {
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
                    "  [q]  Abort".into(),
                ]
            }

            CeremonyState::Done => {
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
                    "  [q]  Quit".into(),
                ]
            }
        }
    }
}

impl Component for CeremonyMode {
    fn handle_key_event(&mut self, key: KeyEvent) -> Action {
        match &self.state {
            CeremonyState::OperationSelect => match key.code {
                KeyCode::Char('1') => Action::SelectOperation(Operation::GenerateRootCa),
                KeyCode::Char('2') => Action::SelectOperation(Operation::SignCsr),
                KeyCode::Char('3') => Action::SelectOperation(Operation::RevokeCert),
                KeyCode::Char('4') => Action::SelectOperation(Operation::IssueCrl),
                KeyCode::Char('5') => Action::SelectOperation(Operation::MigrateDisc),
                KeyCode::Char('6') => Action::SelectOperation(Operation::InitRoot),
                KeyCode::Char('7') => Action::SelectOperation(Operation::RekeyShares),
                _ => Action::Noop,
            },

            CeremonyState::KeyAction => match key.code {
                KeyCode::Char('1') => Action::SelectKeyAction(1),
                KeyCode::Char('2') => Action::SelectKeyAction(2),
                _ => Action::Noop,
            },

            CeremonyState::WritingIntent => Action::Noop, // auto-advance on burn

            CeremonyState::LoadCsr => {
                if let KeyCode::Char(c) = key.code {
                    if let Some(d) = c.to_digit(10) {
                        let idx = d as usize;
                        if idx >= 1 {
                            return Action::SelectCertProfile(idx - 1);
                        }
                    }
                }
                Action::Noop
            }

            CeremonyState::CsrPreview => {
                if key.code == KeyCode::Char('1') {
                    Action::ConfirmCsrSign
                } else {
                    Action::Noop
                }
            }

            CeremonyState::CertPreview => {
                if key.code == KeyCode::Char('1') {
                    Action::ConfirmCertBurn
                } else {
                    Action::Noop
                }
            }

            CeremonyState::RevokeInput => match key.code {
                KeyCode::Char(c) => Action::RevokeInputChar(c),
                KeyCode::Backspace => Action::RevokeInputBackspace,
                KeyCode::Enter => Action::RevokeInputNextPhase,
                KeyCode::Esc => Action::RevokeInputCancel,
                _ => Action::Noop,
            },

            CeremonyState::RevokePreview => {
                if key.code == KeyCode::Char('1') {
                    Action::ConfirmCrlSign
                } else {
                    Action::Noop
                }
            }

            CeremonyState::CrlPreview => {
                if key.code == KeyCode::Char('1') {
                    Action::ConfirmCrlSign
                } else {
                    Action::Noop
                }
            }

            CeremonyState::BurningDisc => Action::Noop, // auto-advance on burn

            CeremonyState::DiscDone => {
                if key.code == KeyCode::Char('1') {
                    Action::DoWriteShuttle
                } else {
                    Action::Noop
                }
            }

            CeremonyState::MigrateConfirm => {
                if key.code == KeyCode::Char('1') {
                    Action::ConfirmMigrate
                } else {
                    Action::Noop
                }
            }

            CeremonyState::WaitMigrateTarget => {
                if key.code == KeyCode::Char('1') {
                    Action::ConfirmMigrateTarget
                } else {
                    Action::Noop
                }
            }

            CeremonyState::InitRootCustodianSetup => match key.code {
                KeyCode::Char(c) => Action::InitRootInputChar(c),
                KeyCode::Backspace => Action::InitRootInputBackspace,
                KeyCode::Enter => Action::InitRootConfirmCustodians,
                KeyCode::Esc => Action::InitRootAbort,
                _ => Action::Noop,
            },

            CeremonyState::InitRootShareReveal => Action::Noop, // handled by ShareReveal component
            CeremonyState::InitRootShareVerify => Action::Noop, // handled by ShareInput component

            CeremonyState::RekeyQuorum => Action::Noop, // handled by ShareInput component
            CeremonyState::RekeyCustodianSetup => match key.code {
                KeyCode::Char(c) => Action::InitRootInputChar(c),
                KeyCode::Backspace => Action::InitRootInputBackspace,
                KeyCode::Enter => Action::RekeyConfirmCustodians,
                KeyCode::Esc => Action::RekeyAbort,
                _ => Action::Noop,
            },
            CeremonyState::RekeyShareReveal => Action::Noop, // handled by ShareReveal component
            CeremonyState::RekeyShareVerify => Action::Noop, // handled by ShareInput component

            CeremonyState::Done => Action::Noop,
        }
    }

    fn render(&self, frame: &mut Frame, area: Rect) {
        // Fallback render without app context
        let block = Block::default().borders(Borders::ALL).title("Ceremony");
        let para = Paragraph::new("  (Ceremony mode)").block(block);
        frame.render_widget(para, area);
    }
}
