/// Which CA operation is being performed.
#[derive(Debug, Clone, PartialEq)]
pub enum Operation {
    InitRoot,
    GenerateRootCa,
    SignCsr,
    RevokeCert,
    IssueCrl,
    RekeyShares,
    MigrateDisc,
}

/// All possible actions in the app. Events produce Actions; update() consumes them.
/// An Action can chain into another Action (returned from update()).
#[derive(Debug)]
pub enum Action {
    Noop,
    Quit,
    Tick,
    Render,
    // Navigation
    SwitchMode(Mode),
    // Status updates
    SetStatus(String),
    // Setup flow
    ConfirmClock,
    ProfileLoaded,
    AdvanceToPinEntry,
    DoLogin,
    HsmLoggedIn,
    // Ceremony flow
    SetupComplete,
    SelectOperation(Operation),
    SelectKeyAction(u8),      // 1=generate, 2=find-existing
    SelectCertProfile(usize), // 0-indexed profile index
    // Disc + Shuttle
    ConfirmDisc,
    DoWriteIntent,
    IntentBurnComplete,
    DoStartBurn,
    BurnComplete,
    DoWriteShuttle,
    // Revocation input
    RevokeInputChar(char),
    RevokeInputBackspace,
    RevokeInputConfirm,
    RevokeInputNextPhase,
    RevokeInputCancel,
    // CSR review
    ConfirmCsrSign,
    // Cert/CRL review
    ConfirmCertBurn,
    ConfirmCrlSign,
    // Migration
    ConfirmMigrate,
    ConfirmMigrateTarget,
    // InitRoot / RekeyShares shared custodian input
    InitRootInputChar(char),
    InitRootInputBackspace,
    InitRootConfirmCustodians,
    InitRootAbort,
    // RekeyShares ceremony
    RekeyConfirmCustodians,
    RekeyAbort,
    // PIN input
    PinChar(char),
    PinBackspace,
    PinCancel,
    // Utilities sub-screens (1=SystemInfo, 2=AuditLog, 3=HsmBrowser)
    UtilScreen(u8),
}

/// Top-level application modes, switchable via F1/F2/F3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Setup,
    Ceremony,
    Utilities,
}

impl Mode {
    pub const ALL: &[Mode] = &[Mode::Setup, Mode::Ceremony, Mode::Utilities];

    pub fn label(&self) -> &'static str {
        match self {
            Mode::Setup => "Setup",
            Mode::Ceremony => "Ceremony",
            Mode::Utilities => "Utilities",
        }
    }

    pub fn index(&self) -> usize {
        match self {
            Mode::Setup => 0,
            Mode::Ceremony => 1,
            Mode::Utilities => 2,
        }
    }
}
