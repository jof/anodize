/// Which CA operation is being performed.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Operation {
    InitRoot,
    SignCsr,
    RevokeCert,
    IssueCrl,
    RekeyShares,
    MigrateDisc,
    KeyBackup,
    ValidateDisc,
    #[cfg(feature = "dev-burn")]
    RefreshDisc,
}

/// All possible actions in the app. Events produce Actions; update() consumes them.
/// An Action can chain into another Action (returned from update()).
#[derive(Debug)]
pub enum Action {
    Noop,
    Quit,
    // Navigation
    SwitchMode(Mode),
    // Setup flow
    ConfirmClock,
    HsmDetected,
    HsmWarnAcknowledged,
    // Ceremony flow
    SetupComplete,
    SelectOperation(Operation),
    ConfirmDisc,
    // Utilities sub-screens (1=SystemInfo, 2=AuditLog, 3=HsmInventory, 4=DiscInspector)
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
