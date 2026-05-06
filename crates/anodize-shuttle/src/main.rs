mod init;
mod lint;

use clap::{Parser, Subcommand};

/// Anodize shuttle USB preparation and validation tool.
///
/// The shuttle is the USB stick that carries configuration and artifacts
/// between the operator's workstation and the air-gapped ceremony machine.
#[derive(Parser)]
#[command(name = "anodize-shuttle", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize a blank USB stick as an anodize shuttle.
    ///
    /// Formats the device as FAT32 with the ANODIZE volume label,
    /// generates profile.toml for the selected HSM mode, and creates
    /// the required directory structure.
    Init(init::InitArgs),

    /// Validate shuttle contents and report readiness.
    ///
    /// Checks that profile.toml exists and parses correctly, validates
    /// DER encoding of certificates and CSRs, warns about extraneous
    /// files, and reports which ceremony operations the shuttle is
    /// ready for.
    Lint(lint::LintArgs),
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init(args) => init::run(args),
        Command::Lint(args) => lint::run(args),
    }
}
