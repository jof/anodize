//! Seed an appendable disc with a minimal "init" session.
//!
//! Writes a single track containing a tiny ISO 9660 session with a marker
//! file (SEED.TXT) and closes the session, but does NOT finalize the disc.
//!
//! Usage:
//!   anodize-seed-disc [--device /dev/sr0]

mod media;

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::SystemTime;

use clap::Parser;

use media::iso9660::{IsoFile, SessionEntry};
use media::{scan_disc, session_dir_name, write_session, BurnProgress};

#[derive(Parser)]
#[command(name = "anodize-seed-disc", about = "Seed an appendable disc with a minimal init session")]
struct Cli {
    /// Optical device path.
    #[arg(long, default_value = "/dev/sr0")]
    device: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let dev = &cli.device;

    eprintln!("Scanning {}…", dev.display());
    let scan = scan_disc(dev).map_err(|e| anyhow::anyhow!("{e}"))?;
    eprintln!(
        "  Existing sessions: {}  Capacity: {}",
        scan.sessions.len(),
        scan.capacity_summary
    );

    if scan.sessions_remaining == 0 {
        anyhow::bail!("disc has no remaining sessions");
    }

    // Build new session: prior sessions + a new minimal one
    let now = SystemTime::now();
    let dir_name = session_dir_name(now);
    let seed_text = format!(
        "anodize seed session\ncreated: {dir_name}\npurpose: enable fresh root CA\n"
    );

    let new_session = SessionEntry {
        dir_name: dir_name.clone(),
        timestamp: now,
        files: vec![IsoFile {
            name: "SEED.TXT".to_string(),
            data: seed_text.into_bytes(),
        }],
    };

    let mut all_sessions = scan.sessions;
    all_sessions.push(new_session);

    eprintln!("Writing session {dir_name} ({} total)…", all_sessions.len());

    let (tx, rx) = mpsc::channel();
    write_session(dev, all_sessions, false, tx);

    // Print progress until Done
    for msg in rx {
        match msg {
            BurnProgress::Step(s) => eprintln!("  {s}"),
            BurnProgress::Done(Ok(())) => {
                eprintln!("Done — session written, disc NOT finalized.");
                return Ok(());
            }
            BurnProgress::Done(Err(e)) => {
                return Err(e);
            }
        }
    }

    anyhow::bail!("burn thread exited without sending Done");
}
