//! Sentinel — terminal gatekeeper for the ceremony.
//!
//! Run this on every terminal at boot (serial console, EFI framebuffer, etc.).
//! When the operator presses Enter it acquires an exclusive flock on the lock
//! file and execs into `anodize-ceremony`.  If another terminal already holds
//! the lock, or any error occurs, the message stays on screen until the
//! operator acknowledges it, then the banner is redrawn and the sentinel loops.
//!
//! The flock fd is kept open across exec (O_CLOEXEC cleared before execvp) so
//! `anodize-ceremony` holds the lock for its entire lifetime; the lock is
//! released automatically when the ceremony process exits.

use std::fs::OpenOptions;
use std::mem;
use std::os::unix::io::{AsFd, AsRawFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

use anyhow::Result;
use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode},
};
use nix::fcntl::{fcntl, Flock, FcntlArg, FdFlag, FlockArg};
use nix::unistd::close;

#[derive(Parser)]
#[command(name = "anodize-sentinel", about = "Terminal gatekeeper for the ceremony")]
struct Cli {
    /// Exclusive lock file path.  /tmp is a shared tmpfs (1777) in the ISO
    /// and on every development machine, so the default works everywhere
    /// without any prior setup.
    #[arg(long, default_value = "/tmp/anodize-ceremony.lock")]
    lock_file: PathBuf,
}

const CEREMONY_BIN: &str = "anodize-ceremony";

fn main() -> Result<()> {
    let cli = Cli::parse();

    loop {
        print_banner();

        // ── Wait for keypress ──────────────────────────────────────────────────
        enable_raw_mode()?;
        let key = read_keypress();
        disable_raw_mode().ok();

        let key = match key {
            Ok(k) => k,
            Err(e) => {
                if show_and_wait(&format!("  keyboard error: {e}")) { break; }
                continue;
            }
        };

        match key {
            KeyCode::Char('q') | KeyCode::Char('Q') => break,
            KeyCode::Enter => {}
            _ => continue,
        }

        // ── Open lock file ─────────────────────────────────────────────────────
        let lock_file = match OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&cli.lock_file)
        {
            Ok(f) => f,
            Err(e) => {
                let msg = format!(
                    "  cannot open lock file {}:\n  {e}",
                    cli.lock_file.display()
                );
                if show_and_wait(&msg) { break; }
                continue;
            }
        };

        // ── Acquire exclusive flock ────────────────────────────────────────────
        match Flock::lock(lock_file, FlockArg::LockExclusiveNonblock) {
            Ok(locked) => {
                let raw_fd = locked.as_fd().as_raw_fd();

                // Clear FD_CLOEXEC before leaking so the fd survives exec.
                if let Err(e) = fcntl(raw_fd, FcntlArg::F_SETFD(FdFlag::empty())) {
                    // locked drops here → flock released
                    if show_and_wait(&format!("  F_SETFD: {e}")) { break; }
                    continue;
                }

                mem::forget(locked); // keeps fd (and flock) alive across exec

                // ESC-c (RIS) resets the terminal before the TUI takes over,
                // wiping the sentinel banner so ratatui starts with a clean slate.
                print!("\x1bc");
                let _ = std::io::Write::flush(&mut std::io::stdout());

                let err = Command::new(CEREMONY_BIN).exec();

                // exec returned → it failed.  Close the fd to release the flock
                // so the next attempt can acquire it.
                let _ = close(raw_fd);

                if show_and_wait(&format!("  exec {CEREMONY_BIN}: {err}")) {
                    break;
                }
            }

            // EWOULDBLOCK (Linux tmpfs) or EACCES (NFS) — already locked.
            Err((_, nix::errno::Errno::EWOULDBLOCK | nix::errno::Errno::EACCES)) => {
                if show_and_wait("  Ceremony is already running on another terminal.") {
                    break;
                }
            }

            Err((_, e)) => {
                if show_and_wait(&format!("  flock: {e}")) { break; }
            }
        }
    }

    Ok(())
}

/// Display `msg` and wait for a keypress.
///
/// Returns `true` if the operator pressed [q]/[Q]/Ctrl-C (wants to exit).
/// The screen is NOT cleared here; `print_banner` at the top of the next loop
/// iteration clears it once the operator has acknowledged.
fn show_and_wait(msg: &str) -> bool {
    disable_raw_mode().ok();
    println!("\r");
    for line in msg.lines() {
        println!("{line}\r");
    }
    println!("\r");
    println!("  Press any key to retry, or [q] to exit.\r");

    enable_raw_mode().ok();
    let key = read_keypress().unwrap_or(KeyCode::Enter);
    disable_raw_mode().ok();

    matches!(key, KeyCode::Char('q') | KeyCode::Char('Q'))
}

/// Wait for the next key event and return its code.
fn read_keypress() -> Result<KeyCode> {
    loop {
        if let Event::Key(key) = event::read()? {
            if key.modifiers.contains(KeyModifiers::CONTROL) {
                if key.code == KeyCode::Char('c') {
                    return Ok(KeyCode::Char('q'));
                }
                continue;
            }
            return Ok(key.code);
        }
    }
}

fn print_banner() {
    // ANSI: clear screen + cursor home; works on both serial and EFI consoles.
    print!("\x1b[2J\x1b[H");
    println!("+-----------------------------------------+");
    println!("|      ANODIZE ROOT CA CEREMONY           |");
    println!("|            S E N T I N E L              |");
    println!("+-----------------------------------------+");
    println!();
    println!("  Press Enter to begin the ceremony.");
    println!("  Press [q] to exit.");
    println!();
}
