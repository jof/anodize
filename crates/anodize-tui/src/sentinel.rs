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
use nix::fcntl::{fcntl, FcntlArg, FdFlag, Flock, FlockArg};
use nix::sys::reboot::{reboot, RebootMode};
use nix::unistd::{close, sync};

#[derive(Parser)]
#[command(
    name = "anodize-sentinel",
    about = "Terminal gatekeeper for the ceremony"
)]
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
                if show_and_wait(&format!("  keyboard error: {e}")) {
                    break;
                }
                continue;
            }
        };

        match key {
            KeyCode::Char('q') | KeyCode::Char('Q') => break,
            KeyCode::Char('s') | KeyCode::Char('S') => {
                if confirm_shutdown() {
                    poweroff();
                }
                continue;
            }
            KeyCode::Char('n') | KeyCode::Char('N') if cfg!(feature = "dev-softhsm-usb") => {
                show_network_info();
                continue;
            }
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
                if show_and_wait(&msg) {
                    break;
                }
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
                    if show_and_wait(&format!("  F_SETFD: {e}")) {
                        break;
                    }
                    continue;
                }

                mem::forget(locked); // keeps fd (and flock) alive across exec

                // Dev builds: ensure cdemu virtual optical drive is running.
                #[cfg(feature = "dev-softhsm-usb")]
                ensure_cdemu();

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
                if show_and_wait(&format!("  flock: {e}")) {
                    break;
                }
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

/// Ask the operator to confirm shutdown. Returns `true` if confirmed.
fn confirm_shutdown() -> bool {
    disable_raw_mode().ok();
    println!("\r");
    println!("  POWER OFF this machine? Press [y] to confirm, any other key to cancel.\r");
    println!("\r");

    enable_raw_mode().ok();
    let key = read_keypress().unwrap_or(KeyCode::Esc);
    disable_raw_mode().ok();

    matches!(key, KeyCode::Char('y') | KeyCode::Char('Y'))
}

/// Sync filesystems and power off. Does not return on success.
fn poweroff() {
    // Flush all pending writes before pulling power.
    sync();

    // reboot() returns Result<Void, Errno>; Ok(Void) is uninhabited so the
    // only reachable branch is Err (CAP_SYS_BOOT missing).
    let Err(e) = reboot(RebootMode::RB_POWER_OFF);
    disable_raw_mode().ok();
    eprintln!("\r\n  poweroff failed: {e}\r");
    let _ = std::io::Write::flush(&mut std::io::stderr());
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
    if cfg!(feature = "dev-softhsm-usb") {
        println!("  Press [n] to show network info.");
    }
    println!("  Press [s] to power off.");
    println!("  Press [q] to exit.");
    println!();
}

/// Read the real UID of the current process from /proc/self/status.
#[cfg(feature = "dev-softhsm-usb")]
fn read_real_uid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find(|l| l.starts_with("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
}

/// Ensure the cdemu virtual optical drive is running (dev builds only).
///
/// Checks `systemctl --user is-active cdemu-load-bdr`; if not active, starts it
/// (which pulls in cdemu-daemon via Requires=).  Best-effort — failures are
/// printed but do not prevent the ceremony from launching.
#[cfg(feature = "dev-softhsm-usb")]
fn ensure_cdemu() {
    // XDG_RUNTIME_DIR is required for `systemctl --user` to find the user
    // manager socket.  PAM/logind normally sets this, but ceremony-shell
    // sources /etc/set-environment which may not include it.
    // Resolve real UID via /proc — avoids needing libc or nix 'user' feature.
    let uid = read_real_uid().unwrap_or(1000);
    let runtime_dir = format!("/run/user/{uid}");
    std::env::set_var("XDG_RUNTIME_DIR", &runtime_dir);

    // Already running?
    if let Ok(out) = Command::new("systemctl")
        .args(["--user", "is-active", "cdemu-load-bdr"])
        .output()
    {
        if out.status.success() {
            return; // already active
        }
    }

    println!("  Starting cdemu virtual optical drive…\r");
    match Command::new("systemctl")
        .args(["--user", "start", "cdemu-load-bdr"])
        .output()
    {
        Ok(out) if out.status.success() => {
            println!("  cdemu started.\r");
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            println!(
                "  WARNING: cdemu start failed (exit {}): {stderr}\r",
                out.status
            );
        }
        Err(e) => {
            println!("  WARNING: could not run systemctl: {e}\r");
        }
    }

    // Give cdemu-daemon a moment to register with VHBA and create /dev/sr0.
    std::thread::sleep(std::time::Duration::from_secs(3));
}

/// Run `ip -brief addr show` and display the output (dev builds only).
fn show_network_info() {
    disable_raw_mode().ok();
    println!("\r");
    println!("  === Network Interfaces ===\r");
    match Command::new("ip").args(["-brief", "addr", "show"]).output() {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                println!("  {line}\r");
            }
        }
        Err(e) => println!("  ip: {e}\r"),
    }
    println!("\r");
    println!("  === SSH Host Keys ===\r");
    match Command::new("sh")
        .args([
            "-c",
            "for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf \"$f\"; done",
        ])
        .output()
    {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                println!("  {line}\r");
            }
        }
        Err(e) => println!("  ssh-keygen: {e}\r"),
    }
    println!("\r");
    println!("  Press any key to return.\r");

    enable_raw_mode().ok();
    let _ = read_keypress();
    disable_raw_mode().ok();
}
