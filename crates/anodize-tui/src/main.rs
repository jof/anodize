//! Ceremony TUI — Component Architecture rewrite.
//!
//! Key invariants (enforced structurally):
//! - `UsbWrite` is only reachable from `DiscDone`.
//! - `DiscDone` is only set after a successful optical disc session burn (or --skip-disc).
//! - USB write is therefore impossible without a committed disc write.

mod action;
mod app;
mod ceremony_ops;
mod components;
mod event;
mod helpers;
mod media;
mod modes;
mod tui;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
#[command(name = "anodize-ceremony", about = "Root CA key ceremony")]
struct Cli {
    /// Mount point for USB stick (created if absent).
    #[arg(long, default_value = "/tmp/anodize-usb")]
    usb_mount: PathBuf,

    /// Skip optical disc burn; write disc artifacts to /tmp/anodize-staging instead.
    /// For development and testing only — never use in a real ceremony.
    #[arg(long)]
    skip_disc: bool,
}

// ── Dev build serial warning ──────────────────────────────────────────────────

#[cfg(feature = "dev-softhsm-usb")]
fn warn_dev_serial() {
    use std::io::Write;
    if let Ok(mut tty) = std::fs::OpenOptions::new().write(true).open("/dev/ttyS0") {
        let _ = writeln!(tty);
        let _ = writeln!(tty, "*** ANODIZE DEV BUILD — NOT FOR PRODUCTION USE ***");
        let _ = writeln!(tty, "*** dev-softhsm-usb feature enabled              ***");
        let _ = writeln!(tty);
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();

    #[cfg(feature = "dev-softhsm-usb")]
    warn_dev_serial();

    // Install panic hook before entering raw mode
    tui::init_panic_hook();

    // Set up tracing to file (best-effort — /run/anodize may not exist in dev)
    let _guard = setup_tracing();

    // Terminal lifecycle
    let mut tui = tui::Tui::new()?;
    tui.enter()?;

    // Application state
    let mut app = app::App::new(cli.usb_mount, cli.skip_disc);

    // Event handler: 100ms tick rate drives background polling
    let events = event::EventHandler::new(Duration::from_millis(100));

    // Main loop
    while app.running {
        // Render
        tui.terminal.draw(|frame| app.render(frame))?;

        // Handle events
        match events.next()? {
            event::Event::Key(key) => {
                let action = app.handle_key_event(key);
                if matches!(action, action::Action::Render) {
                    tui.terminal.clear()?;
                }
                app.update(action);
            }
            event::Event::Tick => {
                let action = app.handle_tick();
                app.update(action);
            }
            event::Event::Resize(_, _) => {
                // ratatui handles resize automatically on next draw
            }
        }
    }

    // Cleanup (Tui::Drop also handles this, but be explicit)
    tui.exit()?;

    // Unmount USB if still mounted (so the next ceremony session can re-mount)
    let _ = media::unmount(&app.usb_mountpoint);

    Ok(())
}

/// Set up tracing-subscriber to write to /run/anodize/ceremony.log (or /tmp fallback).
fn setup_tracing() -> Option<tracing::dispatcher::DefaultGuard> {
    use tracing_subscriber::{fmt, layer::SubscriberExt};

    let log_path = if std::path::Path::new("/run/anodize").exists() {
        std::path::PathBuf::from("/run/anodize/ceremony.log")
    } else {
        std::path::PathBuf::from("/tmp/anodize-ceremony.log")
    };

    let log_file = match std::fs::File::create(&log_path) {
        Ok(f) => f,
        Err(_) => return None,
    };

    let subscriber = tracing_subscriber::registry().with(
        fmt::layer()
            .with_writer(log_file)
            .with_ansi(false)
            .with_target(true),
    );

    Some(tracing::subscriber::set_default(subscriber))
}
