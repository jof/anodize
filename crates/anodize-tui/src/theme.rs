//! Centralised TUI style constants.
//!
//! Every `Block` and prominent widget should use these rather than
//! `Style::default()`.  On the Linux VT framebuffer `Style::default()` means
//! "inherit" (all `None` fields), which lets modifier/colour state leak across
//! cells during crossterm's diff rendering — producing the "random bright
//! letters" artefact visible with `nomodeset`.
//!
//! Spelling out explicit fg/bg ensures crossterm always emits a deterministic
//! SGR sequence for every cell.

use ratatui::style::{Color, Modifier, Style};

/// Base style applied to every content `Block` (borders + inner area).
pub const BLOCK: Style = Style::new().fg(Color::White).bg(Color::Black);

/// Style for block borders (same palette, no bold).
pub const BORDER: Style = Style::new().fg(Color::White).bg(Color::Black);

/// Style for block titles.
pub const TITLE: Style = Style::new().fg(Color::White).bg(Color::Black);

/// Accent border for modal overlays (confirm dialog — yellow).
pub const MODAL_BORDER_YELLOW: Style = Style::new().fg(Color::Yellow).bg(Color::Black);

/// Accent title for modal overlays (confirm dialog — yellow + bold).
pub const MODAL_TITLE_YELLOW: Style = Style::new()
    .fg(Color::Yellow)
    .bg(Color::Black)
    .add_modifier(Modifier::BOLD);

/// Accent border for modal overlays (share input / cert detail — cyan).
pub const MODAL_BORDER_CYAN: Style = Style::new().fg(Color::Cyan).bg(Color::Black);

/// Accent title for modal overlays (cert detail — cyan + bold).
pub const MODAL_TITLE_CYAN: Style = Style::new()
    .fg(Color::Cyan)
    .bg(Color::Black)
    .add_modifier(Modifier::BOLD);

/// Accent border for share reveal (magenta).
pub const MODAL_BORDER_MAGENTA: Style = Style::new().fg(Color::Magenta).bg(Color::Black);
