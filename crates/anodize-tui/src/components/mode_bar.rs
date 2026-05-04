use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::Widget,
};

use crate::action::Mode;

/// Horizontal tab bar showing the top-level modes: Setup | Ceremony | Utilities.
///
/// The active mode is highlighted. Locked modes (e.g. Ceremony before Setup
/// completes) are rendered dimmed.
pub struct ModeBar {
    pub active: Mode,
    pub ceremony_unlocked: bool,
}

impl Widget for ModeBar {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.height < 1 || area.width < 10 {
            return;
        }

        // Background fill
        let bar_style = Style::default().bg(Color::DarkGray);
        for x in area.left()..area.right() {
            buf.set_string(x, area.top(), " ", bar_style);
        }

        let mut x = area.left() + 1;
        for mode in Mode::ALL {
            let label = format!(" {} ", mode.label());
            let fkey = format!("[F{}]", mode.index() + 1);

            let is_active = *mode == self.active;
            let is_locked = *mode == Mode::Ceremony && !self.ceremony_unlocked;

            let style = if is_active {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else if is_locked {
                Style::default()
                    .fg(Color::Gray)
                    .bg(Color::DarkGray)
            } else {
                Style::default()
                    .fg(Color::White)
                    .bg(Color::DarkGray)
            };

            let key_style = if is_locked {
                Style::default().fg(Color::Gray).bg(Color::DarkGray)
            } else {
                Style::default().fg(Color::Yellow).bg(Color::DarkGray)
            };

            if x + label.len() as u16 + fkey.len() as u16 + 2 > area.right() {
                break;
            }

            buf.set_string(x, area.top(), &fkey, key_style);
            x += fkey.len() as u16;
            buf.set_string(x, area.top(), &label, style);
            x += label.len() as u16 + 1; // +1 gap
        }

        // Right-aligned quit hint
        let quit_hint = " [q] quit ";
        let quit_x = area.right().saturating_sub(quit_hint.len() as u16);
        if quit_x > x {
            buf.set_string(
                quit_x,
                area.top(),
                quit_hint,
                Style::default().fg(Color::Yellow).bg(Color::DarkGray),
            );
        }
    }
}
