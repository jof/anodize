use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::Widget,
};

/// Connection/presence state for a hardware peripheral.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HwState {
    /// Not detected.
    Absent,
    /// Detected but not ready (e.g. HSM present but not logged in).
    Present(String),
    /// Ready for use.
    Ready(String),
    /// Error state.
    Error(String),
}

/// Persistent hardware status bar showing HSM, disc, and USB state.
///
/// Rendered as two lines at the bottom of the screen, above the status message.
pub struct StatusBar<'a> {
    pub hsm: &'a HwState,
    pub disc: &'a HwState,
    pub usb: &'a HwState,
}

impl Widget for StatusBar<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.height < 1 || area.width < 20 {
            return;
        }

        let bg = Style::default().bg(Color::Black);
        for y in area.top()..area.bottom() {
            for x in area.left()..area.right() {
                buf.set_string(x, y, " ", bg);
            }
        }

        let mut x = area.left() + 1;
        let y = area.top();

        render_hw_entry(buf, &mut x, y, "HSM", self.hsm, area.right());

        if x + 4 < area.right() {
            buf.set_string(x, y, "  ", bg);
            x += 2;
        }
        render_hw_entry(buf, &mut x, y, "Disc", self.disc, area.right());

        if x + 4 < area.right() {
            buf.set_string(x, y, "  ", bg);
            x += 2;
        }
        render_hw_entry(buf, &mut x, y, "USB", self.usb, area.right());

        // If we have a second line, put the log key hint there
        if area.height >= 2 {
            let hint = " [L] log view ";
            let hint_x = area.right().saturating_sub(hint.len() as u16 + 1);
            buf.set_string(
                hint_x,
                area.top() + 1,
                hint,
                Style::default().fg(Color::Yellow).bg(Color::Black),
            );
        }
    }
}

fn render_hw_entry(
    buf: &mut Buffer,
    x: &mut u16,
    y: u16,
    label: &str,
    state: &HwState,
    max_x: u16,
) {
    let label_style = Style::default()
        .fg(Color::White)
        .bg(Color::Black)
        .add_modifier(Modifier::BOLD);

    let (dot, dot_style, detail) = match state {
        HwState::Absent => (
            "○",
            Style::default().fg(Color::DarkGray).bg(Color::Black),
            "not detected".to_string(),
        ),
        HwState::Present(info) => (
            "●",
            Style::default().fg(Color::Yellow).bg(Color::Black),
            info.clone(),
        ),
        HwState::Ready(info) => (
            "●",
            Style::default().fg(Color::Green).bg(Color::Black),
            info.clone(),
        ),
        HwState::Error(msg) => (
            "✘",
            Style::default().fg(Color::Red).bg(Color::Black),
            msg.clone(),
        ),
    };

    let full = format!("{}: {} {}", label, dot, detail);
    if *x + full.len() as u16 > max_x {
        return;
    }

    let prefix = format!("{}: ", label);
    buf.set_string(*x, y, &prefix, label_style);
    *x += prefix.len() as u16;
    buf.set_string(*x, y, dot, dot_style);
    *x += dot.len() as u16 + 1;
    buf.set_string(
        *x,
        y,
        &detail,
        Style::default().fg(Color::White).bg(Color::Black),
    );
    *x += detail.len() as u16;
}
