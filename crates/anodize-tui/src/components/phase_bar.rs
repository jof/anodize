use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
    widgets::Widget,
};

/// Status of a single phase step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhaseStatus {
    Completed,
    Active,
    Pending,
}

/// A single step in the phase bar.
#[derive(Debug, Clone)]
pub struct PhaseStep {
    pub label: &'static str,
    pub status: PhaseStatus,
}

/// Second-level bar showing workflow steps for the current mode.
///
/// Renders as: ✓ Clock │ ✓ USB │ → Profile │ ○ PIN │ ○ Disc
pub struct PhaseBar<'a> {
    pub steps: &'a [PhaseStep],
}

impl Widget for PhaseBar<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.height < 1 || area.width < 10 || self.steps.is_empty() {
            return;
        }

        let bg = Style::default().bg(Color::Black);
        for x in area.left()..area.right() {
            buf.set_string(x, area.top(), " ", bg);
        }

        let mut x = area.left() + 1;
        for (i, step) in self.steps.iter().enumerate() {
            let (icon, icon_style) = match step.status {
                PhaseStatus::Completed => (
                    "✓",
                    Style::default().fg(Color::Green).bg(Color::Black),
                ),
                PhaseStatus::Active => (
                    "→",
                    Style::default().fg(Color::Yellow).bg(Color::Black),
                ),
                PhaseStatus::Pending => (
                    "○",
                    Style::default().fg(Color::DarkGray).bg(Color::Black),
                ),
            };

            let label_style = match step.status {
                PhaseStatus::Completed => Style::default().fg(Color::White).bg(Color::Black),
                PhaseStatus::Active => Style::default().fg(Color::Yellow).bg(Color::Black),
                PhaseStatus::Pending => Style::default().fg(Color::DarkGray).bg(Color::Black),
            };

            let entry = format!("{} {}", icon, step.label);
            if x + entry.len() as u16 + 3 > area.right() {
                break;
            }

            buf.set_string(x, area.top(), icon, icon_style);
            x += icon.len() as u16 + 1; // icon width (may be >1 for unicode) + space
            // Recalculate: icon was already rendered above, now render label
            // Actually re-do cleanly:
            let label = step.label;
            buf.set_string(x, area.top(), label, label_style);
            x += label.len() as u16;

            // Separator
            if i < self.steps.len() - 1 {
                let sep = " │ ";
                buf.set_string(
                    x,
                    area.top(),
                    sep,
                    Style::default().fg(Color::DarkGray).bg(Color::Black),
                );
                x += sep.len() as u16;
            }
        }
    }
}
