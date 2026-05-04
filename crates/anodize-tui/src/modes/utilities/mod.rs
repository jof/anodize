use crossterm::event::KeyEvent;
use ratatui::{
    layout::Rect,
    text::Text,
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

use crate::action::Action;
use crate::components::Component;

/// Utilities mode component: placeholder for Phase C features.
pub struct UtilitiesMode {
    // Will hold sub-components for system info, audit browser, etc.
}

impl UtilitiesMode {
    pub fn new() -> Self {
        Self {}
    }
}

impl Component for UtilitiesMode {
    fn handle_key_event(&mut self, _key: KeyEvent) -> Action {
        Action::Noop
    }

    fn render(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title("Utilities");
        let content = vec![
            "",
            "  [1]  System Info",
            "  [2]  Audit Log Browser",
            "  [3]  Platform Integrity (TPM)",
            "  [4]  PKCS#11 / HSM Slot Browser",
            "",
            "  (Coming in Phase C)",
        ];
        let para = Paragraph::new(Text::from(content.join("\n")))
            .block(block)
            .wrap(Wrap { trim: false });
        frame.render_widget(para, area);
    }
}
