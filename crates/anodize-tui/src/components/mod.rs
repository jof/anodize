pub mod confirm_dialog;
pub mod custodian_setup;
pub mod mode_bar;
pub mod phase_bar;
pub mod share_input;
pub mod share_reveal;
pub mod status_bar;

use crossterm::event::KeyEvent;

use crate::action::Action;

/// Every interactive screen/panel implements this trait.
///
/// Follows ratatui's recommended Component Architecture:
/// - `handle_key_event`: map a keypress to an `Action`
/// - `handle_tick`: periodic background work (polling, scanning)
///
/// Rendering is done via per-mode `render_with_app` methods (not through this trait).
pub trait Component {
    /// Map a keypress to an Action.
    fn handle_key_event(&mut self, _key: KeyEvent) -> Action {
        Action::Noop
    }

    /// Periodic background work (called on every tick when this component is active).
    fn handle_tick(&mut self) -> Action {
        Action::Noop
    }
}
