pub mod confirm_dialog;
pub mod custodian_setup;
pub mod mode_bar;
pub mod phase_bar;
pub mod share_input;
pub mod share_reveal;
pub mod status_bar;

use crossterm::event::KeyEvent;
use ratatui::{layout::Rect, Frame};

use crate::action::Action;

/// Every interactive screen/panel implements this trait.
///
/// Follows ratatui's recommended Component Architecture:
/// - `handle_key_event`: map a keypress to an `Action`
/// - `handle_tick`: periodic background work (polling, scanning)
/// - `update`: process an `Action`, possibly returning a chained `Action`
/// - `render`: draw into the given `Rect`
pub trait Component {
    /// Called once when the component is first activated.
    fn init(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    /// Map a keypress to an Action.
    fn handle_key_event(&mut self, _key: KeyEvent) -> Action {
        Action::Noop
    }

    /// Periodic background work (called on every tick when this component is active).
    fn handle_tick(&mut self) -> Action {
        Action::Noop
    }

    /// Process an action, possibly returning a chained action.
    fn update(&mut self, _action: &Action) -> Action {
        Action::Noop
    }

    /// Draw this component into the given area.
    fn render(&self, frame: &mut Frame, area: Rect);
}
