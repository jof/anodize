use std::time::Duration;

use crossterm::event::{self, Event as CrosstermEvent, KeyEvent, KeyEventKind};

/// Application-level events produced by the event handler.
#[derive(Debug)]
pub enum Event {
    /// A key was pressed (KeyEventKind::Press only).
    Key(KeyEvent),
    /// Tick interval elapsed — drive background polling.
    Tick,
    /// Terminal was resized.
    Resize(u16, u16),
}

/// Synchronous event handler: polls crossterm and emits `Event`s.
///
/// Uses crossterm's blocking `poll` + `read` (no tokio required).
/// The tick interval drives background operations (USB scan, disc scan, etc.).
pub struct EventHandler {
    tick_rate: Duration,
}

impl EventHandler {
    pub fn new(tick_rate: Duration) -> Self {
        Self { tick_rate }
    }

    /// Poll for the next event. Returns `Some(Event)` if an event occurred
    /// within the tick interval, or `Some(Event::Tick)` if the interval elapsed.
    pub fn next(&self) -> std::io::Result<Event> {
        if event::poll(self.tick_rate)? {
            match event::read()? {
                CrosstermEvent::Key(key) if key.kind == KeyEventKind::Press => Ok(Event::Key(key)),
                CrosstermEvent::Resize(w, h) => Ok(Event::Resize(w, h)),
                // Ignore non-press key events (Release, Repeat) and mouse/focus/paste
                _ => Ok(Event::Tick),
            }
        } else {
            Ok(Event::Tick)
        }
    }
}
