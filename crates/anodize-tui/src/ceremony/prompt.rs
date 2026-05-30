//! The single command vocabulary spoken between a running ceremony script and
//! the TUI, replacing the old `Action` / `OpAction` / `ConfirmTarget` trio.
//!
//! A script (running on its own thread) sends a [`Prompt`] when it needs the
//! operator, and blocks until the main thread sends back a [`Response`]. The
//! renderer is a pure function of the current `Prompt`; the input layer maps a
//! key to a `Response`. These types are an implementation detail of the
//! channel-backed [`crate::ceremony::io::Operator`] / [`crate::ceremony::io::Archive`]
//! adapters — scripts and transcript fakes never see them.

use anodize_config::state::SssMetadata;

use super::io::{Choice, Outcome};

/// A request from a ceremony script for the operator (or a long-running effect
/// the UI should display). Carries everything the renderer needs.
#[derive(Debug, Clone)]
pub enum Prompt {
    /// Present a numbered menu; expects [`Response::Choice`].
    Choose {
        title: String,
        body: Vec<String>,
        options: Vec<Choice>,
    },
    /// Two-key confirmation gate; expects [`Response::Confirm`] or `Abort`.
    Confirm { title: String, body: Vec<String> },
    /// Collect threshold SSS shares; expects [`Response::Shares`].
    CollectShares { sss: SssMetadata },
    /// Re-confirm the system clock; expects [`Response::Ack`] or `Abort`.
    ReconfirmClock { rfc3339: String },
    /// A long-running disc burn is in progress. No input expected; the renderer
    /// shows a spinner and the accumulated burn log.
    Burning { what: String, log: Vec<String> },
    /// Informational status line. No input expected.
    Note(String),
    /// Terminal: the ceremony finished successfully.
    Done(Outcome),
    /// Terminal: the ceremony aborted.
    Aborted(String),
}

/// The operator's answer to a [`Prompt`].
#[derive(Debug, Clone)]
pub enum Response {
    /// Chose option at `index`.
    Choice(usize),
    /// Confirmed / proceed.
    Confirm,
    /// Supplied reconstructed shares.
    Shares(Vec<anodize_sss::Share>),
    /// Acknowledged (clock correct, etc.).
    Ack,
    /// Aborted / quit.
    Abort,
}
