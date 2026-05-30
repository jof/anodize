//! Ceremonies-as-scripts: the experimental ceremony engine.
//!
//! - [`io`] — the effect vocabulary (`Operator` / `Vault` / `Archive`) plus the
//!   typestate tokens that enforce irreversible ordering.
//! - [`scripts`] — one straight-line function per CA operation.
//! - [`prompt`] — the `Prompt` / `Response` pair the TUI adapter speaks (the
//!   single command vocabulary that replaces `Action` / `OpAction` /
//!   `ConfirmTarget`).
//!
//! The transcript tests live alongside each script and drive it with scripted
//! fakes — no terminal, HSM, or disc required.

#[allow(dead_code)]
pub mod adapters;
#[allow(dead_code)]
pub mod harness;
#[allow(dead_code)]
pub mod io;
#[allow(dead_code)]
pub mod prompt;
#[allow(dead_code)]
pub mod run;
#[allow(dead_code)]
pub mod scripts;
#[allow(dead_code)]
pub mod ui;
