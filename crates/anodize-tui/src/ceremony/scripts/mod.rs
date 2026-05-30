//! Ceremony scripts: one straight-line function per CA operation.
//!
//! Each script is generic over the [`crate::ceremony::io`] effect traits, so it
//! is exercised identically by the live TUI adapters and by transcript tests.

pub mod issue_crl;
pub mod revoke_cert;
pub mod sign_csr;
