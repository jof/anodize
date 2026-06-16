//! Ceremony scripts: one straight-line function per CA operation.
//!
//! Each script is generic over the [`crate::ceremony::io`] effect traits, so it
//! is exercised identically by the live TUI adapters and by transcript tests.

pub mod init_root;
pub mod issue_crl;
pub mod key_backup;
pub mod landing_pad;
pub mod migrate_disc;
#[cfg(feature = "dev-burn")]
pub mod refresh_disc;
pub mod rekey_shares;
pub mod revoke_cert;
pub mod sign_csr;
pub mod validate_disc;
