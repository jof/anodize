//! Ceremony scripts: one straight-line function per CA operation.
//!
//! Each script is generic over the [`crate::ceremony::io`] effect traits, so it
//! is exercised identically by the live TUI adapters and by transcript tests.

/// Format a CRL artifact filename for the disc ISO (uppercased).
/// e.g. crl_number=1 → `"ROOT-CRL-001.CRL"`, crl_number=42 → `"ROOT-CRL-042.CRL"`.
pub fn crl_disc_filename(crl_number: u64) -> String {
    format!("ROOT-CRL-{crl_number:03}.CRL")
}

/// Format a CRL filename for the shuttle USB (lowercased).
/// e.g. crl_number=1 → `"root-crl-001.crl"`.
pub fn crl_shuttle_filename(crl_number: u64) -> String {
    format!("root-crl-{crl_number:03}.crl")
}

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
