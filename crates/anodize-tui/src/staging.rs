//! RAII wrapper for the ceremony staging directory.
//!
//! `StagingDir` ensures that `/run/anodize/staging` is created on construction
//! and cleaned up on drop, preventing orphaned staging artifacts.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// RAII guard for a ceremony staging directory.
///
/// Creates the directory on construction; removes it (best-effort) on drop.
pub struct StagingDir {
    path: PathBuf,
}

impl StagingDir {
    /// Create (or re-create) the staging directory at the given path.
    pub fn create(base: &Path) -> Result<Self> {
        if base.exists() {
            std::fs::remove_dir_all(base)
                .with_context(|| format!("failed to clean old staging dir: {}", base.display()))?;
        }
        std::fs::create_dir_all(base)
            .with_context(|| format!("failed to create staging dir: {}", base.display()))?;
        Ok(Self {
            path: base.to_path_buf(),
        })
    }

    /// Path to the staging directory.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn staging_dir_creates_and_cleans_up() {
        let dir = PathBuf::from("/tmp/anodize-staging-test");
        {
            let staging = StagingDir::create(&dir).unwrap();
            assert!(staging.path().exists());
        }
        // After drop, directory should be gone.
        assert!(!dir.exists());
    }

    #[test]
    fn staging_dir_cleans_existing_before_create() {
        let dir = PathBuf::from("/tmp/anodize-staging-test-existing");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("leftover.txt"), b"stale").unwrap();

        let staging = StagingDir::create(&dir).unwrap();
        // Old file should be gone.
        assert!(!staging.path().join("leftover.txt").exists());
        assert!(staging.path().exists());
        drop(staging);
        assert!(!dir.exists());
    }
}
