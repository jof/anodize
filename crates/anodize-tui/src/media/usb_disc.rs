//! Dev-mode disc USB: substitute a USB stick for optical disc writes.
//!
//! A disc USB is identified by an ANODIZE_DISC_ID marker file in the partition
//! root.  It must be a separate physical device from the profile USB (which
//! carries profile.toml).  A partition with both files is rejected.

use std::path::{Path, PathBuf};

use anyhow::Result;

use super::iso9660::{self, SessionEntry};
use super::{mount_usb, scan_usb_partitions, unmount};

/// A USB stick serving as a disc substitute in dev mode.
#[derive(Clone)]
pub struct DiscUsb {
    /// Block device path, e.g. /dev/sdb1
    pub dev: PathBuf,
    /// Filesystem UUID from /dev/disk/by-uuid/ (empty string if not found)
    pub uuid: String,
}

/// Read the filesystem UUID for `dev` by scanning /dev/disk/by-uuid/ symlinks.
/// Symlink targets look like "../../sdb1"; we extract the filename to get the
/// device basename and compare to `dev`.
pub fn dev_uuid(dev: &Path) -> String {
    let Ok(entries) = std::fs::read_dir("/dev/disk/by-uuid") else {
        return String::new();
    };
    for entry in entries.flatten() {
        let Ok(target) = std::fs::read_link(entry.path()) else {
            continue;
        };
        let Some(target_name) = target.file_name() else {
            continue;
        };
        if PathBuf::from("/dev").join(target_name) == dev {
            return entry.file_name().to_string_lossy().into_owned();
        }
    }
    String::new()
}

/// Scan USB partitions for the first one bearing ANODIZE_DISC_ID but not profile.toml.
///
/// `profile_dev` — the device already claimed as the profile USB; skipped by device
/// path before mounting so the two roles can never be on the same device.
///
/// `probe_mountpoint` — temporary mountpoint used sequentially for each candidate.
/// It is always unmounted before returning.
pub fn find_disc_usb(profile_dev: Option<&Path>, probe_mountpoint: &Path) -> Option<DiscUsb> {
    for dev in scan_usb_partitions() {
        if profile_dev.map(|pd| pd == dev).unwrap_or(false) {
            continue;
        }
        if mount_usb(&dev, probe_mountpoint).is_err() {
            continue;
        }
        let has_marker = probe_mountpoint.join("ANODIZE_DISC_ID").exists();
        let has_profile = probe_mountpoint.join("profile.toml").exists();
        let _ = unmount(probe_mountpoint);

        if has_marker && !has_profile {
            let uuid = dev_uuid(&dev);
            return Some(DiscUsb { dev, uuid });
        }
    }
    None
}

/// Read ceremony.iso from the disc USB and parse its sessions.
/// Returns an empty Vec if ceremony.iso does not yet exist (fresh disc USB).
/// Mounts at `probe_mountpoint`, reads, then unmounts before returning.
pub fn read_disc_usb_sessions(disc_usb: &DiscUsb, probe_mountpoint: &Path) -> Vec<SessionEntry> {
    if mount_usb(&disc_usb.dev, probe_mountpoint).is_err() {
        return Vec::new();
    }
    let bytes = std::fs::read(probe_mountpoint.join("ceremony.iso")).unwrap_or_default();
    let _ = unmount(probe_mountpoint);
    if bytes.is_empty() {
        return Vec::new();
    }
    iso9660::parse_iso(&bytes).unwrap_or_default()
}

/// Write `iso_bytes` as ceremony.iso on the disc USB.
/// Mounts at a path derived from the USB's filesystem UUID, writes, then unmounts.
pub fn write_iso_to_disc_usb(disc_usb: &DiscUsb, iso_bytes: &[u8]) -> Result<()> {
    let mp = if disc_usb.uuid.is_empty() {
        PathBuf::from("/tmp/anodize-disc-usb-write")
    } else {
        PathBuf::from(format!("/tmp/anodize-disc-{}", disc_usb.uuid))
    };
    mount_usb(&disc_usb.dev, &mp)?;
    let result = std::fs::write(mp.join("ceremony.iso"), iso_bytes);
    let _ = unmount(&mp);
    result.map_err(|e| anyhow::anyhow!("write ceremony.iso: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn dev_uuid_finds_symlink() {
        // Build a temporary directory tree that mimics /dev/disk/by-uuid/
        let tmp = std::env::temp_dir().join(format!("anodize-uuid-test-{}", std::process::id()));
        fs::create_dir_all(&tmp).unwrap();
        let fake_dev = PathBuf::from("/dev/sdz9");
        // Symlink named after a UUID → relative target resolving to /dev/sdz9
        let link = tmp.join("ABCD-1234");
        std::os::unix::fs::symlink("../../sdz9", &link).unwrap();

        // Manually exercise the loop logic rather than calling dev_uuid() which
        // hard-codes /dev/disk/by-uuid — verify the filename-extraction logic.
        let target = fs::read_link(&link).unwrap();
        let target_dev = PathBuf::from("/dev").join(target.file_name().unwrap());
        assert_eq!(target_dev, fake_dev);
        assert_eq!(link.file_name().unwrap().to_string_lossy(), "ABCD-1234");

        fs::remove_dir_all(&tmp).unwrap();
    }
}
