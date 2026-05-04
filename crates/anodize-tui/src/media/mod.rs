//! Ceremony device management — USB mounting and optical disc session lifecycle.
//!
//! USB mounting uses nix::mount::mount(2) directly (requires CAP_SYS_ADMIN).
//! Disc operations use SG_IO MMC commands via the sgdev/mmc modules.
//! No external tool subprocesses.

pub mod iso9660;
pub mod mmc;
pub mod sgdev;

pub use iso9660::{IsoFile, SessionEntry};

use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::time::SystemTime;

use anyhow::{Context, Result};
use nix::mount::{mount, umount2, MntFlags, MsFlags};

use mmc::{
    close_track_session, get_current_profile, max_sessions_for_profile, profile_is_rewritable,
    profile_name, read_disc_info, read_sectors, read_track_info, reserve_track, send_opc,
    set_write_parameters, synchronize_cache, write_sectors, CloseTarget, DiscStatus, MultiSession,
    WriteParams, WriteType,
};
use sgdev::{SgDev, CDS_DISC_OK};

// ── USB discovery and mounting ────────────────────────────────────────────────

/// Scan /sys/block/sd* and enumerate all sd* block devices and their partitions.
/// Returns device paths like /dev/sda, /dev/sda1, /dev/sdb1, etc.
///
/// The removable=1 sysfs check is intentionally omitted: QEMU usb-storage may report
/// removable=0 depending on kernel/QEMU version, and the profile.toml presence check
/// in find_profile_usb() is the real discriminator — any drive without it is unmounted
/// immediately and has no further effect.
pub fn scan_usb_partitions() -> Vec<PathBuf> {
    let mut result = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/block") else {
        return result;
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.starts_with("sd") {
            continue;
        }

        // Look for partition sub-entries (sda1, sda2, …)
        let block_dir = entry.path();
        if let Ok(sub) = std::fs::read_dir(&block_dir) {
            let mut has_parts = false;
            for sub_entry in sub.flatten() {
                let sub_name = sub_entry.file_name();
                let sub_str = sub_name.to_string_lossy();
                if sub_str.starts_with(name_str.as_ref()) && sub_str.len() > name_str.len() {
                    result.push(PathBuf::from(format!("/dev/{sub_str}")));
                    has_parts = true;
                }
            }
            // If no partitions found, add the raw device itself
            if !has_parts {
                result.push(PathBuf::from(format!("/dev/{name_str}")));
            }
        }
    }

    result
}

/// Return a human-readable summary of sd* devices visible in /sys/block, including
/// their removable flag value. Used by the TUI to show the operator what's happening
/// during USB discovery even when no matching device is found.
///
/// Examples:
///   "No sd* devices in /sys/block"
///   "sda (removable=1)"
///   "sda (removable=0), sdb (removable=1)"
pub fn usb_scan_diagnostics() -> String {
    let Ok(entries) = std::fs::read_dir("/sys/block") else {
        return "Cannot read /sys/block".into();
    };

    let mut found: Vec<String> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name();
            let name_str = name.to_string_lossy();
            if !name_str.starts_with("sd") {
                return None;
            }
            let removable = std::fs::read_to_string(e.path().join("removable"))
                .map(|s| s.trim().to_owned())
                .unwrap_or_else(|_| "?".into());
            Some(format!("{name_str} (removable={removable})"))
        })
        .collect();

    if found.is_empty() {
        "No sd* devices in /sys/block".into()
    } else {
        found.sort();
        found.join(", ")
    }
}

/// Mount a USB partition (vfat, then ext4 on failure) at `mountpoint`.
/// Creates the mountpoint directory if absent.
/// Requires CAP_SYS_ADMIN (granted via NixOS security.wrappers capability).
pub fn mount_usb(dev: &Path, mountpoint: &Path) -> Result<()> {
    std::fs::create_dir_all(mountpoint)
        .with_context(|| format!("create mountpoint {}", mountpoint.display()))?;

    // Security flags: no exec, no suid, no dev
    let flags = MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_NODEV;

    // Try vfat first (most USB sticks), then ext4
    let err_vfat = mount(Some(dev), mountpoint, Some("vfat"), flags, None::<&str>);
    if err_vfat.is_ok() {
        return Ok(());
    }
    mount(Some(dev), mountpoint, Some("ext4"), flags, None::<&str>).with_context(|| {
        format!(
            "mount {} at {} (tried vfat and ext4)",
            dev.display(),
            mountpoint.display()
        )
    })?;
    Ok(())
}

/// Unmount `mountpoint` (lazy detach — safe even if files are open).
pub fn unmount(mountpoint: &Path) -> Result<()> {
    umount2(mountpoint, MntFlags::MNT_DETACH)
        .with_context(|| format!("umount {}", mountpoint.display()))?;
    Ok(())
}

/// Try mounting each candidate partition in turn.
/// Returns `(profile_path, dev_path)` on the first partition that contains a profile.toml.
/// Unmounts all partitions that did not contain a profile.
/// The winning partition is left mounted at `mountpoint`.
///
/// Returns `Err` if every candidate failed to mount (mount errors surface this way).
/// Returns `Ok(None)` if at least one candidate mounted successfully but none had `profile.toml`.
pub fn find_profile_usb(
    candidates: &[PathBuf],
    mountpoint: &Path,
) -> Result<Option<(PathBuf, PathBuf)>> {
    let mut any_mounted = false;
    let mut mount_errors: Vec<String> = Vec::new();

    for dev in candidates {
        match mount_usb(dev, mountpoint) {
            Err(e) => {
                mount_errors.push(format!("{}: {e}", dev.display()));
                continue;
            }
            Ok(()) => {
                any_mounted = true;
            }
        }
        let profile = mountpoint.join("profile.toml");
        if profile.exists() {
            return Ok(Some((profile, dev.clone())));
        }
        let _ = unmount(mountpoint);
    }

    if !any_mounted && !mount_errors.is_empty() {
        anyhow::bail!("{}", mount_errors.join("; "));
    }
    Ok(None)
}

// ── Optical disc discovery ────────────────────────────────────────────────────

/// Scan /sys/block/sr* for optical drives and return their /dev paths.
pub fn scan_optical_drives() -> Vec<PathBuf> {
    let mut result = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/block") else {
        return result;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with("sr") {
            result.push(PathBuf::from(format!("/dev/{}", name_str)));
        }
    }
    result
}

// ── Single-pass disc scan ─────────────────────────────────────────────────────

/// Everything the caller needs after scanning a disc.
pub struct DiscScan {
    /// Parsed session entries read back from disc (authoritative count).
    pub sessions: Vec<SessionEntry>,
    /// Human-readable capacity line, e.g. "BD-R: 2 used, 253 remaining (max 255)".
    pub capacity_summary: String,
    /// How many more sessions the disc can accept.
    pub sessions_remaining: u16,
}

/// Open a device, verify it holds an appendable write-once disc, read back all
/// sessions, and compute the capacity summary — all in a single device open.
///
/// Returns `Err(reason)` (human-readable) if the disc is absent, rewritable,
/// or finalized.
pub fn scan_disc(dev: &Path) -> Result<DiscScan, String> {
    let sg = SgDev::open(dev).map_err(|e| format!("cannot open {}: {e}", dev.display()))?;

    // Drive-status gate
    match sg.drive_status() {
        Ok(s) if s != CDS_DISC_OK => return Err("no disc present".into()),
        Err(e) => return Err(format!("drive status error: {e}")),
        _ => {}
    }

    // Reject rewritable media
    let profile = get_current_profile(&sg).unwrap_or(0);
    if profile_is_rewritable(profile) {
        return Err(format!(
            "rewritable media (profile {profile:#06x}) not allowed — \
             use write-once disc (BD-R, DVD-R, CD-R, or M-Disc)"
        ));
    }

    // Read disc info
    let info = read_disc_info(&sg).map_err(|e| format!("cannot read disc info: {e}"))?;
    if !info.status.is_appendable() {
        return Err("disc is finalized — insert a blank or appendable write-once disc".into());
    }

    // Read sessions from tracks
    let mut sessions: Vec<SessionEntry> = Vec::new();
    if info.status != DiscStatus::Blank && info.sessions > 0 {
        for track_num in 1..=info.sessions as u8 {
            let track = match read_track_info(&sg, track_num) {
                Ok(t) => t,
                Err(_) => continue,
            };
            let n_sectors = track.size_sectors.max(1) as usize;
            let mut image = vec![0u8; n_sectors * iso9660::SECTOR];
            if let Err(e) = read_sectors(&sg, track.start_lba, &mut image) {
                tracing::warn!(
                    "cannot read session {} at LBA {}: {e}",
                    track_num,
                    track.start_lba
                );
                continue;
            }
            match iso9660::parse_iso(&image) {
                Ok(entries) => sessions.extend(entries),
                Err(e) => tracing::warn!("cannot parse ISO for session {track_num}: {e}"),
            }
        }
        sessions.sort_by(|a, b| a.dir_name.cmp(&b.dir_name));
        sessions.dedup_by(|a, b| a.dir_name == b.dir_name);
    }

    // Capacity — derive used count from actually-parsed sessions
    let max = max_sessions_for_profile(profile);
    let used = sessions.len() as u16;
    let remaining = max.saturating_sub(used);
    let name = profile_name(profile);
    let capacity_summary = format!("{name}: {used} used, {remaining} remaining (max {max})");

    Ok(DiscScan {
        sessions,
        capacity_summary,
        sessions_remaining: remaining,
    })
}

// ── Session write ─────────────────────────────────────────────────────────────

/// Write a new TAO session to `dev`.
/// `all_sessions` is prior sessions + the new one (last element = newest).
/// Set `is_final` to close the disc after this session.
/// Designed to be called from a background thread; sends result via `done`.
pub fn write_session(
    dev: &Path,
    all_sessions: Vec<SessionEntry>,
    is_final: bool,
    done: Sender<Result<()>>,
) {
    let dev = dev.to_path_buf();
    std::thread::spawn(move || {
        done.send(write_session_inner(&dev, &all_sessions, is_final))
            .ok();
    });
}

fn write_session_inner(dev: &Path, sessions: &[SessionEntry], is_final: bool) -> Result<()> {
    let sg = SgDev::open(dev).with_context(|| format!("open optical device {}", dev.display()))?;

    // Defense in depth: refuse to write to rewritable media even if caller already checked
    if let Ok(profile) = get_current_profile(&sg) {
        if profile_is_rewritable(profile) {
            anyhow::bail!("refusing to write to rewritable media (profile {profile:#06x})");
        }
    }

    // Verify disc is appendable
    let info = read_disc_info(&sg).context("READ DISC INFORMATION")?;
    if !info.status.is_appendable() {
        anyhow::bail!("disc is not appendable (status={:?})", info.status);
    }

    // Get the NWA (Next Writable Address) for the new session
    // For a blank disc the last track is the invisible track (0xFF)
    let nwa = if info.status == DiscStatus::Blank {
        0u32
    } else {
        read_track_info(&sg, 0xFF)
            .map(|t| t.nwa)
            .unwrap_or(info.nwa)
    };

    // OPC calibration — optional; virtual drives (cdemu) return ILLEGAL_REQUEST for this
    // physical laser calibration command. Real M-Disc drives either support it or handle
    // power calibration internally. Silently ignore failures.
    let _ = send_opc(&sg);

    // Configure TAO write parameters — optional; cdemu virtual drives may return
    // ILLEGAL_REQUEST for MODE SELECT. Physical drives that don't support it use
    // their own defaults. Silently ignore failures.
    let multi = if is_final {
        MultiSession::FinalSession
    } else {
        MultiSession::Open
    };
    let _ = set_write_parameters(
        &sg,
        &WriteParams {
            write_type: WriteType::Tao,
            multi_session: multi,
            bufe: true,
        },
    );

    // Reserve track — optional; cdemu virtual drives may not require this.
    let _ = reserve_track(&sg);

    // Build ISO image in memory (all sessions including new one)
    let image = iso9660::build_iso(sessions);

    // Write in 32-sector (64 KiB) chunks
    const CHUNK_SECTORS: usize = 32;
    let chunk_bytes = CHUNK_SECTORS * iso9660::SECTOR;
    let mut written_sectors = 0u32;

    for chunk in image.chunks(chunk_bytes) {
        // Pad last chunk to sector boundary if needed
        let padded: Vec<u8> = if chunk.len() % iso9660::SECTOR == 0 {
            chunk.to_vec()
        } else {
            let mut p = chunk.to_vec();
            p.resize(p.len().div_ceil(iso9660::SECTOR) * iso9660::SECTOR, 0);
            p
        };
        let lba = nwa + written_sectors;
        write_sectors(&sg, lba, &padded).context("WRITE(10)")?;
        written_sectors += (padded.len() / iso9660::SECTOR) as u32;
    }

    synchronize_cache(&sg).context("SYNCHRONIZE CACHE")?;

    // Close track + session after every write so the drive (and cdemu) commits
    // a proper session boundary.  The multisession write parameter (set above)
    // keeps the disc appendable.  For the final session, Disc close finalizes.
    close_track_session(&sg, CloseTarget::Track).context("CLOSE TRACK")?;
    if is_final {
        close_track_session(&sg, CloseTarget::Disc).context("CLOSE DISC")?;
    } else {
        close_track_session(&sg, CloseTarget::Session).context("CLOSE SESSION")?;
    }

    Ok(())
}

// ── Utility: session directory name from SystemTime ───────────────────────────

/// Format a SystemTime as "YYYYMMDDTHHMMSS_NNNNNNNNNZ" (26 chars, UTC).
/// Nanoseconds prevent directory collision when two sessions start in the same second.
pub fn session_dir_name(ts: SystemTime) -> String {
    let odt = time::OffsetDateTime::from(ts);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}_{:09}Z",
        odt.year(),
        odt.month() as u8,
        odt.day(),
        odt.hour(),
        odt.minute(),
        odt.second(),
        odt.nanosecond(),
    )
}
