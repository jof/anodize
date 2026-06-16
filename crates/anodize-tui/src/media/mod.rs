//! Ceremony device management — shuttle USB access and optical disc session lifecycle.
//!
//! The shuttle USB (labelled ANODIZE) is mounted/unmounted by systemd
//! (mount-anodize-shuttle.service + BindsTo= the udev device unit).
//! The ceremony binary is a pure consumer of /run/anodize/shuttle/.
//! Disc operations use SG_IO MMC commands via the sgdev/mmc modules.
//! No external tool subprocesses.

pub mod iso9660;
pub mod mmc;
pub mod sgdev;

#[allow(unused_imports)]
pub use iso9660::{IsoFile, SessionEntry};

use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::time::SystemTime;

/// Progress updates sent from the background disc-write thread.
pub enum BurnProgress {
    /// Human-readable step description, e.g. "Reading disc info…"
    Step(String),
    /// Terminal message: the write finished (success or failure).
    Done(Result<()>),
}

use anyhow::{Context, Result};

use mmc::{
    close_track_session, get_current_profile, max_sessions_for_profile, profile_is_cd,
    profile_is_rewritable, profile_name, read_disc_info, read_sectors, read_track_info,
    reserve_track, resolve_nwa, send_opc, set_write_parameters, synchronize_cache,
    wait_drive_ready, write_sectors, CloseTarget, DiscStatus, MultiSession, WriteParams, WriteType,
};
use sgdev::{SgDev, CDS_DISC_OK};

// ── USB diagnostics ──────────────────────────────────────────────────────────

/// Return a human-readable summary of sd* devices visible in /sys/block, including
/// their removable flag value. Used by the TUI to show the operator what's happening
/// during USB discovery even when no matching device is found.
///
/// Examples:
///   "No sd* devices in /sys/block"
///   "sda (removable=1)"
///   "sda (removable=0), sdb (removable=1)"
#[allow(dead_code)]
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

// ── Shuttle mount verification ─────────────────────────────────────────────────

/// Verify that `mountpoint` is an active, readable mount.
///
/// Checks two conditions:
/// 1. The mountpoint appears in `/proc/mounts`.
/// 2. `profile.toml` is readable on the mounted filesystem.
///
/// Condition 2 catches "zombie mounts": when a USB device is physically
/// yanked, the kernel keeps the VFS mount entry in `/proc/mounts` but the
/// backing block device is gone.  All file access returns ENOENT even
/// though the mount entry persists.  Hardware testing (NixOS 25.11,
/// kernel 6.x, vfat) confirmed this behaviour.
#[allow(dead_code)]
pub fn verify_shuttle_mount(mountpoint: &Path) -> Result<()> {
    if !mountpoint.exists() {
        anyhow::bail!("shuttle mountpoint {} does not exist", mountpoint.display());
    }

    let mounts = std::fs::read_to_string("/proc/mounts")
        .context("cannot read /proc/mounts to verify shuttle mount")?;

    let target = mountpoint
        .canonicalize()
        .unwrap_or_else(|_| mountpoint.to_path_buf());
    let target_str = target.to_string_lossy();

    let mut found_in_mounts = false;
    for line in mounts.lines() {
        // /proc/mounts format: device mountpoint fstype options dump pass
        let mut fields = line.split_whitespace();
        let _dev = fields.next();
        if let Some(mp) = fields.next() {
            if mp == target_str.as_ref() {
                found_in_mounts = true;
                break;
            }
        }
    }

    if !found_in_mounts {
        anyhow::bail!(
            "shuttle path {} is not an active mount — USB may have been \
             unmounted or remounted elsewhere. Re-insert the shuttle USB.",
            mountpoint.display()
        );
    }

    // Zombie mount detection: the mount entry exists in /proc/mounts but
    // the backing block device was physically removed.  Stat a file that
    // must always be present on a valid shuttle.
    let probe = mountpoint.join("profile.toml");
    if probe.metadata().is_err() {
        anyhow::bail!(
            "shuttle mount {} appears in /proc/mounts but profile.toml is \
             not readable — USB was likely removed. Re-insert the shuttle USB.",
            mountpoint.display()
        );
    }

    Ok(())
}

/// Write `data` to `path`, then fsync the file to ensure the data actually
/// reached the underlying device.  Returns a descriptive error on failure
/// instead of silently succeeding on a stale mount.
#[allow(dead_code)]
pub fn write_and_sync(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;

    let mut f =
        std::fs::File::create(path).with_context(|| format!("create {}", path.display()))?;
    f.write_all(data)
        .with_context(|| format!("write {}", path.display()))?;
    f.sync_all()
        .with_context(|| format!("fsync {}", path.display()))?;
    Ok(())
}

// ── Optical disc discovery ────────────────────────────────────────────────────

/// Scan /sys/block/sr* for optical drives and return their /dev paths.
#[allow(dead_code)]
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

    // Wait for drive readiness — the disc may have just been inserted or a
    // previous session close may still be finalising lead-out / DMS update.
    wait_drive_ready(&sg, std::time::Duration::from_secs(60))
        .map_err(|e| format!("drive not ready: {e}"))?;

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

    // Read sessions from tracks.  Always probe tracks 1..255 regardless of
    // disc_status — the DMA may not have been updated after a CLOSE SESSION
    // (BUG-3), causing read_disc_info to report Blank even when data is
    // present.  On a truly blank disc, read_track_info will fail or tracks
    // will be marked blank, breaking the loop naturally.
    let is_cd = profile_is_cd(profile);
    let is_reported_blank = info.status == DiscStatus::Blank;
    let mut sessions: Vec<SessionEntry> = Vec::new();
    for track_num in 1..=255u8 {
        let track = match read_track_info(&sg, track_num) {
            Ok(t) => t,
            Err(_) => break, // no more tracks
        };
        if track.blank {
            break; // reached the blank/invisible track — no more data
        }
        // CD-R tracks may have a 150-sector (2-second) Red Book pregap
        // before the data area.  DVD and BD do not have pregaps.  Only
        // attempt the pregap-skip probe on CD profiles to avoid issuing
        // a wasteful (and potentially confusing) extra READ on BD/DVD.
        let data_sectors = track.size_sectors.max(1) as usize;
        let candidates: &[(u32, usize)] = if track.start_lba >= 0x8000_0000 {
            // Negative LBA (e.g. -150): data starts at absolute LBA 0
            let gap = 0u32.wrapping_sub(track.start_lba);
            &[(0u32, data_sectors.saturating_sub(gap as usize).max(1))]
        } else if is_cd && data_sectors > 150 {
            // CD: try with 150-sector pregap skip, then without
            &[
                (track.start_lba + 150, data_sectors - 150),
                (track.start_lba, data_sectors),
            ]
        } else {
            // BD-R / DVD-R / small CD tracks: read from track start directly
            &[(track.start_lba, data_sectors)]
        };
        let mut parsed = false;
        for &(read_lba, read_n) in candidates {
            let mut image = vec![0u8; read_n * iso9660::SECTOR];
            if read_sectors(&sg, read_lba, &mut image).is_err() {
                continue;
            }
            match iso9660::parse_iso(&image, read_lba) {
                Ok(entries) => {
                    sessions.extend(entries);
                    parsed = true;
                    break;
                }
                Err(_) => continue,
            }
        }
        if !parsed {
            tracing::warn!("cannot parse ISO for track {track_num}");
        }
    }
    sessions.sort_by(|a, b| a.dir_name.cmp(&b.dir_name));
    sessions.dedup_by(|a, b| a.dir_name == b.dir_name);
    if is_reported_blank && !sessions.is_empty() {
        tracing::warn!(
            "disc reports Blank but found {} parseable track(s) — \
             DMA may not reflect actual disc state",
            sessions.len()
        );
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

// ── Session superset invariant ─────────────────────────────────────────────────

/// Carry forward files from `prior` that are missing in `new`.
/// AUDIT.LOG is always produced fresh by both intent and record sessions, so
/// it is never backfilled.  All other files (including STATE.JSON) are carried
/// forward when absent from the new session, preserving the superset invariant.
///
/// This is the single definition of the superset rule.  `write_session` applies
/// it to the image it burns; callers that retain a burned session as a future
/// prior (see `DiscArchive::burn`) must apply the *same* transform to what they
/// retain, or the next burn would carry forward from an impoverished prior.
/// The operation is idempotent, so applying it twice against the same prior is
/// a harmless no-op.
pub(crate) fn backfill_session(prior: &SessionEntry, new: &mut SessionEntry) {
    const ALWAYS_FRESH: &[&str] = &["AUDIT.LOG"];
    for prev_file in &prior.files {
        let already = new
            .files
            .iter()
            .any(|f| f.name.eq_ignore_ascii_case(&prev_file.name));
        if !already {
            let is_fresh = ALWAYS_FRESH
                .iter()
                .any(|m| prev_file.name.eq_ignore_ascii_case(m));
            if is_fresh {
                tracing::debug!(
                    file = %prev_file.name,
                    "backfill_session: skipping always-fresh file not present in new session"
                );
            } else {
                tracing::warn!(
                    file = %prev_file.name,
                    prior_session = %prior.dir_name,
                    new_session = %new.dir_name,
                    "backfill_session: carrying forward missing file from prior session"
                );
                new.files.push(prev_file.clone());
            }
        }
    }
}

// ── Session write ─────────────────────────────────────────────────────────────

/// Write a new TAO session to `dev`.
/// `prior_sessions` are the sessions already on disc; `new_session` is the one
/// being added.  Missing files from the immediately preceding session are
/// automatically carried forward into `new_session` (the superset invariant).
/// Set `is_final` to close the disc after this session.
pub fn write_session(
    dev: &Path,
    prior_sessions: &[SessionEntry],
    new_session: SessionEntry,
    is_final: bool,
    progress: Sender<BurnProgress>,
) {
    let dev = dev.to_path_buf();
    let prior = prior_sessions.to_vec();
    std::thread::spawn(move || {
        let result = write_session_inner(&dev, &prior, new_session, is_final, &progress);
        progress.send(BurnProgress::Done(result)).ok();
    });
}

/// Send a progress step, ignoring send failures (receiver may have dropped).
fn step(progress: &Sender<BurnProgress>, msg: impl Into<String>) {
    progress.send(BurnProgress::Step(msg.into())).ok();
}

fn write_session_inner(
    dev: &Path,
    prior_sessions: &[SessionEntry],
    mut new_session: SessionEntry,
    is_final: bool,
    progress: &Sender<BurnProgress>,
) -> Result<()> {
    step(progress, format!("Opening {}…", dev.display()));
    tracing::info!("write_session_inner: opening {}", dev.display());
    let sg = SgDev::open(dev).with_context(|| format!("open optical device {}", dev.display()))?;
    tracing::info!("write_session_inner: device opened");

    // Defense in depth: refuse to write to rewritable media even if caller already checked
    step(progress, "Checking media profile…");
    let profile = get_current_profile(&sg).unwrap_or(0);
    if profile_is_rewritable(profile) {
        anyhow::bail!("refusing to write to rewritable media (profile {profile:#06x})");
    }
    let is_bdr = matches!(profile, 0x0041 | 0x0042);
    let media_name = profile_name(profile);
    tracing::info!(
        profile = format_args!("{profile:#06x}"),
        is_bdr,
        "write_session_inner: profile"
    );

    // Verify disc is appendable
    step(progress, format!("Reading disc info ({media_name})…"));
    tracing::info!("write_session_inner: reading disc info");
    let info = read_disc_info(&sg).context("READ DISC INFORMATION")?;
    if !info.status.is_appendable() {
        anyhow::bail!("disc is not appendable (status={:?})", info.status);
    }
    tracing::info!(
        status = ?info.status,
        sessions = info.sessions,
        "write_session_inner: disc info OK"
    );

    // Wait for drive readiness — after CLOSE SESSION the drive may still be
    // writing lead-out / updating the Disc Management Structure.  Physical USB
    // drives (BUFFALO, etc.) can stay busy for tens of seconds.  libburn uses
    // the same TUR polling pattern before every write sequence.
    step(progress, "Waiting for drive ready…");
    tracing::info!("write_session_inner: TEST UNIT READY poll");
    wait_drive_ready(&sg, std::time::Duration::from_secs(120))
        .context("drive not ready before write")?;
    tracing::info!("write_session_inner: drive ready");

    // Resolve NWA using the portable strategy from libburn:
    // query by last_track_l (primary), 0xFF invisible track (fallback),
    // then validate the result.
    step(progress, "Resolving next writable address…");
    let nwa = resolve_nwa(&sg, &info).context("NWA resolution")?;
    step(
        progress,
        format!("Disc OK — {} session(s), NWA={nwa}", info.sessions),
    );
    tracing::info!(nwa, "write_session_inner: NWA resolved");

    // OPC calibration — optional; virtual drives (cdemu) return ILLEGAL_REQUEST for this
    // physical laser calibration command. Real M-Disc drives either support it or handle
    // power calibration internally. Silently ignore failures.
    step(progress, "Laser power calibration (OPC)…");
    tracing::debug!("write_session_inner: SEND OPC");
    let _ = send_opc(&sg);

    // MODE SELECT page 0x05 (CD/DVD Write Parameters) — only applicable to CD-R/RW and
    // DVD±R/RW media.  BD-R uses Sequential Recording Mode (SRM) natively and does not
    // define page 0x05; sending it can put some drives (including cdemu) into an
    // inconsistent state that causes subsequent WRITE(10) to fail.
    if !is_bdr {
        step(progress, "Setting write parameters (TAO mode)…");
        let multi = if is_final {
            MultiSession::FinalSession
        } else {
            MultiSession::Open
        };
        tracing::debug!("write_session_inner: SET WRITE PARAMETERS");
        let _ = set_write_parameters(
            &sg,
            &WriteParams {
                write_type: WriteType::Tao,
                multi_session: multi,
                bufe: true,
            },
        );
    } else {
        tracing::debug!("write_session_inner: skipping SET WRITE PARAMETERS (BD-R SRM)");
    }

    // Reserve track — optional; cdemu virtual drives may not require this.
    step(progress, "Reserving track…");
    tracing::debug!("write_session_inner: RESERVE TRACK");
    let _ = reserve_track(&sg);

    // Enforce the superset invariant: carry forward any files from the
    // immediately preceding session that are missing from the new one.
    if let Some(prev) = prior_sessions.last() {
        backfill_session(prev, &mut new_session);
    }

    // Build ISO image in memory (all sessions including new one)
    step(progress, "Building ISO 9660 image…");
    let mut all_sessions = prior_sessions.to_vec();
    all_sessions.push(new_session);
    let image = iso9660::build_iso(&all_sessions, nwa);
    let total_sectors = image.len().div_ceil(iso9660::SECTOR);
    let image_kib = image.len() / 1024;
    tracing::info!(
        image_bytes = image.len(),
        total_sectors,
        "write_session_inner: ISO built, starting write at LBA {nwa}"
    );

    // Dev only: persist each session ISO to the 9p share so the host can
    // inspect the multi-session disc structure without fighting cdemu's
    // in-memory-only storage.
    #[cfg(feature = "dev-softhsm-usb")]
    {
        let session_num = info.sessions + 1; // next session number
        let share = std::path::Path::new("/run/anodize/share");
        if share.is_dir() {
            let path = share.join(format!("session-{session_num:02}.iso"));
            if let Err(e) = std::fs::write(&path, &image) {
                tracing::warn!("dev: failed to save session ISO to {}: {e}", path.display());
            } else {
                tracing::info!("dev: saved session ISO to {}", path.display());
            }
        }
    }

    // Write in 32-sector (64 KiB) chunks
    const CHUNK_SECTORS: usize = 32;
    let chunk_bytes = CHUNK_SECTORS * iso9660::SECTOR;
    let mut written_sectors = 0u32;

    for (i, chunk) in image.chunks(chunk_bytes).enumerate() {
        // Pad last chunk to sector boundary if needed
        let padded: Vec<u8> = if chunk.len() % iso9660::SECTOR == 0 {
            chunk.to_vec()
        } else {
            let mut p = chunk.to_vec();
            p.resize(p.len().div_ceil(iso9660::SECTOR) * iso9660::SECTOR, 0);
            p
        };
        let lba = nwa + written_sectors;
        step(
            progress,
            format!("WRITE sector {written_sectors}/{total_sectors} ({image_kib} KiB, LBA {lba})…"),
        );
        tracing::debug!(
            chunk = i,
            lba,
            sectors = padded.len() / iso9660::SECTOR,
            "WRITE(10)"
        );
        write_sectors(&sg, lba, &padded).context("WRITE(10)")?;
        written_sectors += (padded.len() / iso9660::SECTOR) as u32;
    }
    step(
        progress,
        format!("Write complete — {written_sectors} sector(s)"),
    );
    tracing::info!(written_sectors, "write_session_inner: write complete");

    step(progress, "SYNCHRONIZE CACHE — flushing to media…");
    tracing::info!("write_session_inner: SYNCHRONIZE CACHE");
    match synchronize_cache(&sg) {
        Ok(()) => {}
        Err(first_err) => {
            let msg = format!("{first_err:#}");
            if msg.contains("transport error") || msg.contains("host=") {
                // USB bridge chips (ASMedia, Realtek, etc.) impose their own
                // command timeout (~30-60 s) independent of SG_IO.  On BD-R
                // back-to-back sessions the DMA update from the previous
                // CLOSE SESSION may still be running, causing the bridge to
                // reset.  The data is already on the disc surface — wait for
                // the drive to re-enumerate and retry.
                tracing::warn!(
                    "SYNCHRONIZE CACHE transport error (likely USB bridge timeout), \
                     waiting for drive recovery: {first_err:#}"
                );
                step(
                    progress,
                    "SYNCHRONIZE CACHE — USB transport error, waiting for drive recovery…",
                );
                std::thread::sleep(std::time::Duration::from_secs(5));
                step(
                    progress,
                    "SYNCHRONIZE CACHE — polling drive readiness (this may take a minute)…",
                );
                wait_drive_ready(&sg, std::time::Duration::from_secs(120))
                    .context("drive not ready after SYNCHRONIZE CACHE transport error")?;
                step(progress, "SYNCHRONIZE CACHE — drive recovered, retrying…");
                synchronize_cache(&sg).context("SYNCHRONIZE CACHE (retry after USB recovery)")?;
            } else {
                return Err(first_err).context("SYNCHRONIZE CACHE");
            }
        }
    }
    tracing::info!("write_session_inner: SYNCHRONIZE CACHE done");

    // Always close track + session so the drive commits a proper session
    // boundary.
    //
    // BD-R SRM note: real BD-R drives commit data on SYNCHRONIZE CACHE
    // and closing the session is optional.  However cdemu needs the
    // explicit CLOSE SESSION to commit the in-memory session into its
    // disc model so subsequent reads and new sessions work.  Our patched
    // cdemu no longer auto-finalizes BD-R on CLOSE SESSION (it only
    // does so for CD media via mode page 0x05), so this is safe.
    step(progress, "CLOSE TRACK…");
    tracing::info!("write_session_inner: CLOSE TRACK");
    close_track_session(&sg, CloseTarget::Track).context("CLOSE TRACK")?;
    tracing::info!("write_session_inner: CLOSE TRACK done");

    // When is_final=true, close the disc (finalize) so no further sessions
    // can be written.  For BD-R this is the only way to finalize — page 0x05
    // MultiSession is CD/DVD only.  For CD-R/DVD-R, this acts as belt-and-
    // suspenders alongside the FinalSession write parameter set earlier.
    let close = if is_final {
        CloseTarget::Disc
    } else {
        CloseTarget::Session
    };
    let label = if is_final {
        "CLOSE DISC — finalizing…"
    } else {
        "CLOSE SESSION — committing session boundary…"
    };
    step(progress, label);
    tracing::info!(is_final, ?close, "write_session_inner: closing");
    close_track_session(&sg, close).context("CLOSE SESSION/DISC")?;
    tracing::info!("write_session_inner: close done");

    // Post-burn verification: wait for the drive to finish any background
    // lead-out / DMA updates, then re-read disc info and verify the session
    // count incremented.  BD-R SRM drives (e.g. BUFFALO USB) may accept
    // CLOSE SESSION without actually committing the session boundary into the
    // Disc Management Area — catch that here instead of silently succeeding.
    step(
        progress,
        "Post-burn verification — waiting for drive ready…",
    );
    tracing::info!("write_session_inner: post-burn TUR poll");
    wait_drive_ready(&sg, std::time::Duration::from_secs(120))
        .context("drive not ready after CLOSE SESSION")?;

    let expected_sessions = info.sessions + 1;

    // Some drives (especially USB bridges) take significant time to update
    // the DMA after CLOSE SESSION.  Retry up to 3 times with increasing
    // delays before declaring failure.
    const VERIFY_DELAYS: &[u64] = &[5, 15, 30];
    let mut verified = false;
    for (attempt, &delay_secs) in std::iter::once(&0u64)
        .chain(VERIFY_DELAYS.iter())
        .enumerate()
    {
        if delay_secs > 0 {
            step(
                progress,
                format!("Session count mismatch — retrying in {delay_secs}s (attempt {attempt})…"),
            );
            tracing::warn!(
                attempt,
                delay_secs,
                "post-burn verify: session count mismatch, retrying"
            );
            std::thread::sleep(std::time::Duration::from_secs(delay_secs));
            wait_drive_ready(&sg, std::time::Duration::from_secs(60))
                .context("drive not ready during post-burn retry")?;
        }
        let post_info = read_disc_info(&sg).context("post-burn READ DISC INFORMATION")?;
        tracing::info!(
            attempt,
            before = info.sessions,
            after = post_info.sessions,
            expected = expected_sessions,
            "write_session_inner: post-burn session count"
        );
        if post_info.sessions >= expected_sessions {
            verified = true;
            break;
        }
    }
    if !verified {
        anyhow::bail!(
            "post-burn verification FAILED: drive reports fewer sessions than expected \
             (expected {expected_sessions}).  WRITE + SYNCHRONIZE CACHE + CLOSE SESSION \
             all returned OK but the drive's TOC/DMA was not updated.  The disc may be \
             in an inconsistent state — eject and inspect manually."
        );
    }

    step(progress, "Session committed successfully.");
    tracing::info!("write_session_inner: session write complete");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_shuttle_mount_rejects_nonexistent_path() {
        let result = verify_shuttle_mount(Path::new("/tmp/anodize-no-such-dir-42"));
        assert!(result.is_err());
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("does not exist"),
            "expected 'does not exist', got: {msg}"
        );
    }

    #[test]
    fn verify_shuttle_mount_rejects_plain_directory() {
        let dir = std::env::temp_dir().join("anodize-test-verify-mount");
        let _ = std::fs::create_dir_all(&dir);
        let result = verify_shuttle_mount(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        // On macOS: /proc/mounts doesn't exist → Err("cannot read /proc/mounts")
        // On Linux: dir exists but is not a mount → Err("not an active mount")
        assert!(
            result.is_err(),
            "plain directory should not pass mount check"
        );
    }

    #[test]
    fn write_and_sync_roundtrips() {
        let dir = std::env::temp_dir().join("anodize-test-write-sync");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.bin");
        let data = b"hello shuttle";

        let result = write_and_sync(&path, data);
        assert!(result.is_ok(), "write_and_sync failed: {result:?}");

        let read_back = std::fs::read(&path).unwrap();
        assert_eq!(read_back, data);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_and_sync_fails_on_bad_path() {
        let result = write_and_sync(Path::new("/no/such/dir/file.bin"), b"data");
        assert!(result.is_err());
    }

    // ── backfill_session tests ────────────────────────────────────────

    fn make_session(name: &str, files: Vec<(&str, &[u8])>) -> iso9660::SessionEntry {
        iso9660::SessionEntry {
            dir_name: name.into(),
            timestamp: std::time::SystemTime::now(),
            files: files
                .into_iter()
                .map(|(n, d)| iso9660::IsoFile {
                    name: n.into(),
                    data: d.to_vec(),
                })
                .collect(),
        }
    }

    #[test]
    fn backfill_adds_missing_files() {
        let prior = make_session("s1", vec![("ROOT.CRT", b"cert"), ("AUDIT.LOG", b"log1")]);
        let mut new = make_session("s2", vec![("AUDIT.LOG", b"log2")]);

        backfill_session(&prior, &mut new);

        assert_eq!(new.files.len(), 2);
        assert!(
            new.files
                .iter()
                .any(|f| f.name == "ROOT.CRT" && f.data == b"cert"),
            "ROOT.CRT should be carried forward from prior session"
        );
        // AUDIT.LOG should keep the new version
        let audit = new.files.iter().find(|f| f.name == "AUDIT.LOG").unwrap();
        assert_eq!(audit.data, b"log2");
    }

    #[test]
    fn backfill_noop_when_superset() {
        let prior = make_session("s1", vec![("ROOT.CRT", b"cert")]);
        let mut new = make_session("s2", vec![("ROOT.CRT", b"cert"), ("INTER.CRT", b"inter")]);

        backfill_session(&prior, &mut new);

        assert_eq!(new.files.len(), 2, "no files should be added");
    }

    #[test]
    fn backfill_skips_audit_log_but_carries_state_json() {
        let prior = make_session(
            "s1",
            vec![
                ("ROOT.CRT", b"cert"),
                ("AUDIT.LOG", b"log1"),
                ("STATE.JSON", b"state1"),
            ],
        );
        let mut new = make_session("s2", vec![("ROOT.CRT", b"cert")]);

        backfill_session(&prior, &mut new);

        // ROOT.CRT already present, AUDIT.LOG is mutable — not backfilled.
        // STATE.JSON should be carried forward (superset invariant).
        assert_eq!(new.files.len(), 2);
        assert!(new.files.iter().any(|f| f.name == "ROOT.CRT"));
        assert!(
            new.files
                .iter()
                .any(|f| f.name == "STATE.JSON" && f.data == b"state1"),
            "STATE.JSON should be carried forward from prior session"
        );
    }

    #[test]
    fn backfill_multi_session_cascade() {
        let s1 = make_session("s1", vec![("A.TXT", b"a")]);
        let mut s2 = make_session("s2", vec![("B.TXT", b"b")]);
        backfill_session(&s1, &mut s2);

        let mut s3 = make_session("s3", vec![("C.TXT", b"c")]);
        backfill_session(&s2, &mut s3);

        assert_eq!(s3.files.len(), 3);
        let names: Vec<&str> = s3.files.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"A.TXT"));
        assert!(names.contains(&"B.TXT"));
        assert!(names.contains(&"C.TXT"));
    }

    #[test]
    fn backfill_single_session_noop() {
        // When there's no prior session, backfill is never called.
        // Verify that write_session_inner's guard works by just checking
        // that backfill on an empty prior doesn't panic.
        let prior = make_session("s0", vec![]);
        let mut new = make_session("s1", vec![("ROOT.CRT", b"cert")]);

        backfill_session(&prior, &mut new);

        assert_eq!(new.files.len(), 1);
    }
}
