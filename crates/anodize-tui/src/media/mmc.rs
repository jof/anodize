//! Typed MMC (Multi-Media Commands) wrappers built on top of SgDev.
//!
//! References: MMC-6 (INCITS 505), ECMA-365.
//! Timeouts are generous — write operations on BD-R can be slow.

use anyhow::{bail, Context, Result};

use super::sgdev::SgDev;

// ── Disc information ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscStatus {
    Blank,      // disc_status = 00h
    Incomplete, // disc_status = 01h (has sessions, still appendable)
    Complete,   // disc_status = 02h (finalized)
    Other(u8),
}

impl DiscStatus {
    pub fn is_appendable(self) -> bool {
        matches!(self, DiscStatus::Blank | DiscStatus::Incomplete)
    }
}

#[derive(Debug, Clone)]
pub struct DiscInfo {
    pub status: DiscStatus,
    pub sessions: u16, // number of complete sessions
    #[allow(dead_code)]
    pub first_track: u8,
    #[allow(dead_code)]
    pub last_track_l: u8,
    pub nwa: u32, // Next Writable Address (last session's NWA)
    #[allow(dead_code)]
    pub free_blocks: u32,
}

/// READ DISC INFORMATION (0x51).
pub fn read_disc_info(dev: &SgDev) -> Result<DiscInfo> {
    let cdb: [u8; 10] = [0x51, 0x00, 0, 0, 0, 0, 0, 0, 34, 0];
    let mut buf = [0u8; 34];
    let n = dev.cdb_in(&cdb, &mut buf, 5_000)?;
    if n < 22 {
        bail!("READ DISC INFORMATION returned too few bytes: {n}");
    }

    let disc_status = match buf[2] & 0x03 {
        0 => DiscStatus::Blank,
        1 => DiscStatus::Incomplete,
        2 => DiscStatus::Complete,
        x => DiscStatus::Other(x),
    };
    let first_track = buf[3];
    let sessions_lo = buf[4];
    let last_track_l = buf[6];
    let raw_sessions = if n >= 35 {
        (buf[9] as u16) << 8 | sessions_lo as u16
    } else {
        sessions_lo as u16
    };
    // MMC includes the incomplete/empty "next" session in the count for
    // non-finalized discs.  Subtract it so `sessions` = complete sessions only.
    let sessions = match disc_status {
        DiscStatus::Complete => raw_sessions,
        _ => raw_sessions.saturating_sub(1),
    };

    // Last Session Lead-in Start Address / Next Writable Address
    // Bytes 17–20: last session lead-in start (LBA for this session's NWA context)
    // Bytes 21–24: last session lead-out start
    // For the NWA we use READ TRACK INFORMATION per track; here provide a best-effort.
    let nwa = u32::from_be_bytes([buf[17], buf[18], buf[19], buf[20]]);

    Ok(DiscInfo {
        status: disc_status,
        sessions,
        first_track,
        last_track_l,
        nwa,
        free_blocks: 0, // filled by caller if needed
    })
}

// ── Track information ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TrackInfo {
    pub start_lba: u32,
    pub size_sectors: u32,
    pub nwa: u32, // Next Writable Address for this track
    #[allow(dead_code)]
    pub free_blocks: u32,
    pub blank: bool,
}

/// READ TRACK INFORMATION (0x52) for a given track number (1-based).
/// Pass 0xFF to query the invisible track (gives overall NWA for next session).
pub fn read_track_info(dev: &SgDev, track: u8) -> Result<TrackInfo> {
    let cdb: [u8; 10] = [0x52, 0x01, 0, 0, 0, track, 0, 0, 36, 0];
    let mut buf = [0u8; 36];
    let n = dev.cdb_in(&cdb, &mut buf, 5_000)?;
    if n < 32 {
        bail!("READ TRACK INFORMATION returned only {n} bytes");
    }

    let start_lba = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
    let size_sectors = u32::from_be_bytes([buf[24], buf[25], buf[26], buf[27]]);
    let free_blocks = u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]);
    let nwa = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
    let blank = buf[6] & 0x40 != 0;

    Ok(TrackInfo {
        start_lba,
        size_sectors,
        nwa,
        free_blocks,
        blank,
    })
}

// ── Write parameters ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub enum WriteType {
    /// Track-at-Once (TAO): write_type=0x01 in MMC mode page 0x05.
    /// Tracks are written one at a time; sessions are closed explicitly via
    /// CLOSE TRACK SESSION.  Only applicable to CD-R/RW and DVD±R/RW.
    /// BD-R uses Sequential Recording Mode (SRM) natively and does not
    /// use mode page 0x05.
    Tao = 0x01,
    #[allow(dead_code)]
    Dao = 0x02,
}

#[derive(Debug, Clone, Copy)]
pub enum MultiSession {
    /// Last session — disc will be closed after CLOSE TRACK SESSION.
    FinalSession = 0x01,
    /// Disc stays open for additional sessions.
    Open = 0x03,
}

#[derive(Debug, Clone)]
pub struct WriteParams {
    pub write_type: WriteType,
    pub multi_session: MultiSession,
    /// Buffer Underrun Free recording Enable.
    pub bufe: bool,
}

/// SET WRITE PARAMETERS via MODE SELECT 10 (0x55) with page 0x05.
/// Configures TAO/DAO write type and multi-session behaviour before each session write.
pub fn set_write_parameters(dev: &SgDev, p: &WriteParams) -> Result<()> {
    // Mode parameter header (8 bytes) + mode page 0x05 (2 hdr + 50 content = 52) = 60 bytes
    let mut data = [0u8; 60];

    // Mode Parameter Header (10-byte form)
    let param_len: u16 = 58; // total data length minus 2-byte length field
    data[0] = (param_len >> 8) as u8;
    data[1] = (param_len & 0xFF) as u8;
    // bytes 2-7: reserved

    // CD/DVD Write Parameters Mode Page (page code 0x05)
    let page = &mut data[8..];
    page[0] = 0x05; // page code
    page[1] = 0x32; // page length = 50 bytes
    page[2] = (if p.bufe { 0x40 } else { 0x00 })   // BUFE bit (bit 6)
            | (p.write_type as u8); // write type (bits 0-3)
    page[3] = ((p.multi_session as u8) << 6)          // multisession (bits 6-7)
            | 0x09; // track mode (bits 0-3)
                    // byte 4: data block type = 0x08 (2048-byte mode-1 data)
    page[4] = 0x08;
    // bytes 5-7: reserved
    // byte 8: session format = 0x00 (data/CD-ROM session)
    page[8] = 0x00;

    let total_len = data.len() as u16;
    let cdb: [u8; 10] = [
        0x55, // MODE SELECT 10
        0x10, // PF = 1 (page format)
        0,
        0,
        0,
        0,
        0,
        (total_len >> 8) as u8,
        (total_len & 0xFF) as u8,
        0,
    ];
    dev.cdb_out(&cdb, &data, 10_000)
        .context("SET WRITE PARAMETERS (MODE SELECT 10, page 0x05)")?;
    Ok(())
}

// ── OPC ───────────────────────────────────────────────────────────────────────

/// SEND OPC INFORMATION (0x54) — Optimal Power Calibration.
/// The drive measures and calibrates laser power for the current disc area.
/// Should be called once before the first write on a fresh writable area.
pub fn send_opc(dev: &SgDev) -> Result<()> {
    // DoOpc = 1 (bit 0), exclude list length = 0
    let cdb: [u8; 10] = [0x54, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
    dev.cdb_none(&cdb, 60_000).context("SEND OPC INFORMATION")?;
    Ok(())
}

// ── Track reservation ─────────────────────────────────────────────────────────

/// RESERVE TRACK (0x53).
/// Signals the drive that a track write is about to begin.
/// In SAO mode the LBA is typically 0 (driver allocates automatically).
pub fn reserve_track(dev: &SgDev) -> Result<()> {
    let cdb: [u8; 10] = [0x53, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    dev.cdb_none(&cdb, 10_000).context("RESERVE TRACK")?;
    Ok(())
}

// ── Sector write ──────────────────────────────────────────────────────────────

/// WRITE (10) (0x2A) — write a contiguous run of 2048-byte sectors.
/// `lba` is the starting Logical Block Address.
/// `sectors` must be a multiple of 2048 bytes.
pub fn write_sectors(dev: &SgDev, lba: u32, sectors: &[u8]) -> Result<()> {
    assert_eq!(
        sectors.len() % 2048,
        0,
        "sectors must be a multiple of 2048"
    );
    let count = (sectors.len() / 2048) as u16;
    let cdb: [u8; 10] = [
        0x2A,
        0x00,
        (lba >> 24) as u8,
        (lba >> 16) as u8,
        (lba >> 8) as u8,
        (lba & 0xFF) as u8,
        0x00,
        (count >> 8) as u8,
        (count & 0xFF) as u8,
        0x00,
    ];
    // Write ops on optical media can be slow; allow 120 s per call.
    dev.cdb_out(&cdb, sectors, 120_000)
        .with_context(|| format!("WRITE(10) lba={lba} count={count}"))?;
    Ok(())
}

// ── Read ─────────────────────────────────────────────────────────────────────

/// READ (10) (0x28) — read a contiguous run of 2048-byte sectors.
/// Large reads are split into 64-sector (128 KiB) chunks to stay within
/// the SG_IO / VHBA maximum transfer size.
pub fn read_sectors(dev: &SgDev, lba: u32, buf: &mut [u8]) -> Result<()> {
    assert_eq!(buf.len() % 2048, 0);
    const CHUNK: usize = 64; // sectors per READ(10)
    let total = buf.len() / 2048;
    let mut off = 0usize;
    while off < total {
        let n = CHUNK.min(total - off) as u16;
        let cur_lba = lba + off as u32;
        let cdb: [u8; 10] = [
            0x28,
            0x00,
            (cur_lba >> 24) as u8,
            (cur_lba >> 16) as u8,
            (cur_lba >> 8) as u8,
            (cur_lba & 0xFF) as u8,
            0x00,
            (n >> 8) as u8,
            (n & 0xFF) as u8,
            0x00,
        ];
        let start = off * 2048;
        let end = start + n as usize * 2048;
        dev.cdb_in(&cdb, &mut buf[start..end], 60_000)
            .with_context(|| format!("READ(10) lba={cur_lba} count={n}"))?;
        off += n as usize;
    }
    Ok(())
}

// ── Cache flush ───────────────────────────────────────────────────────────────

/// SYNCHRONIZE CACHE (0x35) — flush the drive's write buffer to disc.
/// Must be called after the last write before closing the track.
pub fn synchronize_cache(dev: &SgDev) -> Result<()> {
    let cdb: [u8; 10] = [0x35, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    dev.cdb_none(&cdb, 120_000).context("SYNCHRONIZE CACHE")?;
    Ok(())
}

// ── Track / session / disc close ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub enum CloseTarget {
    Track = 0x01,
    Session = 0x02,
    Disc = 0x03,
}

/// CLOSE TRACK SESSION (0x5B).
/// Call Track then Session to close a session while leaving the disc open.
/// Call Disc to finalize the disc (no further sessions possible).
pub fn close_track_session(dev: &SgDev, target: CloseTarget) -> Result<()> {
    let close_func = target as u8;
    let cdb: [u8; 10] = [0x5B, 0x00, close_func, 0, 0, 0, 0, 0, 0, 0];
    // Closing can take a while on DVD-R/BD-R (lead-out writing).
    dev.cdb_none(&cdb, 180_000)
        .with_context(|| format!("CLOSE TRACK SESSION ({target:?})"))?;
    Ok(())
}

// ── Media type detection ──────────────────────────────────────────────────────

/// GET CONFIGURATION (0x46) — returns the MMC Current Profile for the loaded disc.
/// The Current Profile is a 16-bit code that identifies the media type (BD-R, CD-RW, etc.).
/// RT=0x02 requests only the Feature Header (8 bytes), which always contains the profile.
pub fn get_current_profile(dev: &SgDev) -> Result<u16> {
    let cdb: [u8; 10] = [0x46, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00];
    let mut buf = [0u8; 8];
    dev.cdb_in(&cdb, &mut buf, 5_000)?;
    Ok(u16::from_be_bytes([buf[6], buf[7]]))
}

const REWRITABLE_PROFILES: &[u16] = &[
    0x000A, // CD-RW
    0x0012, // DVD-RAM
    0x0013, // DVD-RW Restricted Overwrite
    0x0014, // DVD-RW Sequential Recording
    0x0017, // DVD-RW Dual Layer
    0x001A, // DVD+RW
    0x0043, // BD-RE (Blu-ray Rewritable)
];

pub fn profile_is_rewritable(profile: u16) -> bool {
    REWRITABLE_PROFILES.contains(&profile)
}

/// Maximum number of SAO sessions for a given MMC profile code.
/// Defaults to 99 (CD-R limit) for unknown/unrecognised profiles.
pub fn max_sessions_for_profile(profile: u16) -> u16 {
    match profile {
        0x09 | 0x0A => 99,  // CD-R / CD-RW
        0x11 | 0x13 => 254, // DVD-R / DVD-RW SL
        0x15 | 0x16 => 254, // DVD-R DL / DVD-RW DL
        0x1B | 0x1C => 254, // DVD+R / DVD+RW SL
        0x2B => 254,        // DVD+R DL
        0x41 | 0x42 => 255, // BD-R SL / DL (includes M-Disc BD variant)
        0x51 => 254,        // HD DVD-R
        _ => 99,            // Unknown: use CD-R limit as conservative fallback
    }
}

/// Human-readable name for common MMC profile codes.
pub fn profile_name(profile: u16) -> &'static str {
    match profile {
        0x09 => "CD-R",
        0x0A => "CD-RW",
        0x11 => "DVD-R",
        0x13 => "DVD-RW",
        0x1B => "DVD+R",
        0x1C => "DVD+RW",
        0x2B => "DVD+R DL",
        0x41 => "BD-R",
        0x42 => "BD-R DL",
        0x43 => "BD-RE",
        0x51 => "HD DVD-R",
        0x00 => "no disc",
        _ => "unknown media",
    }
}
