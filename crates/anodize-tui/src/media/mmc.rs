//! Typed MMC (Multi-Media Commands) wrappers built on top of SgDev.
//!
//! References: MMC-6 (INCITS 505), ECMA-365.
//! Timeouts are generous — write operations on BD-R can be slow.

use anyhow::{bail, Context, Result};

use super::sgdev::SgDev;

// ── Disc information ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscStatus {
    Blank,       // disc_status = 00h
    Incomplete,  // disc_status = 01h (has sessions, still appendable)
    Complete,    // disc_status = 02h (finalized)
    Other(u8),
}

impl DiscStatus {
    pub fn is_appendable(self) -> bool {
        matches!(self, DiscStatus::Blank | DiscStatus::Incomplete)
    }
}

#[derive(Debug, Clone)]
pub struct DiscInfo {
    pub status:         DiscStatus,
    pub sessions:       u16,   // number of complete sessions
    #[allow(dead_code)]
    pub first_track:    u8,
    #[allow(dead_code)]
    pub last_track_l:   u8,
    pub nwa:            u32,   // Next Writable Address (last session's NWA)
    #[allow(dead_code)]
    pub free_blocks:    u32,
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
    let sessions_lo = buf[3];
    let first_track = buf[4];
    let last_track_l = buf[5];
    let sessions = if n >= 35 {
        (buf[9] as u16) << 8 | sessions_lo as u16
    } else {
        sessions_lo as u16
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
    pub start_lba:    u32,
    pub size_sectors: u32,
    pub nwa:          u32,   // Next Writable Address for this track
    #[allow(dead_code)]
    pub free_blocks:  u32,
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

    let start_lba    = u32::from_be_bytes([buf[8],  buf[9],  buf[10], buf[11]]);
    let size_sectors = u32::from_be_bytes([buf[24], buf[25], buf[26], buf[27]]);
    let free_blocks  = u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]);
    let nwa          = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);

    Ok(TrackInfo { start_lba, size_sectors, nwa, free_blocks })
}

// ── Write parameters ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub enum WriteType {
    Sao = 0x01,
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
    pub write_type:   WriteType,
    pub multi_session: MultiSession,
    /// Buffer Underrun Free recording Enable.
    pub bufe:         bool,
}

/// SET WRITE PARAMETERS via MODE SELECT 10 (0x55) with page 0x05.
pub fn set_write_parameters(dev: &SgDev, p: &WriteParams) -> Result<()> {
    // Mode parameter header (8 bytes) + mode page 0x05 (50 bytes) = 58 bytes
    let mut data = [0u8; 58];

    // Mode Parameter Header (10-byte form)
    let param_len: u16 = 56; // total data length minus 2-byte length field
    data[0] = (param_len >> 8) as u8;
    data[1] = (param_len & 0xFF) as u8;
    // bytes 2-7: reserved

    // CD/DVD Write Parameters Mode Page (page code 0x05)
    let page = &mut data[8..];
    page[0] = 0x05;           // page code
    page[1] = 0x32;           // page length = 50 bytes
    page[2] = (if p.bufe { 0x40 } else { 0x00 })   // BUFE bit
            | ((p.multi_session as u8) << 6)         // LS_V + multi-session
            | (p.write_type as u8);                  // write type
    // byte 3: test write=0, fgm=0, copy=0, track mode
    page[3] = 0x09; // track mode = 0x09 for data (mode 1)
    // byte 4: data block type = 0x08 (2048-byte mode-1 data)
    page[4] = 0x08;
    // bytes 5-7: reserved
    // byte 8: session format = 0x00 (data/CD-ROM session)
    page[8] = 0x00;

    let total_len = data.len() as u16;
    let cdb: [u8; 10] = [
        0x55,                          // MODE SELECT 10
        0x10,                          // PF = 1 (page format)
        0, 0, 0, 0, 0,
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
    dev.cdb_none(&cdb, 60_000)
        .context("SEND OPC INFORMATION")?;
    Ok(())
}

// ── Track reservation ─────────────────────────────────────────────────────────

/// RESERVE TRACK (0x53).
/// Signals the drive that a track write is about to begin.
/// In SAO mode the LBA is typically 0 (driver allocates automatically).
pub fn reserve_track(dev: &SgDev) -> Result<()> {
    let cdb: [u8; 10] = [0x53, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    dev.cdb_none(&cdb, 10_000)
        .context("RESERVE TRACK")?;
    Ok(())
}

// ── Sector write ──────────────────────────────────────────────────────────────

/// WRITE (10) (0x2A) — write a contiguous run of 2048-byte sectors.
/// `lba` is the starting Logical Block Address.
/// `sectors` must be a multiple of 2048 bytes.
pub fn write_sectors(dev: &SgDev, lba: u32, sectors: &[u8]) -> Result<()> {
    assert_eq!(sectors.len() % 2048, 0, "sectors must be a multiple of 2048");
    let count = (sectors.len() / 2048) as u16;
    let cdb: [u8; 10] = [
        0x2A,
        0x00,
        (lba >> 24) as u8,
        (lba >> 16) as u8,
        (lba >>  8) as u8,
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
pub fn read_sectors(dev: &SgDev, lba: u32, buf: &mut [u8]) -> Result<()> {
    assert_eq!(buf.len() % 2048, 0);
    let count = (buf.len() / 2048) as u16;
    let cdb: [u8; 10] = [
        0x28,
        0x00,
        (lba >> 24) as u8,
        (lba >> 16) as u8,
        (lba >>  8) as u8,
        (lba & 0xFF) as u8,
        0x00,
        (count >> 8) as u8,
        (count & 0xFF) as u8,
        0x00,
    ];
    dev.cdb_in(cdb.as_ref(), buf, 60_000)
        .with_context(|| format!("READ(10) lba={lba} count={count}"))?;
    Ok(())
}

// ── Cache flush ───────────────────────────────────────────────────────────────

/// SYNCHRONIZE CACHE (0x35) — flush the drive's write buffer to disc.
/// Must be called after the last write before closing the track.
pub fn synchronize_cache(dev: &SgDev) -> Result<()> {
    let cdb: [u8; 10] = [0x35, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    dev.cdb_none(&cdb, 120_000)
        .context("SYNCHRONIZE CACHE")?;
    Ok(())
}

// ── Track / session / disc close ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub enum CloseTarget {
    Track   = 0x01,
    Session = 0x02,
    Disc    = 0x03,
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
