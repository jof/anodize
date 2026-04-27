//! Pure-Rust ISO 9660 Level 2 writer and parser (ECMA-119).
//!
//! Layout per image:
//!   Sectors  0–15   System area (zeros)
//!   Sector  16      Primary Volume Descriptor
//!   Sector  17      Volume Descriptor Set Terminator
//!   Sector  18      Path Table L (little-endian LBAs)
//!   Sector  19      Path Table M (big-endian LBAs)
//!   Sector  20      Root directory records
//!   Sectors 21..    One sector per session directory
//!   Following       File data (sector-aligned)

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Result};
use time::OffsetDateTime;

pub const SECTOR: usize = 2048;
const MIN_SECTORS: usize = 300;

/// A file to include in an ISO 9660 image.
#[derive(Debug, Clone)]
pub struct IsoFile {
    /// Uppercase filename, e.g. "ROOT.CRT".
    pub name: String,
    pub data: Vec<u8>,
}

/// All files for one ceremony session, grouped under a timestamped directory.
#[derive(Debug, Clone)]
pub struct SessionEntry {
    /// Directory name: "YYYYMMDDTHHMMSS_NNNNNNNNNZ" (26 chars, UTC) — see `session_dir_name`.
    pub dir_name: String,
    pub timestamp: SystemTime,
    pub files: Vec<IsoFile>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn sectors_for(byte_len: usize) -> usize {
    byte_len.div_ceil(SECTOR)
}

/// Write a both-endian u32 (4 bytes LE then 4 bytes BE) at `off` in `buf`.
fn w32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    buf[off + 4..off + 8].copy_from_slice(&v.to_be_bytes());
}

/// Write a both-endian u16 (2 bytes LE then 2 bytes BE) at `off` in `buf`.
fn w16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
    buf[off + 2..off + 4].copy_from_slice(&v.to_be_bytes());
}

/// 7-byte directory record timestamp (ECMA-119 §9.1.5).
fn dt7(ts: SystemTime) -> [u8; 7] {
    let odt = OffsetDateTime::from(ts);
    [
        (odt.year() - 1900) as u8,
        odt.month() as u8,
        odt.day(),
        odt.hour(),
        odt.minute(),
        odt.second(),
        0, // GMT offset in 15-min units; 0 = UTC
    ]
}

/// 17-byte PVD timestamp (ECMA-119 §8.4.26.1).
fn dt17(ts: SystemTime) -> [u8; 17] {
    let odt = OffsetDateTime::from(ts);
    let s = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}00",
        odt.year(),
        odt.month() as u8,
        odt.day(),
        odt.hour(),
        odt.minute(),
        odt.second(),
    );
    let mut out = [b'0'; 17];
    out[..16].copy_from_slice(s.as_bytes());
    out[16] = 0; // UTC
    out
}

/// Build one directory record.  `id` is the raw identifier bytes.
/// Returns a Vec whose length is always even.
fn dir_rec(is_dir: bool, id: &[u8], lba: u32, data_len: u32, ts: SystemTime) -> Vec<u8> {
    let id_len = id.len();
    let base = 33 + id_len;
    let total = if base.is_multiple_of(2) {
        base
    } else {
        base + 1
    };
    let mut r = vec![0u8; total];
    r[0] = total as u8; // length of directory record
    r[1] = 0; // extended attribute length
    w32(&mut r, 2, lba); // location of extent (both-endian)
    w32(&mut r, 10, data_len); // data length (both-endian)
    r[18..25].copy_from_slice(&dt7(ts));
    r[25] = if is_dir { 0x02 } else { 0x00 }; // file flags
                                              // r[26] file unit size = 0
                                              // r[27] interleave gap = 0
    w16(&mut r, 28, 1); // volume sequence number (both-endian)
    r[32] = id_len as u8; // length of file identifier
    r[33..33 + id_len].copy_from_slice(id);
    r
}

/// One entry in either path table variant.
fn path_entry(dir_id: &[u8], lba: u32, parent: u16, le: bool) -> Vec<u8> {
    let id_len = dir_id.len();
    let base = 8 + id_len;
    let total = if base.is_multiple_of(2) {
        base
    } else {
        base + 1
    };
    let mut e = vec![0u8; total];
    e[0] = id_len as u8;
    e[1] = 0; // extended attribute length
    if le {
        e[2..6].copy_from_slice(&lba.to_le_bytes());
        e[6..8].copy_from_slice(&parent.to_le_bytes());
    } else {
        e[2..6].copy_from_slice(&lba.to_be_bytes());
        e[6..8].copy_from_slice(&parent.to_be_bytes());
    }
    e[8..8 + id_len].copy_from_slice(dir_id);
    e
}

// ── build_iso ─────────────────────────────────────────────────────────────────

/// Build a complete ISO 9660 Level 2 image from all sessions (prior + current).
/// The caller passes sessions in chronological order; the last entry is the newest.
pub fn build_iso(sessions: &[SessionEntry]) -> Vec<u8> {
    let n = sessions.len();
    assert!(n > 0, "build_iso called with no sessions");

    // ── Compute layout ────────────────────────────────────────────────────────
    let root_dir_lba: u32 = 20;
    let session_dir_start: u32 = 21;
    let file_data_start: u32 = session_dir_start + n as u32;

    // For each session, for each file: compute LBA.
    let mut file_lbas: Vec<Vec<u32>> = Vec::with_capacity(n);
    let mut cur_lba = file_data_start;
    for sess in sessions {
        let mut lbas = Vec::with_capacity(sess.files.len());
        for f in &sess.files {
            lbas.push(cur_lba);
            cur_lba += sectors_for(f.data.len()) as u32;
        }
        file_lbas.push(lbas);
    }
    let total_sectors = (cur_lba as usize).max(MIN_SECTORS);

    let mut image = vec![0u8; total_sectors * SECTOR];

    // ── PVD (sector 16) ───────────────────────────────────────────────────────
    {
        let s = &mut image[16 * SECTOR..17 * SECTOR];
        s[0] = 0x01; // volume descriptor type: primary
        s[1..6].copy_from_slice(b"CD001"); // standard identifier
        s[6] = 0x01; // version
                     // s[7] unused
                     // System identifier (bytes 8–39): spaces
        for b in &mut s[8..40] {
            *b = b' ';
        }
        // Volume identifier (bytes 40–71): "ANODIZE" padded with spaces
        for b in &mut s[40..72] {
            *b = b' ';
        }
        let vi = b"ANODIZE";
        s[40..40 + vi.len()].copy_from_slice(vi);
        // bytes 72–79: unused
        // Volume space size (bytes 80–87): total sectors, both-endian
        w32(s, 80, total_sectors as u32);
        // bytes 88–119: unused (escape sequences for Joliet — leave 0)
        // Volume set size (120–123): 1
        w16(s, 120, 1);
        // Volume sequence number (124–127): 1
        w16(s, 124, 1);
        // Logical block size (128–131): 2048
        w16(s, 128, 2048);

        // Path table size — calculate
        let pt_size = path_table_size(sessions);
        w32(s, 132, pt_size as u32);

        // Location of Type L path table (bytes 140–143, LE)
        s[140..144].copy_from_slice(&18u32.to_le_bytes());
        // Location of Optional Type L path table (144–147): 0 (already)
        // Location of Type M path table (bytes 148–151, BE)
        s[148..152].copy_from_slice(&19u32.to_be_bytes());
        // Location of Optional Type M path table (152–155): 0

        // Directory record for root (bytes 156–189, 34 bytes)
        let root_size = root_dir_size(sessions);
        let root_rec = dir_rec(
            true,
            &[0x00],
            root_dir_lba,
            root_size as u32,
            SystemTime::now(),
        );
        assert_eq!(root_rec.len(), 34);
        s[156..190].copy_from_slice(&root_rec);

        // Volume Set Identifier (190–317): spaces
        for b in &mut s[190..318] {
            *b = b' ';
        }
        // Publisher Identifier (318–445): spaces
        for b in &mut s[318..446] {
            *b = b' ';
        }
        // Data Preparer Identifier (446–573): spaces
        for b in &mut s[446..574] {
            *b = b' ';
        }
        // Application Identifier (574–701): "ANODIZE CEREMONY" padded
        for b in &mut s[574..702] {
            *b = b' ';
        }
        let ai = b"ANODIZE CEREMONY";
        s[574..574 + ai.len()].copy_from_slice(ai);
        // Copyright File ID (702–739): spaces
        for b in &mut s[702..740] {
            *b = b' ';
        }
        // Abstract File ID (740–775): spaces
        for b in &mut s[740..776] {
            *b = b' ';
        }
        // Bibliographic File ID (776–812): spaces
        for b in &mut s[776..813] {
            *b = b' ';
        }

        // Creation date (813–829) and modification date (830–846)
        let now_bytes = dt17(SystemTime::now());
        s[813..830].copy_from_slice(&now_bytes);
        s[830..847].copy_from_slice(&now_bytes);
        // Expiration and Effective dates (847–880): zero (already)

        // File Structure Version (881): 1
        s[881] = 0x01;
        // byte 882: reserved
        // bytes 883–1394: application use (zeros)
        // bytes 1395–2047: reserved
    }

    // ── Volume Descriptor Set Terminator (sector 17) ──────────────────────────
    {
        let s = &mut image[17 * SECTOR..18 * SECTOR];
        s[0] = 0xFF;
        s[1..6].copy_from_slice(b"CD001");
        s[6] = 0x01;
    }

    // ── Path Tables (sectors 18 and 19) ───────────────────────────────────────
    for le in [true, false] {
        let sector = if le { 18usize } else { 19usize };
        let pt = &mut image[sector * SECTOR..(sector + 1) * SECTOR];
        let mut off = 0;
        // Entry 1: root directory
        let re = path_entry(&[0x01], root_dir_lba, 1, le);
        pt[off..off + re.len()].copy_from_slice(&re);
        off += re.len();
        // Entries 2..N+1: session subdirectories
        for (i, sess) in sessions.iter().enumerate() {
            let dir_lba = session_dir_start + i as u32;
            let e = path_entry(sess.dir_name.as_bytes(), dir_lba, 1, le);
            pt[off..off + e.len()].copy_from_slice(&e);
            off += e.len();
        }
    }

    // ── Root directory records (sector 20) ────────────────────────────────────
    {
        let root = &mut image[root_dir_lba as usize * SECTOR..(root_dir_lba as usize + 1) * SECTOR];
        let root_data_len = root_dir_size(sessions) as u32;
        let mut off = 0;

        // "." self-reference
        let dot = dir_rec(
            true,
            &[0x00],
            root_dir_lba,
            root_data_len,
            SystemTime::now(),
        );
        root[off..off + dot.len()].copy_from_slice(&dot);
        off += dot.len();
        // ".." parent = root itself for root dir
        let dotdot = dir_rec(
            true,
            &[0x01],
            root_dir_lba,
            root_data_len,
            SystemTime::now(),
        );
        root[off..off + dotdot.len()].copy_from_slice(&dotdot);
        off += dotdot.len();
        // Session subdirectories
        for (i, sess) in sessions.iter().enumerate() {
            let dir_lba = session_dir_start + i as u32;
            let dir_data_len = session_dir_size(&sess.files) as u32;
            let rec = dir_rec(
                true,
                sess.dir_name.as_bytes(),
                dir_lba,
                dir_data_len,
                sess.timestamp,
            );
            root[off..off + rec.len()].copy_from_slice(&rec);
            off += rec.len();
        }
    }

    // ── Session directory records ──────────────────────────────────────────────
    for (i, sess) in sessions.iter().enumerate() {
        let dir_lba = session_dir_start + i as u32;
        let dir_data_len = session_dir_size(&sess.files) as u32;
        let root_data_len = root_dir_size(sessions) as u32;

        let sec = &mut image[dir_lba as usize * SECTOR..(dir_lba as usize + 1) * SECTOR];
        let mut off = 0;

        // "."
        let dot = dir_rec(true, &[0x00], dir_lba, dir_data_len, sess.timestamp);
        sec[off..off + dot.len()].copy_from_slice(&dot);
        off += dot.len();
        // ".." → root
        let dotdot = dir_rec(true, &[0x01], root_dir_lba, root_data_len, sess.timestamp);
        sec[off..off + dotdot.len()].copy_from_slice(&dotdot);
        off += dotdot.len();
        // File records
        for (j, f) in sess.files.iter().enumerate() {
            let file_lba = file_lbas[i][j];
            let rec = dir_rec(
                false,
                f.name.as_bytes(),
                file_lba,
                f.data.len() as u32,
                sess.timestamp,
            );
            sec[off..off + rec.len()].copy_from_slice(&rec);
            off += rec.len();
        }
    }

    // ── File data ─────────────────────────────────────────────────────────────
    for (i, sess) in sessions.iter().enumerate() {
        for (j, f) in sess.files.iter().enumerate() {
            let lba = file_lbas[i][j] as usize;
            let off = lba * SECTOR;
            image[off..off + f.data.len()].copy_from_slice(&f.data);
        }
    }

    image
}

fn path_table_size(sessions: &[SessionEntry]) -> usize {
    // Root entry: 8 + 1 (id=0x01) = 9, padded to 10
    let root = 10usize;
    // Each session entry: 8 + dir_name.len(), padded to even
    let sess_total: usize = sessions
        .iter()
        .map(|s| {
            let base = 8 + s.dir_name.len();
            if base % 2 == 0 {
                base
            } else {
                base + 1
            }
        })
        .sum();
    root + sess_total
}

fn root_dir_size(sessions: &[SessionEntry]) -> usize {
    // "." = 34, ".." = 34
    // Each session dir entry: 33 + dir_name.len(), padded to even
    let sess_total: usize = sessions
        .iter()
        .map(|s| {
            let base = 33 + s.dir_name.len();
            if base % 2 == 0 {
                base
            } else {
                base + 1
            }
        })
        .sum();
    34 + 34 + sess_total
}

fn session_dir_size(files: &[IsoFile]) -> usize {
    // "." = 34, ".." = 34
    // Each file: 33 + name.len(), padded to even
    let mut sz = 68usize;
    for f in files {
        let base = 33 + f.name.len();
        sz += if base.is_multiple_of(2) {
            base
        } else {
            base + 1
        };
    }
    sz
}

// ── parse_iso ─────────────────────────────────────────────────────────────────

/// Parse an ISO 9660 image (raw sector bytes) and extract its SessionEntry list.
/// Only reads timestamped subdirectories of the root (skips "." and "..").
pub fn parse_iso(image: &[u8]) -> Result<Vec<SessionEntry>> {
    if image.len() < 17 * SECTOR + SECTOR {
        bail!("image too small to contain a PVD");
    }

    // ── Read PVD ──────────────────────────────────────────────────────────────
    let pvd = &image[16 * SECTOR..17 * SECTOR];
    if pvd[0] != 0x01 || &pvd[1..6] != b"CD001" {
        bail!("sector 16 is not a Primary Volume Descriptor");
    }
    // Root directory record is at bytes 156–189
    let root_lba = u32::from_le_bytes(pvd[158..162].try_into().unwrap()) as usize;
    let root_size = u32::from_le_bytes(pvd[166..170].try_into().unwrap()) as usize;

    if (root_lba + 1) * SECTOR > image.len() {
        bail!("root directory LBA {root_lba} is outside image");
    }

    // ── Walk root directory ───────────────────────────────────────────────────
    let root_data = &image[root_lba * SECTOR..root_lba * SECTOR + root_size.min(SECTOR)];
    let mut sessions = Vec::new();
    let mut pos = 0usize;

    while pos < root_data.len() {
        let rec_len = root_data[pos] as usize;
        if rec_len == 0 {
            // Zero padding at end of sector — advance to next sector boundary
            let next = (pos / SECTOR + 1) * SECTOR;
            if next >= root_data.len() {
                break;
            }
            pos = next;
            continue;
        }
        if pos + rec_len > root_data.len() {
            break;
        }

        let rec = &root_data[pos..pos + rec_len];
        let flags = rec[25];
        let id_len = rec[32] as usize;

        // Skip "." (id = 0x00) and ".." (id = 0x01)
        if id_len == 1 && (rec[33] == 0x00 || rec[33] == 0x01) {
            pos += rec_len;
            continue;
        }

        // Only process directory entries
        if flags & 0x02 != 0 {
            let dir_name = std::str::from_utf8(&rec[33..33 + id_len])
                .unwrap_or("?")
                .to_string();
            let dir_lba = u32::from_le_bytes(rec[2..6].try_into().unwrap()) as usize;
            let dir_size = u32::from_le_bytes(rec[10..14].try_into().unwrap()) as usize;

            // Reconstruct timestamp from 7-byte dir record field
            let dt = &rec[18..25];
            let timestamp = parse_dt7(dt);

            // Read session subdir
            let files = parse_subdir(image, dir_lba, dir_size)?;

            sessions.push(SessionEntry {
                dir_name,
                timestamp,
                files,
            });
        }

        pos += rec_len;
    }

    // Sort by dir_name (lexicographic = chronological for YYYYMMDDTHHMMSSZ)
    sessions.sort_by(|a, b| a.dir_name.cmp(&b.dir_name));
    Ok(sessions)
}

fn parse_subdir(image: &[u8], dir_lba: usize, dir_size: usize) -> Result<Vec<IsoFile>> {
    if (dir_lba + 1) * SECTOR > image.len() {
        bail!("session subdir LBA {dir_lba} outside image");
    }
    let dir_data = &image[dir_lba * SECTOR..dir_lba * SECTOR + dir_size.min(SECTOR)];
    let mut files = Vec::new();
    let mut pos = 0usize;

    while pos < dir_data.len() {
        let rec_len = dir_data[pos] as usize;
        if rec_len == 0 {
            let next = (pos / SECTOR + 1) * SECTOR;
            if next >= dir_data.len() {
                break;
            }
            pos = next;
            continue;
        }
        if pos + rec_len > dir_data.len() {
            break;
        }

        let rec = &dir_data[pos..pos + rec_len];
        let flags = rec[25];
        let id_len = rec[32] as usize;

        // Skip "." and ".." and any subdirectories
        let is_dot = id_len == 1 && (rec[33] == 0x00 || rec[33] == 0x01);
        if is_dot || (flags & 0x02 != 0) {
            pos += rec_len;
            continue;
        }

        let name = std::str::from_utf8(&rec[33..33 + id_len])
            .unwrap_or("?")
            .to_string();
        let file_lba = u32::from_le_bytes(rec[2..6].try_into().unwrap()) as usize;
        let file_size = u32::from_le_bytes(rec[10..14].try_into().unwrap()) as usize;

        let end = file_lba * SECTOR + file_size;
        if end > image.len() {
            bail!("file '{name}' data at LBA {file_lba} size {file_size} overruns image");
        }
        let data = image[file_lba * SECTOR..file_lba * SECTOR + file_size].to_vec();

        files.push(IsoFile { name, data });
        pos += rec_len;
    }

    Ok(files)
}

fn parse_dt7(dt: &[u8]) -> SystemTime {
    // Best-effort: convert to seconds since epoch
    // dt: [year-1900, month, day, hour, min, sec, tz_offset_15min]
    if dt.len() < 7 {
        return UNIX_EPOCH;
    }
    let year = 1900 + dt[0] as i32;
    let month = dt[1];
    let day = dt[2];
    let hour = dt[3];
    let min = dt[4];
    let sec = dt[5];

    let month_e = time::Month::try_from(month).unwrap_or(time::Month::January);
    let date = time::Date::from_calendar_date(year, month_e, day).ok();
    let time_val = time::Time::from_hms(hour, min, sec).ok();

    match (date, time_val) {
        (Some(d), Some(t)) => {
            let odt = OffsetDateTime::new_utc(d, t);
            let secs = odt.unix_timestamp();
            if secs >= 0 {
                UNIX_EPOCH + std::time::Duration::from_secs(secs as u64)
            } else {
                UNIX_EPOCH
            }
        }
        _ => UNIX_EPOCH,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session(tag: &str, ts_secs: u64, files: &[(&str, &[u8])]) -> SessionEntry {
        SessionEntry {
            dir_name: tag.to_string(),
            timestamp: UNIX_EPOCH + std::time::Duration::from_secs(ts_secs),
            files: files
                .iter()
                .map(|(n, d)| IsoFile {
                    name: n.to_string(),
                    data: d.to_vec(),
                })
                .collect(),
        }
    }

    #[test]
    fn build_iso_min_size() {
        let s = make_session(
            "20260425T143000_000000000Z",
            1_000_000,
            &[("ROOT.CRT", b"fakecert"), ("AUDIT.LOG", b"fakelog")],
        );
        let img = build_iso(&[s]);
        assert_eq!(img.len() % SECTOR, 0);
        assert!(
            img.len() >= MIN_SECTORS * SECTOR,
            "image too small: {} bytes",
            img.len()
        );
    }

    #[test]
    fn pvd_magic() {
        let s = make_session(
            "20260425T143000_000000000Z",
            1_000_000,
            &[("ROOT.CRT", b"x")],
        );
        let img = build_iso(&[s]);
        assert_eq!(img[16 * SECTOR], 0x01);
        assert_eq!(&img[16 * SECTOR + 1..16 * SECTOR + 6], b"CD001");
    }

    #[test]
    fn parse_roundtrip() {
        let sessions = vec![
            make_session(
                "20260425T143000_000000000Z",
                1_000_000,
                &[
                    ("ROOT.CRT", b"cert-der-bytes"),
                    ("AUDIT.LOG", b"log-line-1\n"),
                ],
            ),
            make_session(
                "20260426T091500_000000000Z",
                2_000_000,
                &[
                    ("ROOT.CRT", b"cert-der-bytes"),
                    ("INTCA1.CRT", b"int-cert"),
                    ("AUDIT.LOG", b"log-line-1\nlog-line-2\n"),
                ],
            ),
        ];
        let img = build_iso(&sessions);
        let parsed = parse_iso(&img).expect("parse_iso failed");

        assert_eq!(parsed.len(), 2, "expected 2 sessions, got {}", parsed.len());
        assert_eq!(parsed[0].dir_name, "20260425T143000_000000000Z");
        assert_eq!(parsed[1].dir_name, "20260426T091500_000000000Z");

        // File data roundtrip
        let f0 = parsed[0]
            .files
            .iter()
            .find(|f| f.name == "ROOT.CRT")
            .unwrap();
        assert_eq!(f0.data, b"cert-der-bytes");
        let f1 = parsed[1]
            .files
            .iter()
            .find(|f| f.name == "INTCA1.CRT")
            .unwrap();
        assert_eq!(f1.data, b"int-cert");
    }

    #[test]
    fn both_endian_encoding() {
        let s = make_session(
            "20260425T143000_000000000Z",
            1_000_000,
            &[("ROOT.CRT", b"x")],
        );
        let img = build_iso(&[s]);
        // Volume space size at PVD bytes 80–87: LE then BE
        let pvd = &img[16 * SECTOR..];
        let le = u32::from_le_bytes(pvd[80..84].try_into().unwrap());
        let be = u32::from_be_bytes(pvd[84..88].try_into().unwrap());
        assert_eq!(le, be, "volume space size LE={le} != BE={be}");
        assert!(le >= MIN_SECTORS as u32);
    }
}
