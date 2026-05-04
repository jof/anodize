//! Raw SG_IO ioctl abstraction for SCSI/MMC optical drives.
//!
//! Provides three command-sending methods (cdb_in, cdb_out, cdb_none) and a
//! CDROM_DRIVE_STATUS ioctl wrapper.  All operations are direct syscalls —
//! no subprocess spawning.

use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

use anyhow::{bail, Context, Result};

/// SG_IO header — matches `sg_io_hdr_t` from `<scsi/sg.h>` exactly.
#[repr(C)]
struct SgIoHdr {
    interface_id: i32,
    dxfer_direction: i32,
    cmd_len: u8,
    mx_sb_len: u8,
    iovec_count: u16,
    dxfer_len: u32,
    dxferp: *mut std::ffi::c_void,
    cmdp: *const u8,
    sbp: *mut u8,
    timeout: u32,
    flags: u32,
    pack_id: i32,
    usr_ptr: *mut std::ffi::c_void,
    status: u8,
    masked_status: u8,
    msg_status: u8,
    sb_len_wr: u8,
    host_status: u16,
    driver_status: u16,
    resid: i32,
    duration: u32,
    info: u32,
}

// SG_IO = 0x2285 — non-standard encoding, use _bad variant.
nix::ioctl_readwrite_bad!(sg_io, 0x2285, SgIoHdr);
// CDROM_DRIVE_STATUS = _IO('S', 0x26) = 0x5326; returns status as ioctl return value.
nix::ioctl_none_bad!(cdrom_drive_status_raw, 0x5326);

const SG_DXFER_NONE: i32 = -1;
const SG_DXFER_TO_DEV: i32 = -2;
const SG_DXFER_FROM_DEV: i32 = -3;

#[allow(dead_code)]
pub const CDS_NO_DISC: i32 = 1;
#[allow(dead_code)]
pub const CDS_TRAY_OPEN: i32 = 2;
#[allow(dead_code)]
pub const CDS_DRIVE_NOT_READY: i32 = 3;
pub const CDS_DISC_OK: i32 = 4;

/// An open SCSI device handle (`/dev/sr*`).
pub struct SgDev {
    file: std::fs::File,
}

impl SgDev {
    pub fn open(dev: &Path) -> Result<Self> {
        // O_NONBLOCK is required: without it, opening a blank write-once disc (e.g. BD-R via
        // cdemu) triggers a blocking readiness probe in the kernel sr driver that returns EROFS.
        // O_RDWR is required for write-direction SG_IO (WRITE(10), MODE SELECT, etc.).
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(nix::libc::O_NONBLOCK)
            .open(dev)
            .with_context(|| format!("open optical device {}", dev.display()))?;
        Ok(Self { file })
    }

    /// CDROM_DRIVE_STATUS ioctl.  Returns one of the CDS_* constants.
    pub fn drive_status(&self) -> Result<i32> {
        let fd = self.file.as_raw_fd();
        let s = unsafe { cdrom_drive_status_raw(fd) }.context("CDROM_DRIVE_STATUS ioctl")?;
        Ok(s)
    }

    /// Send a CDB that reads data from the device into `buf`.
    /// Returns the number of bytes actually transferred.
    pub fn cdb_in(&self, cdb: &[u8], buf: &mut [u8], timeout_ms: u32) -> Result<usize> {
        self.send(
            cdb,
            SG_DXFER_FROM_DEV,
            buf.as_mut_ptr() as *mut _,
            buf.len() as u32,
            timeout_ms,
        )
    }

    /// Send a CDB that writes `data` to the device.
    pub fn cdb_out(&self, cdb: &[u8], data: &[u8], timeout_ms: u32) -> Result<()> {
        self.send(
            cdb,
            SG_DXFER_TO_DEV,
            data.as_ptr() as *mut _,
            data.len() as u32,
            timeout_ms,
        )?;
        Ok(())
    }

    /// Send a CDB with no data phase.
    pub fn cdb_none(&self, cdb: &[u8], timeout_ms: u32) -> Result<()> {
        self.send(cdb, SG_DXFER_NONE, std::ptr::null_mut(), 0, timeout_ms)?;
        Ok(())
    }

    fn send(
        &self,
        cdb: &[u8],
        direction: i32,
        dxferp: *mut std::ffi::c_void,
        dxfer_len: u32,
        timeout_ms: u32,
    ) -> Result<usize> {
        assert!(cdb.len() <= 16, "CDB too long");

        let mut cdb_buf = [0u8; 16];
        cdb_buf[..cdb.len()].copy_from_slice(cdb);

        let mut sense = [0u8; 64];

        let mut hdr = SgIoHdr {
            interface_id: b'S' as i32,
            dxfer_direction: direction,
            cmd_len: cdb.len() as u8,
            mx_sb_len: sense.len() as u8,
            iovec_count: 0,
            dxfer_len,
            dxferp,
            cmdp: cdb_buf.as_ptr(),
            sbp: sense.as_mut_ptr(),
            timeout: timeout_ms,
            flags: 0,
            pack_id: 0,
            usr_ptr: std::ptr::null_mut(),
            status: 0,
            masked_status: 0,
            msg_status: 0,
            sb_len_wr: 0,
            host_status: 0,
            driver_status: 0,
            resid: 0,
            duration: 0,
            info: 0,
        };

        let fd = self.file.as_raw_fd();
        unsafe { sg_io(fd, &mut hdr) }.context("SG_IO ioctl")?;

        if hdr.status != 0 {
            let key = sense[2] & 0x0F;
            let asc = if hdr.sb_len_wr >= 13 { sense[12] } else { 0 };
            let ascq = if hdr.sb_len_wr >= 14 { sense[13] } else { 0 };
            bail!(
                "SCSI CHECK CONDITION: sense_key={:#04x} ASC={:#04x} ASCQ={:#04x} \
                 (cdb[0]={:#04x})",
                key,
                asc,
                ascq,
                cdb[0]
            );
        }
        if hdr.host_status != 0 || hdr.driver_status != 0 {
            bail!(
                "SG_IO transport error: host={:#06x} driver={:#06x}",
                hdr.host_status,
                hdr.driver_status
            );
        }

        let transferred = (dxfer_len as i32 - hdr.resid).max(0) as usize;
        Ok(transferred)
    }
}
