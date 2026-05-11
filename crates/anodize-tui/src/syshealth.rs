//! System health information for the sentinel status page.
//!
//! Reads Linux procfs / sysfs to gather host diagnostics.  All functions
//! are best-effort: they return `Option` or empty strings on failure so
//! the sentinel never crashes due to a missing file.

use std::fs;
use std::path::Path;
use std::process::Command;

// ── Data types ────────────────────────────────────────────────────────────────

/// Parsed `/proc/uptime` fields.
#[derive(Debug, PartialEq)]
pub struct Uptime {
    pub days: u64,
    pub hours: u64,
    pub minutes: u64,
    pub seconds: u64,
}

/// Parsed `/proc/loadavg` fields.
#[derive(Debug, PartialEq)]
pub struct LoadAvg {
    pub one: String,
    pub five: String,
    pub fifteen: String,
}

/// One line from `/proc/meminfo`.
#[derive(Debug, PartialEq)]
pub struct MemInfo {
    pub total_kb: u64,
    pub avail_kb: u64,
    pub swap_total_kb: u64,
    pub swap_free_kb: u64,
}

/// A thermal zone reading.
#[derive(Debug, PartialEq)]
pub struct ThermalZone {
    pub name: String,
    pub temp_c: f64,
}

/// A key mount point from `/proc/mounts`.
#[derive(Debug, PartialEq)]
pub struct MountEntry {
    pub device: String,
    pub mountpoint: String,
    pub fstype: String,
}

// ── Pure parsers (unit-testable) ──────────────────────────────────────────────

pub fn parse_uptime(text: &str) -> Option<Uptime> {
    let secs_f: f64 = text.split_whitespace().next()?.parse().ok()?;
    let total = secs_f as u64;
    Some(Uptime {
        days: total / 86400,
        hours: (total % 86400) / 3600,
        minutes: (total % 3600) / 60,
        seconds: total % 60,
    })
}

pub fn parse_loadavg(text: &str) -> Option<LoadAvg> {
    let mut parts = text.split_whitespace();
    Some(LoadAvg {
        one: parts.next()?.to_string(),
        five: parts.next()?.to_string(),
        fifteen: parts.next()?.to_string(),
    })
}

pub fn parse_meminfo(text: &str) -> Option<MemInfo> {
    let mut total = None;
    let mut avail = None;
    let mut swap_total = None;
    let mut swap_free = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total = rest
                .trim()
                .strip_suffix("kB")
                .and_then(|s| s.trim().parse().ok());
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            avail = rest
                .trim()
                .strip_suffix("kB")
                .and_then(|s| s.trim().parse().ok());
        } else if let Some(rest) = line.strip_prefix("SwapTotal:") {
            swap_total = rest
                .trim()
                .strip_suffix("kB")
                .and_then(|s| s.trim().parse().ok());
        } else if let Some(rest) = line.strip_prefix("SwapFree:") {
            swap_free = rest
                .trim()
                .strip_suffix("kB")
                .and_then(|s| s.trim().parse().ok());
        }
    }
    Some(MemInfo {
        total_kb: total?,
        avail_kb: avail?,
        swap_total_kb: swap_total.unwrap_or(0),
        swap_free_kb: swap_free.unwrap_or(0),
    })
}

pub fn parse_mounts(text: &str) -> Vec<MountEntry> {
    // Show only interesting mount points (not cgroup/proc/sys noise).
    const INTERESTING: &[&str] = &["/", "/boot", "/nix", "/tmp", "/run", "/run/anodize", "/mnt"];
    let mut entries = Vec::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let device = match parts.next() {
            Some(d) => d,
            None => continue,
        };
        let mountpoint = match parts.next() {
            Some(m) => m,
            None => continue,
        };
        let fstype = parts.next().unwrap_or("-");
        if INTERESTING.contains(&mountpoint) || mountpoint.starts_with("/mnt/") {
            entries.push(MountEntry {
                device: device.to_string(),
                mountpoint: mountpoint.to_string(),
                fstype: fstype.to_string(),
            });
        }
    }
    entries
}

pub fn parse_kernel_version(text: &str) -> String {
    // /proc/version: "Linux version 6.x.y-... (gcc ...) ..."
    // Extract up to the first paren.
    text.split('(').next().unwrap_or(text).trim().to_string()
}

pub fn parse_thermal_millidegrees(name: &str, text: &str) -> Option<ThermalZone> {
    let millideg: i64 = text.trim().parse().ok()?;
    Some(ThermalZone {
        name: name.to_string(),
        temp_c: millideg as f64 / 1000.0,
    })
}

pub fn format_kb(kb: u64) -> String {
    if kb >= 1_048_576 {
        format!("{:.1} GiB", kb as f64 / 1_048_576.0)
    } else if kb >= 1024 {
        format!("{:.0} MiB", kb as f64 / 1024.0)
    } else {
        format!("{kb} KiB")
    }
}

// ── Readers (hit the filesystem) ──────────────────────────────────────────────

pub fn read_uptime() -> Option<Uptime> {
    parse_uptime(&fs::read_to_string("/proc/uptime").ok()?)
}

pub fn read_loadavg() -> Option<LoadAvg> {
    parse_loadavg(&fs::read_to_string("/proc/loadavg").ok()?)
}

pub fn read_meminfo() -> Option<MemInfo> {
    parse_meminfo(&fs::read_to_string("/proc/meminfo").ok()?)
}

pub fn read_entropy() -> Option<u32> {
    fs::read_to_string("/proc/sys/kernel/random/entropy_avail")
        .ok()?
        .trim()
        .parse()
        .ok()
}

pub fn read_kernel_version() -> Option<String> {
    Some(parse_kernel_version(
        &fs::read_to_string("/proc/version").ok()?,
    ))
}

pub fn read_mounts() -> Vec<MountEntry> {
    fs::read_to_string("/proc/mounts")
        .map(|t| parse_mounts(&t))
        .unwrap_or_default()
}

pub fn read_thermal_zones() -> Vec<ThermalZone> {
    let base = Path::new("/sys/class/thermal");
    let mut zones = Vec::new();
    if let Ok(entries) = fs::read_dir(base) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.starts_with("thermal_zone") {
                continue;
            }
            let type_name = fs::read_to_string(entry.path().join("type"))
                .unwrap_or(name.clone())
                .trim()
                .to_string();
            if let Some(tz) = fs::read_to_string(entry.path().join("temp"))
                .ok()
                .and_then(|t| parse_thermal_millidegrees(&type_name, &t))
            {
                zones.push(tz);
            }
        }
    }
    zones
}

pub fn read_nixos_version() -> Option<String> {
    fs::read_to_string("/run/current-system/nixos-version")
        .ok()
        .map(|s| s.trim().to_string())
}

pub fn read_secure_boot() -> Option<bool> {
    // EFI var directory exists only on UEFI systems.
    let dir = Path::new("/sys/firmware/efi/efivars");
    if !dir.is_dir() {
        return None;
    }
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("SecureBoot-") {
                // Last byte of the EFI variable data: 1 = enabled.
                if let Ok(data) = fs::read(entry.path()) {
                    // First 4 bytes are attributes, data starts at byte 4.
                    if data.len() > 4 {
                        return Some(data[4] == 1);
                    }
                }
            }
        }
    }
    None
}

pub fn read_optical_drive() -> Option<String> {
    // First try the specific model file (works for real SCSI/ATAPI drives).
    let model_path = Path::new("/sys/class/block/sr0/device/model");
    if model_path.exists() {
        let model = fs::read_to_string(model_path)
            .unwrap_or_default()
            .trim()
            .to_string();
        if !model.is_empty() {
            return Some(model);
        }
    }

    // Fallback: scan /sys/block for sr* devices (catches cdemu and other
    // virtual optical drives that don't expose a model string).
    detect_optical_drive_fallback()
}

/// Scan `/sys/block` for `sr*` entries and return a description string for
/// the first one found.  Tries to read the vendor sysfs attribute; falls
/// back to "virtual drive" when no identifying information is available.
pub fn detect_optical_drive_fallback() -> Option<String> {
    let entries = fs::read_dir("/sys/block").ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.starts_with("sr") {
            continue;
        }
        // Try vendor string (e.g. "CDEmu" for virtual drives).
        let vendor = fs::read_to_string(entry.path().join("device/vendor"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        return Some(match vendor {
            Some(v) => format!("{v} virtual drive"),
            None => "virtual drive".to_string(),
        });
    }
    None
}

// ── Command runners ───────────────────────────────────────────────────────────

pub fn run_failed_units() -> String {
    Command::new("systemctl")
        .args(["--failed", "--no-legend", "--no-pager"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

pub fn run_loginctl() -> String {
    Command::new("loginctl")
        .args(["list-sessions", "--no-legend", "--no-pager"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

pub fn run_lsblk() -> String {
    Command::new("lsblk")
        .args(["-o", "NAME,SIZE,TYPE,MOUNTPOINT", "--noheadings"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

pub fn run_timedatectl_ntp() -> Option<String> {
    Command::new("timedatectl")
        .args(["show", "--property=NTPSynchronized", "--value"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

pub fn run_network_interfaces() -> String {
    Command::new("ip")
        .args(["-brief", "addr", "show"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_uptime() {
        let u = parse_uptime("12345.67 98765.43").unwrap();
        assert_eq!(
            u,
            Uptime {
                days: 0,
                hours: 3,
                minutes: 25,
                seconds: 45
            }
        );
    }

    #[test]
    fn test_parse_uptime_multi_day() {
        let u = parse_uptime("100000.00 200000.00").unwrap();
        assert_eq!(u.days, 1);
        assert_eq!(u.hours, 3);
        assert_eq!(u.minutes, 46);
        assert_eq!(u.seconds, 40);
    }

    #[test]
    fn test_parse_uptime_zero() {
        let u = parse_uptime("0.01 0.01").unwrap();
        assert_eq!(
            u,
            Uptime {
                days: 0,
                hours: 0,
                minutes: 0,
                seconds: 0
            }
        );
    }

    #[test]
    fn test_parse_uptime_invalid() {
        assert!(parse_uptime("").is_none());
        assert!(parse_uptime("notanumber 123").is_none());
    }

    #[test]
    fn test_parse_loadavg() {
        let la = parse_loadavg("0.12 0.34 0.56 1/234 5678").unwrap();
        assert_eq!(la.one, "0.12");
        assert_eq!(la.five, "0.34");
        assert_eq!(la.fifteen, "0.56");
    }

    #[test]
    fn test_parse_loadavg_empty() {
        assert!(parse_loadavg("").is_none());
    }

    #[test]
    fn test_parse_meminfo() {
        let text = "\
MemTotal:       16384000 kB
MemFree:         2048000 kB
MemAvailable:    8192000 kB
Buffers:          512000 kB
SwapTotal:       4096000 kB
SwapFree:        4096000 kB
";
        let m = parse_meminfo(text).unwrap();
        assert_eq!(m.total_kb, 16384000);
        assert_eq!(m.avail_kb, 8192000);
        assert_eq!(m.swap_total_kb, 4096000);
        assert_eq!(m.swap_free_kb, 4096000);
    }

    #[test]
    fn test_parse_meminfo_no_swap() {
        let text = "\
MemTotal:       8000000 kB
MemAvailable:   4000000 kB
";
        let m = parse_meminfo(text).unwrap();
        assert_eq!(m.total_kb, 8000000);
        assert_eq!(m.avail_kb, 4000000);
        assert_eq!(m.swap_total_kb, 0);
        assert_eq!(m.swap_free_kb, 0);
    }

    #[test]
    fn test_parse_meminfo_missing_fields() {
        assert!(parse_meminfo("Bogus: 123 kB\n").is_none());
    }

    #[test]
    fn test_parse_mounts() {
        let text = "\
sysfs /sys sysfs rw,nosuid 0 0
proc /proc proc rw,nosuid 0 0
tmpfs /tmp tmpfs rw,nosuid 0 0
/dev/sda1 /boot ext4 rw 0 0
tmpfs /run tmpfs rw 0 0
/dev/sdb1 /mnt/shuttle vfat rw 0 0
none /run/anodize tmpfs rw 0 0
";
        let mounts = parse_mounts(text);
        assert_eq!(mounts.len(), 4);
        assert_eq!(mounts[0].mountpoint, "/tmp");
        assert_eq!(mounts[1].mountpoint, "/boot");
        assert_eq!(mounts[2].mountpoint, "/run");
        assert_eq!(mounts[3].mountpoint, "/run/anodize");
    }

    #[test]
    fn test_parse_mounts_root() {
        let text = "/dev/sda1 / ext4 rw 0 0\n";
        let mounts = parse_mounts(text);
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].mountpoint, "/");
        assert_eq!(mounts[0].fstype, "ext4");
    }

    #[test]
    fn test_parse_mounts_empty() {
        assert!(parse_mounts("").is_empty());
    }

    #[test]
    fn test_parse_kernel_version() {
        let v = parse_kernel_version(
            "Linux version 6.12.6 (nixbld@localhost) (gcc 13.3.0) #1-NixOS SMP",
        );
        assert_eq!(v, "Linux version 6.12.6");
    }

    #[test]
    fn test_parse_kernel_version_no_paren() {
        assert_eq!(parse_kernel_version("Linux 6.0"), "Linux 6.0");
    }

    #[test]
    fn test_parse_thermal_millidegrees() {
        let tz = parse_thermal_millidegrees("x86_pkg_temp", "45000\n").unwrap();
        assert_eq!(tz.name, "x86_pkg_temp");
        assert!((tz.temp_c - 45.0).abs() < 0.001);
    }

    #[test]
    fn test_parse_thermal_invalid() {
        assert!(parse_thermal_millidegrees("zone0", "not_a_number").is_none());
        assert!(parse_thermal_millidegrees("zone0", "").is_none());
    }

    #[test]
    fn test_format_kb() {
        assert_eq!(format_kb(512), "512 KiB");
        assert_eq!(format_kb(2048), "2 MiB");
        assert_eq!(format_kb(16_777_216), "16.0 GiB");
    }

    #[test]
    fn test_read_optical_drive_no_sysfs() {
        // On macOS / CI there is no /sys/class/block/sr0 — returns None.
        // On Linux without an optical drive, same result.
        // This just confirms the function doesn't panic.
        let _result = read_optical_drive();
    }

    #[test]
    fn test_detect_optical_drive_fallback_no_sysfs() {
        // Same: on macOS /sys/block doesn't exist → None, no panic.
        let result = detect_optical_drive_fallback();
        if !Path::new("/sys/block").exists() {
            assert!(result.is_none(), "no /sys/block → should return None");
        }
    }
}
