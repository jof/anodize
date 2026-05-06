use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::{Args, ValueEnum};

/// HSM backend mode for the shuttle profile.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum HsmMode {
    /// SoftHSM2 — for development and testing only.
    Softhsm2,
    /// YubiHSM 2 — production hardware HSM.
    Yubihsm,
}

#[derive(Args)]
pub struct InitArgs {
    /// HSM backend mode.
    #[arg(long, value_enum)]
    mode: HsmMode,

    /// USB device path (e.g. /dev/disk4 on macOS, /dev/sdb on Linux).
    /// Use `anodize-shuttle lint --list-usb` or `diskutil list` to find it.
    #[arg(long)]
    device: String,

    /// CA common name (e.g. "Example Root CA").
    #[arg(long)]
    common_name: String,

    /// CA organization (e.g. "Example Corp").
    #[arg(long)]
    organization: String,

    /// CA country code (e.g. "US").
    #[arg(long)]
    country: String,

    /// CRL distribution point URL (optional).
    #[arg(long)]
    cdp_url: Option<String>,

    /// HSM token label (e.g. "anodize-root-2026").
    #[arg(long)]
    token_label: String,

    /// HSM key label (e.g. "root-key").
    #[arg(long, default_value = "root-key")]
    key_label: String,

    /// Skip the confirmation prompt (dangerous).
    #[arg(long)]
    yes: bool,

    /// Volume label for the FAT32 filesystem.
    #[arg(long, default_value = "ANODIZE")]
    volume_label: String,

    /// For softhsm2 mode: also initialize a SoftHSM2 token on the shuttle.
    /// Requires softhsm2-util and mtools (mmd, mcopy) on the host.
    #[arg(long)]
    init_softhsm_token: bool,

    /// SoftHSM2 user PIN (only used with --init-softhsm-token).
    #[arg(long, default_value = "123456")]
    softhsm_pin: String,

    /// SoftHSM2 SO PIN (only used with --init-softhsm-token).
    #[arg(long, default_value = "12345678")]
    softhsm_so_pin: String,
}

pub fn run(args: InitArgs) -> Result<()> {
    let device = &args.device;

    // Safety: refuse to operate on the boot disk
    if device == "/dev/disk0" || device == "/dev/sda" || device == "/dev/nvme0n1" {
        bail!("Refusing to operate on {device} — this looks like the boot disk.");
    }

    // Confirm with user
    if !args.yes {
        eprintln!("WARNING: This will ERASE ALL DATA on {device}.");
        eprintln!();
        eprintln!("  Mode         : {:?}", args.mode);
        eprintln!("  Volume label : {}", args.volume_label);
        eprintln!("  Common name  : {}", args.common_name);
        eprintln!("  Organization : {}", args.organization);
        eprintln!("  Country      : {}", args.country);
        eprintln!("  Token label  : {}", args.token_label);
        eprintln!();
        eprint!("Type 'yes' to continue: ");

        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .context("read confirmation")?;
        if input.trim() != "yes" {
            bail!("Aborted.");
        }
    }

    // Step 1: Format the device
    format_device(device, &args.volume_label)?;

    // Step 2: Mount the device and get the mount point
    let mount_point = mount_device(device)?;
    // Ensure we unmount on exit
    let _guard = UnmountGuard(mount_point.clone());

    // Step 3: Write profile.toml
    let profile_toml = build_profile_toml(&args);
    let profile_path = mount_point.join("profile.toml");
    std::fs::write(&profile_path, &profile_toml)
        .with_context(|| format!("write {}", profile_path.display()))?;
    eprintln!("  Wrote profile.toml");

    // Step 4: For softhsm2 mode with --init-softhsm-token, set up token
    if matches!(args.mode, HsmMode::Softhsm2) && args.init_softhsm_token {
        init_softhsm_token(
            &mount_point,
            &args.token_label,
            &args.softhsm_pin,
            &args.softhsm_so_pin,
        )?;
        eprintln!(
            "  Initialized SoftHSM2 token (label={:?})",
            args.token_label
        );
    }

    // Step 5: Validate by loading the profile
    match anodize_config::load(&profile_path) {
        Ok(_) => eprintln!("  Profile validates OK"),
        Err(e) => bail!("Generated profile.toml fails validation: {e}"),
    }

    eprintln!();
    eprintln!("Shuttle initialized on {device}.");
    eprintln!("  Volume: {}", args.volume_label);
    eprintln!("  Mode:   {:?}", args.mode);
    eprintln!();
    eprintln!("Next steps:");
    eprintln!("  1. Eject the USB stick");
    eprintln!("  2. Insert into the ceremony machine");
    eprintln!("  3. Boot the anodize ISO");

    Ok(())
}

fn build_profile_toml(args: &InitArgs) -> String {
    let module_path = match args.mode {
        HsmMode::Softhsm2 => "/run/current-system/sw/lib/softhsm/libsofthsm2.so",
        HsmMode::Yubihsm => "/run/current-system/sw/lib/yubihsm_pkcs11.so",
    };

    let cdp_line = match &args.cdp_url {
        Some(url) => format!("cdp_url      = {:?}\n", url),
        None => String::new(),
    };

    format!(
        r#"[ca]
common_name  = {:?}
organization = {:?}
country      = {:?}
{cdp_line}
[hsm]
module_path  = {:?}
token_label  = {:?}
key_label    = {:?}
key_spec     = "ecdsa-p384"
pin_source   = "prompt"
"#,
        args.common_name,
        args.organization,
        args.country,
        module_path,
        args.token_label,
        args.key_label,
    )
}

fn format_device(device: &str, volume_label: &str) -> Result<()> {
    if cfg!(target_os = "macos") {
        // macOS: diskutil eraseDisk
        eprintln!("Formatting {device} as FAT32 ({volume_label})...");
        let status = Command::new("diskutil")
            .args(["eraseDisk", "FAT32", volume_label, "MBRFormat", device])
            .status()
            .context("diskutil eraseDisk")?;
        if !status.success() {
            bail!("diskutil eraseDisk failed (exit {})", status);
        }
    } else {
        // Linux: unmount + mkfs.vfat
        eprintln!("Formatting {device} as FAT32 ({volume_label})...");

        // Try to unmount first (ignore errors if not mounted)
        let _ = Command::new("umount").arg(device).status();

        // Create partition table + partition (use sfdisk for simplicity)
        let sfdisk_input = "type=0c\n"; // FAT32 LBA
        let mut sfdisk = Command::new("sfdisk")
            .arg(device)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .context("sfdisk")?;
        if let Some(ref mut stdin) = sfdisk.stdin {
            use std::io::Write;
            stdin.write_all(sfdisk_input.as_bytes())?;
        }
        let status = sfdisk.wait()?;
        if !status.success() {
            bail!("sfdisk failed (exit {})", status);
        }

        // Determine partition device (device + "1")
        let part_dev = format!("{device}1");

        let status = Command::new("mkfs.vfat")
            .args(["-F", "32", "-n", volume_label, &part_dev])
            .status()
            .context("mkfs.vfat")?;
        if !status.success() {
            bail!("mkfs.vfat failed (exit {})", status);
        }
    };

    Ok(())
}

fn mount_device(device: &str) -> Result<PathBuf> {
    if cfg!(target_os = "macos") {
        // macOS auto-mounts after diskutil eraseDisk.
        // The volume is at /Volumes/<label>. Wait briefly for it.
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Find the mount point by checking diskutil info
        let output = Command::new("diskutil")
            .args(["info", "-plist", &format!("{device}s1")])
            .output()
            .context("diskutil info")?;

        // Parse mount point from plist (simple grep approach)
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(mp) = extract_plist_value(&stdout, "MountPoint") {
            return Ok(PathBuf::from(mp));
        }

        // Fallback: try /Volumes/ANODIZE
        let fallback = PathBuf::from("/Volumes/ANODIZE");
        if fallback.exists() {
            return Ok(fallback);
        }

        bail!(
            "Cannot determine mount point for {device}. \
             Check that the device is mounted (try: diskutil mount {device}s1)"
        );
    } else {
        // Linux: mount manually
        let mount_point = PathBuf::from("/mnt/anodize-shuttle");
        std::fs::create_dir_all(&mount_point)?;
        let part_dev = format!("{device}1");
        let status = Command::new("mount")
            .args([&part_dev, &mount_point.to_string_lossy().to_string()])
            .status()
            .context("mount")?;
        if !status.success() {
            bail!("mount failed (exit {})", status);
        }
        Ok(mount_point)
    }
}

/// Unmount on drop (best-effort).
struct UnmountGuard(PathBuf);

impl Drop for UnmountGuard {
    fn drop(&mut self) {
        if cfg!(target_os = "macos") {
            let _ = Command::new("diskutil")
                .args(["unmount", &self.0.to_string_lossy()])
                .status();
        } else {
            let _ = Command::new("umount").arg(&self.0).status();
        }
    }
}

fn extract_plist_value(plist: &str, key: &str) -> Option<String> {
    let mut lines = plist.lines();
    while let Some(line) = lines.next() {
        if line.contains(&format!("<key>{key}</key>")) {
            if let Some(val_line) = lines.next() {
                let val = val_line.trim();
                if let Some(s) = val.strip_prefix("<string>") {
                    if let Some(s) = s.strip_suffix("</string>") {
                        return Some(s.to_string());
                    }
                }
            }
        }
    }
    None
}

fn init_softhsm_token(
    mount_point: &std::path::Path,
    token_label: &str,
    pin: &str,
    so_pin: &str,
) -> Result<()> {
    let tmp = tempdir()?;
    let conf_path = tmp.join("softhsm2.conf");
    let tokens_dir = tmp.join("tokens");
    std::fs::create_dir_all(&tokens_dir)?;

    let conf = format!(
        "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n",
        tokens_dir.display()
    );
    std::fs::write(&conf_path, &conf)?;

    // Initialize token
    let status = Command::new("softhsm2-util")
        .env("SOFTHSM2_CONF", &conf_path)
        .args([
            "--init-token",
            "--free",
            "--label",
            token_label,
            "--so-pin",
            so_pin,
            "--pin",
            pin,
        ])
        .status()
        .context("softhsm2-util --init-token")?;
    if !status.success() {
        bail!("softhsm2-util failed (exit {})", status);
    }

    // Copy token directory tree to mount_point/softhsm2/tokens/
    let dest_base = mount_point.join("softhsm2").join("tokens");
    std::fs::create_dir_all(&dest_base)?;

    for entry in std::fs::read_dir(&tokens_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let uuid_name = entry.file_name();
            let dest_uuid = dest_base.join(&uuid_name);
            std::fs::create_dir_all(&dest_uuid)?;

            for obj in std::fs::read_dir(entry.path())? {
                let obj = obj?;
                if obj.file_type()?.is_file() {
                    let dest_file = dest_uuid.join(obj.file_name());
                    std::fs::copy(obj.path(), &dest_file)?;
                }
            }
        }
    }

    // Clean up temp dir
    let _ = std::fs::remove_dir_all(&tmp);

    Ok(())
}

fn tempdir() -> Result<PathBuf> {
    let mut path = std::env::temp_dir();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    path.push(format!("anodize-softhsm-{ts}"));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}
