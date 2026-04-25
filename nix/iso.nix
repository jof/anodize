# NixOS module for the Anodize ceremony ISO.
#
# Security properties enforced here:
#   - No network stack at runtime
#   - Ephemeral /tmp in RAM (tmpfs); no writable persistent storage
#   - Read-only squashfs root (inherent to ISO image builds)
#   - udev rule gives the ceremony user access to the YubiHSM 2 USB device
#   - No SSH, no package manager, no arbitrary shell for the operator
#   - Auto-login → ceremony TUI launches immediately on tty1
#
# Disc-before-USB invariant is enforced in the anodize-ceremony binary itself;
# this module only provides the environment in which it runs.

{ config, pkgs, lib, anodize-ceremony, ... }:

let
  # Launcher: finds profile.toml on removable media and starts the ceremony TUI.
  # Runs as the ceremony user; loops until a profile is found so the operator can
  # insert their USB stick after boot.
  ceremonyLaunch = pkgs.writeShellScript "anodize-ceremony-launch" ''
    set -euo pipefail

    clear
    echo "╔═══════════════════════════════════════════╗"
    echo "║        ANODIZE ROOT CA CEREMONY           ║"
    echo "╚═══════════════════════════════════════════╝"
    echo ""

    # Search for a profile.toml on any removable medium mounted by udisks2.
    find_profile() {
      for f in /run/media/ceremony/*/profile.toml; do
        [ -f "$f" ] && echo "$f" && return 0
      done
      return 1
    }

    while true; do
      if profile=$(find_profile); then
        usb_root=$(dirname "$profile")
        echo "Found profile: $profile"
        echo "USB root: $usb_root"
        echo ""
        exec ${anodize-ceremony}/bin/anodize-ceremony \
          --profile "$profile" \
          --disc /run/media/ceremony/disc \
          --usb "$usb_root"
      fi

      echo "Insert USB containing profile.toml, then press Enter."
      read -r
      clear
    done
  '';

in
{
  # ── ISO image settings ─────────────────────────────────────────────────────

  isoImage.squashfsCompression = "zstd -Xcompression-level 6";
  image.baseName = lib.mkForce "anodize";
  isoImage.makeEfiBootable = true;
  isoImage.makeUsbBootable = true;

  # ── Network: disabled entirely ─────────────────────────────────────────────

  networking.useDHCP = false;
  networking.interfaces = lib.mkForce { };
  networking.firewall.enable = false;
  networking.wireless.enable = false;

  # ── Storage: ephemeral RAM only ────────────────────────────────────────────

  # All writes go to tmpfs; nothing survives a reboot.
  boot.tmp.useTmpfs = true;

  # ── Boot ──────────────────────────────────────────────────────────────────

  # nomodeset: disables KMS/DRM so QEMU's SDL display can capture the
  # framebuffer.  On real hardware remove this — the GPU driver is preferable.
  boot.kernelParams = [ "nomodeset" ];

  # ── Packages ──────────────────────────────────────────────────────────────

  environment.systemPackages = [
    anodize-ceremony          # ceremony TUI
    pkgs.softhsm              # dev/testing PKCS#11 backend
    pkgs.opensc               # PKCS#11 utilities (pkcs11-tool, etc.)
    # pkgs.yubihsm-shell     # uncomment if available in your nixpkgs channel
  ];

  # Expose the SoftHSM2 module path as an environment variable so operators
  # can reference it in profile.toml without knowing the Nix store path.
  environment.variables = {
    SOFTHSM2_MODULE = "${pkgs.softhsm}/lib/softhsm/libsofthsm2.so";
  };

  # Include a sample profile so operators know what to put on their USB stick.
  environment.etc."anodize/profile.example.toml".text = ''
    # Copy this file to your USB stick as "profile.toml" and fill in the values.
    # The ceremony tool will find it automatically on boot.

    [ca]
    common_name  = "Example Root CA"
    organization = "Example Corp"
    country      = "US"
    cdp_url      = "http://crl.example.com/root.crl"   # optional

    [hsm]
    # For YubiHSM 2 (production):
    #   module_path = "/run/current-system/sw/lib/yubihsm_pkcs11.so"
    # For SoftHSM2 (dev/testing):
    module_path  = "/run/current-system/sw/lib/softhsm/libsofthsm2.so"
    token_label  = "anodize-root-2026"
    key_label    = "root-key"
    key_spec     = "ecdsa-p384"
    pin_source   = "prompt"
  '';

  # ── udev: YubiHSM 2 USB access ────────────────────────────────────────────

  services.udev.extraRules = ''
    # YubiHSM 2 — grant the ceremony group rw access without requiring root.
    SUBSYSTEM=="usb", ATTR{idVendor}=="1050", MODE="0660", GROUP="wheel"
  '';

  # ── udisks2: automount USB sticks for the ceremony user ───────────────────

  services.udisks2.enable = true;

  # ── Ceremony user ─────────────────────────────────────────────────────────

  users.users.ceremony = {
    isNormalUser = true;
    description  = "Ceremony operator (auto-login)";
    extraGroups  = [ "wheel" "plugdev" ];
    # No password — physical access to the air-gapped machine is the auth factor.
    password     = "";
  };

  # Disable root login; ceremony user is the only interactive account.
  users.users.root.hashedPassword = "!";

  # ── Auto-login → ceremony TUI ─────────────────────────────────────────────

  # Getty auto-logs in as ceremony on tty1 after boot.
  services.getty.autologinUser = "ceremony";

  # The ceremony launch script runs as a systemd service on tty1.
  # Using a service (rather than .bash_profile) gives cleaner restart behaviour
  # if the TUI exits or crashes.
  systemd.services.anodize-ceremony = {
    description = "Anodize Root CA Ceremony";
    after       = [ "multi-user.target" "udisks2.service" ];
    wantedBy    = [ "multi-user.target" ];

    serviceConfig = {
      Type             = "simple";
      User             = "ceremony";
      Group            = "users";
      ExecStart        = "${ceremonyLaunch}";
      Restart          = "on-failure";
      RestartSec       = "3s";
      # Attach to tty1 so the TUI renders on the physical console / QEMU SDL.
      StandardInput    = "tty";
      StandardOutput   = "tty";
      StandardError    = "tty";
      TTYPath          = "/dev/tty1";
      TTYReset         = true;
      TTYVHangup       = true;
    };
  };

  # Suppress getty on tty1 — the ceremony service owns the primary console.
  systemd.services."getty@tty1".enable = false;

  # ── Disable unnecessary services ──────────────────────────────────────────

  services.openssh.enable = false;

  # ── Misc ──────────────────────────────────────────────────────────────────

  system.stateVersion = "25.11";
}
