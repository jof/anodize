# Anodize ceremony ISO — NixOS-based appliance image.
#
# Security properties enforced here:
#   - No network stack at runtime
#   - Ephemeral /tmp in RAM (tmpfs); no writable persistent storage
#   - Read-only squashfs root (inherent to ISO image builds)
#   - udev rules give the ceremony user access to YubiHSM 2 and optical drives
#   - No SSH, no package manager, no arbitrary shell for the operator
#   - Auto-login → sentinel → ceremony TUI on both tty1 and ttyS0
#   - CAP_SYS_ADMIN granted only to the ceremony wrapper (needed for mount(2))
#   - CAP_SYS_BOOT granted only to the sentinel wrapper (needed for reboot(2))
#   - flock on /run/anodize/ceremony.lock prevents two terminals from starting
#     the ceremony simultaneously; the sentinel holds the lock across exec
#
# Disc-before-USB invariant is enforced in the anodize-ceremony binary itself;
# this module only provides the environment in which it runs.

{ config, pkgs, lib, anodize-ceremony, ... }:

let
  # The ceremony user's login shell: exec the sentinel via its capability
  # wrapper (/run/wrappers/bin) so it has CAP_SYS_BOOT for the power-off
  # option and creates a real logind session (unlike a raw systemd service).
  #
  # ESC-c (RIS) resets the Linux VT before the sentinel prompt appears.
  # The sentinel acquires /run/anodize/ceremony.lock (flock) before exec-ing
  # /run/wrappers/bin/anodize-ceremony, preventing two terminals from running
  # the ceremony simultaneously.
  ceremonyShell = (pkgs.writeShellScriptBin "ceremony-shell" ''
    exec /run/wrappers/bin/anodize-sentinel
  '') // { shellPath = "/bin/ceremony-shell"; };

in
{
  # ── ISO image settings ─────────────────────────────────────────────────────

  isoImage.squashfsCompression = "zstd -Xcompression-level 6";
  image.baseName = lib.mkForce "anodize";
  isoImage.makeEfiBootable = true;
  isoImage.makeUsbBootable = true;

  # ── Identity ───────────────────────────────────────────────────────────────

  networking.hostName = "anodize";

  # Replace NixOS identification so tools reading /etc/os-release show "Anodize".
  environment.etc."os-release".text = ''
    NAME="Anodize"
    ID=anodize
    PRETTY_NAME="Anodize Root CA Ceremony"
    ANSI_COLOR="1;34"
  '';

  # ── Network: disabled entirely ─────────────────────────────────────────────

  networking.useDHCP = false;
  networking.interfaces = lib.mkForce { };
  networking.firewall.enable = false;
  networking.wireless.enable = false;

  # ── Storage: ephemeral RAM only ────────────────────────────────────────────

  # All writes go to tmpfs; nothing survives a reboot.
  boot.tmp.useTmpfs = true;

  # ── Boot ──────────────────────────────────────────────────────────────────

  # nomodeset: disables KMS/DRM so the kernel uses the basic efifb/vesa
  # framebuffer.  Verbose boot is intentional; the sentinel clears the screen
  # (ESC-c in ceremony-shell) when it takes over.
  # console=tty0: kernel messages go to the EFI framebuffer (tty1).
  # console=ttyS0,115200: kernel messages also go to the serial port;
  #   listing ttyS0 last makes it the primary console so
  #   systemd-getty-generator activates serial-getty@ttyS0.service.
  boot.kernelParams = [ "nomodeset" "console=tty0" "console=ttyS0,115200n8" ];

  # Disable the graphical Plymouth boot splash — irrelevant for an appliance
  # and would require a framebuffer driver that nomodeset prevents loading.
  boot.plymouth.enable = false;

  # Boot immediately without showing the GRUB menu — there is exactly one
  # valid boot entry and the operator has no reason to interact with GRUB.
  # The iso-image module sets timeout = mkDefault 10, so plain 0 suffices.
  boot.loader.timeout = lib.mkForce 0;

  # isoImage.efiSplashImage is a *separate* option from isoImage.grubTheme;
  # it always places efi-background.png on the ISO (the NixOS blue image).
  # Replace it with a 1×1 black PNG so if GRUB does render anything before
  # the instant-boot fires, it is a black screen rather than NixOS branding.
  isoImage.efiSplashImage = pkgs.runCommand "anodize-efi-splash" {
    nativeBuildInputs = [ pkgs.imagemagick ];
  } "convert -size 1x1 xc:black PNG:$out";

  # Disable the graphical GRUB theme — rendered moot by timeout=0 but kept
  # so any forced menu display (e.g. boot errors) is plain text, not NixOS.
  isoImage.grubTheme = lib.mkForce null;

  # ── Packages ──────────────────────────────────────────────────────────────

  environment.systemPackages = [
    anodize-ceremony          # ceremony TUI (unwrapped — use /run/wrappers/bin/ at runtime)
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

  # ── Capability wrappers ────────────────────────────────────────────────────

  # The ceremony binary mounts USB sticks internally via nix::mount::mount().
  # The sentinel binary calls reboot(2) for the power-off option.
  # Minimal capability wrappers — no setuid bit.
  security.wrappers.anodize-ceremony = {
    source       = "${anodize-ceremony}/bin/anodize-ceremony";
    capabilities = "cap_sys_admin=ep";
    owner        = "root";
    group        = "wheel";
    permissions  = "u+rx,g+rx";
  };

  security.wrappers.anodize-sentinel = {
    source       = "${anodize-ceremony}/bin/anodize-sentinel";
    capabilities = "cap_sys_boot=ep";
    owner        = "root";
    group        = "wheel";
    permissions  = "u+rx,g+rx";
  };

  # ── udev: YubiHSM 2 and optical drive access ──────────────────────────────

  services.udev.extraRules = ''
    # YubiHSM 2 — grant the wheel group rw access without requiring root.
    SUBSYSTEM=="usb", ATTR{idVendor}=="1050", MODE="0660", GROUP="wheel"
    # Optical drives — grant the wheel group rw access for SG_IO disc writes.
    SUBSYSTEM=="block", KERNEL=="sr[0-9]*", MODE="0660", GROUP="wheel"
  '';

  # ── tmpfiles: runtime directories for the ceremony binary ─────────────────

  systemd.tmpfiles.rules = [
    "d /run/anodize     0755 ceremony ceremony -"
    "d /run/anodize/usb 0700 ceremony ceremony -"
  ];

  # ── Ceremony user ─────────────────────────────────────────────────────────

  users.users.ceremony = {
    isNormalUser = true;
    description  = "Ceremony operator (auto-login)";
    extraGroups  = [ "wheel" "plugdev" ];
    # No password — physical access to the air-gapped machine is the auth factor.
    password     = "";
    shell        = ceremonyShell;
  };

  environment.shells = [ ceremonyShell ];   # PAM requires it to be listed here

  # Disable root login; ceremony user is the only interactive account.
  users.users.root.hashedPassword = "!";

  # ── Auto-login → sentinel (tty1) ──────────────────────────────────────────

  # Getty on tty1 auto-logs in as ceremony → exec's ceremonyShell immediately.
  services.getty.autologinUser = "ceremony";

  # Suppress the "Run 'nixos-help' for the NixOS manual." line that getty
  # prints before the login prompt — it bleeds into the TUI on Linux VTs.
  services.getty.helpLine = lib.mkForce "";

  # Clear /etc/issue so getty prints no banner before auto-login.
  environment.etc."issue".text = "";

  # NAutoVTs=0: prevent logind from dynamically spawning gettys when the
  # operator presses Alt+F2..F6.  The static autovt@tty1 entry in
  # getty.target.wants is unaffected — tty1 still works normally.
  services.logind.settings.Login = {
    NAutoVTs = 0;
    ReserveVT = 0;
  };

  # ── Serial console: auto-login → sentinel ─────────────────────────────────

  # systemd-getty-generator activates serial-getty@ttyS0 because ttyS0 is
  # listed last in console= kernel params.  Override ExecStart to add
  # --autologin so it behaves identically to the VT getty on tty1: the
  # ceremony user is logged in immediately and ceremonyShell → sentinel runs.
  systemd.services."serial-getty@ttyS0" = {
    enable = true;
    wantedBy = [ "getty.target" ];
    # Disable systemd's restart rate-limit so the sentinel is relaunched
    # unconditionally even after repeated rapid exits or crashes.
    unitConfig.StartLimitIntervalSec = 0;
    serviceConfig = {
      ExecStart = [
        ""   # clear the template's ExecStart before adding ours
        "${pkgs.util-linux}/sbin/agetty --autologin ceremony --keep-baud 115200,57600,38400,9600 ttyS0 vt220"
      ];
      Restart    = "always";
      RestartSec = "0";
    };
  };

  # Same rate-limit override for the VT getty so tty1 also restarts forever.
  systemd.services."getty@tty1".unitConfig.StartLimitIntervalSec = 0;

  # ── Disable unnecessary services ──────────────────────────────────────────

  services.openssh.enable = false;

  # ── Misc ──────────────────────────────────────────────────────────────────

  system.stateVersion = "25.11";
}
