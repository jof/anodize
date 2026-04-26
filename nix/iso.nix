# Anodize ceremony ISO — NixOS-based appliance image.
#
# Security properties enforced here:
#   - No network stack at runtime
#   - Ephemeral /tmp in RAM (tmpfs); no writable persistent storage
#   - Read-only squashfs root (inherent to ISO image builds)
#   - udev rules give the ceremony user access to YubiHSM 2 and optical drives
#   - No SSH, no package manager, no arbitrary shell for the operator
#   - Auto-login → ceremony TUI launches immediately on tty1
#   - CAP_SYS_ADMIN granted only to the ceremony wrapper (needed for mount(2))
#
# Disc-before-USB invariant is enforced in the anodize-ceremony binary itself;
# this module only provides the environment in which it runs.

{ config, pkgs, lib, anodize-ceremony, ... }:

let
  # The ceremony user's login shell: exec the wrapper binary directly.
  # Using getty (not a raw systemd service) is important: it creates a real
  # logind user session.  The binary handles all device discovery internally.
  #
  # ESC-c (RIS) resets the Linux VT to a clean state before the TUI starts,
  # wiping any getty/login residue that would bleed through into the TUI.
  ceremonyShell = (pkgs.writeShellScriptBin "ceremony-shell" ''
    printf '\033c'
    exec /run/wrappers/bin/anodize-ceremony
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

  # nomodeset: disables KMS/DRM so QEMU's SDL display can capture the
  # framebuffer.  On real hardware remove this — the GPU driver is preferable.
  # Verbose boot is intentional — kernel messages are visible during boot and
  # the TUI clears the screen (ESC-c in ceremony shell) when it takes over.
  boot.kernelParams = [ "nomodeset" ];

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

  # ── Capability wrapper — mount(2) requires CAP_SYS_ADMIN ──────────────────

  # The ceremony binary mounts USB sticks internally via nix::mount::mount().
  # A minimal capability wrapper grants only CAP_SYS_ADMIN; no setuid bit.
  security.wrappers.anodize-ceremony = {
    source      = "${anodize-ceremony}/bin/anodize-ceremony";
    capabilities = "cap_sys_admin=ep";
    owner       = "root";
    group       = "wheel";
    permissions = "u+rx,g+rx";
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

  # ── Auto-login → ceremony TUI ─────────────────────────────────────────────

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

  # ── Disable unnecessary services ──────────────────────────────────────────

  services.openssh.enable = false;

  # ── Misc ──────────────────────────────────────────────────────────────────

  system.stateVersion = "25.11";
}
