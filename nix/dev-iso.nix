# Dev ISO module — cdemu virtual optical drive + SSH + networking.
#
# Included by the dev ISO configurations in flake.nix (both amd64 and arm64).
# Provides a virtual BD-R via cdemu SCSI generic passthrough so the real
# SG_IO MMC disc write code path is exercised end-to-end without hardware.
# Also enables SSH (key-based), DHCP networking, and a debug user.

{ config, lib, pkgs, cdemu-src, ... }:
let
  # Build cdemu-daemon from the custom fork (multi-session recording fixes).
  # Reuses nixpkgs' cdemu-daemon derivation, only replacing the source tree.
  cdemu-daemon = pkgs.cdemu-daemon.overrideAttrs (old: {
    src = "${cdemu-src}/cdemu-daemon";
  });
in
{
  # Keep ceremony user's systemd --user alive across TTY session restarts so
  # cdemu-daemon (and its in-memory disc state) survives getty respawns.
  systemd.tmpfiles.rules = [
    "f /var/lib/systemd/linger/ceremony"          # keep user manager alive across TTY restarts
    "d /run/anodize/share 0775 root wheel -"      # 9p mount point for dev-disc
  ];

  # Virtual SCSI HBA kernel module.
  # Creates /dev/sr0 (block) and /dev/sg0 (SCSI generic) for cdemu virtual drives.
  boot.kernelModules       = [ "vhba" ];
  boot.extraModulePackages = [ config.boot.kernelPackages.vhba ];

  # vhba_ctl: allow the ceremony user (group "wheel") to communicate with the
  # vhba kernel module.  cdemu-daemon runs as the ceremony user and opens
  # /dev/vhba_ctl to register the virtual SCSI host adapter.
  services.udev.extraRules = ''
    SUBSYSTEM=="misc", KERNEL=="vhba_ctl", MODE="0660", GROUP="wheel"
  '';

  # ── Networking (dev ISOs) ──────────────────────────────────────────────────
  networking.useDHCP = lib.mkForce true;

  # ── SSH (dev ISOs) ─────────────────────────────────────────────────────────
  services.openssh = {
    enable = lib.mkForce true;
    settings = {
      PasswordAuthentication = false;
      KbdInteractiveAuthentication = false;
    };
  };

  # ceremony: authenticated for interactive ceremony sessions.
  users.users.ceremony.openssh.authorizedKeys.keyFiles = [
    ../scripts/dev-ssh-key.pub
  ];

  # debug: bash login shell for non-interactive diagnosis via SSH.
  # Same dev key; wheel group grants access to /dev/sr*, /dev/vhba_ctl, etc.
  users.users.debug = {
    isNormalUser = true;
    extraGroups  = [ "wheel" ];
    password     = "";
    shell        = pkgs.bash;
    openssh.authorizedKeys.keyFiles = [ ../scripts/dev-ssh-key.pub ];
  };

  # ── Dev packages ────────────────────────────────────────────────────────────

  environment.systemPackages = [
    pkgs.sg3_utils              # SCSI diagnostic tools
    pkgs.softhsm                # SoftHSM2 PKCS#11 module (dev/testing)
    pkgs.opensc                 # PKCS#11 utilities (pkcs11-tool, etc.)
  ];

  # Add SoftHSM2 to the PKCS#11 allowlist alongside the prod YubiHSM entry.
  environment.variables = {
    SOFTHSM2_MODULE = "${pkgs.softhsm}/lib/softhsm/libsofthsm2.so";
    ANODIZE_PKCS11_MODULES = lib.mkForce (lib.concatStringsSep ":" [
      "${pkgs.softhsm}/lib/softhsm/libsofthsm2.so"
      "${pkgs.yubihsm-shell}/lib/pkcs11/yubihsm_pkcs11.so"
    ]);
  };

  # cdemu-daemon: userspace optical drive emulator, run as a user service.
  systemd.user.services.cdemu-daemon = {
    description = "CDEmu daemon — virtual optical drive";
    wantedBy    = [ "default.target" ];
    serviceConfig = {
      Type       = "simple";
      ExecStart  = "${cdemu-daemon}/bin/cdemu-daemon --num-devices=1";
      Restart    = "on-failure";
      RestartSec = "1s";
    };
  };

  # Load a blank BD-R image into cdemu slot 0 once the daemon is D-Bus-ready.
  systemd.user.services.cdemu-load-bdr = {
    description = "Load blank BD-R into cdemu slot 0";
    wantedBy    = [ "default.target" ];
    after       = [ "cdemu-daemon.service" ];
    requires    = [ "cdemu-daemon.service" ];
    serviceConfig = {
      Type            = "oneshot";
      RemainAfterExit = true;
      ExecStart = pkgs.writeShellScript "cdemu-load-bdr" ''
        set -euo pipefail
        share=/run/anodize/share

        # Wait for cdemu-daemon to register on the session D-Bus (up to 30 s).
        for i in $(seq 1 30); do
          if ${pkgs.glib}/bin/gdbus introspect --session \
               --dest net.sf.cdemu.CDEmuDaemon \
               --object-path /Daemon >/dev/null 2>&1; then
            break
          fi
          if [ "$i" -eq 30 ]; then
            echo "ERROR: cdemu-daemon not on session bus after 30s" >&2
            exit 1
          fi
          sleep 1
        done

        # Create blank BD-R image at the 9p-shared path.
        ${pkgs.glib}/bin/gdbus call --session \
          --dest net.sf.cdemu.CDEmuDaemon \
          --object-path /Daemon \
          --method net.sf.cdemu.CDEmuDaemon.DeviceCreateBlank \
          0 "$share/test-bdr.img" \
          "{'writer-id': <'WRITER-ISO'>, 'medium-type': <'bdr'>}"
      '';
    };
  };

  # Mount point for the virtio-9p host share (dev-disc/ in the repo).
  fileSystems."/run/anodize/share" = {
    device  = "dev-disc";
    fsType  = "9p";
    options = [ "trans=virtio" "version=9p2000.L" "msize=104857600" "nofail" "access=any" ];
  };
}
