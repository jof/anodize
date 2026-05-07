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
  systemd.tmpfiles.rules = [
    "d /run/anodize/share 0775 root wheel -"      # 9p mount point for dev-disc
  ];

  # Virtual SCSI HBA kernel module.
  # Creates /dev/sr0 (block) and /dev/sg0 (SCSI generic) for cdemu virtual drives.
  boot.kernelModules       = [ "vhba" "sg" ];
  boot.extraModulePackages = [ config.boot.kernelPackages.vhba ];

  # vhba_ctl: allow the ceremony user (group "wheel") to communicate with the
  # vhba kernel module.  cdemu-daemon runs as the ceremony user and opens
  # /dev/vhba_ctl to register the virtual SCSI host adapter.
  services.udev.extraRules = ''
    SUBSYSTEM=="misc", KERNEL=="vhba_ctl", MODE="0660", GROUP="wheel"
    SUBSYSTEM=="scsi_generic", MODE="0660", GROUP="wheel"
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
    pkgs.iproute2               # ip(8) — network diagnostics

    # Quick network info for remote SSH access.
    (pkgs.writeShellScriptBin "anodize-netinfo" ''
      echo "=== Network Interfaces ==="
      ${pkgs.iproute2}/bin/ip -brief addr show
      echo
      echo "=== SSH Host Keys ==="
      for f in /etc/ssh/ssh_host_*_key.pub; do
        ${pkgs.openssh}/bin/ssh-keygen -lf "$f"
      done
    '')
  ];

  # SoftHSM2 module path — the SoftHsmBackend reads this env var to locate
  # the PKCS#11 library.  The YubiHSM backend uses native USB HID and does
  # not need any PKCS#11 module.
  environment.variables.SOFTHSM2_MODULE = "${pkgs.softhsm}/lib/softhsm/libsofthsm2.so";

  # cdemu-daemon: userspace optical drive emulator, run as a user service.
  # Auto-starts on login and pulls in cdemu-load-bdr to populate the drive.
  systemd.user.services.cdemu-daemon = {
    description = "CDEmu daemon — virtual optical drive";
    wantedBy    = [ "default.target" ];
    wants       = [ "cdemu-load-bdr.service" ];
    serviceConfig = {
      Type       = "simple";
      ExecStart  = "${cdemu-daemon}/bin/cdemu-daemon --num-devices=1";
      Restart    = "on-failure";
      RestartSec = "1s";
    };
  };

  # Load a blank BD-R image into cdemu slot 0 once the daemon is D-Bus-ready.
  # Pulled in by cdemu-daemon via Wants= or started explicitly by the TUI.
  systemd.user.services.cdemu-load-bdr = {
    description = "Load blank BD-R into cdemu slot 0";
    after       = [ "cdemu-daemon.service" ];
    requires    = [ "cdemu-daemon.service" ];
    serviceConfig = {
      Type            = "oneshot";
      RemainAfterExit = true;
      ExecStart = pkgs.writeShellScript "cdemu-load-bdr" ''
        set -euo pipefail
        share=/run/anodize/share

        # Wait for the 9p mount (system mount unit, can't depend from user service).
        for i in $(seq 1 30); do
          if mountpoint -q "$share" 2>/dev/null; then break; fi
          if [ "$i" -eq 30 ]; then
            echo "ERROR: 9p share not mounted at $share after 30s" >&2
            exit 1
          fi
          sleep 1
        done

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

        # cdemu's DeviceCreateBlank saves the file as .iso regardless of
        # what path you pass, so always use .iso extension.
        if [ -s "$share/test-bdr.iso" ]; then
          # Load existing BD-R image — preserves prior session data so
          # multi-session ceremonies work across VM reboots.
          echo "Loading existing BD-R image from $share/test-bdr.iso"
          ${pkgs.glib}/bin/gdbus call --session \
            --dest net.sf.cdemu.CDEmuDaemon \
            --object-path /Daemon \
            --method net.sf.cdemu.CDEmuDaemon.DeviceLoad \
            0 "['$share/test-bdr.iso']" \
            "{'writer-id': <'WRITER-ISO'>}"
        else
          # Create blank BD-R image at the 9p-shared path.
          echo "Creating new blank BD-R image at $share/test-bdr.iso"
          ${pkgs.glib}/bin/gdbus call --session \
            --dest net.sf.cdemu.CDEmuDaemon \
            --object-path /Daemon \
            --method net.sf.cdemu.CDEmuDaemon.DeviceCreateBlank \
            0 "$share/test-bdr.iso" \
            "{'writer-id': <'WRITER-ISO'>, 'medium-type': <'bdr'>}"
        fi
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
