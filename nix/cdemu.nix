{ config, lib, pkgs, ... }:
{
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

  # ── Networking (dev ISO only) ─────────────────────────────────────────────
  networking.useDHCP = lib.mkForce true;

  # ── SSH (dev ISO only) ────────────────────────────────────────────────────
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

  # ── Diagnostic packages (dev ISO only) ───────────────────────────────────

  environment.systemPackages = [ pkgs.sg3_utils ];

  # cdemu-daemon: userspace optical drive emulator, run as a user service.
  systemd.user.services.cdemu-daemon = {
    description = "CDEmu daemon — virtual optical drive";
    wantedBy    = [ "default.target" ];
    serviceConfig = {
      Type       = "simple";
      ExecStart  = "${pkgs.cdemu-daemon}/bin/cdemu-daemon --num-devices=1";
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

        # --- Pre-load diagnostics ---
        echo "=== pre-load ===" >"$share/cdemu-status.txt"
        echo "--- vhba module ---" >>"$share/cdemu-status.txt"
        lsmod | grep vhba >>"$share/cdemu-status.txt" 2>&1 || echo "(vhba not in lsmod)" >>"$share/cdemu-status.txt"
        echo "--- /dev/vhba_ctl ---" >>"$share/cdemu-status.txt"
        ls -la /dev/vhba_ctl >>"$share/cdemu-status.txt" 2>&1 || echo "(not found)" >>"$share/cdemu-status.txt"
        echo "--- id ---" >>"$share/cdemu-status.txt"
        id >>"$share/cdemu-status.txt" 2>&1
        echo "--- kernel messages (vhba) ---" >>"$share/cdemu-status.txt"
        dmesg | grep -i vhba >>"$share/cdemu-status.txt" 2>&1 || echo "(no vhba in dmesg)" >>"$share/cdemu-status.txt"
        echo "--- existing sr/sg devices ---" >>"$share/cdemu-status.txt"
        ls -la /dev/sr* /dev/sg* >>"$share/cdemu-status.txt" 2>&1 || true

        # Wait for cdemu-daemon to register on the session D-Bus (up to 30 s).
        for i in $(seq 1 30); do
          if ${pkgs.glib}/bin/gdbus introspect --session \
               --dest net.sf.cdemu.CDEmuDaemon \
               --object-path /Daemon >/dev/null 2>&1; then
            echo "cdemu-daemon ready after $i s" >>"$share/cdemu-status.txt"
            break
          fi
          if [ "$i" -eq 30 ]; then
            echo "ERROR: cdemu-daemon not on session bus after 30s" \
              >>"$share/cdemu-status.txt" >&2
            exit 1
          fi
          sleep 1
        done

        # Dump cdemu-daemon journal before we call DeviceCreateBlank.
        echo "--- cdemu-daemon journal ---" >>"$share/cdemu-status.txt"
        journalctl --user -u cdemu-daemon --no-pager -n 50 >>"$share/cdemu-status.txt" 2>&1 || true

        # Create blank BD-R image at the 9p-shared path.
        ${pkgs.glib}/bin/gdbus call --session \
          --dest net.sf.cdemu.CDEmuDaemon \
          --object-path /Daemon \
          --method net.sf.cdemu.CDEmuDaemon.DeviceCreateBlank \
          0 "$share/test-bdr.img" \
          "{'writer-id': <'WRITER-ISO'>, 'medium-type': <'bdr'>}" \
          >"$share/cdemu-load-result.txt" 2>&1
        echo "DeviceCreateBlank exit=$?" >>"$share/cdemu-status.txt"

        # --- Post-load diagnostics ---
        echo "=== post-load ===" >>"$share/cdemu-status.txt"
        ${pkgs.glib}/bin/gdbus call --session \
          --dest net.sf.cdemu.CDEmuDaemon \
          --object-path /Daemon \
          --method net.sf.cdemu.CDEmuDaemon.DeviceGetStatus \
          0 >>"$share/cdemu-status.txt" 2>&1 || true
        ${pkgs.glib}/bin/gdbus call --session \
          --dest net.sf.cdemu.CDEmuDaemon \
          --object-path /Daemon \
          --method net.sf.cdemu.CDEmuDaemon.DeviceGetMapping \
          0 >>"$share/cdemu-status.txt" 2>&1 || true
        echo "--- devices after load ---" >>"$share/cdemu-status.txt"
        ls -la /dev/sr* /dev/sg* >>"$share/cdemu-status.txt" 2>&1 || true
        echo "--- dmesg (vhba/cdemu) ---" >>"$share/cdemu-status.txt"
        dmesg | grep -iE 'vhba|cdemu|scsi' >>"$share/cdemu-status.txt" 2>&1 || true
      '';
    };
  };

  # Mount point for the virtio-9p host share (dev-disc/ in the repo).
  systemd.tmpfiles.rules = [ "d /run/anodize/share 0775 root wheel -" ];
  fileSystems."/run/anodize/share" = {
    device  = "dev-disc";
    fsType  = "9p";
    options = [ "trans=virtio" "version=9p2000.L" "msize=104857600" "nofail" "access=any" ];
  };
}
