# Dev-burn ISO module — real optical drives + SSH debug shell, no cdemu.
#
# Included by the dev-burn ISO configurations in flake.nix.
# Targets physical optical hardware for burn validation testing.
# SSH and a debug user are enabled for remote diagnosis; cdemu and
# virtual SCSI are intentionally absent.

{ config, lib, pkgs, ... }:
{
  # ── Networking (dev-burn ISOs) ──────────────────────────────────────────────
  networking.useDHCP = lib.mkForce true;

  # ── SSH (dev-burn ISOs) ─────────────────────────────────────────────────────
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
  # Same dev key; wheel group grants access to /dev/sr*, etc.
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
  # the PKCS#11 library.
  environment.variables.SOFTHSM2_MODULE = "${pkgs.softhsm}/lib/softhsm/libsofthsm2.so";
}
