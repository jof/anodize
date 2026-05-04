{
  description = "Anodize — offline root CA ceremony tool";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";

    # Crane: incremental Rust builds with good workspace support.
    crane.url = "github:ipetkov/crane";

    # rust-overlay: pins the Rust toolchain to rust-toolchain.toml.
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";

    flake-utils.url = "github:numtide/flake-utils";

    # Custom cdemu fork with multi-session recording fixes (dev ISO only).
    cdemu-src = {
      url = "github:jof/cdemu/anodize";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, crane, rust-overlay, flake-utils, cdemu-src }:
    let
      # ---------------------------------------------------------------------------
      # Helpers shared across systems
      # ---------------------------------------------------------------------------

      mkPkgs = system: import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };

      # Build the crane lib pinned to the toolchain in rust-toolchain.toml.
      mkCraneLib = system:
        let
          pkgs = mkPkgs system;
          toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        in
        (crane.mkLib pkgs).overrideToolchain toolchain;

      # Common cargo build args for every crate in this workspace.
      mkCommonArgs = system:
        let craneLib = mkCraneLib system;
        in {
          src = craneLib.cleanCargoSource ./.;
          strictDeps = true;
          # Tests require SoftHSM2 at runtime; skip them here.
          doCheck = false;
        };

      # Pre-build all workspace dependencies once so both binaries share the cache.
      # pname suppresses crane's warning about missing name in a virtual workspace root.
      mkCargoArtifacts = system:
        (mkCraneLib system).buildDepsOnly ((mkCommonArgs system) // { pname = "anodize-deps"; version = "0.1.0"; });
    in

    # ---------------------------------------------------------------------------
    # Per-system outputs (packages + devShell)
    # ---------------------------------------------------------------------------
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs       = mkPkgs system;
        craneLib   = mkCraneLib system;
        commonArgs = mkCommonArgs system;
        cargoArtifacts = mkCargoArtifacts system;

        anodize-ceremony = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname         = "anodize-ceremony";
          version       = "0.1.0";
          cargoExtraArgs = "--package anodize-tui";
        });

        # dev-softhsm-usb: SoftHSM2 on profile USB replaces YubiHSM2 in dev/QEMU.
        # Exercises the real SG_IO MMC disc path via cdemu SCSI passthrough.
        # For development and testing only — never ship in a real ceremony ISO.
        anodize-ceremony-cdemu = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname         = "anodize-ceremony";
          version       = "0.1.0";
          cargoExtraArgs = "--package anodize-tui --features dev-softhsm-usb";
        });

      in
      {
        packages = {
          inherit anodize-ceremony anodize-ceremony-cdemu;
          default = anodize-ceremony;

          # nix build .#iso  →  bootable ceremony ISO image (x86_64-linux only).
          # Build this via Docker on any host: make anodize.iso
          iso = self.nixosConfigurations.ceremony-iso.config.system.build.isoImage;

          # nix build .#dev-iso  →  dev ISO with dev-usb-disc feature (USB as disc).
          # Build this via Docker on any host: make anodize-dev.iso
          dev-iso = self.nixosConfigurations.ceremony-dev-iso.config.system.build.isoImage;

          # nix build .#dev-iso-aarch64  →  dev ISO for Apple Silicon (aarch64).
          # Build this via Docker on any host: make anodize-dev-aarch64.iso
          dev-iso-aarch64 = self.nixosConfigurations.ceremony-dev-iso-aarch64.config.system.build.isoImage;

          # nix build .#proddbg-iso  →  debug ISO with SSH/DHCP for hardware iteration.
          # Build this via Docker on any host: make anodize-proddbg.iso
          proddbg-iso = self.nixosConfigurations.ceremony-proddbg-iso.config.system.build.isoImage;

          # nix build .#cdemu-iso  →  dev ISO with dev-softhsm-usb + cdemu BD-R.
          # Build this via Docker on any host: make anodize-cdemu.iso
          cdemu-iso = self.nixosConfigurations.ceremony-cdemu-iso.config.system.build.isoImage;
        };

        # Development shell — Rust toolchain comes from rustup (rust-toolchain.toml).
        # Nix provides the supporting tools so the host stays clean.
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            cargo-deny
            softhsm
            opensc
          ];
          # Mirror the ISO allowlist so developers exercise the module check
          # locally. Only SoftHSM2 is listed; add yubihsm-shell entries if
          # you plug a YubiHSM into your dev machine.
          SOFTHSM2_MODULE        = "${pkgs.softhsm}/lib/softhsm/libsofthsm2.so";
          ANODIZE_PKCS11_MODULES = "${pkgs.softhsm}/lib/softhsm/libsofthsm2.so";
        };
      }
    )

    # ---------------------------------------------------------------------------
    # NixOS configuration for the bootable ceremony ISO
    # ---------------------------------------------------------------------------
    // {
      nixosConfigurations.ceremony-iso = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";

        # Pass the compiled ceremony binary into the NixOS module.
        specialArgs = {
          anodize-ceremony = self.packages.x86_64-linux.anodize-ceremony;
          serialPort = "ttyS0";
        };

        modules = [
          "${nixpkgs}/nixos/modules/installer/cd-dvd/iso-image.nix"
          ./nix/iso.nix
          {
            # Pin the NixOS revision to the git commit so the system closure
            # is identical across builds from the same commit.
            system.nixos.revision = nixpkgs.lib.mkForce (self.rev or "dirty-tree");
          }
        ];
      };

      # cdemu ISO: dev-softhsm-usb binary + real SG_IO path.
      # Optical writes go through cdemu SCSI generic passthrough (real MMC commands).
      nixosConfigurations.ceremony-cdemu-iso = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";

        specialArgs = {
          anodize-ceremony = self.packages.x86_64-linux.anodize-ceremony-cdemu;
          serialPort = "ttyS0";
          inherit cdemu-src;
        };

        modules = [
          "${nixpkgs}/nixos/modules/installer/cd-dvd/iso-image.nix"
          ./nix/iso.nix
          ./nix/cdemu.nix
          {
            system.nixos.revision = nixpkgs.lib.mkForce (self.rev or "dirty-tree");
            image.fileName    = nixpkgs.lib.mkForce "anodize-cdemu";
            isoImage.volumeID = nixpkgs.lib.mkForce "ANODIZE-CDEMU";

            # Route kernel + early-userspace output to ttyS0 so the dev warning
            # printed by anodize-ceremony (before TUI raw mode) appears on serial.
            # console=tty0 keeps framebuffer output as well.
            boot.kernelParams = [ "console=ttyS0,115200" "console=tty0" ];

            environment.variables.ANODIZE_BUILD_TYPE = "dev";
          }
        ];
      };

      # Production debug ISO — real hardware support (YubiHSM 2) with DHCP
      # networking and SSH for remote iteration from a development workstation.
      # SSH as ceremony → sentinel menu.  SSH as root → bash shell.
      # Default password: anodize-debug (override via Crusoe/downstream branch).
      nixosConfigurations.ceremony-proddbg-iso = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";

        specialArgs = {
          anodize-ceremony = self.packages.x86_64-linux.anodize-ceremony;
          serialPort = "ttyS0";
        };

        modules = [
          "${nixpkgs}/nixos/modules/installer/cd-dvd/iso-image.nix"
          ./nix/iso.nix
          {
            system.nixos.revision = nixpkgs.lib.mkForce (self.rev or "dirty-tree");
            image.fileName    = nixpkgs.lib.mkForce "anodize-proddbg.iso";
            isoImage.volumeID = nixpkgs.lib.mkForce "ANODIZE-DBG";
            boot.kernelParams = [ "console=tty0" "console=ttyS0,115200" ];

            environment.variables.ANODIZE_BUILD_TYPE = "proddbg";

            # Extra tools for network debugging.
            environment.systemPackages = with nixpkgs.legacyPackages.x86_64-linux; [
              iproute2   # ip addr, ip route
              iputils    # ping
            ];

            # ── Network: DHCP on all discovered wired interfaces ──
            networking.useDHCP = nixpkgs.lib.mkForce true;

            # ── SSH: password auth for remote debugging ──
            services.openssh = {
              enable = nixpkgs.lib.mkForce true;
              settings = {
                PermitRootLogin = "yes";
                PasswordAuthentication = true;
              };
            };

            # ── Debug credentials ──
            # ceremony → sentinel menu, root → bash shell.
            users.users.ceremony.password = nixpkgs.lib.mkForce "anodize-debug";
            users.users.root = {
              hashedPassword = nixpkgs.lib.mkForce null;
              password = "anodize-debug";
            };
          }
        ];
      };

      # Development ISO for Apple Silicon Macs — runs at near-native speed via HVF.
      # aarch64 QEMU virt machine exposes a PL011 UART at ttyAMA0, not a 16550 at ttyS0.
      nixosConfigurations.ceremony-dev-iso-aarch64 = nixpkgs.lib.nixosSystem {
        system = "aarch64-linux";

        specialArgs = {
          anodize-ceremony = self.packages.aarch64-linux.anodize-ceremony-dev;
          serialPort = "ttyAMA0";
        };

        modules = [
          "${nixpkgs}/nixos/modules/installer/cd-dvd/iso-image.nix"
          ./nix/iso.nix
          {
            system.nixos.revision = nixpkgs.lib.mkForce (self.rev or "dirty-tree");
            image.fileName    = nixpkgs.lib.mkForce "anodize-dev-aarch64.iso";
            isoImage.volumeID = nixpkgs.lib.mkForce "ANODIZE-DEV-A64";

            # Single console so all output reaches ttyAMA0 (PL011 UART) in
            # QEMU nographic mode.
            boot.kernelParams = [ "console=ttyAMA0,115200" ];

            environment.variables.ANODIZE_BUILD_TYPE = "dev";
          }
        ];
      };
    };
}
