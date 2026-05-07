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

        # Dev binary: SoftHSM2 on profile USB replaces YubiHSM2 in dev/QEMU.
        # Exercises the real SG_IO MMC disc path via cdemu SCSI passthrough.
        # For development and testing only — never ship in a production ISO.
        anodize-ceremony-dev = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname         = "anodize-ceremony";
          version       = "0.1.0";
          cargoExtraArgs = "--package anodize-tui --features dev-softhsm-usb";
        });

      in
      {
        packages = {
          inherit anodize-ceremony anodize-ceremony-dev;
          default = anodize-ceremony;

          # Two image types (prod / dev) × two architectures (amd64 / arm64).
          # Build via Docker on any host: make prod-amd64, make dev-arm64, etc.
          prod-amd64 = self.nixosConfigurations.ceremony-prod-amd64.config.system.build.isoImage;
          prod-arm64 = self.nixosConfigurations.ceremony-prod-arm64.config.system.build.isoImage;
          dev-amd64  = self.nixosConfigurations.ceremony-dev-amd64.config.system.build.isoImage;
          dev-arm64  = self.nixosConfigurations.ceremony-dev-arm64.config.system.build.isoImage;
        };

        # Development shell — Rust toolchain comes from rustup (rust-toolchain.toml).
        # Nix provides the supporting tools so the host stays clean.
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            cargo-deny
            softhsm
            opensc
          ];
          # SoftHSM backend reads this env var to locate the PKCS#11 library.
          SOFTHSM2_MODULE = "${pkgs.softhsm}/lib/softhsm/libsofthsm2.so";
        };
      }
    )

    # ---------------------------------------------------------------------------
    # NixOS ISO configurations — prod (locked-down) and dev (feature-rich)
    #
    # Prod: no network, no SSH, no cdemu, no debug tools.
    # Dev:  cdemu (virtual BD-R), SSH, DHCP, 9p share, diagnostic tools.
    # ---------------------------------------------------------------------------
    // {
      # ── Production ISOs ──────────────────────────────────────────────────────

      nixosConfigurations.ceremony-prod-amd64 = nixpkgs.lib.nixosSystem {
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
            image.fileName = nixpkgs.lib.mkForce "anodize-prod-amd64";
          }
        ];
      };

      nixosConfigurations.ceremony-prod-arm64 = nixpkgs.lib.nixosSystem {
        system = "aarch64-linux";

        specialArgs = {
          anodize-ceremony = self.packages.aarch64-linux.anodize-ceremony;
          serialPort = "ttyAMA0";
        };

        modules = [
          "${nixpkgs}/nixos/modules/installer/cd-dvd/iso-image.nix"
          ./nix/iso.nix
          {
            system.nixos.revision = nixpkgs.lib.mkForce (self.rev or "dirty-tree");
            image.fileName    = nixpkgs.lib.mkForce "anodize-prod-arm64";
            isoImage.volumeID = nixpkgs.lib.mkForce "ANODIZE-PROD-A64";

            # aarch64 QEMU virt machine exposes a PL011 UART at ttyAMA0.
            boot.kernelParams = [ "console=ttyAMA0,115200" ];
          }
        ];
      };

      # ── Development ISOs ─────────────────────────────────────────────────────
      # Built with dev-softhsm-usb so SoftHSM2 on the profile USB replaces
      # YubiHSM2.  cdemu provides virtual BD-R via SCSI generic passthrough.

      nixosConfigurations.ceremony-dev-amd64 = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";

        specialArgs = {
          anodize-ceremony = self.packages.x86_64-linux.anodize-ceremony-dev;
          serialPort = "ttyS0";
          inherit cdemu-src;
        };

        modules = [
          "${nixpkgs}/nixos/modules/installer/cd-dvd/iso-image.nix"
          ./nix/iso.nix
          ./nix/dev-iso.nix
          {
            system.nixos.revision = nixpkgs.lib.mkForce (self.rev or "dirty-tree");
            image.fileName    = nixpkgs.lib.mkForce "anodize-dev-amd64";
            isoImage.volumeID = nixpkgs.lib.mkForce "ANODIZE-DEV-AMD";

            boot.kernelParams = [ "console=ttyS0,115200" "console=tty0" ];

            environment.variables.ANODIZE_BUILD_TYPE = "dev";
          }
        ];
      };

      nixosConfigurations.ceremony-dev-arm64 = nixpkgs.lib.nixosSystem {
        system = "aarch64-linux";

        specialArgs = {
          anodize-ceremony = self.packages.aarch64-linux.anodize-ceremony-dev;
          serialPort = "ttyAMA0";
          inherit cdemu-src;
        };

        modules = [
          "${nixpkgs}/nixos/modules/installer/cd-dvd/iso-image.nix"
          ./nix/iso.nix
          ./nix/dev-iso.nix
          {
            system.nixos.revision = nixpkgs.lib.mkForce (self.rev or "dirty-tree");
            image.fileName    = nixpkgs.lib.mkForce "anodize-dev-arm64";
            isoImage.volumeID = nixpkgs.lib.mkForce "ANODIZE-DEV-A64";

            # aarch64 QEMU virt machine exposes a PL011 UART at ttyAMA0.
            boot.kernelParams = [ "console=ttyAMA0,115200" ];

            environment.variables.ANODIZE_BUILD_TYPE = "dev";
          }
        ];
      };
    };
}
