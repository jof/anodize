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
  };

  outputs = { self, nixpkgs, crane, rust-overlay, flake-utils }:
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

        # dev-usb-disc + dev-softhsm-usb: USB sticks for disc and HSM in dev/QEMU.
        # For development and testing only — never ship in a real ceremony ISO.
        anodize-ceremony-dev = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname         = "anodize-ceremony";
          version       = "0.1.0";
          cargoExtraArgs = "--package anodize-tui --features dev-usb-disc,dev-softhsm-usb";
        });

      in
      {
        packages = {
          inherit anodize-ceremony anodize-ceremony-dev;
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

      # Dev ISO: same NixOS configuration but with the dev-usb-disc binary.
      # Uses USB sticks instead of M-Disc optical writes for development testing.
      nixosConfigurations.ceremony-dev-iso = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";

        specialArgs = {
          anodize-ceremony = self.packages.x86_64-linux.anodize-ceremony-dev;
          serialPort = "ttyS0";
        };

        modules = [
          "${nixpkgs}/nixos/modules/installer/cd-dvd/iso-image.nix"
          ./nix/iso.nix
          {
            system.nixos.revision = nixpkgs.lib.mkForce (self.rev or "dirty-tree");
            # Distinguish the dev ISO from the production ISO by name.
            isoImage.isoName = nixpkgs.lib.mkForce "anodize-dev";
            isoImage.volumeID = nixpkgs.lib.mkForce "ANODIZE-DEV";

            # Route kernel + early-userspace output to ttyS0 so the dev warning
            # printed by anodize-ceremony (before TUI raw mode) appears on serial.
            # console=tty0 keeps framebuffer output as well.
            boot.kernelParams = [ "console=ttyS0,115200" "console=tty0" ];

            environment.variables.ANODIZE_BUILD_TYPE = "dev";
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
