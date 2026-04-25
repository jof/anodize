{
  description = "Anodize — offline root CA ceremony tool";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";

    # Crane: incremental Rust builds with good workspace support.
    crane.url = "github:ipetkov/crane";
    crane.inputs.nixpkgs.follows = "nixpkgs";

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
      mkCargoArtifacts = system:
        (mkCraneLib system).buildDepsOnly (mkCommonArgs system);
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

        anodize = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname         = "anodize";
          version       = "0.1.0";
          cargoExtraArgs = "--package anodize-cli";
        });
      in
      {
        packages = {
          inherit anodize-ceremony anodize;
          default = anodize-ceremony;

          # nix build .#iso  →  bootable ceremony ISO image (x86_64-linux only).
          # Build this via Docker on any host: make nix-iso
          iso = self.nixosConfigurations.ceremony-iso.config.system.build.isoImage;
        };

        # Development shell — Rust toolchain comes from rustup (rust-toolchain.toml).
        # Nix provides the supporting tools so the host stays clean.
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            cargo-deny
            softhsm
            opensc
            act          # run GitHub Actions locally via Docker
          ];
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
        };

        modules = [
          "${nixpkgs}/nixos/modules/installer/cd-dvd/iso-image.nix"
          ./nix/iso.nix
        ];
      };
    };
}
