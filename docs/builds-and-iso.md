# Builds & ISO

Anodize produces a bootable NixOS live ISO. The ISO is reproducible: any party with the same source revision and flake lock file can independently rebuild and verify byte-for-byte identity.

---

## Nix flake structure

The build is driven by `flake.nix` at the workspace root:

| Input | Purpose |
|---|---|
| `nixpkgs` (nixos-25.11) | Base packages |
| `crane` | Incremental Rust builds with workspace support |
| `rust-overlay` | Pins Rust toolchain to `rust-toolchain.toml` |
| `flake-utils` | Per-system outputs |
| `cdemu-src` | Custom cdemu fork with multi-session recording fixes (dev ISO only) |

The Rust toolchain is pinned via `rust-bin.fromRustupToolchainFile ./rust-toolchain.toml` and `crane.mkLib` is overridden to use this exact toolchain.

---

## Build targets

No Nix installation is required on the developer's host. Builds run in Docker:

```sh
make nix-check      # nix build .#anodize-ceremony (via Docker)
make nix-iso        # nix build .#iso (NixOS ISO, --privileged, release-only)
make dev-amd64      # nix build .#dev-iso-amd64 (dev ISO with SoftHSM + cdemu)
make dev-arm64      # nix build .#dev-iso-arm64
```

For release:
- `anodize-YYYYMMDD.iso`
- `anodize-YYYYMMDD.iso.sha256`
- `anodize-YYYYMMDD.iso.sig` (detached signature)

The commit hash → ISO hash mapping is documented in releases.

---

## Production ISO constraints

The ISO is intentionally minimal. These properties are enforced in `nix/iso.nix`:

```nix
networking.useDHCP = false;
networking.interfaces = {};          # no network stack at runtime
boot.kernelParams = [ "quiet" "ro" ];
fileSystems."/".options = [ "ro" ];  # read-only root
boot.tmpOnTmpfs = true;              # ephemeral state only in RAM
```

### Packages included

- `anodize-ceremony` — the TUI binary
- `anodize-sentinel` — terminal gatekeeper (auto-login on all TTYs)
- `libusb1` — USB HID access for YubiHSM 2 native backend

### Packages excluded

- No SSH daemon
- No package manager
- No shell for the operator
- No network tools

The operator interaction surface is entirely the numbered ratatui TUI menu.

---

## Dev ISO

The dev ISO (`nix/dev-iso.nix`) adds tools for testing:

| Package | Purpose |
|---|---|
| `softhsm2` | PKCS#11 HSM for dev/CI |
| `opensc` | `pkcs11-tool` for HSM diagnostics |
| `sg3_utils` | `sg_inq`, `sg_raw` for optical disc debugging |
| `cdemu` (custom fork) | SCSI generic passthrough for virtual BD-R |
| `openssh` | Debug SSH access (ceremony user + debug user) |

### Dev ISO features

- **SSH access**: `ceremony` user (drops into sentinel), `debug` user (shell).
- **cdemu BD-R persistence**: `cdemu-load-bdr` service loads/creates virtual disc at boot.
- **SoftHSM token persistence**: tokens stored on the shuttle image, surviving unmount/remount.
- **`--skip-disc` flag**: bypass optical disc operations for faster iteration.
- **`dev-softhsm-usb` feature**: enables dev paths for SoftHSM token location.

---

## CI pipeline

GitHub Actions (`.github/workflows/ci.yml`):

```
cargo fmt --check
cargo clippy --all-targets
cargo test --workspace
cargo deny check
make nix-check         # Nix build of ceremony binary
```

The CI pipeline uses the same Docker/Nix build path as local development. `cargo-deny` enforces license and advisory policies. `cargo-vet` tracks audit status of crate versions.

---

## Reproducibility

The Nix store is content-addressed: every package is identified by a cryptographic hash of its inputs (source + build recipe + all transitive dependencies). Given the same flake lock file:

1. Two machines produce **byte-identical** derivation hashes.
2. The resulting ISO is deterministic.
3. An auditor can compare their local build against the distributed ISO.

Verification:
```sh
sha256sum --check anodize-YYYYMMDD.iso.sha256
gpg --verify anodize-YYYYMMDD.iso.sig anodize-YYYYMMDD.iso
```

---

## QEMU testing

```sh
make qemu-dev                # launch local QEMU with dev ISO
make qemu-dev-nographic      # headless (for CI)
make ssh-dev                 # SSH to ceremony user (local)
make ssh-dev-debug           # SSH to debug user (local)
make ssh-vm                  # SSH to remote VM (DEV_VM_IP)
make ssh-vm-debug            # debug shell on remote VM
make cdemu-swap-disc         # swap cdemu BD-R during MigrateDisc (remote)
make cdemu-swap-disc-local   # same, local QEMU
```

---

## Related documents

- **[Architecture](architecture.md)** — crate structure
- **[E2E Test Plan](e2e-test-plan.md)** — full ceremony lifecycle testing
- **[Multi-Session Test](ceremony-multisession-test.md)** — cross-reboot validation
