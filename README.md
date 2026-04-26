# Anodize

> An offline Rust root CA. Like aluminum's oxide layer, the rust *is* the protection.
> ("Anodize" — to deliberately oxidize for protection. Also: to make *not a node*.)

Anodize is a small, auditable root-CA tool written in Rust. It runs air-gapped from a verified live ISO on a laptop, talks to its signing key only through a PKCS#11 module, and produces byte-identical ISO builds via Nix.

## What it does

- Signs intermediate CA certificates from CSRs
- Issues CRLs
- Maintains a hash-chained audit log tied to the specific ceremony (genesis hash = SHA-256 of profile.toml bytes, established before the HSM key operation)
- Records each CA operation as a timestamped session on a write-once optical disc (BD-R, DVD-R, or M-Disc)
- Runs offline — no network stack compiled into the ISO
- Gates each physical terminal via `anodize-sentinel` — only one terminal can run the ceremony at a time; a second terminal shows an error and waits

## What it does not do

- Online CA, OCSP, ACME — out of scope
- Generic certificate management — intermediates handle day-to-day operations
- Web UI of any kind

## Hardware model

| Environment | HSM | Optical archive |
|---|---|---|
| Dev / CI | SoftHSM2 | `--skip-disc` flag; writes staging ISO to `/run/anodize/staging` |
| Production | YubiHSM 2 | BD-R or DVD-R in an optical drive (SG_IO SAO) |

The `Hsm` trait abstracts both HSM backends. The binary has no compile-time knowledge of which backend it will use.

## Security invariants

- **Disc before USB**: no certificate or CRL artifact reaches USB until it has been committed to a write-once optical disc (a full SG_IO SAO session burn). Enforced structurally in the TUI state machine — `DiscDone` is the only predecessor state to the USB write step.
- **Write-ahead log**: before any HSM key operation, an intent session (AUDIT.LOG with a `cert.root.intent` record anchored to SHA-256(profile.toml)) is committed to disc. The HSM only signs after that disc commit confirms. A signed cert cannot exist without a disc record of intent.
- **Log genesis**: audit log `prev_hash[0]` = SHA-256(profile.toml bytes) — established before the HSM key operation (WAL prerequisite); any stable operator-chosen byte sequence works as an anchor
- **CSR validation**: signature verified before any field is parsed
- **PIN source**: `pin_source = "prompt"` is the only safe value in ceremony; `env:` and `file:` variants emit a runtime warning
- **Clock check**: the TUI's first screen requires the operator to confirm the UTC system clock before any timestamped session is written to disc
- **Single-ceremony terminal**: `anodize-sentinel` acquires an exclusive flock before exec-ing the ceremony process; a second terminal cannot start a ceremony while one is already running

## Optical disc archive format

Each CA operation appends **two** SAO sessions to the optical disc: an intent session (written before the HSM key operation) followed by a cert session (written after). Sessions accumulate — the disc stays open between ceremonies. Every session's ISO 9660 image contains timestamped subdirectories for all prior and current sessions (copy-in), so the last session is always the complete, browsable view from a standard OS mount:

```
Session 4 ISO (last written — what `mount` shows):
  /20260425T143000Z-intent/    ← session 1: AUDIT.LOG (cert.root.intent, 1 entry)
  /20260425T143122Z/           ← session 2: ROOT.CRT + AUDIT.LOG (2-entry chain, references intent)
  /20260426T091500Z-intent/    ← session 3: AUDIT.LOG (signing intent for INTCA1)
  /20260426T091645Z/           ← session 4: ROOT.CRT + INTCA1.CRT + AUDIT.LOG (4-entry chain)
```

The disc capacity guard requires at least 2 sessions remaining before any key operation begins. Maximum sessions per media: CD-R = 99, DVD-R = 254, BD-R/M-Disc = 255.

All disc operations use SG_IO MMC ioctls — no external tools, no subprocesses. Rewritable media (CD-RW, DVD-RW, BD-RE) is rejected at insert time.

## Workspace layout

```
anodize/
├── Cargo.toml                    # workspace
├── flake.nix                     # Nix flake — reproducible build + ISO
├── rust-toolchain.toml           # pinned stable Rust
├── deny.toml                     # cargo-deny supply-chain policy
├── Makefile                      # dev shortcuts
├── crates/
│   ├── anodize-hsm/              # PKCS#11 abstraction — Hsm trait + cryptoki backend
│   ├── anodize-ca/               # X.509 cert/CRL generation, CSR validation
│   ├── anodize-audit/            # hash-chained JSONL audit log
│   ├── anodize-config/           # TOML profile loader (profile.toml)
│   └── anodize-tui/              # ceremony binary (anodize-ceremony) + terminal gatekeeper (anodize-sentinel), ship on ISO
│       └── src/media/            # ISO 9660 writer, SG_IO MMC, USB/optical discovery
├── nix/
│   └── iso.nix                   # NixOS module for the live image
├── tests/
│   └── softhsm-fixtures/         # softhsm2.conf template for integration tests
└── docs/
    ├── design.md                 # architecture and rationale
    ├── ceremony-init.md          # printable runbook: root ceremony
    └── ceremony-sign.md          # printable runbook: intermediate signing
```

## Development

```sh
# Prerequisites: softhsm2, rust (pinned via rust-toolchain.toml)
make test       # cargo test --all -- --test-threads=1
make lint       # cargo clippy -D warnings
make fmt        # cargo fmt --check

# HSM tests need env var:
export SOFTHSM2_MODULE=/usr/lib/softhsm/libsofthsm2.so
cargo test -p anodize-hsm

# ISO 9660 unit tests (no hardware required):
cargo test -p anodize-tui iso9660
```

### Dev features (never enable in a real ceremony)

Two compile-time features enable full end-to-end testing without optical hardware:

| Feature | Replaces |
|---|---|
| `dev-usb-disc` | Optical disc: scans for a FAT USB partition marked with `ANODIZE_DISC_ID`, reads/writes `ceremony.iso` in place of SG_IO SAO burns |
| `dev-softhsm-usb` | YubiHSM: reads a SoftHSM2 token directory from the profile USB partition |

```sh
# Set up a fake profile USB with an embedded SoftHSM2 token:
scripts/init-softhsm-usb.sh

make build-dev          # cargo build --features dev-usb-disc,dev-softhsm-usb
make fake-disc-usb.img  # 64 MiB FAT image pre-marked with ANODIZE_DISC_ID

# Boot the dev ISO in QEMU with both fake USB images attached:
make dev-iso            # build anodize-dev.iso (NixOS, dev features)
make qemu-dev           # QEMU SDL — fake-usb.img (profile) + fake-disc-usb.img (disc)
make qemu-dev-curses    # same but curses display
```

## Reproducible builds

`nix build .#iso` produces a bootable NixOS ISO. The Nix store is content-addressed, so two machines building from the same flake lock produce byte-identical images.

The ISO is intentionally minimal: no network drivers, no SSH, no package manager at runtime. It boots directly to the ceremony TUI. The binary auto-discovers USB sticks and optical drives — no arguments needed.

```sh
make nix-check      # nix build .#anodize-ceremony  (via act + Docker, same as make ci)
make nix-iso        # nix build .#iso               (nixos/nix image, --privileged, release-only)
```

## Status

| Phase | Description | Status |
|---|---|---|
| 0 | Bootstrap: workspace, CI, toolchain pin | Done |
| 1 | HSM abstraction + SoftHSM integration tests | Done |
| 2 | CA core: root cert, CSR signing, CRL | Done |
| 3 | Audit log: hash-chained JSONL | Done |
| 4 | CLI + ceremony TUI | Done |
| 5 | Live ISO (Nix flake, reproducible build) | Done |
| 6 | Self-managed disc lifecycle: SG_IO SAO, ISO 9660, internal USB mount | Done |
| 7 | Production hardening: WAL, sentinel, disc capacity guard, dev ISO | Ongoing |
