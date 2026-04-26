# Anodize

> An offline Rust root CA. Like aluminum's oxide layer, the rust *is* the protection.
> ("Anodize" — to deliberately oxidize for protection. Also: to make *not a node*.)

Anodize is a small, auditable root-CA tool written in Rust. It runs air-gapped from a verified live ISO on a laptop, talks to its signing key only through a PKCS#11 module, and produces byte-identical ISO builds via Nix.

## What it does

- Signs intermediate CA certificates from CSRs
- Issues CRLs
- Maintains a hash-chained audit log tied to the specific ceremony (genesis hash = SHA-256 of root cert DER)
- Records each CA operation as a timestamped session on a write-once optical disc (BD-R, DVD-R, or M-Disc)
- Runs offline — no network stack compiled into the ISO

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
- **Log genesis**: audit log `prev_hash[0]` = SHA-256(root_cert_DER) — ties the log to the specific root ceremony
- **CSR validation**: signature verified before any field is parsed
- **PIN source**: `pin_source = "prompt"` is the only safe value in ceremony; `env:` and `file:` variants emit a runtime warning
- **Clock check**: the TUI's first screen requires the operator to confirm the UTC system clock before any timestamped session is written to disc

## Optical disc archive format

Each CA operation appends one SAO session to the optical disc. Sessions accumulate — the disc stays open between ceremonies. Every session's ISO 9660 image contains timestamped subdirectories for all prior and current sessions (copy-in), so the last session is always the complete, browsable view from a standard OS mount:

```
Session 3 ISO (last written — what `mount` shows):
  /20260425T143000Z/    ← session 1: ROOT.CRT + AUDIT.LOG (1 entry)
  /20260426T091500Z/    ← session 2: ROOT.CRT + INTCA1.CRT + AUDIT.LOG (2 entries)
  /20260510T110000Z/    ← session 3: ROOT.CRT + INTCA2.CRT + AUDIT.LOG (3 entries)
```

All disc operations use SG_IO MMC ioctls — no external tools, no subprocesses.

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
│   ├── anodize-tui/              # ceremony binary: ratatui TUI, ships on ISO
│   │   └── src/media/            # ISO 9660 writer, SG_IO MMC, USB/optical discovery
│   └── anodize-cli/              # dev binary: clap subcommands, never on ISO
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

## CLI

```sh
anodize --profile profile.toml init
anodize --profile profile.toml sign-csr --csr int-ca.csr --root-cert root.crt \
        --cert-out int-ca.crt --log audit.log --path-len 0 --validity-days 1825
anodize --profile profile.toml issue-crl --root-cert root.crt \
        --crl-out root.crl --log audit.log --next-update-days 30
anodize --profile profile.toml verify-log audit.log
```

Every mutating command: loads profile → opens HSM → prompts PIN → performs op → appends signed audit record → prints fingerprint.

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
| 7 | Production hardening, threat model, runbooks | Ongoing |
