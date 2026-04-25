# Anodize

> An offline Rust root CA. Like aluminum's oxide layer, the rust *is* the protection.
> ("Anodize" — to deliberately oxidize for protection. Also: to make *not a node*.)

Anodize is a small, auditable root-CA tool written in Rust. It runs air-gapped from a verified live ISO on a laptop, talks to its signing key only through a PKCS#11 module, and produces byte-identical ISO builds via Nix.

## What it does

- Signs intermediate CA certificates from CSRs
- Issues CRLs
- Maintains a hash-chained audit log tied to the specific ceremony (genesis hash = SHA-256 of root cert DER)
- Runs offline — no network stack compiled into the ISO

## What it does not do

- Online CA, OCSP, ACME — out of scope
- Generic certificate management — intermediates handle day-to-day operations
- Web UI of any kind

## Hardware model

| Environment | HSM | How |
|---|---|---|
| Dev / CI | SoftHSM2 | `SOFTHSM2_MODULE` + `SOFTHSM2_CONF` env vars |
| Production | YubiHSM 2 | config swap, same binary |

The `Hsm` trait abstracts both. The binary has no compile-time knowledge of which backend it will use.

## Security invariants

- **Disc before USB**: no certificate or CRL artifact reaches USB until it has been committed to M-Disc (write-once archival optical)
- **Log genesis**: audit log `prev_hash[0]` = SHA-256(root_cert_DER) — ties the log to the specific root ceremony
- **CSR validation**: signature verified before any field is parsed
- **PIN source**: `pin_source = "prompt"` is the only safe value in ceremony; `env:` and `file:` variants emit a runtime warning

## Workspace layout

```
anodize/
├── Cargo.toml                    # workspace (7 crates)
├── rust-toolchain.toml           # pinned stable Rust
├── deny.toml                     # cargo-deny supply-chain policy
├── Makefile                      # dev shortcuts
├── crates/
│   ├── anodize-hsm/              # PKCS#11 abstraction — Hsm trait + cryptoki backend
│   ├── anodize-ca/               # X.509 cert/CRL generation, CSR validation
│   ├── anodize-audit/            # hash-chained JSONL audit log
│   ├── anodize-config/           # TOML profile loader (profile.toml)
│   ├── anodize-tui/              # ceremony binary: ratatui TUI, ships on ISO
│   └── anodize-cli/              # dev binary: clap subcommands, never on ISO
├── nix/
│   ├── flake.nix                 # reproducible build + ISO (planned Phase 5)
│   ├── iso.nix                   # NixOS module for the live image
│   └── anodize.nix               # package definition
├── tests/
│   └── softhsm-fixtures/         # softhsm2.conf template for integration tests
└── docs/
    ├── design.md                 # architecture and rationale
    ├── ceremony-init.md          # printable runbook: root ceremony
    ├── ceremony-sign.md          # printable runbook: intermediate signing
    └── threat-model.md           # honest threat model
```

## Development

```sh
# Prerequisites: softhsm2, rust (pinned via rust-toolchain.toml)
make test       # cargo test --all -- --test-threads=1

# HSM tests need env vars:
export SOFTHSM2_MODULE=/usr/lib/softhsm/libsofthsm2.so
export SOFTHSM2_CONF=/path/to/softhsm2.conf
cargo test -p anodize-hsm
```

## CLI (planned Phase 4)

```
anodize init        --profile root.toml [--key-spec ecdsa-p384]
anodize show        --profile root.toml
anodize sign-csr    --profile root.toml --csr int-ca.csr --out int-ca.crt \
                    --validity 5y --path-len 0
anodize revoke      --profile root.toml --serial 0x... --reason key-compromise
anodize gen-crl     --profile root.toml --out anodize.crl --next-update 90d
anodize export-pubkey --profile root.toml --out root.pub
anodize verify-log  --profile root.toml --log audit.log
```

Every mutating command: loads profile → opens HSM → prompts PIN → verifies audit log tail → performs op → appends signed record → prints fingerprint for operator to record on paper.

## Reproducible builds

`nix build .#iso` produces a bootable NixOS ISO. The Nix store is content-addressed, so two machines building from the same flake lock produce byte-identical images. The output includes `anodize-YYYYMMDD.iso`, a `.sha256`, and a detached signature over both.

The ISO is intentionally minimal: no network drivers, no SSH, no package manager at runtime. It boots to a ratatui TUI that exposes only numbered ceremony menu items — no shell access for the operator.

## Status

| Phase | Description | Status |
|---|---|---|
| 0 | Bootstrap: workspace, CI, toolchain pin | Done |
| 1 | HSM abstraction + SoftHSM integration tests | Done |
| 2 | CA core: root cert, CSR signing, CRL | In progress |
| 3 | Audit log: hash-chained JSONL | Planned |
| 4 | CLI + ceremony TUI | Planned |
| 5 | Live ISO (Nix flake, reproducible build) | Planned |
| 6 | Production hardening, threat model, runbooks | Planned |
