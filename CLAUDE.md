# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```sh
make test    # cargo test --all -- --test-threads=1
make lint    # cargo clippy --all-targets --all-features -- -D warnings
make fmt     # cargo fmt --all -- --check
make deny    # cargo deny check
make ci      # full CI job locally via act + Docker
```

```sh
# Build ceremony binary with dev features (never use in a real ceremony)
make build-dev

# ISO builds — Nix in Docker, first run 10–30 min, cached after
# Two types (prod / dev) × two architectures (amd64 / arm64)
make prod-amd64        # production ISO (YubiHSM + real optical drive)
make dev-amd64         # dev ISO (SoftHSM2 USB + cdemu inside the VM)
make dev-arm64         # dev ISO for Apple Silicon

# QEMU dev loop — requires dev ISO and fake shuttle; no host cdemu setup needed
make fake-shuttle.img          # 64 MiB FAT profile USB, SoftHSM2 token, PIN: 123456
make qemu-dev-nographic    # boot dev ISO amd64 (Ctrl-A X to quit)
make qemu-dev-sdl          # same with SDL graphics window
make qemu-aarch64          # boot dev ISO arm64 (Apple Silicon via HVF)
make qemu-nographic        # boot production ISO (no-graphics)
make ssh-dev               # SSH into running dev VM

# After a dev session, inspect the BD-R disc image on the host:
ls dev-disc/test-bdr.img
```

`--test-threads=1` is used in `make test` as a safe default. It is required for `anodize-hsm` and `anodize-ca` integration tests because `init_test_token()` uses a shared `target/test-softhsm/` directory (rm-rf + recreate). Pure-logic crates (`anodize-config`, `anodize-audit`) do not need it.

### Running a single test

```sh
cargo test -p anodize-hsm p384_keygen_sign_verify -- --test-threads=1
cargo test -p anodize-audit hash_chain_arithmetic   # no flag needed
```

### HSM integration tests

Tests in `crates/anodize-hsm/tests/softhsm_basic.rs` and `crates/anodize-ca/tests/ca_integration.rs` require:

```sh
export SOFTHSM2_MODULE=/usr/lib/softhsm/libsofthsm2.so
```

Each test calls `init_test_token(label)` which runs `softhsm2-util --init-token` and writes a config from `tests/softhsm-fixtures/softhsm2.conf.template` into `target/test-softhsm/`. If `SOFTHSM2_MODULE` is absent the tests print `SKIP` and return — they do not fail.

## Architecture

### Workspace structure

Five library crates plus one binary crate.

| Crate | Role | Status |
|---|---|---|
| `anodize-hsm` | PKCS#11 abstraction | Implemented |
| `anodize-ca` | X.509 cert/CRL/CSR | Implemented |
| `anodize-audit` | Hash-chained JSONL log | Implemented |
| `anodize-config` | TOML profile loader | Implemented |
| `anodize-tui` | Ceremony binary (ratatui) | Implemented |

### HSM abstraction layer (`anodize-hsm`)

The `Hsm` trait (`crates/anodize-hsm/src/lib.rs`) is the central seam. All signing happens inside the HSM; private key material never crosses into the process.

Two implementations:

- **`Pkcs11Hsm`**: opens a PKCS#11 module via `dlopen` at runtime (handled by `cryptoki::Pkcs11::new(path)`). Finds the token by label (not slot index — YubiHSM slot indices are unstable across USB reconnects). The same struct works against SoftHSM2 in dev and YubiHSM 2 in prod — only the module path in the config changes.

- **`HsmActor`**: `Pkcs11Hsm` is `!Sync` because `cryptoki::Session` holds a raw pointer. `HsmActor` resolves this by owning `Pkcs11Hsm` on a dedicated thread and forwarding all calls via `SyncSender<HsmRequest>` rendezvous channels. `HsmActor` is `Send + Sync` and is the type to use everywhere outside the HSM crate itself.

### X.509 signing bridge (`anodize-ca`)

`x509-cert`'s builder API requires a signer implementing `signature::Keypair + spki::DynSignatureAlgorithmIdentifier`. The bridge is `P384HsmSigner<H: Hsm>` in `crates/anodize-ca/src/lib.rs`:

- Constructed with a `KeyHandle` and a `p384::ecdsa::VerifyingKey` (parsed from `hsm.public_key_der()`)
- `try_sign(msg)` calls `hsm.sign(key, EcdsaSha384, msg)` → parses the 96-byte P1363 result → converts to DER via `p384::ecdsa::Signature::try_from(bytes)?.to_der()`
- No CRL builder exists in x509-cert 0.2; `issue_crl` manually constructs `TbsCertList`, signs its DER bytes, calls `to_bitstring()` on the `DerSignature`
- `sign_intermediate_csr` verifies the CSR self-signature before reading any fields

### Ceremony TUI (`anodize-tui`)

Two binaries ship on the ISO:

- **`anodize-ceremony`** (`src/main.rs`): ratatui TUI implementing the full 10-state ceremony state machine — `ClockCheck → WaitUsb → ProfileLoaded → EnterPin → WaitDisc → KeyAction → WritingIntent → CertPreview → BurningDisc → DiscDone → Done`. The disc-before-USB invariant is enforced structurally: the USB write step is only reachable from the `DiscDone` state.

- **`anodize-sentinel`** (`src/sentinel.rs`): terminal gatekeeper. Acquires an exclusive `flock` on `/run/anodize/ceremony.lock` before exec-ing the ceremony binary. Prevents concurrent ceremony runs across multiple TTYs. Offers power-off via `reboot(2)` with `CAP_SYS_BOOT`.

**Write-ahead log (WAL)**: before any HSM key operation, an intent session is committed to disc (`cert.root.intent` AUDIT.LOG entry anchored to SHA-256(profile.toml)). The HSM only signs after that disc commit succeeds. A half-burned session is detectable on resume; the ceremony must refuse to burn a second session to the same disc position.

**Media layer** (`src/media/`): pure-Rust ISO 9660 Level 2 writer (`iso9660.rs`), typed MMC/SCSI disc commands over SG_IO ioctl (`mmc.rs`, `sgdev.rs`), USB partition scanning via sysfs and `nix::mount` (`mod.rs`).

**Dev compile feature** (never enable in a real ceremony):
- `dev-softhsm-usb`: loads a SoftHSM2 token directory from the profile USB instead of the YubiHSM 2. The disc write path (SG_IO MMC via mmc.rs/sgdev.rs) is unchanged — dev testing uses cdemu SCSI generic passthrough so the real write code is exercised.
- Dev builds display a red "DEV BUILD" warning banner so production and dev environments are visually distinct

### Security invariants to preserve

- **Disc before USB**: no cert or CRL may be written to USB until the write-once optical disc commit succeeds. Enforce structurally in the TUI state machine — `DiscDone` is the only predecessor state to the USB write step.
- **Write-ahead log**: intent committed to disc before HSM key operation. A half-burned session is detectable on resume; the TUI must refuse to burn again at the same disc position.
- **Audit log genesis**: `prev_hash[0]` must be SHA-256(profile.toml bytes) — established as a WAL prerequisite before any key operation. Do not allow a configurable or zero genesis hash.
- **CSR policy**: verify the CSR signature before parsing any fields. Only copy a fixed extension allowlist (BasicConstraints, KeyUsage, SKID, AKID, CDP). Reject all others.
- **PIN source warning**: `pin_source = env:` or `file:` must emit a runtime warning; `prompt` is the only safe ceremony value.

## Development workflow

### QEMU dev loop

All TUI feature testing happens through QEMU + the cdemu dev ISO. `cargo test` covers library crate logic. There is no standalone CLI for ad-hoc HSM operations.

The cdemu dev ISO exercises the real SG_IO MMC disc write path (mmc.rs + sgdev.rs) via cdemu SCSI generic passthrough — the same code path used in production, unlike any USB-based substitute.

**One-time setup** (delete files to regenerate):

```sh
make fake-shuttle.img        # profile USB with SoftHSM2 token (dev PIN: 123456)
make dev-amd64           # dev ISO — first run is slow, cached after
# or: make dev-arm64     # for Apple Silicon
```

**Each dev session** (no host cdemu/vhba setup needed — runs inside the VM):

```sh
make qemu-dev-nographic       # Ctrl-A X to quit
# or
make qemu-dev-sdl             # SDL window
# Apple Silicon:
make qemu-aarch64             # near-native speed via HVF
```

**After a session**, inspect the BD-R image on your laptop:

```sh
ls -lh dev-disc/test-bdr.img
# isoinfo, cdemu (if installed), or anodize's own read path for analysis
```

The dev ISO runs `anodize-sentinel` on tty1 and ttyS0. Sentinel execs `anodize-ceremony` built with `dev-softhsm-usb`. The ceremony binary shows a red "DEV BUILD" banner. Inside the guest, vhba + cdemu-daemon start automatically and expose a blank BD-R as `/dev/sr0`.

### Tests as you go

Each new function or module gets a test in the same commit that introduces it — not deferred to later. Follow the pattern already established in `anodize-hsm`:

- **Unit tests** (`#[cfg(test)]` mod at the bottom of the source file) for pure logic: parsing, validation, error paths, hash-chain arithmetic.
- **Integration tests** (`crates/<name>/tests/`) for anything that crosses a crate boundary or talks to SoftHSM2. Mirror the softhsm fixture pattern from `crates/anodize-hsm/tests/softhsm_basic.rs` — `init_test_token(label)` + env-var skip guard.
- Negative tests matter here: malformed CSRs, corrupted audit log bytes, wrong PIN, path-len overflow. Add them alongside the happy-path test.

### Commit cadence

Commit when a coherent unit of functionality works and its tests pass — not at the end of a session. Natural boundaries:

- A new public function + its tests = one commit
- A complete module (e.g., all of `anodize-config`) = one commit
- A security invariant enforcement (e.g., CSR signature check before field parsing) = its own commit, clearly named

Run `make test && make lint` before each commit. Don't batch unrelated changes.

### `deny.toml`

License allow-list is strict. `RUSTSEC-2024-0436` (`paste` crate, transitive via `cryptoki`) is explicitly ignored as unmaintained-but-safe. Any new advisory ignores need a comment explaining why.
