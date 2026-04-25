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

`--test-threads=1` is mandatory: PKCS#11's `C_Initialize` is process-global and parallel test threads in the same binary will SIGSEGV.

### Running a single test

```sh
cargo test -p anodize-hsm p384_keygen_sign_verify -- --test-threads=1
```

### HSM integration tests

Tests in `crates/anodize-hsm/tests/softhsm_basic.rs` require two env vars:

```sh
export SOFTHSM2_MODULE=/usr/lib/softhsm/libsofthsm2.so
export SOFTHSM2_CONF=/path/to/softhsm2.conf
```

Each test calls `init_test_token(label)` which runs `softhsm2-util --init-token` and writes a config from `tests/softhsm-fixtures/softhsm2.conf.template` into `target/test-softhsm/`. If the env vars are absent the tests print `SKIP` and return — they do not fail.

## Architecture

### Workspace structure

Seven crates. The only ones with real implementations are `anodize-hsm` and the two binaries (currently `todo!()`). The rest are placeholders awaiting Phase 2–4.

| Crate | Role | Status |
|---|---|---|
| `anodize-hsm` | PKCS#11 abstraction | Implemented |
| `anodize-ca` | X.509 cert/CRL/CSR | Placeholder |
| `anodize-audit` | Hash-chained JSONL log | Placeholder |
| `anodize-config` | TOML profile loader | Placeholder |
| `anodize-tui` | Ceremony binary (ratatui) | Placeholder |
| `anodize-cli` | Dev binary (clap) | Placeholder |

### HSM abstraction layer (`anodize-hsm`)

The `Hsm` trait (`crates/anodize-hsm/src/lib.rs`) is the central seam. All signing happens inside the HSM; private key material never crosses into the process.

Two implementations:

- **`Pkcs11Hsm`**: opens a PKCS#11 module via `dlopen` at runtime (handled by `cryptoki::Pkcs11::new(path)`). Finds the token by label (not slot index — YubiHSM slot indices are unstable across USB reconnects). The same struct works against SoftHSM2 in dev and YubiHSM 2 in prod — only the module path in the config changes.

- **`HsmActor`**: `Pkcs11Hsm` is `!Sync` because `cryptoki::Session` holds a raw pointer. `HsmActor` resolves this by owning `Pkcs11Hsm` on a dedicated thread and forwarding all calls via `SyncSender<HsmRequest>` rendezvous channels. `HsmActor` is `Send + Sync` and is the type to use everywhere outside the HSM crate itself.

### X.509 signing bridge (to be built in Phase 2)

`x509-cert`'s builder API requires a signer implementing `signature::Keypair + spki::DynSignatureAlgorithmIdentifier`. The bridge is `P384HsmSigner<H: Hsm>`:

- Constructed with a `KeyHandle` and a `p384::ecdsa::VerifyingKey` (parsed from `hsm.public_key_der()`)
- `try_sign(msg)` calls `hsm.sign(key, EcdsaSha384, msg)` → parses the 96-byte P1363 result → converts to DER via `ecdsa::Signature::from_slice(bytes)?.to_der()`
- Requires the `builder` feature on `x509-cert` and the `der` feature on `ecdsa`

### Security invariants to preserve

- **Disc before USB**: in `anodize-tui`, no cert or CRL may be written to USB until M-Disc commit succeeds. Enforce structurally in the TUI state machine — the data must not exist on any writable path before the disc write.
- **Audit log genesis**: `prev_hash[0]` must be SHA-256(root_cert_DER). Do not allow a configurable or zero genesis hash.
- **CSR policy**: verify the CSR signature before parsing any fields. Only copy a fixed extension allowlist (BasicConstraints, KeyUsage, SKID, AKID, CDP). Reject all others.
- **PIN source warning**: `pin_source = env:` or `file:` must emit a runtime warning; `prompt` is the only safe ceremony value.

## Development workflow

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
