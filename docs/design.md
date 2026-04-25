# Anodize — Design Document

## Goals

1. A small, auditable root-CA tool written in Rust.
2. Runs from a verified live ISO on an air-gapped machine.
3. Talks to its signing key only through a **PKCS#11** module.
4. Tests against **SoftHSM2** in dev/CI; runs against a **YubiHSM 2** in production with no code changes — only a config swap.
5. Reproducible build of both the binary and the ISO.

## Non-goals

- Online CA, OCSP responder, ACME — out of scope. Anodize signs intermediates and CRLs only.
- Generic certificate management. Intermediates do the day-to-day work.
- A web UI of any kind.

---

## Architectural decisions

### Dynamic linking is required

PKCS#11 is a `dlopen`-at-runtime contract. The whole point of the abstraction is that the same binary loads `libsofthsm2.so` in dev and `yubihsm_pkcs11.so` in prod by changing a path in a config file. So:

- The Anodize binary is built against **musl** and linked statically *for everything except the C runtime's dynamic loader*. This gives a single self-contained ELF that still has `dlopen`.
- The ISO ships the PKCS#11 `.so` modules as separate files alongside the binary.
- A config file (or `--pkcs11-module` flag) selects which module to load.

`cryptoki` (the maintained PKCS#11 binding) handles the `dlopen` via `Pkcs11::new(path)`. Static linkage of the PKCS#11 module would defeat the whole swap-ability that motivates the abstraction.

### One binary, two profiles

The binary has no compile-time knowledge of the HSM backend. The operator (or the boot process) selects a profile:

```toml
# /media/usb/profile.toml
[ca]
common_name  = "Example Root CA"
organization = "Example Corp"
country      = "US"
cdp_url      = "http://crl.example.com/root.crl"

[hsm]
module_path  = "/usr/lib/softhsm/libsofthsm2.so"   # or yubihsm_pkcs11.so
token_label  = "anodize-root-2026"
key_label    = "root-key"
key_spec     = "ecdsa-p384"
pin_source   = "prompt"   # "prompt" | "env:ANODIZE_PIN" | "file:/run/anodize/pin"
```

### HsmActor for thread safety

PKCS#11's `C_Initialize` is process-global and `cryptoki`'s `Session` contains a raw pointer (`*mut u32`), making `Pkcs11Hsm` `!Sync`. The actor pattern resolves this without `unsafe`:

- `Pkcs11Hsm` is owned exclusively by a dedicated thread.
- `HsmActor` wraps it with `SyncSender<HsmRequest>` rendezvous channels.
- `HsmActor` is `Send + Sync` and can be shared freely across threads.

```
caller thread ──SyncSender<HsmRequest>──► hsm-actor thread (owns Pkcs11Hsm)
              ◄──SyncSender<Result<T>>───
```

### Two binaries

- **`anodize-ceremony`** (`anodize-tui` crate): ratatui TUI, ships on the ISO. All operator actions are numbered menu items. No shell exposed.
- **`anodize`** (`anodize-cli` crate): clap-based CLI for dev/CI only. Never included on the ISO.

### Disc before USB invariant

Every signed artifact (cert, CRL) is held in RAM after signing. The TUI commits the artifact to M-Disc (write-once archival optical) before writing to USB. The USB write step is only reachable in the TUI state machine after the disc write completes successfully. This is enforced structurally — the data is not on disk in any writable location until after M-Disc commit.

### Append-only signed audit log

Every operation appends a record to `audit.log`:

```
{ seq, timestamp, event, op_data, prev_hash, entry_hash }
```

- `prev_hash[0]` = SHA-256(root_cert_DER) — ties the log genesis to the specific root ceremony
- Each subsequent `prev_hash` = SHA-256(previous record's raw bytes)
- `entry_hash` = SHA-256(seq ‖ timestamp ‖ event ‖ op_data ‖ prev_hash)

Format: JSONL (one JSON object per line). JSON is chosen over CBOR for grep-ability; the file is never large.

`anodize verify-log` walks the file, recomputes hashes, and verifies that corrupting any single byte causes failure at exactly that record.

---

## The Hsm trait

The soft-vs-hard swap lives entirely behind this trait:

```rust
pub trait Hsm: Send {
    fn login(&mut self, pin: &SecretString) -> Result<()>;
    fn logout(&mut self) -> Result<()>;

    fn find_key(&self, label: &str) -> Result<KeyHandle>;
    fn generate_keypair(&mut self, label: &str, spec: KeySpec) -> Result<KeyHandle>;

    /// `data` is hashed-then-signed inside the HSM for ECDSA/RSA.
    /// Private key material never crosses this boundary.
    fn sign(&self, key: KeyHandle, mech: SignMech, data: &[u8]) -> Result<Vec<u8>>;

    /// Returns DER-encoded SubjectPublicKeyInfo.
    fn public_key_der(&self, key: KeyHandle) -> Result<Vec<u8>>;
}
```

Implementations:
- `Pkcs11Hsm` — production + dev. One backend covers SoftHSM2 and YubiHSM 2.
- `HsmActor` — `Send + Sync` wrapper via actor thread (see above).

### X.509 signing bridge

The x509-cert builder requires a signer that implements `signature::Keypair` + `spki::DynSignatureAlgorithmIdentifier`. We bridge the `Hsm` trait to these via `P384HsmSigner<H: Hsm>`:

- Stores a `p384::ecdsa::VerifyingKey` (parsed from `hsm.public_key_der()` at construction time).
- `try_sign(msg)` calls `hsm.sign(key, EcdsaSha384, msg)` → parses the 96-byte P1363 result → converts to DER-encoded `ecdsa::der::Signature<NistP384>`.
- P1363 → DER: `ecdsa::Signature::from_slice(bytes)?.to_der()`

The HSM signs hash-then-sign via `CKM_ECDSA_SHA384`; the raw message bytes are passed to `sign()`.

---

## Crate selections and rationale

| Need | Crate | Rationale |
|---|---|---|
| PKCS#11 | `cryptoki 0.7` | Maintained, real `dlopen`, production-proven |
| X.509 building | `x509-cert 0.2` + `der 0.7` + `spki 0.7` | More control than `rcgen`. We construct the TbsCertificate and hand bytes to the HSM for signing. `rcgen` wants to own the signing key — we can't allow that. |
| ECDSA | `p384 0.13` with `ecdsa`, `pkcs8` features | Verification in tests; VerifyingKey from SPKI DER for HsmSigner |
| DER signature | `ecdsa` with `der` feature | `ecdsa::der::Signature<C>` for X.509 builder; `From<ecdsa::Signature<C>>` for P1363→DER |
| CRL | `x509-cert::crl` | Same RustCrypto family |
| CLI | `clap 4` derive | Standard |
| Config | `serde` + `toml` | Standard |
| Secrets | `secrecy 0.8` | `SecretString` for PINs, zeroizes on drop |
| Audit hashing | `sha2 0.10` | SHA-256. More boring than BLAKE3 — that's good for a CA |
| Logging | `tracing 0.1` + `tracing-subscriber` | Plain text on console; audit log is separate |
| Errors | `thiserror 2` in libs, `anyhow 1` in binaries | |
| Audit serialization | `serde_json` | JSONL audit records |

---

## Algorithm decisions

- **Default algorithm**: ECDSA P-384. Safer enterprise pick than Ed25519 for relying-party compatibility. YubiHSM 2 supports it. SoftHSM2 supports it.
- **Root validity**: 20 years. Hardcoded constant — not a config value. Pick once.
- **Signature format**: P1363 from HSM (`r ‖ s`, 96 bytes for P-384), converted to DER-encoded `ECDSA-Sig-Value` for embedding in X.509.
- **Token identification**: by label, not slot index. YubiHSM slot indices are unstable across USB reconnects.

---

## CSR policy (Phase 2)

Conservative by default. When signing a CSR to produce an intermediate:

- CSR signature is verified before any field is parsed.
- Only these extensions are copied or generated:
  - `BasicConstraints`: CA:TRUE, `pathLen` from CLI argument
  - `KeyUsage`: `keyCertSign | cRLSign` (hardcoded)
  - `SubjectKeyIdentifier`: computed from SPKI
  - `AuthorityKeyIdentifier`: from root
  - `CRLDistributionPoints`: from `[ca].cdp_url` in profile
- All other extensions from the CSR are rejected.
- Oversized fields, unusual OIDs, and path-length overflow are explicitly tested.

---

## Reproducible builds

### Why reproducible

Reproducibility means that any party with the same source revision can independently verify that the ISO they receive matches what was built — no hidden modifications possible in the build system.

### How

The ISO is built with **Nix** (`nix/flake.nix`). The Nix store is content-addressed: every package is identified by a cryptographic hash of its inputs (source + build recipe + all transitive dependencies). Two machines building the same flake lock file produce byte-identical outputs.

`nix build .#iso` outputs:
- `anodize-YYYYMMDD.iso`
- `anodize-YYYYMMDD.iso.sha256`
- `anodize-YYYYMMDD.iso.sig` (detached signature)

The commit hash → ISO hash mapping is documented in releases.

### ISO constraints

The ISO is intentionally minimal. These properties are enforced in `nix/iso.nix`:

```nix
networking.useDHCP = false;
networking.interfaces = {};          # no network stack at runtime
boot.kernelParams = [ "quiet" "ro" ];
fileSystems."/".options = [ "ro" ];  # read-only root
boot.tmpOnTmpfs = true;              # ephemeral state only in RAM
```

Packages included:
- `anodize-ceremony` (the TUI binary)
- `softhsm2` (dev/testing)
- `opensc` + `yubihsm-shell` (prod)
- No SSH, no package manager, no shell for the operator

The operator interaction surface is entirely the numbered ratatui TUI menu.

---

## Phased implementation plan

### Phase 0 — Bootstrap (done)
- Cargo workspace, 7-crate skeleton
- `rust-toolchain.toml` pinned to stable
- `deny.toml` for supply-chain policy
- CI: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`, `cargo deny check`
- Makefile

### Phase 1 — HSM abstraction (done)
- `anodize-hsm`: `Hsm` trait, `Pkcs11Hsm`, `HsmActor`
- `softhsm2.conf.template` fixture
- Integration tests: generate P-384 keypair, sign, verify signature with `p384` crate

### Phase 2 — CA core (in progress)
- `anodize-config`: parse `profile.toml`, `PinSource` variants
- `anodize-ca`: `build_root_cert`, `sign_csr`, `issue_crl`
- `P384HsmSigner` bridging `Hsm` to x509-cert builder
- End-to-end verified with `openssl verify` / `step certificate verify`

### Phase 3 — Audit log
- `anodize-audit`: `Record` struct, JSONL append, `verify-log` walker
- Genesis `prev_hash` = SHA-256(root_cert_DER)
- Corruption test: single-byte flip causes failure at correct record

### Phase 4 — CLI + ceremony TUI
- `anodize-cli`: wire all crates, clap subcommands, confirmation prompts
- `anodize-tui`: ratatui ceremony menu, disc-before-USB state machine
- Printable fingerprints at each step
- Runbooks: `docs/ceremony-init.md`, `docs/ceremony-sign.md`

### Phase 5 — Live ISO
- `nix/flake.nix` + `nix/iso.nix`
- Minimal NixOS: no network, read-only root, tmpfs, udev for YubiHSM USB
- Reproducible: `nix build .#iso` is byte-identical across machines
- udev rule: `SUBSYSTEM=="usb", ATTR{idVendor}=="1050", MODE="0660", GROUP="wheel"`

### Phase 6 — Production hardening (ongoing)
- `cargo-deny` + `cargo-vet` in CI
- Reproducible binary builds documented (commit hash → ISO hash)
- Tabletop key-compromise drill: revoke intermediate, issue CRL, distribute
- `docs/threat-model.md`: honest accounting of what Anodize does not protect against

---

## Open questions (tracked)

1. **Key backup**: YubiHSM wrapped-export to a second YubiHSM. M-of-N custodians for the wrap key? How many devices? Policy question, but shapes the `init` ceremony runbook.
2. **CRL hosting**: Anodize generates the CRL; something else hosts it. The URL must be committed at intermediate-signing time in the CDP extension — needs an answer before Phase 2 ships.
3. **Entropy on the ISO**: `jitterentropy` + hardware TRNG. Confirm the target hardware has a TRNG the kernel will use.

---

## Threat model (stub — Phase 6)

Where Anodize does *not* protect you:

- **Ceremony discipline**: an operator who ignores the paper checklist can make errors that no software can catch
- **ISO build host**: if the machine running `nix build` is compromised, the ISO may be too — reproducibility lets you verify against an independent build, not against a trusted build host
- **Physical security**: a stolen YubiHSM with a known PIN is a compromised root
- **Supply chain on dependencies**: `cargo-deny` + `cargo-vet` reduce but don't eliminate this
