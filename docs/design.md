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
- `HsmActor` is `Send + Sync + Clone`. Cloning gives a second handle to the same session — all requests are serialised on the actor thread, so sharing is safe.

```
caller thread ──SyncSender<HsmRequest>──► hsm-actor thread (owns Pkcs11Hsm)
              ◄──SyncSender<Result<T>>───
```

### Multiple Pkcs11Hsm instances

`C_Initialize` returns `CKR_CRYPTOKI_ALREADY_INITIALIZED` when called a second time in the same process. `Pkcs11Hsm::new` treats this as success — the library is already running and the new context can issue C-level calls normally. This allows unit tests and binaries that create more than one `Pkcs11Hsm` (e.g., opening two different tokens) to work without special handling.

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
- `HsmActor` — `Send + Sync + Clone` wrapper via actor thread (see above).

`KeyHandle` stores both `priv_handle` and `pub_handle: Option<ObjectHandle>`. Storing the public key handle directly from `generate_key_pair` avoids a label-based object search that fails on some SoftHSM2 builds.

### X.509 signing bridge

The x509-cert builder requires a signer that implements `signature::Keypair` + `spki::DynSignatureAlgorithmIdentifier`. We bridge the `Hsm` trait to these via `P384HsmSigner<H: Hsm>`:

- Stores a `p384::ecdsa::VerifyingKey` (parsed from `hsm.public_key_der()` at construction time).
- `try_sign(msg)` pre-hashes `msg` with SHA-384 in Rust, then calls `hsm.sign(key, EcdsaSha384, digest)` using raw `CKM_ECDSA`. The returned 96-byte P1363 result is converted to DER via `p384::ecdsa::Signature::try_from(bytes)?.to_der()`.

Pre-hashing in Rust rather than using `CKM_ECDSA_SHA384` is necessary because SoftHSM2 2.6.x (the Ubuntu package version) returns `CKR_MECHANISM_INVALID` for the combined hash-sign mechanism. `CKM_ECDSA` with a pre-computed digest works on both SoftHSM2 and YubiHSM 2.

### CRL construction

`x509-cert 0.2` has no `CrlBuilder`. `issue_crl` manually constructs `TbsCertList`, DER-encodes it, signs the raw bytes with `P384HsmSigner`, and assembles the final `CertificateList` structure. This is the same pattern the x509-cert builder uses internally for certificates.

`public_key_der` has a fallback path for `CKA_PUBLIC_KEY_INFO` returning empty (SoftHSM2 2.6.x on some builds): it reads `CKA_EC_PARAMS` and `CKA_EC_POINT` and assembles a DER SPKI manually.

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
- **Root validity**: configurable (`validity_days: u32` argument to `build_root_cert`). Ceremony tooling defaults to 7305 days (20 years).
- **Signature format**: pre-hash with SHA-384 in Rust; sign digest with raw `CKM_ECDSA`; result is 96-byte P1363 (`r ‖ s`), converted to DER-encoded `ECDSA-Sig-Value` for embedding in X.509.
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

The ISO is built with **Nix** (`flake.nix` at the workspace root). The Nix store is content-addressed: every package is identified by a cryptographic hash of its inputs (source + build recipe + all transitive dependencies). Two machines building the same flake lock file produce byte-identical outputs.

No Nix installation is required on the developer's host. Builds run in Docker:

```sh
make nix-check      # nix build .#anodize-ceremony  (via act + Docker, same as make ci)
make nix-iso        # nix build .#iso               (nixos/nix image, --privileged, release-only)
```

`nix build .#iso` outputs an ISO image. For release:
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

### Phase 2 — CA core (done)
- `anodize-config`: `Profile` / `CaConfig` / `HsmConfig` structs; `PinSource` with custom `Deserialize` for `"prompt"` / `"env:VAR"` / `"file:/path"`; runtime `tracing::warn` for non-`prompt` sources
- `anodize-ca`: `P384HsmSigner<H: Hsm>` bridging `Hsm` to x509-cert builder; `build_root_cert`, `sign_intermediate_csr` (CSR sig verified before field parsing, extension allowlist enforced, all others rejected), `issue_crl`
- SoftHSM2 integration tests: `build_root_cert_roundtrip`, `sign_csr_happy_path`, `csr_with_extra_extension_rejected`, `issue_crl_encodes_revoked_serials`

### Phase 3 — Audit log (done)
- `anodize-audit`: `Record` struct, JSONL append, `AuditLog::create/open/append`, `verify_log` free function
- `genesis_hash(root_cert_der)` = SHA-256(root cert DER) — ties genesis to the specific ceremony
- Corruption test: single-byte flip detected at correct record index

### Phase 4 — CLI + ceremony TUI (done)
- `anodize-cli` (`anodize` binary): clap subcommands `init`, `sign-csr`, `issue-crl`, `verify-log`; resolves PIN from `PinSource` (prompt / env / file); prints SHA-256 fingerprint after each signing operation; appends an audit record on every CA operation
- `anodize-tui` (`anodize-ceremony` binary): ratatui ceremony wizard with six screens (Welcome → EnterPin → KeyAction → CertPreview → DiscDone → Done); disc-before-USB invariant enforced structurally — `do_write_usb()` is only reachable from the `DiscDone` match arm; cert DER held in RAM until disc write succeeds
- PIN input masked with random-length noise: display length ∈ [8, 20], independent of actual PIN length, refreshed on every keystroke. Prevents shoulder-surf length disclosure without requiring a CSPRNG — `SystemTime::now().subsec_nanos()` is sufficient for a human-visible display. Field shows 0 stars only when empty (confirms cleared), nonzero otherwise.
- Runbooks (`docs/ceremony-init.md`, `docs/ceremony-sign.md`): deferred to Phase 5

### Phase 5 — Live ISO (done)
- `flake.nix` (workspace root) + `nix/iso.nix`: Nix flake with `crane` + `rust-overlay` builds `anodize-ceremony` and `anodize` packages; `nix build .#iso` produces the bootable image
- Minimal NixOS ISO: no network stack, ephemeral tmpfs, read-only squashfs root; packages: `anodize-ceremony`, `softhsm`, `opensc`
- udev rule: `SUBSYSTEM=="usb", ATTR{idVendor}=="1050", MODE="0660", GROUP="wheel"` — grants ceremony user access to YubiHSM 2 without requiring root
- Auto-login → `anodize-ceremony` launches on tty1 via systemd service; no shell exposed to operator
- udisks2 automounts USB; launcher scans `/run/media/ceremony/*/profile.toml` and execs the TUI with the found profile
- Sample profile at `/etc/anodize/profile.example.toml` on the ISO
- **Builds run in Docker** (same philosophy as Rust CI): `make nix-check` runs the `nix` CI job via `act`; `make nix-iso` runs `nixos/nix` Docker image with `--privileged` for release ISO builds
- Runbooks: `docs/ceremony-init.md` (root key ceremony), `docs/ceremony-sign.md` (intermediate signing + CRL)

### Phase 6 — Production hardening (ongoing)
- `cargo-deny` + `cargo-vet` in CI
- Reproducible binary builds documented (commit hash → ISO hash)
- Tabletop key-compromise drill: revoke intermediate, issue CRL, distribute
- `docs/threat-model.md`: honest accounting of what Anodize does not protect against

---

## Open questions (tracked)

1. **Key backup**: YubiHSM wrapped-export to a second YubiHSM. M-of-N custodians for the wrap key? How many devices? Policy question, but shapes the `init` ceremony runbook.
2. ~~**CRL hosting**~~: Resolved — `cdp_url` is an optional field in `[ca]` config and passed explicitly to `sign_intermediate_csr`. The operator supplies the URL at signing time; Anodize embeds it in the CDP extension.
3. **Entropy on the ISO**: `jitterentropy` + hardware TRNG. Confirm the target hardware has a TRNG the kernel will use.

---

## Threat model (stub — Phase 6)

Where Anodize does *not* protect you:

- **Ceremony discipline**: an operator who ignores the paper checklist can make errors that no software can catch
- **ISO build host**: if the machine running `nix build` is compromised, the ISO may be too — reproducibility lets you verify against an independent build, not against a trusted build host
- **Physical security**: a stolen YubiHSM with a known PIN is a compromised root
- **Supply chain on dependencies**: `cargo-deny` + `cargo-vet` reduce but don't eliminate this
