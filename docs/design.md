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

### Two binaries (one crate)

Both binaries live in the `anodize-tui` crate and ship on the ISO:

- **`anodize-ceremony`**: ratatui TUI implementing the full ceremony state machine. All operator actions are numbered menu items. No shell exposed.
- **`anodize-sentinel`**: terminal gatekeeper. Acquires an exclusive `flock` before exec-ing the ceremony binary; prevents concurrent ceremony runs on multiple TTYs. Offers power-off via `reboot(2)`.

### No secrets on the terminal

**Design invariant**: sensitive values and secrets must never be printed to the terminal. This includes HSM PINs, raw private key material, wrap keys, and any intermediate secret used during signing.

Rationale:
- The ceremony shell runs inside `tmux` with a 50,000-line scrollback buffer. Any value that reaches the terminal persists in the scrollback until reboot.
- Future work will add `tmux pipe-pane` session logging for a complete audit trail of every terminal interaction. Secrets in the output would then be written to the audit log in cleartext.
- An operator photographing the screen (common during witnessed ceremonies) would capture any displayed secret.

PIN entry uses masked input with random-length noise (see Phase 4). All other secret values are handled exclusively via the `Hsm` trait boundary — they never cross into the TUI layer.

### Disc before USB invariant

Every signed artifact (cert, CRL) is held in RAM after signing. The TUI commits the artifact to a write-once optical disc (BD-R, DVD-R, or M-Disc) before writing to USB. The USB write step is only reachable in the TUI state machine after the disc write completes — a full SG_IO SAO session burn, not a file write to a pre-mounted path. This is enforced structurally: the data does not exist on any writable path until after the disc session closes successfully.

### Ceremony disc: multi-session SAO archive

The ceremony disc (BD-R, DVD-R, or any write-once optical media) is a permanent, accumulating archive. Each CA operation appends one Session At Once (SAO) session. The disc is left open after each session so future operations can append further sessions; finalization is a deliberate final act.

Every session's ISO 9660 image contains timestamped subdirectories for **all** prior and current sessions (copy-in). The last session is always the complete, browsable view from a standard OS mount. Each session directory contains a full snapshot of the audit log at that point, independently verifiable without reading earlier sessions.

```
Session 4 ISO (last written — what `mount` shows):
  /20260425T143000Z-intent/  ← session 1 (root init intent)
    AUDIT.LOG                ← log with intent entry only
  /20260425T143000Z-record/  ← session 2 (root init record)
    ROOT.CRT
    ROOT.CRL
    AUDIT.LOG                ← log through root init (genesis + intent + issue)
  /20260426T091500Z-intent/  ← session 3 (sign intermediate intent)
    AUDIT.LOG
  /20260426T091500Z-record/  ← session 4 (sign intermediate record)
    ROOT.CRT
    INTCA1.CRT
    AUDIT.LOG                ← full log through session 4
```

Directory naming: `YYYYMMDDTHHMMSS_nnnnnnnnnZ` (27 chars, UTC timestamp with nanosecond fractional part). ISO 9660 Level 2 (31-char directory names). File names are uppercase 8.3 for broad reader compatibility.

Each CA operation writes **two** sessions as a WAL pair:

1. **`<timestamp>-intent`** — written *before* the HSM operation. Records the operator's declared intent (operation type, parameters) in the audit log. If the HSM operation fails or the machine loses power, the incomplete intent is visible on the disc for forensic review.
2. **`<timestamp>-record`** — written *after* the HSM operation succeeds. Contains the signed artifacts (cert, CRL) and the completion audit entries.

The suffixes are chosen so `-intent` sorts before `-record` lexicographically, matching chronological order on the disc. Both directories share the same timestamp, tying the pair together.

All disc operations use SG_IO ioctl MMC commands — no external tools, no subprocesses. Key commands:

- `CDROM_DRIVE_STATUS` (0x5326): disc presence check
- `GET CONFIGURATION` (0x46): media type detection — rejects rewritable profiles (CD-RW, DVD-RW, BD-RE, etc.)
- `READ DISC INFORMATION` (0x51): disc status (blank / incomplete / complete), session count, NWA
- `READ TRACK INFORMATION` (0x52): per-track LBA and size for reading prior sessions
- `READ(10)` (0x28): read sectors to reconstruct prior session ISO images
- `SEND OPC INFORMATION` (0x54): laser power calibration before writing
- `MODE SELECT 10` (0x55) page 0x05: set SAO write mode, open multi-session, BUFE on
- `RESERVE TRACK` (0x53): obtain the Next Writable Address
- `WRITE(10)` (0x2A): write ISO image in 32-sector (64 KiB) chunks
- `SYNCHRONIZE CACHE` (0x35): flush drive write buffer
- `CLOSE TRACK SESSION` (0x5B): close track (01h), close session (02h), or finalize disc (03h)

Minimum ISO image size is 300 sectors (614 KiB); images are zero-padded to this minimum for DVD-R SAO compatibility.

The system clock is verified first — the TUI's `ClockCheck` screen displays the current UTC time and requires the operator to confirm accuracy before any timestamped session can be written. If the clock is wrong, the operator exits and corrects it before relaunching.

### Ceremony device discovery

The ceremony binary discovers USB sticks and optical drives internally via Linux sysfs (`/sys/block/`). USB partitions are mounted with `nix::mount::mount(2)` (requires `CAP_SYS_ADMIN`, granted via NixOS `security.wrappers` capability wrapper with `cap_sys_admin=ep`). No udisks2 or automount daemon is involved. The USB stick supplying `profile.toml` remains mounted throughout the ceremony and is the output target for the post-disc USB write.

USB mount uses the `nix` crate (v0.29) with `MS_NOEXEC | MS_NOSUID | MS_NODEV` flags; tries vfat first, falls back to ext4. Optical drives are identified by `/sys/block/sr*`. Unmount uses `umount2(MNT_DETACH)` so the binary never leaves a stale mount entry on failure.

### Append-only signed audit log

Every operation appends a record to `audit.log`:

```
{ seq, timestamp, event, op_data, prev_hash, entry_hash }
```

- `prev_hash[0]` = SHA-256(root_cert_DER) — ties the log genesis to the specific root ceremony
- Each subsequent `prev_hash` = SHA-256(previous record's raw bytes)
- `entry_hash` = SHA-256(seq ‖ timestamp ‖ event ‖ op_data ‖ prev_hash)

Format: JSONL (one JSON object per line). JSON is chosen over CBOR for grep-ability; the file is never large.

The `verify_log` function (in `anodize-audit`) walks the file, recomputes hashes, and verifies that corrupting any single byte causes failure at exactly that record.

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

### Phase 4 — Ceremony TUI (done)
- `anodize-tui` (`anodize-ceremony` binary): ratatui ceremony wizard; disc-before-USB invariant enforced structurally — USB write step only reachable from `DiscDone` state; cert DER held in RAM until disc write succeeds
- PIN input masked with random-length noise: display length ∈ [8, 20], independent of actual PIN length, refreshed on every keystroke. Prevents shoulder-surf length disclosure without requiring a CSPRNG — `SystemTime::now().subsec_nanos()` is sufficient for a human-visible display. Field shows 0 stars only when empty (confirms cleared), nonzero otherwise.
- Runbooks (`docs/ceremony-init.md`, `docs/ceremony-sign.md`): deferred to Phase 5

### Phase 5 — Live ISO (done)
- `flake.nix` (workspace root) + `nix/iso.nix`: Nix flake with `crane` + `rust-overlay` builds `anodize-ceremony` and `anodize` packages; `nix build .#iso` produces the bootable image
- Minimal NixOS ISO: no network stack, ephemeral tmpfs, read-only squashfs root; packages: `anodize-ceremony`, `softhsm`, `opensc`
- udev rules: YubiHSM 2 (`idVendor==1050`) and optical drives (`sr[0-9]*`) accessible to wheel group without root
- `security.wrappers.anodize-ceremony` with `cap_sys_admin=ep` — grants only `CAP_SYS_ADMIN` for `mount(2)`; no setuid
- Auto-login → ceremony shell on tty1 via getty; shell execs `/run/wrappers/bin/anodize-ceremony` directly; no arguments needed — binary handles device discovery internally
- `systemd.tmpfiles.rules` create `/run/anodize` and `/run/anodize/usb` with correct ownership before launch
- No udisks2 — USB discovery and mounting handled internally by the ceremony binary via sysfs + nix::mount
- Sample profile at `/etc/anodize/profile.example.toml` on the ISO
- **Builds run in Docker** (same philosophy as Rust CI): `make nix-check` runs the `nix` CI job via `act`; `make nix-iso` runs `nixos/nix` Docker image with `--privileged` for release ISO builds
- Runbooks: `docs/ceremony-init.md` (root key ceremony), `docs/ceremony-sign.md` (intermediate signing + CRL)

### Phase 6 — Self-managed disc lifecycle (done)
- Pure-Rust ISO 9660 Level 2 writer (`media/iso9660.rs`): `build_iso` + `parse_iso` roundtrip; both-endian ECMA-119 fields; ≥300-sector padding for DVD-R SAO compatibility
- SG_IO abstraction (`media/sgdev.rs`): `SgDev` wraps `/dev/sr*`; `cdb_in/cdb_out/cdb_none` over `sg_io` (0x2285) ioctl; SCSI CHECK CONDITION decoded to key/ASC/ASCQ
- Typed MMC wrappers (`media/mmc.rs`): all disc operations (OPC, write params, reserve, WRITE(10), READ(10), sync cache, close track/session/disc)
- Multi-session SAO archive: each CA operation appends one session; disc stays open; each session's ISO contains all prior sessions in timestamped subdirectories
- `ClockCheck` TUI screen: operator confirms UTC clock before any timestamped session is written
- Internal USB discovery and mounting: `scan_usb_partitions` via `/sys/block`, `mount_usb` via `nix::mount`, vfat→ext4 fallback
- `--skip-disc` flag: writes staging ISO to `/run/anodize/staging` for dev/test without optical hardware
- `write_session` background thread: OPC → write params → reserve NWA → WRITE(10) chunks → sync → close track → close session

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
