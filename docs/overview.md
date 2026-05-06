# Anodize — Overview

Anodize is a small, auditable root-CA ceremony tool written in Rust. It runs from a verified live ISO on an air-gapped machine and talks to its signing key exclusively through a PKCS#11 module.

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

## Domain concepts

### One binary, two profiles

The binary has no compile-time knowledge of the HSM backend. A `profile.toml` on the shuttle USB selects the PKCS#11 module (`libsofthsm2.so` in dev, `yubihsm_pkcs11.so` in prod) and configures CA identity. The same binary is used in every environment.

### Shuttle and disc

Two physical media participate in every ceremony:

- **Shuttle** — a USB stick (`ANODIZE-SHUTTLE` volume label) carrying `profile.toml`, inbound CSRs, and outbound signed artifacts.
- **Disc** — a write-once optical disc (BD-R, DVD-R, or M-Disc) serving as the permanent, append-only audit archive. Each CA operation appends sessions to the disc; the disc is never rewritten.

The **disc-before-shuttle invariant** ensures that every signed artifact is committed to the write-once disc before it is written to the shuttle. This is enforced structurally in the ceremony pipeline.

### Shamir Secret Sharing for the HSM PIN

The HSM PIN is a 32-byte random value split via Shamir over GF(256). Share parameters (threshold *k*, total *n*, custodian names) are chosen at root-init and stored as metadata on the audit disc. Shares are never stored digitally — custodians hold paper transcripts using a 256-word wordlist encoding with CRC-8 checksums.

Share commitments and a PIN verification hash are stored on the disc, allowing pre-login validation of reconstructed PINs without wasting PKCS#11 retry attempts.

### Audit log

Every CA operation appends an entry to a hash-chained JSONL audit log. The genesis hash is SHA-256 of the root certificate DER, tying the log irrevocably to the specific root ceremony. Each subsequent entry chains to its predecessor via SHA-256. The log is independently verifiable.

---

## Ceremony pipeline

The ceremony TUI has two phases: **Setup** and **Ceremony**. Setup runs once per session; Ceremony can execute multiple operations.

### Setup

Setup gates the ceremony by verifying prerequisites in order:

1. **Clock** — operator confirms UTC time accuracy
2. **Shuttle** — detect and mount shuttle USB with `profile.toml`
3. **Profile** — parse and validate `profile.toml`
4. **Disc** — detect write-once optical disc, load prior sessions + `STATE.JSON`

### Ceremony operations

After setup completes, the operator selects an operation. Each operation follows a six-phase pipeline:

1. **Preflight** — load `STATE.JSON`, verify disc chain, detect WAL recovery
2. **Planning** — configure parameters (operation-specific sub-screens)
3. **Commit** — write intent WAL session to disc (crash-safe point)
4. **Quorum** — collect threshold shares from custodians, reconstruct PIN, verify against commitment + hash. For `InitRoot` (no prior PIN), this phase generates the random PIN and performs SSS distribution instead.
5. **Execute** — HSM login with reconstructed PIN, perform crypto operation, HSM logout
6. **Export** — write record session to disc, copy artifacts to shuttle

### Operations

- **`InitRoot`** — generate root CA keypair, split PIN into shares, distribute to custodians, build root cert + initial CRL. This is the primary first-ceremony operation.
- **`SignCsr`** — sign an intermediate CSR from the shuttle
- **`RevokeCert`** — add revocation entry + issue new CRL
- **`IssueCrl`** — re-sign the current revocation list
- **`RekeyShares`** — reconstruct old PIN, generate new PIN, split new shares, distribute and verify new shares, then `C_SetPIN`, commit
- **`MigrateDisc`** — migrate all sessions to a new optical disc (no HSM involvement; Quorum skipped)

### Crash recoverability

Before any irreversible operation (HSM key generation, `C_SetPIN`), an intent WAL session is committed to disc. The WAL contains enough state to recover: the old PIN hash (for re-key), the operation parameters, and intermediate results. If the ceremony machine crashes, the next session detects and resumes from the WAL.

---

## Reproducible builds

The ISO is built with **Nix** (`flake.nix` at the workspace root). The Nix store is content-addressed: every package is identified by a cryptographic hash of its inputs. Two machines building the same flake lock file produce byte-identical outputs.

Builds run in Docker — no Nix installation is required on the developer's host:

```sh
make nix-check      # nix build .#anodize-ceremony
make nix-iso        # nix build .#iso
```

The ISO is intentionally minimal: no network stack, read-only root, ephemeral state only in RAM. The operator interaction surface is entirely the numbered ratatui TUI menu — no shell is exposed.

---

## Algorithm defaults

- **ECDSA P-384**: safer enterprise pick for relying-party compatibility; supported by both YubiHSM 2 and SoftHSM2.
- **Root validity**: configurable; ceremony tooling defaults to 20 years.
- **Token identification**: by label, not slot index (YubiHSM slot indices are unstable across USB reconnects).

---

## Two binaries

Both binaries live in the `anodize-tui` crate and ship on the ISO:

- **`anodize-ceremony`**: ratatui TUI implementing the full ceremony state machine. All operator actions are numbered menu items.
- **`anodize-sentinel`**: terminal gatekeeper. Acquires an exclusive `flock` before exec-ing the ceremony binary; prevents concurrent ceremony runs on multiple TTYs. Offers power-off via `reboot(2)`.

---

## Related documents

- [Detailed Design](design.md) — architectural decisions, implementation details, crate rationale
- [Threat Model](threat-model.md) — trust boundaries, attack surface, mitigations
