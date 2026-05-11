# Ceremony Pipeline

The ceremony TUI implements a structured state machine that enforces ordering invariants. No operator action can skip or reorder phases. The pipeline is divided into **Setup** (runs once per session) and **Ceremony** (repeatable operations).

---

## Setup

Setup gates the ceremony by verifying prerequisites in order. Each gate must pass before the next is attempted.

| # | Gate | What happens |
|---|---|---|
| 1 | **ClockCheck** | Displays current UTC time. Operator confirms accuracy before any timestamped operation. Re-confirmed before each signing operation. |
| 2 | **Shuttle** | Detects and mounts shuttle USB (`ANODIZE-SHUTTLE` volume label) with `profile.toml`. Mount uses `MS_NOEXEC ∣ MS_NOSUID ∣ MS_NODEV`. |
| 3 | **Profile** | Parses and validates `profile.toml`. Loads cert profiles. |
| 4 | **HSM** | Detects HSM device via the configured backend. No login yet — just probe. |
| 5 | **Disc** | Detects write-once optical disc, rejects rewritable media. Loads prior sessions + `STATE.JSON` from the disc. |

### Device discovery

Shuttles and optical drives are discovered via Linux sysfs (`/sys/block/`). Shuttle partitions are mounted with `nix::mount::mount(2)` (requires `CAP_SYS_ADMIN` via NixOS capability wrapper). No udisks2 or automount daemon. Optical drives are identified by `/sys/block/sr*`. Unmount uses `umount2(MNT_DETACH)`.

---

## Operation lifecycle

After setup completes, the operator selects an operation from a numbered menu. Each operation follows a six-phase pipeline:

```
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│ Preflight│───►│ Planning │───►│  Commit  │───►│  Quorum  │───►│ Execute  │───►│  Export  │
└──────────┘    └──────────┘    └──────────┘    └──────────┘    └──────────┘    └──────────┘
```

1. **Preflight** — Load `STATE.JSON`, verify disc chain, detect WAL recovery from a prior crash.
2. **Planning** — Configure operation-specific parameters (custodian names, CSR selection, cert profile, revocation details).
3. **Commit** — Write intent WAL session to disc. This is the crash-safe point — the declared intent is on record even if the machine dies.
4. **Quorum** — Collect threshold shares from custodians, reconstruct PIN, verify against commitment hashes and `pin_verify_hash`. For `InitRoot` (no prior PIN), this phase generates the random PIN and performs SSS distribution instead.
5. **Execute** — HSM login with reconstructed PIN, perform the crypto operation (keygen, sign, CRL), HSM logout.
6. **Export** — Write record session to disc (artifacts + updated audit log), copy artifacts to shuttle USB.

### Phase bar

The TUI displays a phase progress bar showing the current phase. Each phase transitions only forward — there is no back button.

---

## Operations

### InitRoot

Bootstrap the root CA. Generates a P-384 keypair on the HSM, creates a self-signed root certificate + initial empty CRL, splits the HSM PIN into SSS shares.

- **Planning**: custodian names, threshold *k*, total *n*.
- **Quorum**: generates 32-byte random PIN, splits via SSS, distributes shares (ShareReveal), verifies all shares via round-trip re-entry (ShareInput).
- **Execute**: HSM bootstrap → `C_GenerateKeyPair` → root cert + CRL construction.
- **Export**: `ROOT.CRT`, `ROOT.CRL`, `STATE.JSON`, `AUDIT.LOG` to disc; same to shuttle.

### SignCsr

Sign an intermediate CA CSR from the shuttle.

- **Planning**: select CSR file, choose cert profile (validity, pathLen), preview CSR fields.
- **Quorum**: standard share collection → PIN reconstruction → HSM login.
- **Execute**: CSR signature verification → intermediate cert issuance via `P384HsmSigner`.
- **Export**: intermediate cert + updated `AUDIT.LOG` to disc and shuttle.

### RevokeCert

Add a revocation entry and issue an updated CRL.

- **Planning**: select certificate (from disc state or manual serial entry), enter revocation reason.
- **Execute**: append to `REVOKED.TOML`, sign fresh CRL.
- **Export**: `REVOKED.TOML` + `ROOT.CRL` to disc and shuttle.

### IssueCrl

Re-sign the current revocation list (CRL refresh without new revocations).

- **Execute**: sign CRL with current revocation entries, incremented CRL number.
- **Export**: `ROOT.CRL` to disc and shuttle.

### RekeyShares

Full PIN rotation — the HSM credential is replaced, not merely re-split. See [SSS & PIN Management](sss-pin-management.md) for the detailed protocol.

- **Quorum (old)**: reconstruct old PIN from existing custodian shares.
- **Planning**: configure new custodians + threshold.
- **Quorum (new)**: generate new random PIN, split, distribute, verify via round-trip.
- **Execute**: `change_pin(old, new)` on primary HSM, propagate to all fleet backup HSMs.
- **Export**: updated `STATE.JSON` (new commitments, `pin_verify_hash`, incremented `generation`) to disc.

### MigrateDisc

Copy all sessions from the current disc to a fresh blank disc. No HSM involvement; Quorum phase is skipped.

- **Preflight**: verify current disc chain integrity.
- **Commit**: no intent WAL (no HSM op).
- **Execute**: read all prior sessions, prompt operator to insert blank disc, write accumulated sessions to new media.

### KeyBackup

Two-phase flow to back up the signing key to a second HSM device:

1. **Pair**: generate a shared AES-256 wrap key, install on both source and target devices.
2. **Backup**: wrap-export signing key from source, wrap-import to target, verify public keys match.

See [HSM Fleet & Key Backup](hsm-fleet.md) for details.

### ValidateDisc

Read-only disc integrity check. No HSM operation required for offline checks; optional HSM cross-check if a quorum is available.

See [Disc Validation](ceremony-validate.md) for the full check matrix.

---

## TUI modes

The TUI has three top-level modes, switchable via a tab bar:

| Mode | Content |
|---|---|
| **Setup** | Sequential gate screens (Clock → Shuttle → Profile → HSM → Disc) |
| **Ceremony** | Operation selection menu → six-phase pipeline |
| **Utilities** | Key backup, disc inspector, disc sync |

---

## Crash recoverability

Before any irreversible operation, an intent WAL session is committed to disc. The WAL contains:

- Operation type and parameters
- Old PIN hash (for rekey recovery)
- Intermediate results

If the ceremony machine crashes after the intent session but before the record session, the next boot detects the incomplete WAL and offers to resume. The disc always has a forensic record of what was attempted.

### Disc-before-shuttle invariant

Every signed artifact is held in RAM after signing. The artifact is committed to write-once optical disc **before** being written to the shuttle. The Export phase is only reachable after the disc session closes successfully — a full SG_IO SAO burn, not a file write to a pre-mounted path. This is enforced structurally in the state machine.

---

## Related documents

- **[Architecture](architecture.md)** — crate structure, HSM traits
- **[Optical Disc Archive](optical-disc.md)** — disc format details
- **[SSS & PIN Management](sss-pin-management.md)** — share handling, PIN rotation
- **[Root Ceremony Init](ceremony-init.md)** — printable runbook
