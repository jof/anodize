# Optical Disc Archive

The ceremony disc (BD-R, DVD-R, M-Disc, or CD-R) is a permanent, append-only archive. Each CA operation appends sessions using Session At Once (SAO) writing. All disc I/O uses SG_IO ioctl MMC commands — no external tools, no subprocesses.

---

## Multi-session format

Each CA operation writes **two** sessions as a WAL pair:

1. **`<timestamp>-intent`** — written *before* the HSM operation. Records declared intent in the audit log. If the HSM operation fails or the machine loses power, the incomplete intent is visible on disc for forensic review.
2. **`<timestamp>-record`** — written *after* the HSM operation. Contains signed artifacts (cert, CRL) and completion audit entries.

Suffixes are chosen so `-intent` sorts before `-record` lexicographically, matching chronological order.

### Copy-in accumulation

Every session's ISO 9660 image contains timestamped subdirectories for **all** prior and current sessions. The last session is always the complete, browsable view from a standard OS `mount`. Earlier sessions provide redundancy.

```
Session 4 ISO (last written — what `mount` shows):
  /20260425T143000_000000000Z-intent/    ← session 1 (root init intent)
    AUDIT.LOG
  /20260425T143000_000000000Z-record/    ← session 2 (root init record)
    ROOT.CRT
    ROOT.CRL
    STATE.JSON
    AUDIT.LOG
  /20260426T091500_000000000Z-intent/    ← session 3 (sign intermediate intent)
    AUDIT.LOG
  /20260426T091500_000000000Z-record/    ← session 4 (sign intermediate record)
    ROOT.CRT
    INTCA1.CRT
    STATE.JSON
    AUDIT.LOG
```

### Directory naming

`YYYYMMDDTHHMMSS_nnnnnnnnnZ` — 27 characters, UTC timestamp with nanosecond fractional part. Fits within ISO 9660 Level 2's 31-character directory name limit. File names use uppercase 8.3 for broad reader compatibility.

---

## SG_IO MMC commands

All disc operations use Linux SG_IO ioctls to send SCSI MMC commands directly to the optical drive:

| Command | Opcode | Purpose |
|---|---|---|
| `TEST UNIT READY` | 0x00 | Drive readiness polling (TUR loop with backoff) |
| `CDROM_DRIVE_STATUS` | 0x5326 | Disc presence check |
| `GET CONFIGURATION` | 0x46 | Media type detection — **rejects** rewritable profiles (CD-RW, DVD-RW, BD-RE) |
| `READ DISC INFORMATION` | 0x51 | Disc status (blank / incomplete / complete), session count, last track number |
| `READ TRACK INFORMATION` | 0x52 | Per-track LBA, size, and NWA (via `last_track_l`) |
| `READ(10)` | 0x28 | Read sectors to reconstruct prior session ISO images |
| `SEND OPC INFORMATION` | 0x54 | Laser power calibration before writing |
| `MODE SELECT 10` | 0x55 pg 0x05 | Set SAO write mode, open multi-session, BUFE on |
| `RESERVE TRACK` | 0x53 | Obtain the Next Writable Address |
| `WRITE(10)` | 0x2A | Write ISO image in 32-sector (64 KiB) chunks |
| `SYNCHRONIZE CACHE` | 0x35 | Flush drive write buffer |
| `CLOSE TRACK SESSION` | 0x5B | Close track (01h), close session (02h), or finalize disc (03h) |

### Source layout

All disc I/O lives in `crates/anodize-tui/src/media/`:

| File | Role |
|---|---|
| `sgdev.rs` | Raw SG_IO ioctl wrapper, CDB construction |
| `mmc.rs` | MMC command implementations (read disc info, write, close, OPC, etc.) |
| `iso9660.rs` | Pure-Rust ISO 9660 Level 2 writer — no external library |
| `mod.rs` | Session assembly, copy-in logic, device discovery, staging |

---

## Capacity and limits

| Media | Max sessions |
|---|---|
| CD-R | 99 |
| DVD-R | 254 |
| BD-R / M-Disc | 255 |

The disc capacity guard requires at least **2 sessions remaining** before any key operation begins (one for intent, one for record).

Minimum ISO image size is **300 sectors** (614 KiB). Images are zero-padded to this minimum for DVD-R SAO compatibility.

---

## Rewritable media rejection

At disc insert time, `GET CONFIGURATION` probes the media profile. Rewritable profiles are rejected:

- CD-RW (0x000A)
- DVD-RW Sequential (0x0013), DVD-RW Restricted Overwrite (0x0014)
- DVD+RW (0x001A), DVD+RW DL (0x002A)
- BD-RE (0x0043)

Only write-once profiles are accepted: CD-R, DVD-R, DVD+R, BD-R.

---

## Clock verification

The TUI's `ClockCheck` screen displays the current UTC time and requires the operator to confirm accuracy before any timestamped session can be written. The `confirmed_time` is captured once at ClockCheck and used for session directory naming. A clock re-confirmation gate fires before each signing operation.

---

## Disc migration

`MigrateDisc` copies all sessions from an existing disc to a fresh blank disc. The process:

1. Read all prior session ISO images from the source disc.
2. Prompt operator to insert a blank disc (cdemu disc swap in dev).
3. Write a single session containing all accumulated directories to the new disc.
4. Session 0 on the new disc is flagged as a migration in the audit log.

---

## SCSI design choices and invariants

### Drive readiness

Every disc interaction (`scan_disc`, `write_session`) begins with a `TEST UNIT READY` (0x00) polling loop with exponential backoff (250 ms → 5 s, 60–120 s timeout). Physical USB drives (BUFFALO, Pioneer) can stay busy for tens of seconds after session close while writing lead-out or updating the Disc Management Structure. This mirrors `libburn`'s TUR pattern.

### NWA resolution

The Next Writable Address for each session is resolved via `READ TRACK INFORMATION` for the **last track number** reported by `READ DISC INFORMATION` (`last_track_l`). This is the most portable method and works on all tested drives.

Fallback: if the `last_track_l` query fails, try track 0xFF ("invisible track" per Feature 0021h Incremental Streaming Writable). This is a CD-R era concept that USB bridge chipsets frequently reject — hence fallback, not primary.

Validation: NWA must be > 0 on a non-blank disc. A zero NWA would mean overwriting session 1 — the code bails with a clear error rather than silently corrupting the archive.

Reference: `libburn` (the canonical Linux burning library) never uses track 0xFF; it always queries by actual track number from `READ DISC INFORMATION`.

### Profile-aware pregap handling

CD-R tracks may have a 150-sector (2-second) Red Book pregap before the data area. `scan_disc` only attempts the pregap-skip read probe on CD profiles (0x0008–0x000A). BD-R and DVD-R do not have pregaps, so reading starts directly at the track start LBA — avoiding a wasteful (and potentially confusing) extra `READ(10)`.

### Disc finalization

When `is_final=true`, the session close uses `CLOSE TRACK SESSION` close function **0x03** (`CloseTarget::Disc`) instead of 0x02 (`CloseTarget::Session`). This is the only way to finalize BD-R, which skips MODE SELECT page 0x05 entirely. For CD-R/DVD-R it acts as belt-and-suspenders alongside the `MultiSession::FinalSession` write parameter. All current ceremony callers pass `is_final=false` — discs remain appendable throughout the ceremony lifecycle.

### MODE SELECT page 0x05

Write parameters (SAO mode, BUFE, multi-session state) are set via MODE SELECT page 0x05 for CD-R and DVD-R only. BD-R drives manage write parameters internally and typically reject or ignore page 0x05 — it is intentionally skipped for BD-R profiles.

---

## Dev environment: cdemu

In dev builds, optical disc writes go through cdemu SCSI generic passthrough, exercising the real SG_IO MMC code path end-to-end in QEMU. The `cdemu-load-bdr` systemd service in `nix/dev-iso.nix` manages the virtual BD-R:

- **First boot**: creates a blank BD-R via `DeviceCreateBlank`
- **Subsequent boots**: loads the existing image via `DeviceLoad`, preserving all prior session data

This mirrors production behavior where a physical BD-R retains written sessions.

---

## Related documents

- **[Ceremony Pipeline](ceremony-pipeline.md)** — WAL intent/record lifecycle
- **[Security](security.md)** — disc-before-shuttle invariant
- **[Disc Validation](ceremony-validate.md)** — offline and HSM cross-checks
