# TODO

## anodize-shuttle: add `list-usb` top-level command

Add a command to enumerate USB devices that could be discs (e.g. USB mass-storage
devices, optical drives). Useful for operator discovery before ceremony start.
The `lint --list-usb` help text references this but it doesn't exist yet.

## Findings from e2e runs

### cdemu-swap-disc.sh: gdbus not found

`make cdemu-swap-disc` fails with "ERROR: gdbus not found" because
`gdbus` is only in the Nix store, not in `$PATH`.  The fallback path
(`/run/current-system/sw/bin/gdbus`) doesn't exist; the actual binary is
deep in `/nix/store/...glib-2.86.3-bin/bin/gdbus`.
Workaround: run the swap commands manually via debug SSH as ceremony user.
Fix: have the NixOS module drop a wrapper at `/run/anodize/bin/gdbus`.

### e2e-test.expect needs update for new ceremony gates

The expect script doesn't account for:
- **Clock re-confirm** gate that fires before every signing operation
- **Two-step write confirmation** (press `[1]` then `[Enter]`) on disc writes
- **KeyBackup two-phase flow** (Pair first, then Backup in a second session)
- **Migrate Disc** flow with cdemu disc swap

### Disc migration skips shuttle export

Unlike all other operations, Migrate Disc ends with "no USB export" and no
option to copy artifacts to the shuttle.  If the new disc is the only copy
of state.json / certs / CRLs, the shuttle should still receive a fresh
export so operators have an offline backup of the latest manifest.

## Future: cross-vendor HSM resilience

Currently all fleet devices must share the same backend kind.  Future work:

- **Mixed-vendor fleets**: allow `HsmDevice` entries with different `backend`
  values; dispatch `open_session_by_id` through the correct backend per device.
- **Quorum-based fleet changes**: require threshold custodian approval before
  adding or removing fleet members.
- **Fleet health checks**: during ValidateDisc, enumerate connected devices,
  cross-reference fleet membership, report missing/unexpected devices.
- **Automatic failover**: if the usual primary device is absent at ceremony
  start, `open_session_any_recognized` already falls through to the next fleet
  member.  Add UI indication of which device was selected.

## Future: crash-resumption and WAL recovery

Once the WAL has been written, it should be possible to resume a ceremony
after a system crash or unexpected power loss.

- **WAL replay**: on startup, detect incomplete WAL entries and offer to
  resume the interrupted operation from the last committed step.
- **HSM audit-log reconciliation**: compare the HSM's on-device audit log
  against the WAL to determine whether any key operations (generate, sign,
  wrap/unwrap) actually executed before the crash.
- **Manual state fixup with audit trail**: if out-of-order or manual fixes
  to `state.json` are required, log an audit event that includes an
  operator-supplied explanation of the incongruity so the discrepancy is
  permanently recorded.

## Vestigial code removal: no audit log on shuttle

There should be no audit log on the shuttle. It doesn't make any sense that it should only be on the CD drive but I think during development sometimes it did that. There shouldn't be an audit log on the shuttle; this is holdovers from my past usage of this shuttle stick.



## Retry logic on disc write failures
Additionally: if the write fails, the TUI should offer a retry option or at minimum
block the user from returning to the ceremony menu (preventing silent data loss).


## Rekey abort after share reveal still commits to HSM

Aborting the RekeyShares ceremony after all Shamir shares have been revealed
(but before the operator confirms transcription on the last share) still
appears to complete the rekey on the HSM and/or state.json.  The ceremony should either:
- defer the irreversible HSM operation until after all confirmations, or
- detect the incomplete confirmation and roll back / warn the operator that
  the new shares are now live despite the abort.

## HSM Pairing -- no shares
When pairing two HSMs together, we shouldn't gather share inputs from the operators and the HSM PIN is not needed for this operation.


## Subsequent amounts of the shuttle.
Subsequent mounts of the shuttle do not appear to be working consistently with the auto mount.

## Validation: session continuity errors on normal ceremony flow

A clean ceremony run (bootstrap → sign → backup) produces 4 continuity ERRORs in
the validation tool because different phases write different file sets:

1. **Seed-only session has no AUDIT.LOG** — the initial seed session writes only
   `SEED.TXT` without an `AUDIT.LOG`, so the next session appears to lose it.
2. **SEED.TXT dropped after root cert generation** — the record session replaces
   the file set with `ROOT.CRT`, `ROOT.CRL`, `AUDIT.LOG`, `STATE.JSON`.
3. **STATE.JSON not carried into subsequent intents** — intent sessions only
   write `AUDIT.LOG` + operation-specific files, losing `STATE.JSON`.
4. **ROOT.CRT/CRL dropped in later record sessions** — backup record sessions
   only write `AUDIT.LOG`.

Possible fixes:
- **Superset invariant**: each session's ISO should include all files from the
  previous session plus any new/changed files.  `write_session_inner` should
  merge the prior session's file set with the new files before calling `build_iso`.
- **Or relax the validator**: make continuity a WARN instead of ERROR when the
  missing files are expected for the phase transition (e.g. SEED consumed after
  bootstrap, STATE.JSON only in record sessions).  The validator should
  understand the ceremony phase model.

## CRITICAL: SignCSR ceremony completes without burning sessions to disc

Observed during e2e test on 2026-06-02. After InitRoot completes (2 sessions
burned: seed + record), SignCSR runs to completion — signs the intermediate on
the HSM, exports intermediate.crt + audit.log to shuttle, and shows the
"Ceremony Complete" screen with the correct fingerprint. However, the disc
still has only 2 sessions; the intent and record sessions for SignCSR were
never burned. The validator confirms only 2 sessions with a passing report.

**Evidence:**
- SCSI TOC: 2 tracks, last session = 02, lead-out at LBA 0x123C
- Shuttle audit.log has seq:0 (intent) and seq:1 (record) for SignCSR
- F12 log buffer shows no burn entries after InitRoot's record commit — only
  the disc scan poll spam ("Scanning optical drive… 2 prior session(s)")
- No "Committing intent" or "Committing record session" log entries for SignCSR

**Root cause — BD-R TOC not updated after CLOSE SESSION:**
`/run/anodize/ceremony.log` proves all 4 burns completed successfully:
  1. 22:54:03 — InitRoot intent (NWA=0, sessions_before=0)
  2. 22:55:39 — InitRoot record (NWA=320, sessions_before=1)
  3. 22:57:46 — SignCSR intent  (NWA=640, sessions_before=2)
  4. 23:00:42 — SignCSR record  (NWA=960, sessions_before=3)
All WRITE(10), SYNCHRONIZE CACHE, CLOSE TRACK, and CLOSE SESSION SCSI
commands returned success. Physical verification confirms **all 4 PVDs are
readable** at LBA 16, 336, 656, and 976 (all contain valid "CD001"/"ANODIZE"
ISO headers). The data IS on the disc.

However, the SCSI TOC (READ TOC, format 02) only reports 2 tracks (first=01,
last=02). Sessions 3 and 4 are invisible to the TOC. The `scan_disc` function
reads tracks from the TOC, so it only finds 2 sessions. The validator sees 2.

The BUFFALO USB BD-R drive (profile 0x0041, BD-R SRM) accepted CLOSE SESSION
but did not update its Disc Management Area (DMA) / track descriptors for
sessions 3 and 4. This may be a drive firmware bug, or BD-R SRM may require
additional commands (e.g. an explicit RESERVE TRACK before each new session,
or a specific CLOSE function code for BD-R) that the current write path
does not issue.

**Secondary issue — F12 log missing SignCSR entries:**
The F12 status log shows no burn messages for SignCSR (despite the ceremony
completing). This is because `bridge.log()` entries from the ceremony thread
are drained by `write_ceremony_log()` (which writes CEREMONY.LOG to shuttle)
before `on_tick()` has a chance to forward them to `app.log_lines`. The
`Prompt::Burning` entries sent via the rendezvous channel ARE received by the
main thread, but only the most recent progress line is forwarded per tick;
if the burn completes between ticks, only the final "Session committed" line
makes it through, and it may be deduplicated by `set_status()`.

**Tertiary issue — timestamp collision:**
`archive_config()` uses `self.confirmed_time` which is set once during Setup
and never reset between ceremonies. Both InitRoot and SignCSR produce the
same session dir_name prefix (`20260602T225138_048981931Z`). This doesn't
cause the burn to fail (each ceremony gets a fresh DiscArchive with prior
sessions from disc scan), but means directory names collide. The `scan_disc`
dedup (`sessions.dedup_by(|a, b| a.dir_name == b.dir_name)`) would merge
them if the TOC ever does expose all 4 tracks.

**Fixes needed:**
1. **BD-R session management**: investigate proper BD-R SRM session
   boundaries. May need RESERVE TRACK or a different CLOSE function code.
   Test with other BD-R drives to determine if this is BUFFALO-specific.
2. **Post-burn verification**: after CLOSE SESSION, re-read the TOC/disc
   info and verify the session count incremented. Fail loudly if not.
3. **Fresh timestamp per ceremony**: use `SystemTime::now()` instead of the
   stale `confirmed_time` when spawning each ceremony.
4. **Log drain race**: drain bridge log into `app.log_lines` before
   `write_ceremony_log()` consumes it, or clone the entries.

## Share Input title counter doesn't update after accepting a share

The `Share Input (Gen 1) — 1/2 shares` title stays at "1/2" after the first
share is accepted and the input moves on to the next custodian.  It should
update to "2/2" (or more generally, increment the counter) so operators can
see progress.  The body correctly shows `✓ #1 Alice Robertson` and prompts
for the next share, but the title is stale.


