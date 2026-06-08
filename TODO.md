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


## Subsequent mounts of the shuttle.
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

## BD-R SRM session management investigation

BUFFALO USB BD-R drive (profile 0x0041, BD-R SRM) accepted CLOSE SESSION
but did not update its Disc Management Area / track descriptors for sessions
3 and 4 during an e2e test on 2026-06-02.  Data was physically written and
readable, but the SCSI TOC only reported 2 tracks.  Post-burn verification
now catches this at runtime (`write_session_inner` re-reads disc info after
CLOSE SESSION and logs a warning if the session count didn't increment).

Needs investigation: test with other BD-R drives to determine if this is
BUFFALO-specific or if BD-R SRM requires additional commands (e.g. a
different CLOSE function code, explicit RESERVE TRACK before each new
session, or a firmware-specific DMA flush sequence).

## Input CSRs: flexibility
Allow the input CSR to be in either PEM or DSR format.
Add a simple file browser to select the CSR file from the contents of the shuttle filesystem.
