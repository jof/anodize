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



# Vestigial code removal: no audit log on shuttle

There should be no audit log on the shuttle. It doesn't make any sense that it should only be on the CD drive but I think during development sometimes it did that. There shouldn't be an audit log on the shuttle; this is holdovers from my past usage of this shuttle stick.

# Ceremonies should resist accidental cancellation

It seems that during the InitRoot ceremony process while initializing the shares, we pushed escape to go back and this state seems like we've picked a generation number and the custodians were set, but it hasn't been written to disk or HSM yet.

# anodize-sss share input screen should be more user friendly

At the share input screen, it's possible that the final word has a prefix which is unique but does not contain all the letters of the word. The auto-completion logic will redraw the screen before the user has finished typing and this may be confusing. At the end, we should carefully validate the content that is being presented and try and auto-validate it and provide immediate feedback. But it should not clear the screen or reset the modal and allow the user to go back and edit the input that they gave.
It should look more like a text editor where you can go back edit the text and it will auto-complete as you type. In case of an error or invalid input of a share, rather than emptying the complete input, it should just highlight the invalid input and allow the user to go back and edit the text to correct it.


# Self-signed certificate fingerprint display

For the certificate preview modal, it says compare this fingerprint against your paper checklist, but when we're initializing the root CA that doesn't really make any sense.

# Disk detection feedback

When performing the disk detection operations, the initial spin-up operation can be pretty slow. So we should give some feedback when we give some of the SG and SCSI read commands that we're waiting for a response.

# BD-R subsequent session write failures

WRITE(10) (SCSI opcode 0x2A) fails on the second session write to physical BD-R
(BUFFALO USB drive, Verbatim BD-R media). Session 1 writes, syncs, and closes
successfully (320 blocks at LBA 0). Track 2 starts at LBA 320 but is completely
blank — the second write never landed a single sector.

Disc examination (drutil trackinfo) confirms:
  - Track 1: session 1, LBA 0–319, closed, valid ISO 9660 with intent audit log
  - Track 2: session 2, LBA 320, blank=true, NWA=320, 12M free blocks
  - Disc status: incomplete/appendable

Hypotheses (in order of likelihood):

1. Drive not ready after session close. After CLOSE SESSION (0x5B) completes for
   session 1, disc_sync immediately spawns a new write_session thread. The BUFFALO
   USB firmware may still be physically writing the session lead-out/lead-in and
   updating the Disc Management Structure. The next WRITE(10) arrives while the
   drive is busy and gets CHECK CONDITION (likely sense 02h/04h/08h — NOT READY,
   LONG WRITE IN PROGRESS). Fix: add a TEST UNIT READY (0x00) polling loop with
   backoff at the start of write_session_inner before issuing any writes.

2. Missing MODE SELECT page 0x05 for physical BD-R. The code skips mode page 0x05
   for BD-R (because cdemu had issues), but the physical drive's GET CONFIGURATION
   lists Write Parameters Mode Page (05h) as a supported feature. Without setting
   MultiSession::Open, the drive may default to single-session behavior and reject
   writes after the first session close. Fix: conditionally set page 0x05 on
   physical drives, or try-and-fallback.

3. ISO LBA addressing bug (read-back issue, not write failure). build_iso hardcodes
   all internal LBAs from 0 (root_dir_lba=20, etc.). For session 2 at disc LBA 320,
   the PVD points to absolute LBA 20 (session 1 territory). Even if the write
   succeeds, mounting session 2 would show session 1's directory tree. build_iso
   needs an lba_offset parameter so internal LBAs are disc-absolute.


# Retry logic on disc write failures
Additionally: if the write fails, the TUI should offer a retry option or at minimum
block the user from returning to the ceremony menu (preventing silent data loss).
