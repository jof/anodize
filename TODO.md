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

## SignCsr: display CSR public-key fingerprint before signing

The Certificate Preview screen currently shows the SHA-256 fingerprint of the
*resulting* certificate DER.  For the SignCsr flow, the operator should also see
a fingerprint derived from the CSR's public key so they can independently verify
(e.g. via `openssl req -in req.pem -noout -pubkey | openssl sha256`) that the
key about to be signed matches what they expect.

## Key Backup
When initially gathering key shares to reconstruct the HSM pin for the backup, the TUI output got a bit garbled and didn't show the expected output. There is a string that says "Selecting threadhold shares to reconstruct the HSM PIN" but it is taking over the space on the screen where the green/accepted word parts are shown.

There is some other weird text fighting for the screen after I start to type that says "share input component is active".

Maybe there are multiple components fighting for the same screen space?
