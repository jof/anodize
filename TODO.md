# TODO

## InitRoot: escape during share validation can leave half-initialized state

During InitRoot, after shares have been generated and the operator is validating
them (re-entering words), it is possible to press Escape or quit. This leaves
the ceremony in a half-initialized state: the HSM key material may already exist
and shares may have been partially distributed, but no cert or disc write has
occurred. On the next boot the appliance may not recognize the incomplete state
cleanly. Need to either:
- Prevent escape/quit during the share validation phase, or
- Detect and recover from the half-initialized state on next launch.

## anodize-shuttle: add `list-usb` top-level command

Add a command to enumerate USB devices that could be discs (e.g. USB mass-storage
devices, optical drives). Useful for operator discovery before ceremony start.
The `lint --list-usb` help text references this but it doesn't exist yet.

## cdemu: verify multi-session append after CLOSE SESSION

The intent session write confirmed `sessions=0 → write → CLOSE TRACK → CLOSE
SESSION` all succeed. The disc reported `status=Incomplete sessions=1` on the
second open, confirming the first session was committed and the disc remained
appendable. Full end-to-end test (two complete session writes in one ceremony run)
is blocked by the state machine bug above.

## 6. RekeyShares: propagate PIN change to all backup HSMs

After changing the primary HSM's PIN, all backup HSMs must also be updated.
Requires:

- A way to discover which HSMs hold backup copies of the signing key (from
  backup audit events in the disc log, or tracked in `STATE.JSON`).
- Iterating over all discovered backup HSMs and calling `change_pin()` on each.

Depends on: PIN rotation (done).

## 7. RekeyShares: failure recovery for multi-HSM PIN change

If PIN change succeeds on HSM A but fails on HSM B, there must be a defined
recovery path:

- The old PIN is still known (just reconstructed from shares), so rollback on A
  is possible.
- Options: (a) roll back A to old PIN on any failure, (b) record partial state
  and let the operator retry B, (c) both.
- Must not leave any HSM in an unknown authentication state.

Depends on: TODO #6.

## 8. Dev disc swap automation for MigrateDisc testing

`MigrateDisc` prompts "Insert Blank Target Disc."  In the dev/QEMU environment
the operator must swap the cdemu BD-R image.  Currently this requires manual SSH
+ gdbus commands.  Add either:

- A `make cdemu-swap-disc` target, or
- A helper script callable from the debug SSH session

that stops cdemu, moves old ISO files aside, and restarts with a fresh blank
BD-R image.

No code dependencies; can be done in parallel with the above.

## 9. Full end-to-end ceremony test

Depends on **all** of the above plus the existing "cdemu multi-session append"
TODO (#3).  Covers the complete ceremony lifecycle:

InitRoot → KeyBackup (pair + backup) → SignCsr → RevokeCert → IssueCrl →
RekeyShares (with real PIN rotation across all HSMs) → MigrateDisc →
ValidateDisc.

Test methodology document to be written as a separate plan once prerequisites
are complete.
