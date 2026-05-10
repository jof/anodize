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

## Findings from e2e run (2026-05-10)

### Shuttle copy silently fails after Phase 1

After InitRoot the shuttle (`/mnt/usb`) correctly received `root.crt`,
`root.crl`, and `audit.log`.  Every subsequent phase reported "Copy artifacts
to shuttle" success, but the shuttle contents never changed — no
`intermediate.crt`, no updated `audit.log`, no updated `root.crl`.

The likely cause is a stale mount / symlink at `/tmp/anodize-shuttle`.  On the
first ceremony session the shuttle USB is auto-detected and mounted; on later
sessions the path still exists but the mount may have gone stale (the debug
user also mounts the same device at `/mnt/usb`).  The shuttle-copy code should
re-verify the mount is live before writing, and return a visible error when the
copy actually fails.

### ~~ValidateDisc should be more comprehensive~~ (DONE)

The validation report now covers:

    disc.finalization, session.count, session.migration, audit_chain,
    session.continuity (superset + immutability), state.root_cert_hash,
    state.crl_number, state.custodians, state.hsm_log_seq,
    cert.root_self_signed, cert.intermediate_chain, cert.crl_signature, cert.crl_number

- ~~**Certificate signature verification**~~ — ROOT.CRT self-signature,
  INTERMEDIATE.CRT chain to root, ROOT.CRL signature and CRL number extraction.
- ~~**STATE.JSON consistency**~~ — `root_cert_sha256` matches ROOT.CRT on disc,
  custodian list changes require rekey event, CRL number ≥ CRL events,
  `last_hsm_log_seq` monotonicity across sessions.
- ~~**HSM audit log reconciliation**~~ — `cross_check_hsm_log` was already
  wired; `last_hsm_log_seq` monotonicity now also checked in state consistency.
- ~~**Cross-session file immutability**~~ — `validate_session_continuity`
  already checks adjacent-session pairs for missing or changed files (exempting
  mutable AUDIT.LOG/STATE.JSON); adjacent-pair comparison gives full
  transitivity across all sessions.

### Share word count mismatch in UI ("34" vs "36")

Share Distribution says "Total: 9 groups, **36 words**" but Share Input
prompts for "Word 1/**34**".  The 2-word discrepancy is the identifier prefix
(`acid`/`aged` first word), but this is never explained to the operator.
Either:
- Display "Word 1/36" and auto-fill the prefix, or
- Add a hint: "The first word identifies the share. Enter words 2–35:".

### No progress indicator during disc writes

After confirming a disc write, the TUI blocks with no spinner, progress bar,
or elapsed timer.  On bare-metal this completed quickly (~2 s), but on slower
media or with large audit logs it could look like a hang.  A simple
"Writing session… (elapsed Xs)" would eliminate operator anxiety.

### cdemu-swap-disc.sh brittle PATH handling

The script failed on the debug user because `gdbus` is only in the Nix
store, not in `$PATH`.  The `GDBUS=` fallback tries `command -v` first
which misses the Nix path.  Fix: search known Nix store paths as a
second-order fallback, or have the NixOS module drop a wrapper script at
a well-known location (e.g. `/run/anodize/bin/gdbus`).

### MigrateDisc step ordering wrong in e2e-test-plan.md

The test plan shows step 5 as "Write confirmation: press Enter" before the disc
swap prompt, but the actual flow is:

    MigrateConfirm → (press 1) → WaitMigrateTarget → (swap disc) → (press 1) → write

The plan should drop the premature "write confirmation" step and clarify that
the swap happens before the write, not after.

### ~~RekeyShares: no verification that old shares are invalidated~~ (DONE)

Post-rekey smoke-check implemented: after `change_pin` succeeds on all HSMs,
`do_rekey_verify_old_pin_rejected` opens a fresh session with the old PIN
(already cached in memory from the quorum phase) and confirms the HSM rejects
it.  If the old PIN still works, the ceremony aborts with a CRITICAL error
before writing to disc.

### Cosmetic: "Disc Session Written" title is generic

Every operation shows the same "Disc Session Written" banner.  It would be
clearer to include the operation name, e.g. "Revocation Record Written" or
"CRL Refresh Written" — the status line beneath does this already, but the
banner title is what operators see first.
