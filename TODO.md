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

### ~~Shuttle copy silently fails after Phase 1~~ (DONE)

`do_write_shuttle()` now calls `media::verify_shuttle_mount()` before writing
any artifacts.  The check reads `/proc/mounts` and confirms the shuttle path
is an active mount — stale directories (left behind by a previous session or
a concurrent debug mount at a different path) are rejected with a clear error.
All file writes use `media::write_and_sync()` which fsyncs each file to catch
silent I/O failures.  Operations that produce no shuttle artifacts (RekeyShares,
KeyBackup, ValidateDisc, MigrateDisc) skip the mount check entirely.

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

### ~~Share word count mismatch in UI ("34" vs "36")~~ (DONE)

Share Distribution computed total words as `groups × 4`, overcounting when the
last group had fewer than 4 words (e.g. 34 words = 8×4 + 2 = 9 groups, but
`9×4 = 36`).  Fixed `NamedShare::total_words()` to count actual words across
groups.  Share Input's `expected_words` was already correct (`secret_len + 2`).

### ~~No progress indicator during disc writes~~ DONE

Both `Commit` and `BurningDisc` phases now show an animated Braille spinner,
elapsed-seconds counter, and real-time step messages from the background
burn thread (e.g. "WRITE sector 4/8 (128 KiB, LBA 150)…").

### ~~Sentinel status page: add system health info~~ (DONE)

The sentinel banner now auto-refreshes every 5 seconds (via `event::poll`)
and displays system health inline.  Ceremony lock status is shown
prominently at the top ("CEREMONY IS RUNNING" / "idle").

Gathered via `syshealth.rs` (pure procfs/sysfs parsers + command runners):

    ceremony lock status, uptime, load averages, memory/swap, entropy,
    kernel version, NixOS generation, NTP sync, Secure Boot, optical
    drive model, thermal zones, network interfaces, failed systemd
    units, block devices

All parsers have unit tests (`syshealth::tests`).

### cdemu-swap-disc.sh brittle PATH handling

The script failed on the debug user because `gdbus` is only in the Nix
store, not in `$PATH`.  The `GDBUS=` fallback tries `command -v` first
which misses the Nix path.  Fix: search known Nix store paths as a
second-order fallback, or have the NixOS module drop a wrapper script at
a well-known location (e.g. `/run/anodize/bin/gdbus`).

### ~~MigrateDisc step ordering wrong in e2e-test-plan.md~~ (DONE)

Removed the premature "Write confirmation: press Enter" and "Wait for disc burn"
steps from the MigrateDisc section.  The plan now matches the actual flow:
MigrateConfirm → press 1 → WaitMigrateTarget (swap disc) → press 1 → write.

### ~~RekeyShares: no verification that old shares are invalidated~~ (DONE)

Post-rekey smoke-check implemented: after `change_pin` succeeds on all HSMs,
`do_rekey_verify_old_pin_rejected` opens a fresh session with the old PIN
(already cached in memory from the quorum phase) and confirms the HSM rejects
it.  If the old PIN still works, the ceremony aborts with a CRITICAL error
before writing to disc.

## Findings from e2e run (2026-05-11)

Full 7-of-8 phase lifecycle (KeyBackup skipped — single SoftHSM) on bare-metal
dev VM (192.168.178.76).  Phases run: InitRoot → SignCsr → RevokeCert →
IssueCrl → RekeyShares → MigrateDisc → ValidateDisc.

### Confirmed fixes working

- **Share word count**: displays "9 groups, 34 words" — correct.
- **Hex serial revocation**: RevokeCert shows serial `632AAC91F575A0ED2B8BA361B19FD343` in hex.
- **Shuttle copy**: shuttle artifacts present after every phase (root.crt, root.crl, audit.log, intermediate.crt, revoked.toml).
- **ValidateDisc**: 4 PASS / 0 WARN / 0 ERROR on migrated disc.
- **Audit chain**: hash chain verified across all sessions.
- **MigrateDisc**: 9 sessions consolidated to new blank disc successfully.
- **RekeyShares**: custodian rotation (Alice/Bob → Charlie/Diana) accepted, new shares verified.
- **Two-step write confirmation**: disc write dialogs require `[1]` then `[Enter]`.

### ~~BUG: CertPreview shows root cert fields during SignCsr~~ (FIXED)

Fixed: CertPreview now parses the actual cert from `cert_der` to extract
subject and validity, instead of always showing root CA profile fields.
Falls back to profile data only when `cert_der` is absent.

### Sentinel: remove press-N-to-show-network functionality

Now that the refresh loop displays network interface info inline, the
manual "press N to show network" action is redundant.  Remove the
keybinding and associated handler.

### Sentinel: color ceremony-lock status

Use color to indicate ceremony lock state: **red** if a ceremony is
running on another terminal, **green** if the appliance is idle/ready.

### Sentinel: dev-mode warning banner

Show a prominent red "DEV MODE" banner in the sentinel, matching the
style of the existing dev-mode warning in the TUI.

### Sentinel: bottom-justify the refresh display

The auto-refresh status text currently renders mid-screen after the last
line of content.  Pin it to the bottom of the terminal so the layout
stays stable across refreshes.

### Sentinel: double-buffer repaints to prevent flicker

Build the new frame in a buffer before clearing and repainting the
screen, so the user never sees a blank/partial frame between refreshes.

### cdemu-swap-disc.sh still broken in `make` target

`make cdemu-swap-disc` still fails with "ERROR: gdbus not found" because the
script's fallback path (`/run/current-system/sw/bin/gdbus`) doesn't exist.
The actual path is deep in `/nix/store/...glib-2.86.3-bin/bin/gdbus`.
Workaround: run the swap commands manually via debug SSH as ceremony user.
The TODO item from the prior run (brittle PATH handling) remains open.

