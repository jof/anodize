# TODO

## Audit disc migration utility

When a disc approaches its session limit (≤10 sessions remaining), the ceremony warns the
operator. A future migration flow would let them carry the audit chain to a fresh disc:

1. Read all sessions from the nearly-full disc via `read_disc_sessions()`
2. Write a migration session to the new disc:
   - `MIGRATION.JSON`: source disc fingerprint, session count, migration timestamp
   - `AUDIT.LOG`: `audit.disc.migrate` event with `source_disc_fingerprint`
3. Chain continuity: new disc's audit log genesis = SHA-256(last cert DER from source disc)
4. Store old disc as immutable archive; continue ceremonies on new disc

Separate TUI state or `--migrate-disc` CLI flag. Plan when multi-cert ceremony flow matures.

## ~~State machine: intent burn → cert generation transition~~ (FIXED)

Fixed: added `PostCommitError` phase to `CeremonyPhase`. `do_bootstrap_hsm`,
`do_login_with_pin`, `do_generate_and_build`, `do_find_and_build`, and
`do_build_cert` now return `Result<(), String>`. Extracted `post_intent_init_root`
helper. `tick_intent_burn` transitions to `PostCommitError` on failure instead of
silently advancing to `Execute`. Operator sees the error and can `[1]` retry or
`[Esc]` abort. Safety-net removed.

## Clock drift guard blocks disc write

The "Clock drift > 5 min since ClockCheck" warning appears in the status bar after
the ceremony takes several minutes (e.g. typing 34-word shares twice). Once the
drift guard fires, the cert preview shows `[1] Proceed to disc write` but the
write modal's confirm step doesn't advance. Either:
- Relax the drift threshold for dev builds, or
- Let the operator re-confirm the clock without restarting the entire ceremony.

## ~~TUI: add j/k scroll hint to share display panel~~ ✅

Done. Key hints (`[j/k] Scroll`, `[Enter]`, `[S]`, `[Esc]`) now render in a
fixed 2-line footer pinned to the bottom of the share reveal panel, always
visible regardless of scroll position. Scroll offset is also clamped.

## TUI: share panel height

Consider making the share panel expand to fill available terminal height, or
auto-paginate shares into groups that fit the panel. Currently the panel is a fixed
12-row box regardless of terminal size.

## InitRoot: escape during share validation can leave half-initialized state

During InitRoot, after shares have been generated and the operator is validating
them (re-entering words), it is possible to press Escape or quit. This leaves
the ceremony in a half-initialized state: the HSM key material may already exist
and shares may have been partially distributed, but no cert or disc write has
occurred. On the next boot the appliance may not recognize the incomplete state
cleanly. Need to either:
- Prevent escape/quit during the share validation phase, or
- Detect and recover from the half-initialized state on next launch.

## ~~InitRoot: share validation should verify all shares, not just a quorum~~ (FIXED)

Fixed: `ShareInput` now has a `verify_all` flag. When set (during `ShareVerify`
and `RekeyShareVerify` phases), every custodian must re-enter their share—not
just a threshold quorum. The UI title, remaining-count, completion message, and
instruction panels all reflect the all-shares requirement.

## TUI: revoke cert input should accept Escape in serial field

The revoke-certificate input dialog should allow the operator to press Escape to
cancel even while the cursor is in the serial number field.

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
