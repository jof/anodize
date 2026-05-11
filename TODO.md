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

### cdemu-swap-disc.sh brittle PATH handling

The script failed on the debug user because `gdbus` is only in the Nix
store, not in `$PATH`.  The `GDBUS=` fallback tries `command -v` first
which misses the Nix path.  Fix: search known Nix store paths as a
second-order fallback, or have the NixOS module drop a wrapper script at
a well-known location (e.g. `/run/anodize/bin/gdbus`).

## Findings from e2e run (2026-05-11)

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

## Multi-HSM fleet architecture

STATE.JSON now contains an `HsmFleet` with `HsmDevice` entries tracking each
enrolled device by `device_id` (USB serial for YubiHSM, token label for SoftHSM),
model description, backend type, enrollment timestamp, last-seen timestamp, and
status (Active / Removed).

- `SssMetadata.generation` tracks the SSS share generation (incremented on rekey).
- `HsmBackend.open_session_by_id(device_id, pin)` targets a specific device.
- `open_session_any_recognized(fleet_ids, pin)` for fleet-aware login with
  membership enforcement.
- InitRoot bootstraps the primary HSM and enrolls it in the fleet.
- KeyBackup enrolls the destination device in the fleet after successful
  pair/backup.
- Daily ops (quorum login) use fleet-aware session opening and update
  `last_seen_at`.

### Future: cross-vendor HSM resilience

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

