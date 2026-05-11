# TODO

## anodize-shuttle: add `list-usb` top-level command

Add a command to enumerate USB devices that could be discs (e.g. USB mass-storage
devices, optical drives). Useful for operator discovery before ceremony start.
The `lint --list-usb` help text references this but it doesn't exist yet.

## Findings from e2e runs

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

### cdemu-swap-disc.sh: gdbus not found

`make cdemu-swap-disc` fails with "ERROR: gdbus not found" because
`gdbus` is only in the Nix store, not in `$PATH`.  The fallback path
(`/run/current-system/sw/bin/gdbus`) doesn't exist; the actual binary is
deep in `/nix/store/...glib-2.86.3-bin/bin/gdbus`.
Workaround: run the swap commands manually via debug SSH as ceremony user.
Fix: have the NixOS module drop a wrapper at `/run/anodize/bin/gdbus`.

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
