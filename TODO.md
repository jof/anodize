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

## Support serial terminal and EFI framebuffer simultaneously

A single `anodize-tui` process can only run on one terminal. To support both a serial
console and an EFI framebuffer without race conditions, introduce a small **sentinel**
program that runs at boot on each terminal:

- Displays a prompt and waits for a keypress (e.g. `Enter` or a chord)
- On keypress, attempts to acquire an exclusive `flock` on a well-known lockfile
  (e.g. `/run/anodize-ceremony.lock`)
- If the lock is acquired, execs into `anodize-tui` on that terminal
- If the lock is already held, prints a message ("ceremony in progress on another terminal")
  and exits or loops

This guarantees at most one TUI instance runs regardless of which terminal an operator
reaches first. The lockfile is released automatically when `anodize-tui` exits.
