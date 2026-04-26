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

## Wire sentinel into the ceremony ISO

`anodize-sentinel` is implemented (`crates/anodize-tui/src/sentinel.rs`).
It uses `Flock::lock` (non-blocking) on `/run/anodize/ceremony.lock`, clears
`FD_CLOEXEC`, and `exec`s into `anodize-ceremony`. The lock fd is inherited by
the ceremony process and released automatically on exit.

Remaining work:
- Add a `systemd` (or `agetty`-replacement) service unit that runs
  `anodize-sentinel` on both `ttyS0` and the EFI framebuffer (`tty1`) at boot.
- Ensure `/run/anodize/` is created by a `tmpfiles.d` entry or the service unit
  before sentinel starts.
