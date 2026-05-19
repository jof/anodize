# TODO

## TUI refactoring follow-ups (refactor/tui-state branch)

The `ops/` module, `OpContext` trait, `AppShared` borrow-split, and
`HardwareManager` extraction are done.  The items below are what remains
to fully capitalise on the new architecture.

### Delete `staging.rs`

`staging.rs` is an empty placeholder:

```
//! Placeholder — StagingDir was removed during dead-code cleanup.
```

Delete the file and remove `mod staging;` from `main.rs`.

### Rename or split `ceremony_ops.rs`

This is the highest-value naming fix.  The actual per-operation ceremony
logic now lives in `ops/`.  What remains in `ceremony_ops.rs` (~2050
lines, ~950 tests) is app-level orchestration:

- **Setup ticks** — `tick_wait_shuttle`, `tick_wait_disc`,
  `process_disc_scan`, `do_detect_hsm`
- **Disc burn lifecycle** — `do_write_intent`, `tick_intent_burn`,
  `do_start_burn`, `tick_record_burn`, `build_burn_session`
- **Shuttle write** — `do_write_shuttle`
- **Operation dispatch** — `do_select_operation`,
  `do_dispatch_after_clock_reconfirm`, `build_intent_audit_event`
- **Rendering helpers** — `render_setup_content`,
  `render_ceremony_content`

Options:
1. Rename to `dispatch.rs` (simple, accurate).
2. Split into `setup_ops.rs` (shuttle/disc/HSM detection ticks),
   `disc_ops.rs` (intent/record burn lifecycle, shuttle write), and
   `dispatch.rs` (select, clock reconfirm, rendering).

Either way the tests move with their functions.

### Add `wants_disc_scan()` to `OpContext`

`background_tick` in `app.rs` hardcodes a `matches!` on
`ActiveOperation::MigrateDisc` to decide whether to call
`tick_wait_disc(true)`.  This defeats the trait abstraction:

```rust
let is_migrate_wait = matches!(
    &self.active_op,
    Some(ActiveOperation::MigrateDisc(ctx))
        if ctx.phase == MigratePhase::WaitTarget
);
```

Add a trait method `fn wants_disc_scan(&self) -> bool` (default `false`)
and implement it on `MigrateCtx`.  Then `background_tick` becomes:

```rust
let needs_scan = self.active_op.as_ref().map_or(false, |op| op.wants_disc_scan());
if needs_scan { self.tick_wait_disc(true); }
```

### Fold `InitRootAbort` / `RetryPostCommit` into existing actions

Both are InitRoot-specific but live in the global `Action` enum:

- `InitRootAbort` — identical effect to `CeremonyCancel` (clears
  `active_op`, resets to `OperationSelect`).  Merge into
  `CeremonyCancel`.
- `RetryPostCommit` — only one call site (`PostCommitError` key
  handler).  Could become an `OpAction::Retry` variant handled inside
  the op, or an `OpAction` method on `OpContext`, keeping the global
  enum smaller.

### Move `DiscContext` to its own module

`DiscContext` (15 fields) and `DiscScanBatch` are defined in `app.rs`
but are large enough to warrant their own file, mirroring the
`HardwareManager` extraction.  A `disc.rs` would own:

- `DiscContext` struct + `impl`
- `DiscScanBatch` struct
- `CertSummary` (disc-derived data)

### Rename `AppShared` → `OpEnv`

`AppShared` is vague — it's specifically the execution environment that
per-operation contexts receive.  `OpEnv` (or `OpContext` if it didn't
shadow the trait) communicates purpose more clearly.  This is cosmetic
but improves readability across all `ops/*.rs` files.

### Collapse `PostCommitError` / `Execute` into op-internal phases

`CeremonyPhase::PostCommitError` and `CeremonyPhase::Execute` are
essentially InitRoot/SignCsr concerns.  Other ops already handle their
error/preview states via their own phase enums (e.g.
`SignCsrPhase::CertPreview`, `InitRootPhase::PostCommitError`).

Reducing the ceremony FSM to:

```
OperationSelect → ActiveOp → Commit → BurningDisc → DiscDone → Done
```

…would push all op-specific phases behind the `OpContext` trait.  This
is the riskiest change — the existing `CeremonyMode::build_body()` and
key handlers for `Execute`/`PostCommitError` would need to move into the
per-op contexts.  Only worth doing after the simpler items above are
done and the test suite is green.

---

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

## Session Continuity
There is a session continuity error where session 2 is missing three files from session 1, like root.cll, root.crt and state.json. We need to make sure it is invariant that each session is a superset of all the files of the session that precedes it.


## Subsequent amounts of the shuttle.
Subsequent mounts of the shuttle do not appear to be working consistently with the auto mount.

## SignCsr: display CSR public-key fingerprint before signing

The Certificate Preview screen currently shows the SHA-256 fingerprint of the
*resulting* certificate DER.  For the SignCsr flow, the operator should also see
a fingerprint derived from the CSR's public key so they can independently verify
(e.g. via `openssl req -in req.pem -noout -pubkey | openssl sha256`) that the
key about to be signed matches what they expect.

## anodize-shuttle adds no default [[cert_profiles]] to profile.toml

We should add some kind of reasonable L1 profile in here so that a default anodize deployment works out of the box.
