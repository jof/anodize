# Ceremonies as Scripts

> **Status: experimental.** This engine lives under `anodize-tui/src/ceremony/`
> and runs in parallel with the legacy `ops/` + `dispatch.rs` state machine.
> Operations are being ported one at a time; once all eight are on the new path
> the legacy machinery is removed. See [Porting status](#porting-status).

## Why

The legacy ceremony machinery spreads a single operation across three places:
the global `Action` enum, a per-operation `OpContext` phase FSM (`ops/*.rs`), and
the `ConfirmTarget` re-entry table in `dispatch.rs`. To understand what one
ceremony *does* — and in what order it touches the HSM and the write-once disc —
you have to trace control flow across all three.

The script engine replaces that with **one straight-line function per
operation**. The function reads top to bottom as the ceremony itself; every line
is a real-world effect (ask the operator, sign on the HSM, burn to disc). There
is no hidden state and no other entry point, so the function *is* the complete,
auditable behavior.

## The effect vocabulary

A script is generic over four traits, defined in `ceremony/io.rs`. These are the
*only* things a script can do — its entire authority is its parameter list:

| Trait | Role | Key methods |
|---|---|---|
| `Operator` | The human in the loop | `choose`, `confirm`, `collect_quorum`, `reconfirm_clock`, `prompt_text`, `note` |
| `Vault` → `Session` | The HSM | `login(pin) -> Session`; `Session::issue_crl`, `sign_intermediate`, `record_audit_seq` |
| `Archive` | Write-once disc + shuttle USB | `commit_intent`, `commit_record`, `export_shuttle` |
| `Env<P>` | Read-only inputs | `sss` metadata + the operation's `plan: P`, both computed before the ceremony starts |

Every fallible method returns `Result<_, Abort>`. Because `Session` logs out and
zeroizes the PIN on `Drop`, an early `?` anywhere in a script unwinds cleanly —
the HSM is logged out and no partial state survives. **Abort safety is therefore
a property of the `?` operator, not of any cleanup code the script must
remember to write.**

The same script runs in two worlds:

- **Live** — the adapters in `ceremony/adapters.rs` (`ChannelOperator`, `HsmVault`,
  `DiscArchive`) talk to the real terminal, HSM, and optical drive.
- **Test** — transcript tests pass in fakes that record each call into a `Vec`,
  with no terminal, HSM, or disc required.

## Anatomy of a script file

Every file in `ceremony/scripts/` has the same three parts. Using
`scripts/sign_csr.rs` as the example:

1. **A doc-comment header — the shape in prose.** The numbered list at the top is
   the ceremony written for a human reviewer.

2. **A single `pub fn` — the shape in code.** This is the function you review:

   ```rust
   pub fn sign_csr(
       op: &mut dyn Operator,
       vault: &mut dyn Vault,
       arc: &mut dyn Archive,
       env: &Env<SignCsrPlan>,
   ) -> Result<Outcome, Abort> { ... }
   ```

   The signature is the capability list. The body, top to bottom, is the
   ceremony. Nothing happens off-screen.

3. **`#[cfg(test)] mod tests` — *not* the ceremony.** Fake `Operator`/`Vault`/
   `Archive` impls plus transcript assertions. You read this to confirm the
   ordering is locked down, not to learn what the ceremony does.

## How to review a script

Read the `pub fn` top to bottom and check the **order of effects** against the
security invariants:

- **Intent before anything irreversible** — `arc.commit_intent(...)` precedes
  `vault.login(...)` / signing. The intent WAL records the *attempt* before the
  HSM is touched, so a crash is always recoverable.
- **Unlock before HSM touch** — `op.collect_quorum(...)?` precedes
  `vault.login(pin)?`.
- **Record after signing, shuttle last** — `commit_record(...)` then
  `export_shuttle(...)`.
- **`?` is the abort path** — every `?` is a clean exit; there is no other.

Then drop into `mod tests` and confirm the transcript test asserts exactly that
sequence. For `sign_csr`:

```rust
assert_eq!(effects, vec![
    Effect::Choose,
    Effect::Confirm,          // profile / document review
    Effect::CommitIntent,
    Effect::CollectQuorum,
    Effect::ReconfirmClock,
    Effect::Login,
    Effect::SignIntermediate,
    Effect::Confirm,          // fingerprint verification
    Effect::CommitRecord,
    Effect::ExportShuttle,
]);
```

That `vec!` is the machine-checkable version of the prose header. An `abort_at_*`
test proves an early decline runs nothing irreversible. If a future edit reorders
a step (e.g. signs before committing intent), these tests fail.

Recommended reading order — each is a few minutes and they rhyme:

- `scripts/issue_crl.rs` — simplest (confirm → intent → quorum → clock → sign → record → shuttle)
- `scripts/revoke_cert.rs` — adds a select/prompt loop to pick a cert + reason
- `scripts/sign_csr.rs` — adds a profile menu and a post-sign fingerprint gate

Read those three `pub fn`s plus the trait definitions in `ceremony/io.rs` and you
have reviewed the whole architecture.

## Ordering enforced by the type system

Two invariants are encoded as unconstructible **typestate tokens** rather than
runtime checks (`ceremony/io.rs`):

- `Archive::commit_intent` returns an `IntentCommitted`. `commit_record`
  *consumes* one, so a record can never be burned before its intent exists.
- `commit_record` returns a `RecordCommitted`, which `export_shuttle` requires —
  the disc-before-shuttle rule, expressed as a type.

Neither token can be built by a struct literal outside `io.rs`, so a script
cannot fake the proof. Mis-ordering these steps is a *compile error*, not a
review catch.

## STATE.JSON is the archive's job

A script never assembles `STATE.JSON`. It hands `commit_record` a `RecordSession`
containing a semantic `StateDelta` (e.g. "crl_number is now N", "hsm_log_seq is
M"); the `Archive` folds that delta into the base `SessionState` it holds and
fills in the new audit-chain head computed from the just-appended record event.
This keeps disc/session bookkeeping out of every script.

## How the live TUI drives a script

A running script lives on its own thread. When it needs the operator it sends a
`Prompt` (`ceremony/prompt.rs`) and blocks for a `Response`. The renderer is a
pure function of the current `Prompt`, and the input layer maps a keypress to a
`Response`. This single `Prompt`/`Response` pair replaces the legacy `Action` /
`OpAction` / `ConfirmTarget` trio. Scripts and transcript fakes never see these
types — they are an implementation detail of the channel-backed adapters.

`CeremonyRun` (`ceremony/run.rs`) owns the thread handle, the current prompt, and
any overlay component (e.g. the SSS `ShareInput`), and exposes `spawn_*`
constructors the `App` calls when an operation is selected.

## Porting status

| # | Operation | New engine | Notes |
|---|---|---|---|
| 4 | IssueCrl | ✅ ported | first ceremony on the new path |
| 3 | RevokeCert | ✅ ported | generic `Env<P>`, multi-event records, free-text input |
| 2 | SignCsr | ✅ ported | profile select + post-sign fingerprint gate |
| 1 | InitRoot | ⏳ legacy | needs genesis/bootstrap + custodian-setup + share-reveal primitives |
| 5 | RekeyShares | ⏳ legacy | dual quorum + share reveal |
| 6 | MigrateDisc | ⏳ legacy | disc copy, no HSM signing |
| 7 | KeyBackup | ⏳ legacy | HSM device pairing |
| 8 | ValidateDisc | ⏳ legacy | read-only verification |

Ported operations are routed in `app.rs` (`Action::SelectOperation`); the rest
still fall through to the legacy `do_select_operation` path.

## Related documents

- **[Ceremony Pipeline](ceremony-pipeline.md)** — the legacy state machine this engine replaces
- **[Security](security.md)** — invariants and threat model
- **[Architecture](architecture.md)** — crate structure and HSM traits
