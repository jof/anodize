# Disc Validation Ceremony

Validates the integrity of a ceremony audit disc before and between ceremony
operations. Can be run as a TUI ceremony phase or as a standalone CLI tool.

## Purpose

The Disc Validator answers three questions:

1. **Is the disc consistent?** — sessions form a superset chain, CRL numbers
   don't regress, root cert SHA-256 is constant, and the disc is not
   prematurely finalized.
2. **Is the audit log intact?** — every record's hash chain links correctly
   from genesis through the current session.
3. **Does the HSM agree?** (optional, requires quorum) — the YubiHSM's
   internal audit log is cross-checked against the disc audit log: same
   number of signing operations, no foreign auth keys, no unexpected commands,
   and no unlogged events.

## Checks Performed

### Offline (disc-only)

| Check | Severity | Description |
|---|---|---|
| `disc.finalization` | PASS/ERROR | Disc must be appendable (not finalized) |
| `session.count` | PASS/ERROR | At least one session must exist |
| `session.continuity[N→M]` | PASS/ERROR | Each session's directory listing is a superset of the prior |
| `session.root_cert[N→M]` | ERROR | `root_cert_sha256` must not change between sessions |
| `session.crl_number[N→M]` | ERROR | CRL number must not decrease |
| `session.migration` | PASS | Flags session 0 as a migration from a prior disc |
| `audit.chain[session N]` | PASS/ERROR | Per-session audit log hash chain verification |
| `audit.superset[N→M]` | PASS/ERROR | Later session's audit log is a prefix-superset of earlier |
| `audit.state_hash[N]` | PASS/ERROR | `STATE.JSON` `last_audit_hash` matches actual last record |

### Online (HSM cross-check)

| Check | Severity | Description |
|---|---|---|
| `hsm.unlogged_boots` | PASS/ERROR | No boot events lost to ring buffer overflow |
| `hsm.unlogged_auths` | PASS/ERROR | No auth events lost to ring buffer overflow |
| `hsm.continuity` | PASS/ERROR | No gap between `last_hsm_log_seq` in STATE.JSON and oldest HSM entry |
| `hsm.auth_key` | PASS/ERROR | All operations used anodize's auth key (0x0002) |
| `hsm.command_set` | WARN | Flags unexpected command codes |
| `hsm.sign_count` | PASS/ERROR | HSM sign ops on the ceremony key match `cert.issue` + `crl.issue` disc events |

## TUI Usage

1. Boot the ceremony environment and load the shuttle.
2. At the operation selection screen, press **[8] Validate Disc**.
3. The validator reads the disc and displays the report.
4. If the HSM is available (quorum was run), press **[1] Run HSM cross-check**.
5. Review the updated report with HSM findings.
6. Press **[2] Export report** to write `VALIDATE.LOG` to the shuttle.

## Standalone CLI

```bash
anodize-validate --staging /run/anodize/staging
```

Reads session subdirectories from the staging path. Each subdirectory should
contain at minimum `AUDIT.LOG` and `STATE.JSON`. A top-level `audit.log`
(combined log) is also checked if present.

### Exit Codes

| Code | Meaning |
|---|---|
| 0 | All checks PASS |
| 1 | At least one WARN, no ERRORs |
| 2 | At least one ERROR |

### Example

```
$ anodize-validate --staging /mnt/ceremony-disc
=== Disc Validation Report ===
8 PASS, 0 WARN, 0 ERROR

[PASS] disc.finalization: Disc is appendable (not finalized)
[PASS] session.count: 3 session(s) found
[PASS] session.continuity[0→1]: Session 1 is a superset of session 0 (2 dirs → 4 dirs)
[PASS] session.continuity[1→2]: Session 2 is a superset of session 1 (4 dirs → 6 dirs)
[PASS] audit.chain[session 0]: 5 records, hash chain valid
[PASS] audit.chain[session 1]: 8 records, hash chain valid
[PASS] audit.chain[session 2]: 12 records, hash chain valid
[PASS] audit.combined_chain: Combined audit.log hash chain verified (12 entries)

--- VALIDATION PASSED ---
```

## When to Run

- **Before every ceremony operation** — run validate to confirm the disc is
  in a good state before signing, revoking, or migrating.
- **After unattended storage** — if the disc was stored and later retrieved,
  validate confirms nothing was altered.
- **During audits** — external auditors can run the standalone validator
  without needing HSM access for the offline checks.

## Architecture

- `crates/anodize-audit/src/validate.rs` — pure validation functions, no
  side effects. Takes parsed `SessionSnapshot` structs and returns `Finding`
  vectors.
- `crates/anodize-hsm/src/lib.rs` — `get_audit_log()` / `drain_audit_log()`
  on the `Hsm` trait; `HsmAuditEntry` / `HsmAuditSnapshot` types.
- `crates/anodize-tui/src/ceremony_ops.rs` — TUI integration:
  `do_validate_disc()`, `do_validate_hsm_check()`, `do_validate_export_report()`.
- `crates/anodize-tui/src/validate_disc.rs` — standalone `anodize-validate`
  binary.
- `crates/anodize-config/src/state.rs` — `SessionState.last_hsm_log_seq`
  field for HSM audit continuity anchoring.

## HSM Audit Log Hardening

During bootstrap (`YubiHsmBackend::bootstrap()`), the following audit
configuration is applied:

1. **Force Audit = Fix** — the HSM will halt rather than silently drop log
   entries when the ring buffer fills.
2. **Per-command audit = Fix** — all ceremony-critical commands
   (`SignEcdsa`, `GenerateAsymmetricKey`, `ExportWrapped`, `ImportWrapped`,
   `PutWrapKey`, `ChangeAuthenticationKey`) are permanently set to audit.
3. **Initial log drain** — the bootstrap log entries are drained so the first
   ceremony operation starts with a clean sequence.
