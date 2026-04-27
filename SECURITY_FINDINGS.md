# Anodize Security Findings

Reviewed: 2026-04-26  
Scope: all crates (`anodize-hsm`, `anodize-ca`, `anodize-config`, `anodize-audit`, `anodize-tui`), ceremony state machine, NixOS ISO configuration, and operational procedure.

Findings are ordered by severity. Each is a confirmed true positive, cross-referenced to the exact source location.

---

## CRITICAL

### FIND-01 — SHA-384 hash is computed in the calling process, not inside the HSM

**File:** [crates/anodize-hsm/src/lib.rs:222–235](crates/anodize-hsm/src/lib.rs#L222)  
**Also:** [crates/anodize-ca/src/lib.rs:76–82](crates/anodize-ca/src/lib.rs#L76) (misleading doc comment)

The `Pkcs11Hsm::sign` implementation pre-hashes the message with `sha2::Sha384::digest(data)` in the calling process, then forwards only the digest to the HSM via raw `CKM_ECDSA`. The hash operation therefore runs in the same address space as the ceremony binary, not inside the hardware trust boundary.

```rust
// anodize-hsm/src/lib.rs
fn sign(&self, key: KeyHandle, mech: SignMech, data: &[u8]) -> Result<Vec<u8>> {
    let digest: Vec<u8> = match mech {
        SignMech::EcdsaSha384 => sha2::Sha384::digest(data).to_vec(), // ← in software
        ...
    };
    Ok(self.session().sign(&Mechanism::Ecdsa, key.priv_handle, &digest)?) // raw ECDSA
}
```

The `P384HsmSigner` struct carries a contradictory doc comment:

```rust
// anodize-ca/src/lib.rs
/// The HSM performs hash-then-sign internally via `CKM_ECDSA_SHA384`.
```

This statement is false. The `Hsm` trait also documents: *"All signing operations happen inside the HSM"*, which is only true for the private-key operation, not for hashing.

**Impact:** Any code-execution primitive in the ceremony process — even a logic bug that allows controlled data to reach `sign()` — can substitute a chosen digest for the one that would be produced by the legitimately-presented data, without the HSM detecting the substitution. The primary stated security property of "hash-then-sign inside HSM" is not realized. In the current airgapped, read-only-root environment the exploitability is low, but the architecture does not match the documented security model.

**Fix:** Use `CKM_ECDSA_SHA384` directly (the PKCS#11 v3.0 standard mandates it; SoftHSM2 >= 2.6 and YubiHSM 2 both support it). Remove the software pre-hash. Update the `P384HsmSigner` doc comment.

---

## HIGH

### FIND-02 — Audit-chain verification always fails for legitimate multi-session discs

**File:** [crates/anodize-tui/src/main.rs:1958–1982](crates/anodize-tui/src/main.rs#L1958)

`verify_audit_chain` attempts to treat the AUDIT.LOG files across all disc sessions as a single continuous hash chain. It records the last `entry_hash` seen from session N and checks that the first `prev_hash` of session N+1 equals it.

```rust
fn verify_audit_chain(sessions: &[SessionEntry]) -> bool {
    let mut prev_hash: Option<String> = None;
    for session in sessions.iter() {
        for line in audit_log_lines {
            if let Some(ph) = prev_hash.as_deref() {
                if record.prev_hash != ph { return false; }  // ← always fires
            }
            prev_hash = Some(record.entry_hash);
        }
    }
    true
}
```

A normal disc has two sessions for one operation:
1. **Intent session**: AUDIT.LOG contains `{seq:0, prev_hash: <genesis_hex>, ...}`.
2. **Cert session**: AUDIT.LOG also starts with `{seq:0, prev_hash: <genesis_hex>, ...}` because it was written from the same staging log that was freshly `AuditLog::create`d.

After processing session 1, `prev_hash` = `H(intent_record)`. Session 2's first record has `prev_hash` = `genesis_hex` ≠ `H(intent_record)`. The function returns `false` for every legitimate disc that has at least two sessions.

**MigrateDisc impact:** `do_migrate_confirm` sets `self.migrate_chain_ok = false` for every valid disc. The operator always sees `Chain: FAIL` during migration. Because the check provides no signal value, operators learn to ignore it — defeating the entire purpose of the verification step.

**Fix:** Each session's audit log is an independent chain whose genesis is `SHA-256(profile.toml)`. Verification should either (a) verify each session's log independently, or (b) design the audit-log append in `build_burn_session` to read the chain head from the last disc session's log rather than re-starting from staging.

---

### FIND-03 — `pin_source` safety warning is silently overwritten before the TUI renders

**File:** [crates/anodize-tui/src/main.rs:471–484](crates/anodize-tui/src/main.rs#L471)

When a profile with `pin_source = "env:VAR"` or `pin_source = "file:/path"` is loaded, the background tick sets a warning, then immediately overwrites it with "Profile loaded from USB." in the same function call, before the TUI frame is rendered:

```rust
if profile.hsm.pin_source != PinSource::Prompt {
    self.status = "WARNING: pin_source is not 'prompt' — unsuitable for ceremony".into();
}
// ... check_module_allowed ...
self.profile = Some(profile);
self.state = AppState::ProfileLoaded;
self.status = "Profile loaded from USB.".into();  // ← silently overwrites the warning
```

The operator never sees the PIN-source warning. The ceremony transitions to `ProfileLoaded`, proceeds to HSM login, and runs to completion using a PIN drawn from an environment variable or file on an unprotected path — without any visible indication.

**Impact:** A misconfigured profile that violates the ceremony security policy passes silently. The `PinSource::warn_if_unsafe` method exists but is not called anywhere in the TUI path.

**Fix:** Do not overwrite the warning. Either (a) block the state transition to `ProfileLoaded` when `pin_source != Prompt` and display an explicit error that requires operator acknowledgement, or (b) set the warning as a persistent banner rather than the transient status line.

---

## MEDIUM

### FIND-04 — `AuditLog::open` initialises `last_hash = ""` for empty files

**File:** [crates/anodize-audit/src/lib.rs:152–207](crates/anodize-audit/src/lib.rs#L152)

`AuditLog::create` initialises `last_hash = hex::encode(genesis)` and writes nothing to the file. If the process crashes or errors between `create` and the first `append`, the file on disk is empty. When `build_burn_session` later calls `AuditLog::open` on that empty file, `last_hash` defaults to `""`:

```rust
pub fn open(path: &Path) -> Result<Self, AuditError> {
    ...
    let mut last_hash = String::new();  // ← empty, not genesis
    for line in reader.lines() { ... } // no lines → last_hash stays ""
    Ok(Self { ..., last_hash, ... })
}
```

The first `append` will write a record with `prev_hash = ""`, silently severing the genesis anchor. `verify_log` will accept the chain (it re-derives the hash using `""` as the prev_hash, which matches), but the chain is no longer anchored to `SHA-256(profile.toml)`. Auditors relying on the genesis link to verify a specific profile was in use will get a false positive.

**Fix:** Either write the genesis sentinel record to disk during `create`, or have `open` return an error for an empty file rather than an empty `last_hash`.

---

### FIND-05 — EC point parsing heuristic can misidentify an unwrapped P-384 point as wrapped

**File:** [crates/anodize-hsm/src/lib.rs:308–322](crates/anodize-hsm/src/lib.rs#L308)

The fallback SPKI builder strips the DER OCTET STRING wrapper from `CKA_EC_POINT` using a structural heuristic:

```rust
if ec_point_raw.len() > 2 && ec_point_raw[0] == 0x04 && ec_point_raw[2] == 0x04 {
    let inner_len = ec_point_raw[1] as usize;
    if inner_len + 2 == ec_point_raw.len() {
        &ec_point_raw[2..]  // strip outer OCTET STRING
    } else { ec_point_raw }
} else { ec_point_raw }
```

For a raw (unwrapped) P-384 uncompressed point `0x04 || X(48) || Y(48)` (97 bytes):
- `[0] = 0x04` ✓
- `[2] = X[1]` — if the second byte of X happens to equal `0x04` (~1/256 chance)
- `[1] = X[0]` — the inner_len check requires `X[0] + 2 == 97`, i.e. `X[0] == 0x5F`

If both conditions are met (~1 in 65,536 keys), the heuristic incorrectly strips the first two bytes, producing a malformed SPKI. The resulting certificate would embed an invalid public key. The `VerifyingKey::from_public_key_der` call in `P384HsmSigner::new` would likely fail at this point, preventing a bad cert from being issued, but the error message would be opaque.

**Fix:** Apply the OCTET STRING stripping only when `ec_point_raw[0] == 0x04` (OCTET STRING tag) and verify that the inner content starts with `0x04` (uncompressed point marker) rather than assuming position `[2]` is the uncompressed point marker. Alternatively, use a proper DER parser.

---

## LOW

### FIND-06 — Duplicate revocation entries not detected

**File:** [crates/anodize-tui/src/main.rs:795–841](crates/anodize-tui/src/main.rs#L795)

`do_add_revocation_entry` appends a `RevocationEntry` to `self.revocation_list` without checking whether the serial number is already present. An operator who accidentally revokes the same certificate twice in separate ceremony sessions (each loading from disc and appending) would produce a REVOKED.TOML and CRL with duplicate entries. X.509 CRLs with repeated serial numbers are technically non-conformant per RFC 5280 §5.3.3.

**Fix:** Check for duplicate serial numbers before appending and display an error or warning.

---

### FIND-07 — CRL entries carry no revocation reason codes

**File:** [crates/anodize-ca/src/lib.rs:261–269](crates/anodize-ca/src/lib.rs#L261)

The `issue_crl` function sets `crl_entry_extensions: None` for all revoked certificates:

```rust
Ok(RevokedCert {
    serial_number: SerialNumber::from(*serial),
    revocation_date: ...,
    crl_entry_extensions: None,  // ← reason code never encoded
})
```

The operator-entered reason (e.g. "key-compromise") is stored in REVOKED.TOML on disc, but is never encoded into the CRL's per-entry extensions (RFC 5280 §5.3.1). Relying parties consuming the CRL cannot determine why a certificate was revoked, and OCSP stapling or policy automation that checks for `keyCompromise` vs `affiliation­Changed` has no signal.

**Fix:** Map known free-text reasons (e.g. "key-compromise") to RFC 5280 reason code OIDs and encode them as `CRLReason` extensions on `RevokedCert`.

---

### FIND-08 — Root certificate serial number is always hardcoded to 1

**File:** [crates/anodize-ca/src/lib.rs:148](crates/anodize-ca/src/lib.rs#L148)

```rust
let builder = CertificateBuilder::new(
    Profile::Root,
    SerialNumber::from(1u64),  // ← hardcoded
    ...
)
```

RFC 5280 §4.1.2.2 requires serial numbers to be unique per issuer and recommends unpredictability. A self-signed root CA is its own issuer; issuing a second root certificate for the same CA (e.g., via the "Use existing key / resume" path) would produce two certificates with the same issuer and serial 1. Browsers and certificate transparency logs that track by (issuer, serial) would treat them as the same certificate.

**Fix:** Generate a cryptographically random or entropy-derived serial number rather than the constant 1.

---

### FIND-09 — Session directory name collision within the same second causes silent data loss

**File:** [crates/anodize-tui/src/media/mod.rs:287–289](crates/anodize-tui/src/media/mod.rs#L287)

`session_dir_name` formats `confirmed_time` to one-second precision (`YYYYMMDDTHHMMSSZ`). If two separate ceremony runs complete within the same UTC second (possible after a crash-and-immediate-reboot), both produce the same disc directory name. `read_disc_sessions` deduplicates by `dir_name`:

```rust
all_sessions.sort_by(|a, b| a.dir_name.cmp(&b.dir_name));
all_sessions.dedup_by(|a, b| a.dir_name == b.dir_name);
```

`dedup_by` removes the second element (the newer session's data), silently discarding it. The disc record of the second ceremony is permanently lost.

**Fix:** Append nanoseconds or a monotonic counter to the directory name format, or detect the collision and append a numeric suffix.

---

### FIND-10 — `--skip-disc` bypasses the optical archive requirement with no visual indicator

**File:** [crates/anodize-tui/src/main.rs:57–60](crates/anodize-tui/src/main.rs#L57), [main.rs:1254](crates/anodize-tui/src/main.rs#L1254)

The `--skip-disc` CLI flag causes the ceremony to write ISO images to `/run/anodize/staging` (tmpfs, cleared on reboot) instead of the write-once optical disc. Dev feature flags (`dev-usb-disc`, `dev-softhsm-usb`) display a prominent red "DEV BUILD" banner; `--skip-disc` on a production binary shows no visual distinction. The state machine still transitions through `DiscDone → UsbWrite`, satisfying structural state checks, but no optical record is ever created.

**Mitigating factor:** On the production NixOS ISO, `ceremony-shell` execs the sentinel with no arguments, and the sentinel execs `anodize-ceremony` with no arguments (`Command::new(CEREMONY_BIN).exec()`), making `--skip-disc` inaccessible through the normal boot path. A developer host running the binary directly, or any path that allows argument injection, would not have this protection.

**Fix:** If `skip_disc` is set, display the same red warning banner as the dev-feature builds. Consider removing the flag from release builds entirely.

---

### FIND-11 — `confirmed_time` is used for session directory names but not for certificate timestamps

**File:** [crates/anodize-tui/src/main.rs:1260](crates/anodize-tui/src/main.rs#L1260), [main.rs:1530](crates/anodize-tui/src/main.rs#L1530); [crates/anodize-ca/src/lib.rs:143](crates/anodize-ca/src/lib.rs#L143)

`confirmed_time` (captured once at `ClockCheck`) is correctly used for session directory names but is **not** used for certificate validity periods or audit log timestamps. Both are derived from `SystemTime::now()` at the time of signing.

- In `build_root_cert`: `Validity::from_now(...)` uses the instant the signing call is made.
- In `now_rfc3339()` inside `anodize-audit`: uses `SystemTime::now()`.

The ClockCheck step shows the operator the clock and requires explicit confirmation that it is correct. However, if the system clock drifts between ClockCheck and the actual HSM operation (unlikely on a live-boot system with no NTP, but possible if CMOS is wrong), the confirmed clock and the certificate timestamps will diverge. This also means audit log timestamps can differ from the session directory name, making cross-referencing harder.

**Fix:** Derive certificate `notBefore` and audit log timestamps from `confirmed_time` rather than `SystemTime::now()`, or — where wall-clock precision is required — at least assert that `SystemTime::now()` remains within a configurable tolerance of `confirmed_time` before proceeding.
