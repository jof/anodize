# TODO

## Clock drift guard blocks disc write

The "Clock drift > 5 min since ClockCheck" warning appears in the status bar after
the ceremony takes several minutes (e.g. typing 34-word shares twice). Once the
drift guard fires, the cert preview shows `[1] Proceed to disc write` but the
write modal's confirm step doesn't advance. Either:
- Relax the drift threshold for dev builds, or
- Let the operator re-confirm the clock without restarting the entire ceremony.

## InitRoot: escape during share validation can leave half-initialized state

During InitRoot, after shares have been generated and the operator is validating
them (re-entering words), it is possible to press Escape or quit. This leaves
the ceremony in a half-initialized state: the HSM key material may already exist
and shares may have been partially distributed, but no cert or disc write has
occurred. On the next boot the appliance may not recognize the incomplete state
cleanly. Need to either:
- Prevent escape/quit during the share validation phase, or
- Detect and recover from the half-initialized state on next launch.

## TUI: revoke cert input should accept Escape in serial field

The revoke-certificate input dialog should allow the operator to press Escape to
cancel even while the cursor is in the serial number field.

## anodize-shuttle: add `list-usb` top-level command

Add a command to enumerate USB devices that could be discs (e.g. USB mass-storage
devices, optical drives). Useful for operator discovery before ceremony start.
The `lint --list-usb` help text references this but it doesn't exist yet.

## TUI: clock re-confirm screen shows nanosecond precision

The clock re-confirm screen displays the timestamp with nanosecond granularity.
Seconds is sufficient—truncate the display to whole seconds.

## TUI: signing review should show the resulting certificate structure, not just CSR + profile name

The CSR-signing review screen currently displays the raw CSR fields alongside the
certificate profile name. This gives reviewers insufficient information to
understand what the final signed certificate will actually contain. The review
screen should instead present the *compiled* certificate document structure—i.e.
the result of applying the selected profile to the CSR—so that custodians can
verify the exact extensions, key usages, validity period, issuer chain, and any
profile-injected fields before authorizing the signature. Showing the certificate
as it will be signed (rather than its two inputs separately) eliminates guesswork
and makes the approval decision meaningful.

## Unify certificate serial number generation and prevent reuse

Serial number generation in `anodize-ca/src/lib.rs` uses two unrelated codepaths:

- **Root CA** (`build_self_signed_root`): 128-bit random via `random_serial()`.
- **Subordinate certs** (`sign_intermediate_csr`): nanosecond Unix timestamp
  truncated to `u64`.

These should be consolidated into a single `generate_serial()` function that:

1. **Uses the same entropy source for all certs.** 128-bit random is the right
   default (per CA/Browser Forum Baseline Requirements §7.1, serials must contain
   at least 64 bits of output from a CSPRNG). The timestamp approach is weaker—two
   signing operations in the same nanosecond would collide, and the serial leaks
   the exact signing time.

2. **Checks for collisions against previously-issued serials.** For the self-signed
   root there is nothing to check against (it is the first cert the CA issues). For
   every subsequent certificate the CA signs, the function should accept an iterator
   of previously-issued serial numbers (extracted from `prior_sessions` `.CRT`
   files) and reject/regenerate if a collision is found. With 128-bit random serials
   this is astronomically unlikely, but an explicit check costs nothing and
   eliminates the theoretical risk entirely.

### Proposed API

```rust
/// Generate a fresh serial number that does not collide with any
/// previously-issued serial.  `existing` may be empty for the root cert.
fn generate_serial(
    existing: &HashSet<SerialNumber>,
) -> Result<SerialNumber, CaError>;
```

### Call sites to update

- `build_self_signed_root()` — pass empty set (no prior certs).
- `sign_intermediate_csr()` — pass set of serials from `prior_sessions`.
- Any future CRL or cross-sign codepaths.

### Notes

- The `cert_list` gathered for the revocation picker (`CertSummary`) already
  walks `prior_sessions` and extracts serials. Factor the serial-set extraction
  into a shared helper so both the picker and serial generation can use it.
- The collision check loop should cap retries (e.g. 8) and fail hard rather than
  loop forever, as a paranoid defense against CSPRNG failure.

## CSR signature verification: flexible algorithm support

`verify_csr_signature()` in `anodize-ca/src/lib.rs` currently hard-codes two
combinations: P-256/SHA-256 and P-384/SHA-384. It assumes the signature algorithm
OID implies a specific curve—e.g. `ecdsa-with-SHA256` → P-256—so a CSR that pairs
a P-384 key with a SHA-256 signature (perfectly valid, and what OpenSSL produces by
default for `ecparam -name secp384r1`) is rejected as corrupt.

The fix should decouple curve detection from the hash algorithm OID:

1. **Parse the SPKI to determine the actual curve** (from the algorithm parameters
   OID inside SubjectPublicKeyInfo), independent of the signature algorithm.
2. **Match the signature hash from the outer algorithm OID** (SHA-256, SHA-384,
   SHA-512).
3. **Verify using the correct (curve, hash) pair.** This gives a matrix of
   supported combinations rather than a 1:1 mapping.

Target combinations to support:

| Curve   | Hash    | OID (sigAlg)              | Status   |
|---------|---------|---------------------------|----------|
| P-256   | SHA-256 | 1.2.840.10045.4.3.2       | ✅ works |
| P-256   | SHA-384 | 1.2.840.10045.4.3.3       | missing  |
| P-384   | SHA-256 | 1.2.840.10045.4.3.2       | ❌ broken|
| P-384   | SHA-384 | 1.2.840.10045.4.3.3       | ✅ works |
| P-384   | SHA-512 | 1.2.840.10045.4.3.4       | missing  |
| Ed25519 | —       | 1.3.101.112               | missing  |
| Ed448   | —       | 1.3.101.113               | missing  |
| RSA-PSS | SHA-256 | 1.2.840.113549.1.1.10     | missing  |
| RSA-PSS | SHA-384 | 1.2.840.113549.1.1.10     | missing  |

EdDSA and RSA-PSS are lower priority but worth supporting since subordinate CAs
from other PKI stacks may use them. The `spki` and `signature` crates already
provide the building blocks; the main work is restructuring the match to dispatch
on (curve, hash) rather than assuming OID ↔ curve.

## cdemu: verify multi-session append after CLOSE SESSION

The intent session write confirmed `sessions=0 → write → CLOSE TRACK → CLOSE
SESSION` all succeed. The disc reported `status=Incomplete sessions=1` on the
second open, confirming the first session was committed and the disc remained
appendable. Full end-to-end test (two complete session writes in one ceremony run)
is blocked by the state machine bug above.
