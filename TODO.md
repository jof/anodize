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
