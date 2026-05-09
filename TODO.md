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

## CSR signature verification: remaining algorithm support

ECDSA (curve, hash) decoupling is done — `verify_csr_signature()` now parses the
curve from SPKI and the hash from the signature algorithm OID independently, using
`PrehashVerifier` for all combinations. Covered matrix:

| Curve | Hash    | OID (sigAlg)          | Status |
|-------|---------|-----------------------|--------|
| P-256 | SHA-256 | 1.2.840.10045.4.3.2   | ✅     |
| P-256 | SHA-384 | 1.2.840.10045.4.3.3   | ✅     |
| P-256 | SHA-512 | 1.2.840.10045.4.3.4   | ✅     |
| P-384 | SHA-256 | 1.2.840.10045.4.3.2   | ✅     |
| P-384 | SHA-384 | 1.2.840.10045.4.3.3   | ✅     |
| P-384 | SHA-512 | 1.2.840.10045.4.3.4   | ✅     |

Still missing — needed when accepting CSRs from other PKI stacks:

- **RSA PKCS#1 v1.5** — the standard RSA signature scheme used by the vast
  majority of enterprise and legacy PKI deployments. Needs three OIDs:

  | Key    | Hash    | OID (sigAlg)          |
  |--------|---------|-----------------------|
  | RSA    | SHA-256 | 1.2.840.113549.1.1.11 |
  | RSA    | SHA-384 | 1.2.840.113549.1.1.12 |
  | RSA    | SHA-512 | 1.2.840.113549.1.1.13 |

  The `rsa` crate (`pkcs1v15::VerifyingKey`) provides verification. The SPKI
  algorithm OID is `rsaEncryption` (1.2.840.113549.1.1.1) with NULL parameters.
  `spki_curve()` needs to be generalised to a `spki_key_type()` that returns an
  enum covering EC curves and RSA, then dispatch verification accordingly.

- **Ed25519** (OID 1.3.101.112) — lower priority but increasingly common in
  newer PKI stacks. No hash parameter; signature is over raw TBS. The `ed25519`
  crate provides a verifier.

## Broader key algorithm support

The CA currently only generates and operates with P-384 ECDSA keys (via HSM).
Subordinate CAs and end-entity certificates from other PKI stacks may use
different key types. Support should be added incrementally:

### Classic RSA

Many enterprise and legacy PKI deployments use RSA-2048 or RSA-4096 keys.
Accepting RSA CSRs (PKCS#1 v1.5 signatures) and issuing certificates for RSA
public keys is needed for interop with these environments. The `rsa` crate
provides the building blocks. This does **not** require the root CA key itself
to be RSA — only that `sign_intermediate_csr` can accept and embed RSA SPKIs.

### Post-quantum cryptography (PQC)

NIST PQC standards (ML-DSA / Dilithium, SLH-DSA / SPHINCS+) are being
standardised and will eventually be required for certificate chains. Hybrid
certificates (e.g. P-384 + ML-DSA-65 via composite signatures) are the likely
transition path. No Rust crate ecosystem is mature enough today, but the
architecture should anticipate pluggable signature verification so PQC
algorithms can be added without restructuring `verify_csr_signature` again.

## cdemu: verify multi-session append after CLOSE SESSION

The intent session write confirmed `sessions=0 → write → CLOSE TRACK → CLOSE
SESSION` all succeed. The disc reported `status=Incomplete sessions=1` on the
second open, confirming the first session was committed and the disc remained
appendable. Full end-to-end test (two complete session writes in one ceremony run)
is blocked by the state machine bug above.
