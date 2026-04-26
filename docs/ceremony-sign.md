# Root CA Signing Ceremony — Intermediate CA Runbook

This runbook covers signing an intermediate CA certificate from a CSR, and optionally
issuing an updated CRL.

**Frequency**: this ceremony is performed each time a new intermediate CA is commissioned.
It is less sensitive than the init ceremony but still requires the YubiHSM 2 with the
root key.

> **Note**: CSR signing and CRL issuance via the ceremony TUI are not yet implemented.
> Until then, perform these operations on a controlled, offline machine with direct
> access to the `anodize-ca` and `anodize-audit` library crates.

---

## Prerequisites

- [ ] Intermediate CA operator has generated a keypair and produced a CSR (DER-encoded)
- [ ] CSR has been delivered to the root CA custodian via a verified channel
- [ ] Root CA custodian has the YubiHSM 2 containing the root key
- [ ] `root.crt` (root certificate DER) is available
- [ ] `audit.log` from the init ceremony is available
- [ ] `profile.toml` is configured with `key_label` matching the root key on the HSM

---

## Procedure

### Step 1 — Verify the CSR

On any machine, inspect the CSR before signing:

```sh
openssl req -in intermediate.csr -inform DER -noout -text
```

Confirm with the intermediate CA operator:
- Subject matches what was agreed (CN, O, C)
- Public key algorithm is correct (EC P-384 recommended)
- No unexpected extensions

### Step 2 — Sign the intermediate CSR

CSR signing is not yet exposed through the ceremony TUI. It must be performed programmatically
using the `anodize-ca` library:

- `sign_intermediate_csr` verifies the CSR self-signature before parsing any fields
- Extension allowlist enforced: BasicConstraints (CA:TRUE, configurable pathLen), KeyUsage
  (keyCertSign | cRLSign), SKID, AKID, CDP only — all other CSR extensions are rejected
- Audit record appended to `audit.log` on success

### Step 3 — Verify the issued certificate

```sh
openssl x509 -in intermediate.crt -inform DER -noout -text
openssl verify -CAfile root.crt intermediate.crt
```

Confirm with the intermediate CA operator:
- Subject matches the CSR
- Issuer is the root CA
- `pathLenConstraint` is present and correct
- Validity period is as expected
- `CRLDistributionPoints` extension contains the correct CDP URL (from `[ca].cdp_url`)

### Step 4 — Deliver the certificate

Deliver `intermediate.crt` to the intermediate CA operator via a verified channel.
They should independently verify the fingerprint.

---

## Issuing a CRL

CRL issuance is not yet exposed through the ceremony TUI. Use the `anodize-ca` library's
`issue_crl` function directly. Publish the resulting DER-encoded CRL to the CDP URL
specified in `[ca].cdp_url`.

Verify the CRL:

```sh
openssl crl -in root.crl -inform DER -noout -text
```

---

## Revoking an intermediate

Revocation support (passing serial numbers to `issue-crl`) is documented in the `anodize-ca`
API but not yet exposed via the TUI. Track this in the open questions section of
`docs/design.md`.
