# Root CA Signing Ceremony — Intermediate CA Runbook

This runbook covers signing an intermediate CA certificate from a CSR, and optionally
issuing an updated CRL.

**Frequency**: this ceremony is performed each time a new intermediate CA is commissioned.
It is less sensitive than the init ceremony but still requires the YubiHSM 2 with the
root key.

**Tool used**: `anodize sign-csr` (CLI, runs on any Linux machine with the YubiHSM plugged
in). The ceremony ISO is not required for signing — it is available if a higher-assurance
environment is needed.

> **Note**: TUI support for CSR signing is planned but not yet implemented. Until then,
> signing is performed with the `anodize` CLI on a controlled, offline machine.

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

```sh
anodize --profile profile.toml sign-csr \
  --csr intermediate.csr \
  --root-cert root.crt \
  --cert-out intermediate.crt \
  --log audit.log \
  --path-len 0 \
  --validity-days 1825
```

**Flags:**

| Flag | Description |
|---|---|
| `--path-len 0` | `pathLenConstraint=0` — the intermediate cannot issue sub-CAs |
| `--validity-days 1825` | 5 years; adjust for your policy |
| `--log audit.log` | Appends a signed audit record; required |

The `sign-csr` command:
1. Decodes the CSR
2. Verifies the CSR self-signature before reading any fields
3. Applies the extension allowlist (BasicConstraints, KeyUsage, SKID, AKID, CDP only)
4. Rejects any CSR that requests extensions outside the allowlist
5. Signs with the HSM and writes `intermediate.crt`
6. Prints the intermediate's SHA-256 fingerprint
7. Appends an audit record to `audit.log`

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

### Step 4 — Verify the audit log

```sh
anodize --profile profile.toml verify-log audit.log
# Expected: Log OK: N records verified  (one more than before this signing)
```

### Step 5 — Deliver the certificate

Deliver `intermediate.crt` to the intermediate CA operator via a verified channel.
They should independently verify the fingerprint.

---

## Issuing a CRL

Issue an initial (empty) CRL immediately after the root ceremony and whenever the
CRL validity window is about to expire:

```sh
anodize --profile profile.toml issue-crl \
  --root-cert root.crt \
  --crl-out root.crl \
  --log audit.log \
  --next-update-days 30
```

Publish `root.crl` to the CDP URL specified in `[ca].cdp_url`.
Verify the CRL:

```sh
openssl crl -in root.crl -inform DER -noout -text
```

---

## Revoking an intermediate

Revocation support (passing serial numbers to `issue-crl`) is currently documented
in the API but not yet exposed via the CLI. Track this in the open questions section
of `docs/design.md`. As a temporary measure, issue a new CRL that pre-dates the
compromised intermediate's notBefore, then distribute it urgently.
