# Root CA Signing Ceremony — Intermediate CA Runbook

This runbook covers signing an intermediate CA certificate from a CSR, and optionally
issuing an updated CRL.

**Frequency**: this ceremony is performed each time a new intermediate CA is commissioned.
It is less sensitive than the init ceremony but still requires the YubiHSM 2 with the
root key and a quorum of custodian shares.

---

## Prerequisites

- [ ] Intermediate CA operator has generated a keypair and produced a CSR (DER-encoded)
- [ ] CSR has been delivered to the root CA custodian via a verified channel
- [ ] Root CA custodian has the YubiHSM 2 containing the root key
- [ ] At least *k* share-holding custodians are present (where *k* is the SSS threshold)
- [ ] Ceremony audit disc from the init ceremony is available
- [ ] `profile.toml` is configured with `key_label` matching the root key on the HSM
- [ ] CSR file is on the shuttle USB stick

---

## Procedure

### Step 1 — Boot and set up

1. Boot the Anodize ISO and complete the Setup tab (clock check, profile load, HSM detect).
2. Place the CSR file on the shuttle USB stick before inserting it.

### Step 2 — Select Sign CSR

1. On the Ceremony tab, press `[2]` to select **Sign Intermediate CSR**.
2. The TUI reads the CSR from the shuttle and shows a preview:
   - Subject, public key algorithm, requested extensions.
   - Review and confirm the CSR matches what was agreed.

### Step 3 — Intent burn

The TUI writes an intent session to the audit disc (operation type + parameters)
before any HSM operation. This ensures the declared intent is on record even if
the ceremony is interrupted.

### Step 4 — Quorum: reconstruct the HSM PIN

1. The TUI enters the **Quorum** phase and prompts for custodian shares.
2. Each custodian enters their share word-by-word:
   - Tab autocomplete and per-word validation (green = valid, red = invalid).
   - Each submitted share is verified against its commitment in `STATE.JSON`.
3. Once *k* valid shares are collected, the PIN is reconstructed and verified
   against the PIN verification hash.
4. The TUI logs into the HSM with the reconstructed PIN.

### Step 5 — Sign and verify

1. The TUI signs the CSR using the HSM private key. A two-key confirmation
   dialog requires two sequential keypresses to prevent accidental signing.
2. The Certificate Preview screen shows the issued certificate. Both operators
   verify the fingerprint, subject, issuer, pathLen, validity, and CDP URL.

### Step 6 — Write to disc and shuttle

1. The record session is burned to the audit disc (cert, updated CRL, audit log).
2. The signed certificate is copied to the shuttle USB for delivery.

### Step 7 — Deliver the certificate

Deliver the shuttle USB (or just `intermediate.crt`) to the intermediate CA operator.
They should independently verify the fingerprint.

---

## Issuing a CRL

1. On the Ceremony tab, press `[4]` to select **Issue CRL**.
2. The quorum phase collects shares and reconstructs the PIN (same as above).
3. The TUI signs a fresh CRL using the HSM, burns it to disc, and copies it to
   the shuttle.
4. Publish the resulting DER-encoded CRL to the CDP URL specified in `[ca].cdp_url`.

Verify the CRL:

```sh
openssl crl -in root.crl -inform DER -noout -text
```

---

## Revoking an intermediate

1. On the Ceremony tab, press `[3]` to select **Revoke Certificate**.
2. Enter the serial number of the certificate to revoke.
3. The quorum phase collects shares and reconstructs the PIN.
4. The TUI signs a CRL including the revoked serial, burns it to disc, and
   copies it to the shuttle.
