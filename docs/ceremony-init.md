# Root CA Key Ceremony — Initialization Runbook

This runbook covers the one-time ceremony to generate the root CA keypair,
issue the self-signed root certificate, and commit both to archival media.

**Threat model reminder**: Anodize cannot protect you from ceremony discipline failures,
a compromised ISO build host, or a stolen YubiHSM with a known PIN. See `docs/design.md`
for the full threat model stub.

---

## Prerequisites

### Hardware checklist

- [ ] Air-gapped machine (no network interfaces active; verify with BIOS)
- [ ] YubiHSM 2 (fresh, factory-reset or verified clean)
- [ ] M-Disc optical drive + one blank M-DISC
- [ ] USB stick with profile.toml (prepared below)
- [ ] Paper checklist printed in advance (for fingerprint verification)
- [ ] At least two operators present (four-eyes principle)

### Software: verify the ISO

Before the ceremony, verify the ISO integrity on a connected machine:

```sh
# Download the ISO and its signature from the release page.
sha256sum --check anodize-YYYYMMDD.iso.sha256
gpg --verify anodize-YYYYMMDD.iso.sig anodize-YYYYMMDD.iso
```

The commit hash → ISO hash mapping is published in the release notes.
Anyone with the source can independently reproduce the build: `nix build .#iso`.

### Prepare the USB profile

Create `profile.toml` on the USB stick that will be inserted during ceremony:

```toml
[ca]
common_name  = "Example Root CA"
organization = "Example Corp"
country      = "US"
cdp_url      = "http://crl.example.com/root.crl"  # must be reachable after ceremony

[hsm]
module_name  = "yubihsm_pkcs11.so"
token_label  = "anodize-root-2026"   # must match the token you initialised
key_label    = "root-key"
key_spec     = "ecdsa-p384"
pin_source   = "prompt"              # always prompt for ceremony
```

Print a copy of this file. Two operators should independently verify the values
before the ceremony begins.

---

## Ceremony procedure

### Step 1 — Prepare the YubiHSM 2

On a separate air-gapped machine (or before bringing the HSM to the ceremony room):

```sh
# Reset to factory defaults (clears all keys and objects).
yubihsm-shell -p password
> session open 1
> reset device
> session close
```

The HSM PIN is **not** chosen manually. It will be generated as a 32-byte random value
by the ceremony TUI and split via Shamir Secret Sharing among the custodians.

Seal the HSM in a tamper-evident bag labelled with today's date and the token label.

### Step 2 — Boot the ceremony ISO

1. Insert the ISO on USB (or optical) and the blank M-Disc into the ceremony machine.
2. Power on; boot from the Anodize ISO.
3. The ceremony TUI starts automatically on the console. You should see the welcome screen.
4. Verify the CA subject, org, country, disc path, and USB path shown on screen match
   your printed profile.

### Step 3 — Insert USB and YubiHSM

1. Insert the USB stick containing `profile.toml`.
2. The launcher detects `profile.toml` and loads the TUI with your profile values.
3. Insert the YubiHSM 2. The TUI detects the HSM via PKCS#11 (no login yet).
   The status bar shows "HSM detected" once the token is found.

### Step 4 — Select InitRoot and configure custodians

1. Switch to the Ceremony tab and press `[1]` to select **Init Root CA**.
2. The Custodian Setup screen appears:
   - Enter each custodian's name and press Enter to add them (minimum 2).
   - After all names are entered, press Enter to advance to threshold selection.
   - Choose the threshold *k* (minimum 2, maximum *n*). This is the number of
     shares required to reconstruct the HSM PIN.
   - Press Enter to confirm.
3. The TUI generates a 32-byte random PIN, splits it into *n* Shamir shares
   (*k*-of-*n*), and computes per-share commitments and a PIN verification hash.
   These are stored in `STATE.JSON` on the audit disc.

### Step 5 — Distribute shares to custodians

1. The Share Reveal screen shows one share at a time as a numbered word grid.
   Shares are hidden by default — the custodian presses `[S]` to reveal.
2. Each custodian transcribes their share onto paper, then presses Enter to confirm.
   The screen clears before the next custodian steps forward.
3. After all shares are distributed, a verification round collects *k* shares
   back via word-by-word entry with Tab autocomplete and per-word validation.
   Shares are verified against their commitments.

### Step 6 — Generate the root keypair

1. On the Key Management screen, press `[1]` to generate a new P-384 keypair,
   or `[2]` to use an existing key.
   - The TUI logs into the HSM using the generated PIN (held in memory).
   - `C_GenerateKeyPair` is called on the HSM; the private key never leaves the device.
   - The public key is read back for certificate construction.

### Step 7 — Verify the fingerprint

The Certificate Preview screen shows:

```
  Subject  : CN=Example Root CA, O=Example Corp, C=US
  Validity : 7305 days (20 years)

  SHA-256 Fingerprint:
  A1B2C3D4:E5F6A7B8:...
```

**Both operators must independently verify this fingerprint against the printed copy
prepared before the ceremony. Do not proceed if they do not match.**

If the fingerprint is wrong, press `[q]` to abort. Investigate before retrying.

### Step 8 — Write to M-Disc

1. Insert the blank M-DISC into the optical drive.
2. Ensure the disc path (shown on welcome screen, default `/run/media/ceremony/disc`)
   corresponds to the mounted M-Disc.
3. The TUI writes an intent session first, then performs the HSM operation,
   then writes the record session. This two-session WAL pattern ensures
   crash recoverability.

The ceremony tool writes:
- `root.crt` — DER-encoded root certificate
- `root.crl` — initial empty CRL
- `STATE.JSON` — SSS metadata (custodian roster, share commitments, PIN verify hash)
- `audit.log` — JSONL audit log with genesis hash = SHA-256(root.crt)

Both operators record the time and confirm the disc write succeeded.

### Step 9 — Write to USB (shuttle)

1. Press `[1]` — Write to shuttle USB.

The ceremony tool copies artifacts to the USB stick. This step is
only reachable after the M-Disc write completes successfully.

### Step 10 — Verify audit log

On a separate machine (can be the USB copy), verify the audit log using the
`verify_log` function from the `anodize-audit` library. Expected result: 1 record
verified, hash chain intact.

> **Note**: a standalone audit log verification tool via the TUI is not yet implemented.

### Step 11 — Finalise and store

1. Remove the YubiHSM 2.
2. Remove the M-Disc; label it with date, CA name, and SHA-256 fingerprint.
3. Remove the USB stick.
4. Power off the ceremony machine.
5. Store the YubiHSM 2, M-Disc, and USB in separate locations with separate custodians.
6. Each custodian stores their paper share securely. No single custodian can
   reconstruct the PIN — at least *k* shares are required.

---

## Post-ceremony

- Publish `root.crt` (the DER file) to your CRL distribution point and any relying parties.
- Record the fingerprint in your CA Policy documentation.
- File the signed audit log print-out with the ceremony paperwork.

---

## Abort procedure

If anything unexpected occurs:

1. Press `[q]` to exit the TUI at any point before M-Disc commit — nothing has been written.
2. If M-Disc write has completed but USB write has not — the M-Disc is the primary record
   and is valid. The USB write can be retried from the M-Disc copy.
3. If the keypair was generated but cert build failed — the key exists on the HSM with
   the configured label. On retry, press `[2]` (Use existing key) on the Key Management
   screen instead of `[1]` (Generate new keypair).
