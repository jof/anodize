# Multi-Session Ceremony Test

End-to-end test that validates the full ceremony lifecycle across VM reboots:
root CA generation → shutdown → CSR injection → reboot → intermediate signing →
audit log continuity.

## What it validates

| Property | How |
|---|---|
| **InitRoot ceremony** | Generates root CA keypair + self-signed cert via SoftHSM2 |
| **Disc persistence** | BD-R image in `dev-disc/` survives VM reboot (cdemu loads existing image) |
| **Shuttle round-trip** | Artifacts written to shuttle FAT image, CSR injected between boots |
| **HSM state persistence** | SoftHSM2 token state on shuttle survives unmount/remount cycle |
| **SSS quorum reconstruction** | Shares captured during InitRoot are re-entered during SignCsr to reconstruct the HSM PIN |
| **SignCsr ceremony** | Intermediate CA cert signed using root key + disc-resident root cert |
| **Multi-session audit log** | Disc contains sessions from both ceremonies; audit log hash chain spans operations |

## Prerequisites

```sh
# Build the dev ISO (requires Nix + Docker for cross-compilation)
make dev-arm64          # or make dev-amd64

# Create the shuttle image (includes [[cert_profiles]] for SignCsr)
rm -f fake-shuttle.img  # force recreation if stale
make fake-shuttle.img

# Host tools
# - expect (Tcl expect)
# - openssl (for CSR generation)
# - mtools (mcopy, mdir — for shuttle image manipulation)
# - qemu-system-aarch64 (or qemu-system-x86_64)
```

## Running the test

```sh
# arm64 (default on Apple Silicon)
expect scripts/e2e-multisession.expect

# x86_64 (requires KVM)
ARCH=amd64 expect scripts/e2e-multisession.expect
```

Full terminal output is logged to `/tmp/anodize-e2e-multisession.log`.

## Test flow

### Phase 1: InitRoot

1. Launch QEMU with dev ISO, shuttle, and empty `dev-disc/`
2. SSH into ceremony user → sentinel → setup screens
3. Select **Init root CA** (option 1)
4. Configure 2-of-2 SSS with custodians Alice and Bob
5. Capture both shares during distribution
6. Verify shares by re-entry
7. Generate P-384 keypair → build self-signed root cert
8. Write intent + record sessions to disc
9. Copy root.crt, root.crl, audit.log to shuttle
10. Quit ceremony, shutdown VM

### Inter-boot: CSR preparation

1. Verify `dev-disc/test-bdr.img` persisted on host
2. Generate ephemeral P-384 key + CSR on host via `openssl`
3. Inject `csr.der` into shuttle FAT image via `mcopy`

### Phase 2: SignCsr

1. Reboot QEMU — cdemu loads existing BD-R (preserving InitRoot sessions)
2. SSH into ceremony user → setup screens
3. Select **Sign intermediate CSR** (option 2)
4. CSR loaded from shuttle, select cert profile (sub-ca)
5. Confirm CSR preview → write intent to disc
6. **Quorum phase**: re-enter Alice's and Bob's shares to reconstruct PIN
7. HSM login with reconstructed PIN → sign CSR → intermediate cert preview
8. Write record session to disc
9. Copy intermediate.crt to shuttle
10. Quit ceremony, shutdown VM

### Validation

- `dev-disc/` contains ≥ 4 session ISO files (2 intent + 2 record)
- Shuttle contains `root.crt`, `intermediate.crt`, `audit.log`
- Audit log has records from both ceremonies with intact hash chain

## Key implementation details

### Disc persistence across reboots

The `cdemu-load-bdr` systemd service in `nix/dev-iso.nix` detects whether
`/run/anodize/share/test-bdr.img` already exists:

- **First boot**: Creates a blank BD-R via `DeviceCreateBlank`
- **Subsequent boots**: Loads the existing image via `DeviceLoad`, preserving
  all prior session data

This mirrors production behavior where a physical BD-R retains all written
sessions.

### Shuttle manipulation

The shuttle is a 64 MiB FAT image (`fake-shuttle.img`) accessed by QEMU as a
USB storage device. Between VM boots (while QEMU is not running), the host can
safely modify it using mtools:

```sh
mcopy -oi fake-shuttle.img /tmp/csr.der ::csr.der   # inject CSR
mdir  -i  fake-shuttle.img ::                        # list contents
```

### Share persistence

SSS shares are captured from the TUI during InitRoot's share distribution
phase. The expect script parses kebab-case word groups from the terminal
output and stores them as Tcl lists. These same shares are re-entered
word-by-word during SignCsr's quorum phase to reconstruct the HSM PIN.

In production, custodians would transcribe shares to paper and re-enter
them manually during subsequent ceremonies.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `cdemu not on session bus after 30s` | VHBA kernel module failed to load; check ISO build includes vhba |
| `Quorum: timed out after intent burn` | Disc state from Phase 1 not persisted; check `dev-disc/test-bdr.img` exists |
| `Root key not found` | SoftHSM2 token state not on shuttle; check `softhsm2/tokens/` directory |
| `CSR signature verification failed` | CSR was generated with wrong algorithm; must be P-384 (`secp384r1`) |
| `No cert_profiles defined` | Shuttle `profile.toml` missing `[[cert_profiles]]`; recreate with `make fake-shuttle.img` |
| Share entry fails | Shares may have been captured incorrectly; check `/tmp/anodize-e2e-multisession.log` for captured words |
