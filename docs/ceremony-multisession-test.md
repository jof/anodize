# Multi-Session Ceremony Test

End-to-end test that validates the full ceremony lifecycle across VM reboots:
root CA generation → shutdown → CSR injection → reboot → intermediate signing →
audit log continuity.

## Methodology: AI-driven via term-cli

This test is driven interactively by the AI assistant (Claude/Cascade) using
**term-cli** — interactive terminal sessions that let the assistant read the
rendered TUI screen and send keystrokes adaptively.

**Why not expect?**  The ceremony TUI uses ratatui, which renders with ANSI
cursor-positioning escape codes between words.  Multi-word phrases (e.g.
`Detect HSM`) are not contiguous in the byte stream, making expect-style
pattern matching unreliable and fragile.  Term-cli reads the composed screen
buffer, not the raw escape-code stream, and adapts to whatever is displayed.

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

# Host tools needed:
# - openssl (for CSR generation)
# - mtools (mcopy, mdir — for shuttle image manipulation)
# - qemu-system-aarch64 (or qemu-system-x86_64)
```

## Test flow

### Phase 1: InitRoot

1. `rm -rf dev-disc && mkdir dev-disc` — clean slate
2. Launch QEMU via term-cli (`make qemu-arm64` or the raw command)
3. In a separate terminal, SSH as ceremony user: `ssh -i scripts/dev-ssh-key -p 2222 ceremony@localhost`
4. Drive sentinel (Enter) → setup screens (press 1 through each) → **Init root CA** (option 1)
5. Configure 2-of-2 SSS with custodians Alice and Bob
6. **Capture both shares** from the share distribution screens (press `S` to reveal, read the kebab-case words from the rendered screen)
7. Verify shares by re-entering them word-by-word
8. Generate P-384 keypair → cert preview → confirm
9. Disc burn → shuttle copy → done
10. Quit ceremony (`q`), shutdown VM (`s` at sentinel)

### Inter-boot: CSR preparation

1. Verify `dev-disc/test-bdr.img` persisted on host
2. Generate ephemeral P-384 key + CSR:
   ```sh
   openssl ecparam -name secp384r1 -genkey -noout -out /tmp/ephemeral.key
   openssl req -new -key /tmp/ephemeral.key -subj "/CN=Intermediate CA" -outform DER -out /tmp/csr.der
   ```
3. Inject into shuttle: `mcopy -oi fake-shuttle.img /tmp/csr.der ::csr.der`

### Phase 2: SignCsr

1. Relaunch QEMU — cdemu loads existing BD-R (preserving InitRoot sessions)
2. SSH as ceremony user, drive setup screens
3. Select **Sign intermediate CSR** (option 2)
4. Select cert profile (sub-ca), confirm CSR preview
5. **Quorum phase**: re-enter Alice's and Bob's shares (captured from Phase 1)
6. HSM login → sign CSR → intermediate cert preview → confirm
7. Disc burn → shuttle copy → done
8. Quit and shutdown

### Validation

```sh
ls -la dev-disc/                                      # ≥ 4 session ISOs
mdir -i fake-shuttle.img ::                           # root.crt, intermediate.crt, audit.log
```

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

SSS shares are captured by the AI assistant reading the rendered TUI screen
during InitRoot's share distribution phase.  Each share is a set of BIP39-like
words in kebab-case groups (e.g. `acid-cope-deer-bell`).  The assistant records
these and re-enters them word-by-word during SignCsr's quorum phase.

In production, custodians transcribe shares to paper and re-enter them manually.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `cdemu not on session bus after 30s` | VHBA kernel module failed to load; check ISO build includes vhba |
| Disc state from Phase 1 not found | `dev-disc/test-bdr.img` not persisted; rebuild ISO with cdemu persistence fix |
| `Root key not found` | SoftHSM2 token state not on shuttle; check `softhsm2/tokens/` directory |
| `CSR signature verification failed` | CSR was generated with wrong algorithm; must be P-384 (`secp384r1`) |
| `No cert_profiles defined` | Shuttle `profile.toml` missing `[[cert_profiles]]`; recreate with `make fake-shuttle.img` |
| SSH to ceremony user hangs | VM not ready; poll with `ssh -i scripts/dev-ssh-key -p 2222 debug@localhost true` first |
| Port 2222 in use | Stale QEMU: `lsof -ti :2222 \| xargs kill -9` |
