# Full End-to-End Ceremony Test Plan

Covers the complete ceremony lifecycle on a dev VM (bare-metal or QEMU)
running the NixOS dev ISO with SoftHSM and cdemu:

    InitRoot → KeyBackup → SignCsr → RevokeCert → IssueCrl →
    RekeyShares → MigrateDisc → ValidateDisc

Each operation is a separate ceremony session (Ctrl+C exits → sentinel
restarts → next SSH connects to a fresh TUI).

All verification is done via the **debug SSH shell** on the guest.  The
cdemu BD-R image and session ISOs live at `/run/anodize/share/` inside
the VM.  There is no 9p host share on standalone hardware.

## Prerequisites

| Item | Command / Notes |
|------|-----------------|
| Dev ISO built | `make dev-amd64` or `make dev-arm64` |
| Shuttle image | `make fake-shuttle.img` |
| VM running | `make qemu-dev` (local) or bare-metal with `DEV_VM_IP` set |
| SSH reachable | `make ssh-dev-debug` (local) or `make ssh-vm-debug` (remote) |
| CSR on shuttle | Place `csr.der` in `fake-shuttle.img` before SignCsr (see step 3) |

### Environment variables

```sh
# Remote VM (bare metal or cloud):
export DEV_VM_IP=192.168.178.76

# Local QEMU:
#   Uses localhost:2222 (DEV_SSH_PORT) — no DEV_VM_IP needed.
```

### SSH helper

All `make ssh-*` and `make cdemu-*` targets use `scripts/dev-ssh-key`:

```sh
# Ceremony TUI (interactive):
make ssh-vm              # remote
make ssh-dev             # local QEMU

# Debug shell:
make ssh-vm-debug        # remote
make ssh-dev-debug       # local QEMU
```

---

## Phase 1: InitRoot

**Goal**: Bootstrap root CA — generate P-384 key, create self-signed root cert,
split HSM PIN into 2-of-2 SSS shares, burn session 0 to disc.

**Menu key**: `1` (Init root CA)

### Steps

1. SSH into ceremony TUI.
2. Sentinel: press Enter.
3. ClockCheck: press `1` (clock correct).
4. ProfileLoaded: press `1` (detect HSM).
5. HSM detection: press `1` (acknowledge — token not yet initialized).
6. InsertDisc: press `1` (confirm disc — cdemu BD-R).
7. OperationSelect: press `1` (Init root CA).
8. CustodianSetup: enter `Alice<Enter>`, `Bob<Enter>`, `<Tab>`, `<Enter>` (2-of-2).
9. ShareReveal #1: press `S` to reveal, **record all words**, press Enter.
10. ShareReveal #2: press `S` to reveal, **record all words**, press Enter.
11. ShareInput #1 (Alice): re-enter words one at a time separated by spaces.
12. ShareInput #2 (Bob): re-enter words.
13. KeyAction: press `1` (generate new P-384 keypair).
14. Wait for intent burn + HSM keygen + cert build (up to 120 s).
15. CertPreview: **record root cert fingerprint**, press `1` (proceed to disc write).
16. Write confirmation: press Enter.
17. Wait for disc burn (up to 180 s).
18. DiscDone: press `1` (copy artifacts to shuttle).
19. Done: Ctrl+C to exit.

### Verification

All verification runs via the debug shell on the guest:

```sh
make ssh-vm-debug   # or: make ssh-dev-debug (local QEMU)

# BD-R image written by cdemu:
ls -lh /run/anodize/share/test-bdr*.iso

# Shuttle artifacts (root.crt + root.crl + audit.log):
ls -l /mnt/usb/
openssl x509 -in /mnt/usb/root.crt -inform DER -noout -subject -fingerprint
```

### Artifacts to save

| Artifact | Location | Used by |
|----------|----------|---------|
| Alice's share words | transcribed | Phase 3, 4, 5, 6 |
| Bob's share words | transcribed | Phase 3, 4, 5, 6 |
| Root cert fingerprint | screen / shuttle `root.crt` | all subsequent phases |
| `pin_verify_hash` | STATE.JSON on disc | debug reference |

---

## Phase 2: KeyBackup

**Goal**: Pair a second SoftHSM token and backup the signing key via
wrap-export / wrap-import.

**Menu key**: `7` (Key backup)

**Prerequisite**: Phase 1 complete (STATE.JSON exists on disc).

### Steps

1. SSH into ceremony TUI (sentinel restarts automatically).
2. Boot through ClockCheck → Profile → HSM → Disc as before.
3. OperationSelect: press `7` (Key backup).
4. BackupQuorum: re-enter threshold shares (Alice + Bob) to reconstruct PIN.
5. Backup device discovery: TUI shows available SoftHSM tokens.
6. Select source → select target → confirm.
7. Wait for wrap-export + wrap-import.
8. DiscDone: press `1` (shuttle write).
9. Done: Ctrl+C.

### Verification

```sh
make ssh-vm-debug

# Verify both SoftHSM tokens have the signing key:
pkcs11-tool --module $SOFTHSM2_MODULE --list-objects --token-label anodize-root-2026
# Repeat with the backup token label.
```

---

## Phase 3: SignCsr

**Goal**: Sign an intermediate CA CSR with the root key.

**Menu key**: `2` (Sign intermediate CSR)

**Prerequisite**: `csr.der` on the shuttle USB.

### Preparing the CSR

On the host, before this phase, inject a test CSR into the shuttle image:

```sh
# Generate a test intermediate key + CSR (outside the ceremony):
openssl ecparam -genkey -name secp384r1 -out /tmp/inter-key.pem
openssl req -new -key /tmp/inter-key.pem -out /tmp/inter.csr \
    -subj "/CN=Test Intermediate CA/O=Test/C=US"
openssl req -in /tmp/inter.csr -outform DER -out /tmp/csr.der

# Copy into shuttle image:
mcopy -i fake-shuttle.img -o /tmp/csr.der ::csr.der
```

### Steps

1. SSH into ceremony TUI.
2. Boot through setup screens.
3. OperationSelect: press `2` (Sign intermediate CSR).
4. CsrPreview: verify subject, select cert profile, press `1`.
5. Quorum: re-enter threshold shares to reconstruct PIN → HSM login.
6. ClockReconfirm: press `1`.
7. CertPreview: **verify intermediate cert fingerprint**, press `1`.
8. Write confirmation: press Enter.
9. Wait for disc burn.
10. DiscDone: press `1` (shuttle write — `intermediate.crt`).
11. Done: Ctrl+C.

### Verification

```sh
make ssh-vm-debug

# Shuttle should contain intermediate.crt:
ls -l /mnt/usb/intermediate.crt
openssl x509 -in /mnt/usb/intermediate.crt -inform DER -noout -subject -issuer
```

---

## Phase 4: RevokeCert

**Goal**: Revoke the intermediate certificate and issue an updated CRL.

**Menu key**: `3` (Revoke a certificate)

### Steps

1. SSH into ceremony TUI.
2. Boot through setup screens.
3. OperationSelect: press `3` (Revoke a certificate).
4. RevokeSelect: select the intermediate cert (or `m` for manual serial entry).
5. Confirm revocation reason.
6. Quorum: re-enter threshold shares → HSM login.
7. ClockReconfirm: press `1`.
8. CRL preview: verify revocation list, press `1`.
9. Write confirmation: press Enter.
10. Wait for disc burn.
11. DiscDone: press `1` (shuttle write — `revoked.toml` + `root.crl`).
12. Done: Ctrl+C.

### Verification

```sh
make ssh-vm-debug

# CRL on shuttle should list the revoked serial:
openssl crl -in /mnt/usb/root.crl -inform DER -noout -text | head -30
```

---

## Phase 5: IssueCrl

**Goal**: Re-sign the CRL (refresh without new revocations).

**Menu key**: `4` (Issue CRL refresh)

### Steps

1. SSH into ceremony TUI.
2. Boot through setup screens.
3. OperationSelect: press `4` (Issue CRL refresh).
4. CRL preview: verify, press `1`.
5. Quorum: re-enter threshold shares → HSM login.
6. ClockReconfirm: press `1`.
7. Write confirmation: press Enter.
8. Wait for disc burn.
9. DiscDone: press `1` (shuttle write — `root.crl`).
10. Done: Ctrl+C.

### Verification

```sh
make ssh-vm-debug

# CRL thisUpdate should be fresh:
openssl crl -in /mnt/usb/root.crl -inform DER -noout -lastupdate -nextupdate
```

---

## Phase 6: RekeyShares

**Goal**: Rotate the HSM PIN and re-split into new SSS shares.  Verifies that
PIN change propagates to all backup HSMs and rollback works on failure.

**Menu key**: `5` (Re-key shares)

**Prerequisite**: Phase 1 + Phase 2 complete (STATE.JSON + backup HSMs exist).

### Steps

1. SSH into ceremony TUI.
2. Boot through setup screens.
3. OperationSelect: press `5` (Re-key shares).
4. RekeyQuorum: re-enter **old** threshold shares (Alice + Bob) → reconstruct old PIN.
5. CustodianSetup: enter new custodian names + threshold (can reuse Alice/Bob or change).
6. ShareReveal: record **new** shares.
7. ShareInput: re-enter new shares for verification.
8. Wait for PIN change on primary HSM + propagation to backups.
9. DiscDone: press `1` (shuttle write).
10. Done: Ctrl+C.

### Verification

```sh
make ssh-vm-debug

# Audit log should show rekey event with backup_devices_updated:
cat /mnt/usb/audit.log | jq 'select(.event == "sss.rekey")'
```

### Artifacts to save

| Artifact | Notes |
|----------|-------|
| New Alice share words | Needed for Phase 7 onwards (old shares are dead) |
| New Bob share words | Needed for Phase 7 onwards |

---

## Phase 7: MigrateDisc

**Goal**: Copy all sessions from the current disc to a fresh blank BD-R.

**Menu key**: `6` (Migrate disc)

### Steps

1. SSH into ceremony TUI.
2. Boot through setup screens.
3. OperationSelect: press `6` (Migrate disc).
4. MigrateConfirm: verify session count + chain status, press `1`.
5. Prompt: "Insert Blank Target Disc."

   **From the host** (separate terminal), swap the cdemu disc:

   ```sh
   # Remote VM:
   DEV_VM_IP=192.168.178.76 make cdemu-swap-disc

   # Local QEMU:
   make cdemu-swap-disc-local
   ```

6. Press `1` to confirm new disc is inserted.
7. Wait for migration write to new disc.
8. Done: Ctrl+C.

### Verification

```sh
make ssh-vm-debug

# Old ISOs archived, new blank BD-R loaded:
ls -lh /run/anodize/share/test-bdr*
# Should show *.iso.bak (archived) + fresh test-bdr.iso with migrated sessions.
```

---

## Phase 8: ValidateDisc

**Goal**: Verify disc integrity — audit chain, file hashes, HSM log consistency.

**Menu key**: `8` (Validate disc)

### Steps

1. SSH into ceremony TUI.
2. Boot through setup screens.
3. OperationSelect: press `8` (Validate disc).
4. Validation runs automatically — review findings.
5. Done: Ctrl+C.

### Verification

The validation report is displayed in the TUI.  All checks should pass:

- Audit chain integrity: OK
- Session continuity: OK
- File hash verification: OK
- No orphaned or missing files

---

## Automation Notes

### Expect-based automation

The existing `scripts/e2e-test.expect` automates Phase 1 (InitRoot).  To extend
it to the full lifecycle:

1. After each Done screen, `send` Ctrl+C to exit and `expect eof`.
2. Re-`spawn` a new SSH connection for the next operation.
3. Boot through the common setup screens (ClockCheck → Profile → HSM → Disc).
4. The shares captured in Phase 1 can be stored in Tcl variables and re-entered
   for Phases 3–6 (quorum).
5. Phase 3 (SignCsr) requires pre-injecting `csr.der` into the shuttle — do this
   with `exec mcopy` before spawning the SSH session.
6. Phase 7 (MigrateDisc) requires a disc swap mid-operation — call
   `exec ssh ... 'sudo bash -s' < scripts/cdemu-swap-disc.sh` from within the
   expect script.

### Key variables for test harness

```tcl
set ssh_key   "$repo/scripts/dev-ssh-key"
set ssh_opts  "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i $ssh_key"

# Remote VM:
set ssh_target "debug@$env(DEV_VM_IP)"
set ssh_ceremony "ceremony@$env(DEV_VM_IP)"

# Local QEMU:
set ssh_target "debug@localhost"
set ssh_ceremony "ceremony@localhost"
set ssh_port 2222   ;# add: -p $ssh_port
```

### Disc swap from expect

```tcl
# Mid-MigrateDisc: swap the cdemu BD-R via debug SSH
spawn ssh {*}$ssh_opts $ssh_target {sudo bash -s}
send [exec cat $repo/scripts/cdemu-swap-disc.sh]
send "\x04"  ;# EOF
expect eof
# Return to the ceremony SSH session to confirm new disc
```

### CI integration

For headless CI (no QEMU window):

```sh
# Start VM:
make qemu-dev-nographic &
QEMU_PID=$!

# Run the test:
expect scripts/e2e-full-test.expect

# Teardown:
kill $QEMU_PID
```

---

## Pass / Fail Criteria

| # | Phase | Pass condition |
|---|-------|---------------|
| 1 | InitRoot | Root cert on shuttle, session 0 on disc, STATE.JSON valid |
| 2 | KeyBackup | Signing key present on both SoftHSM tokens |
| 3 | SignCsr | Intermediate cert on shuttle, chains to root |
| 4 | RevokeCert | CRL contains revoked serial, revoked.toml updated |
| 5 | IssueCrl | CRL refreshed with new thisUpdate timestamp |
| 6 | RekeyShares | New shares work, old shares rejected, all HSMs on new PIN |
| 7 | MigrateDisc | New disc contains all sessions, audit chain valid |
| 8 | ValidateDisc | All validation checks pass with zero findings |
