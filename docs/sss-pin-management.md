# SSS & PIN Management

The HSM PIN is a 32-byte random value, never chosen by an operator. It is split via Shamir Secret Sharing over GF(256) among named custodians. A threshold *k* of *n* custodians must present their shares to reconstruct the PIN for any HSM operation. Shares are never stored digitally — custodians hold paper transcripts.

---

## Shamir Secret Sharing

Implemented in the `anodize-sss` crate. Each byte of the 32-byte PIN is split independently using a random polynomial of degree *k* − 1 in GF(256). Share indices start at 1 (x = 0 is reserved for the secret itself).

### Share format

A share is serialized as: `index (1 byte) ‖ data (32 bytes) ‖ CRC-8 checksum (1 byte)`.

- **Index**: the x-coordinate (evaluation point), 1-indexed.
- **Data**: the y-values — one byte per byte of the original secret.
- **CRC-8**: CRC-8/AUTOSAR (polynomial 0x2F) over `[index] ‖ data`. Branchless implementation using arithmetic masking.
- **Zeroize**: share data is zeroized on drop.

### Wordlist encoding

Shares are encoded as human-readable words from a fixed 256-word list (one word per byte). A 32-byte PIN produces 34 words per share (1 index + 32 data + 1 checksum). Operators transcribe the words onto paper.

Tab-autocomplete and per-word validation are provided during share entry. `prefix_matches()` returns candidate words matching a typed prefix.

### Share commitments

Each share has a SHA-256 commitment stored in `STATE.JSON`:

```
commitment = SHA-256(index ‖ custodian_name ‖ y_bytes)
```

At quorum time, the presented share is checked against its commitment before reconstruction proceeds. This prevents:
- **Share-index spoofing**: changing the index and recomputing the checksum still fails the commitment.
- **Cross-custodian substitution**: the custodian name is bound into the commitment.

### PIN verification hash

`SHA-256(pin_bytes)` is stored as `pin_verify_hash` in `STATE.JSON`. After reconstructing the PIN from threshold shares, the TUI verifies the hash before attempting HSM login — avoiding wasting HSM retry attempts on transcription errors.

---

## SSS generation counter

`SssMetadata.generation` starts at 1 during `InitRoot` and increments on every `RekeyShares`. The generation number is displayed in the share reveal and share input screens (e.g., "Generation 2 — Share 1 of 3") so custodians can distinguish current shares from obsolete ones.

---

## STATE.JSON: SSS metadata

```json
{
  "sss": {
    "generation": 1,
    "threshold": 2,
    "total": 3,
    "custodians": [
      { "name": "Alice", "index": 1 },
      { "name": "Bob",   "index": 2 },
      { "name": "Carol", "index": 3 }
    ],
    "pin_verify_hash": "abcd1234...",
    "share_commitments": [
      "sha256hex_for_alice...",
      "sha256hex_for_bob...",
      "sha256hex_for_carol..."
    ]
  }
}
```

Validation rules (enforced by `SessionState::validate()`):
- `threshold >= 2`
- `total >= threshold`
- `custodians.len() == total`
- `share_commitments.len() == total`
- Custodian indices are 1..=total, unique

---

## PIN rotation (RekeyShares)

`RekeyShares` performs a full PIN rotation — the HSM authentication credential is replaced, not merely re-split among new custodians. The protocol:

1. **Reconstruct old PIN** from a quorum of existing shares (standard Quorum phase).
2. **Login to HSM** with the reconstructed old PIN.
3. **Generate new random 32-byte PIN** via the system CSPRNG.
4. **SSS-split the new PIN** to the new set of custodians (new names, new threshold).
5. **Distribute shares** to custodians (ShareReveal phase — one at a time, hidden by default, revealed on `[S]` press).
6. **Verify all shares** — every new custodian re-enters their share word by word. The TUI reconstructs the PIN from the entered shares and verifies it matches the generated value (round-trip check). This ensures no transcription errors before the irreversible PIN change.
7. **Change PIN on primary HSM** via `change_pin(old, new)` — only after the round-trip check succeeds.
8. **Propagate PIN to backup HSMs** — for each fleet device that holds a copy of the signing key (and is not the primary), call `change_pin_on_device(old, new)`. The audit log records `backup_devices_updated`.
9. **Update `pin_verify_hash`** and increment `generation` in `STATE.JSON`.
10. **Write rekey record session** to disc with `pin_rotated: true`.

### Failure recovery

- If `change_pin` fails on the **primary**, the old PIN remains valid. The operation aborts cleanly — no state is written to disc.
- If a **backup device** fails mid-propagation, the system performs automatic rollback: all already-changed backups are reverted via `change_pin_on_device(new, old)`, then the primary is rolled back via `change_pin(new, old)`. Every HSM is left in a consistent state (old PIN) on any failure.
- Rollback errors are logged at CRITICAL level. If rollback itself fails, the operator is informed and the audit log records the partial state.

This eliminates the risk that former custodians could reconstruct the original PIN after losing custodianship.

---

## Share display invariants

- **No secrets on terminal**: the HSM PIN is never displayed. SSS shares are the one controlled exception.
- **One-way reveal**: the `[S]` key is a latch — it reveals but never hides. A `⚠ REVEALED` indicator tracks exposure.
- **Sequential display**: shares are shown one at a time. The screen is cleared before the next custodian steps forward.
- **tty2 mirror exclusion**: the TUI mirrors its status log to tty2 for audit trail, but secrets are excluded from this mirror.

---

## Related documents

- **[Architecture](architecture.md)** — `anodize-sss` crate details
- **[Ceremony Pipeline](ceremony-pipeline.md)** — RekeyShares operation lifecycle
- **[HSM Fleet & Key Backup](hsm-fleet.md)** — PIN propagation to backup devices
