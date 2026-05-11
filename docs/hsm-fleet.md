# HSM Fleet & Key Backup

Anodize supports a fleet of multiple HSM devices sharing the same signing key. The fleet is tracked in `STATE.JSON` with device lifecycle metadata. Key backup uses wrap-export/import to replicate the signing key across devices. Fleet-aware login ensures the ceremony uses a recognized device, and PIN changes propagate automatically to all fleet members.

---

## Fleet state

The `HsmFleet` structure in `STATE.JSON` tracks all enrolled HSM devices:

```json
{
  "fleet": {
    "devices": [
      {
        "device_id": "0034332673",
        "model": "YubiHSM2 fw 2.2.0",
        "backend": "yubihsm",
        "enrolled_at": "2026-01-15T14:30:00Z",
        "last_seen_at": "2026-03-20T09:00:00Z",
        "status": { "state": "Active" }
      },
      {
        "device_id": "0034332674",
        "model": "YubiHSM2 fw 2.2.0",
        "backend": "yubihsm",
        "enrolled_at": "2026-01-15T15:00:00Z",
        "last_seen_at": "2026-03-20T09:05:00Z",
        "status": { "state": "Active" }
      }
    ]
  }
}
```

### Device identification

`device_id` is backend-specific:
- **YubiHSM**: 10-digit USB serial number (e.g., `0034332673`)
- **SoftHSM / PKCS#11**: token label

### Device status

```rust
enum HsmDeviceStatus {
    Active,
    Removed { at: String, reason: String },
}
```

Removed devices are kept in the fleet array for the audit trail. `HsmFleet::active_device_ids()` filters to active members only.

### Enrollment

- **Primary device**: enrolled during `InitRoot` → `bootstrap()`.
- **Backup devices**: enrolled during `KeyBackup`. The backup operation bootstraps the target device if it still has factory-default auth, then pairs and imports the signing key.

---

## Fleet-aware login

The ceremony no longer tries tokens by label — it uses the fleet device list to authenticate against a recognized device:

```rust
fn open_session_any_recognized(
    backend: &dyn HsmBackend,
    inventory: &dyn HsmInventory,
    fleet_device_ids: &[&str],
    pin: &SecretString,
) -> Result<(String, Box<dyn Hsm>)>;
```

1. `HsmInventory::enumerate_devices()` lists all connected devices **without** requiring the ceremony PIN.
2. Each connected device's serial is compared against the fleet's active device IDs.
3. `HsmBackend::open_session_by_id(device_id, pin)` opens a session on the first recognized device.
4. Returns `(device_id, session)` so the caller knows which device was used (stored in `HwContext.device_id`).

---

## HsmInventory trait

Unauthenticated enumeration of connected devices:

```rust
pub struct HsmDeviceInfo {
    pub serial: String,
    pub model: String,
    pub firmware: Option<String>,
    pub auth_state: String,
    pub log_used: Option<u8>,       // YubiHSM audit log entries used
    pub log_total: Option<u8>,      // YubiHSM audit log capacity
    pub has_wrap_key: Option<bool>,
    pub has_signing_key: Option<bool>,
}
```

For YubiHSM, inventory uses `yubihsm::connector::usb::Devices::serial_numbers()` to list all connected devices natively — no `rusb` dependency needed. Two simultaneous `yubihsm::Client` sessions to different physical devices work correctly (independent USB HID connections).

---

## Key backup

The `HsmBackup` trait provides a two-phase flow:

### Phase 1: Pair

`pair_devices(src, dst, pin)` generates a fresh AES-256 wrap key and installs it on both source and target devices. Returns a description (e.g., `"0x0200"`).

### Phase 2: Backup

`backup_key(src, dst, pin, key_id)`:
1. `export_wrapped` on source — wraps the signing key with the shared wrap key.
2. `import_wrapped` on target — unwraps into the target device.
3. Reads back public keys from both devices and verifies they match.

Returns `BackupResult { source_id, dest_id, key_id, public_keys_match }`.

### Target bootstrapping

If the target device still has factory-default auth, the backup operation bootstraps it first (changes the default password to the ceremony PIN, applies audit hardening).

### PIN propagation

During `RekeyShares`, after the PIN is changed on the primary, all fleet backup devices receive the new PIN via `change_pin_on_device()`. This ensures every fleet member stays in sync. Failure triggers automatic rollback — see [SSS & PIN Management](sss-pin-management.md#failure-recovery).

---

## HSM audit log

YubiHSM 2 has an internal audit log (62-entry ring buffer). Anodize integrates this for cross-verification:

### Bootstrap hardening

During `YubiHsmBackend::bootstrap()`:
1. **Force Audit = Fix** — HSM halts rather than silently dropping entries when the ring buffer fills.
2. **Per-command audit = Fix** — all ceremony-critical commands (`SignEcdsa`, `GenerateAsymmetricKey`, `ExportWrapped`, `ImportWrapped`, `PutWrapKey`, `ChangeAuthenticationKey`) are set to audit.
3. **Initial log drain** — bootstrap entries are consumed so the first ceremony operation starts with a clean sequence.

### Audit continuity

`STATE.JSON.last_hsm_log_seq` records the sequence number of the last consumed HSM audit entry. This anchors the disc audit log to the HSM's internal log for cross-verification during `ValidateDisc`.

### Audit log types

```rust
pub struct HsmAuditEntry {
    pub item: u16,         // monotonic sequence
    pub command: u8,       // command code
    pub session_key: u16,  // auth key ID
    pub target_key: u16,   // target object ID
    pub second_key: u16,   // secondary key (e.g., wrap key)
    pub result: u8,        // result code
    pub tick: u32,         // HSM systick
    pub digest: [u8; 16],  // truncated SHA-256 chain
}

pub struct HsmAuditSnapshot {
    pub unlogged_boot_events: u16,
    pub unlogged_auth_events: u16,
    pub entries: Vec<HsmAuditEntry>,
}
```

---

## Related documents

- **[Architecture](architecture.md)** — HSM traits, backend details
- **[SSS & PIN Management](sss-pin-management.md)** — PIN rotation and propagation
- **[Disc Validation](ceremony-validate.md)** — HSM cross-check during validation
