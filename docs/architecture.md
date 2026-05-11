# Architecture

Anodize is a Cargo workspace of seven crates, compiled into three binaries that ship on the NixOS ISO. The binary has no compile-time knowledge of which HSM backend it will use — that is selected at runtime via `profile.toml`.

---

## Crate dependency graph

```
anodize-tui ─────► anodize-hsm ─────► anodize-config
    │                   │
    ├──► anodize-ca ────┘
    │        │
    ├──► anodize-audit
    │
    ├──► anodize-sss
    │
    └──► anodize-config

anodize-shuttle ──► anodize-audit
    │
    └──► anodize-config
```

### Crate responsibilities

- **`anodize-config`** — TOML profile loader (`profile.toml`), `SessionState` / `STATE.JSON` schema, `HsmBackendKind` enum, `CertProfile`, `RevocationEntry`. No crypto dependencies.
- **`anodize-hsm`** — Pluggable HSM abstraction. `Hsm` trait (session ops), `HsmBackend` trait (device lifecycle), `HsmInventory` (unauthenticated enumeration), `HsmBackup` (wrap-export/import), `HsmActor` (thread-safe wrapper). Two backends: `SoftHsmBackend` (PKCS#11) and `YubiHsmBackend` (native USB).
- **`anodize-ca`** — X.509 operations: root cert issuance, CSR signing, CRL generation. All via `P384HsmSigner` bridge. CSR signature verification supports EC P-256/P-384, RSA PKCS#1v1.5, and Ed25519.
- **`anodize-audit`** — Hash-chained JSONL audit log. Genesis hash, append, verify, disc validation functions (`SessionSnapshot` → `Finding` vectors).
- **`anodize-sss`** — Shamir Secret Sharing over GF(256). Split/reconstruct, 256-word wordlist encoding, CRC-8 checksums, share commitments (`SHA-256(index ‖ name ‖ data)`), PIN verification hash.
- **`anodize-shuttle`** — Standalone CLI for shuttle USB preparation (`init`) and pre-ceremony linting (`lint`).
- **`anodize-tui`** — All three binaries: `anodize-ceremony` (ratatui TUI), `anodize-sentinel` (terminal gatekeeper), `anodize-validate` (standalone disc validator).

---

## Binaries

| Binary | Crate | Role |
|---|---|---|
| `anodize-ceremony` | `anodize-tui` | Ratatui TUI — full ceremony state machine. All operator actions are numbered menu items. |
| `anodize-sentinel` | `anodize-tui` | Terminal gatekeeper. Acquires exclusive `flock` before exec-ing ceremony. Shows system health banner (uptime, memory, entropy, kernel, thermal, NTP, SecureBoot, optical, network, block devices). Offers power-off via `reboot(2)`. |
| `anodize-validate` | `anodize-tui` | Standalone disc validation. Reads session directories and runs all offline checks. |
| `anodize-shuttle` | `anodize-shuttle` | CLI: `init` (create shuttle image), `lint` (validate shuttle contents). |

---

## HSM trait hierarchy

Two trait layers separate device lifecycle from session operations:

```rust
/// Device lifecycle — probe, bootstrap, open session.
pub trait HsmBackend: Send {
    fn list_tokens(&self) -> Result<Vec<SlotTokenInfo>>;
    fn probe_token(&self, label: &str) -> Result<bool>;
    fn open_session(&self, label: &str, pin: &SecretString) -> Result<Box<dyn Hsm>>;
    fn open_session_by_id(&self, device_id: &str, pin: &SecretString) -> Result<Box<dyn Hsm>>;
    fn bootstrap(&self, slot_id: u64, so_pin: &SecretString, user_pin: &SecretString, label: &str) -> Result<Box<dyn Hsm>>;
    fn list_all_slots(&self) -> Result<Vec<SlotTokenInfo>>;  // includes empty slots
}

/// Session operations — signing, key management.
pub trait Hsm: Send {
    fn login(&mut self, pin: &SecretString) -> Result<()>;
    fn logout(&mut self) -> Result<()>;
    fn find_key(&self, label: &str) -> Result<KeyHandle>;
    fn generate_keypair(&mut self, label: &str, spec: KeySpec) -> Result<KeyHandle>;
    fn sign(&self, key: KeyHandle, mech: SignMech, data: &[u8]) -> Result<Vec<u8>>;
    fn public_key_der(&self, key: KeyHandle) -> Result<Vec<u8>>;
    fn get_audit_log(&self) -> Result<HsmAuditSnapshot>;      // YubiHSM only
    fn drain_audit_log(&self, up_to_seq: u16) -> Result<()>;  // YubiHSM only
    fn change_pin(&mut self, old_pin: &SecretString, new_pin: &SecretString) -> Result<()>;
}
```

Additional trait layers for fleet and backup operations:

```rust
/// Unauthenticated device enumeration.
pub trait HsmInventory: Send {
    fn enumerate_devices(&self) -> Result<Vec<HsmDeviceInfo>>;
}

/// Key backup: wrap-export/import between devices.
pub trait HsmBackup: Send {
    fn enumerate_backup_targets(&self, pin: Option<&SecretString>) -> Result<Vec<BackupTarget>>;
    fn pair_devices(&self, src: &str, dst: &str, pin: &SecretString) -> Result<String>;
    fn backup_key(&self, src: &str, dst: &str, pin: &SecretString, key_id: &str) -> Result<BackupResult>;
    fn change_pin_on_device(&self, device_id: &str, old_pin: &SecretString, new_pin: &SecretString) -> Result<()>;
}
```

### Backends

| Backend | Trait impl | Library | Notes |
|---|---|---|---|
| `SoftHsmBackend` / `Pkcs11Hsm` | `HsmBackend` + `Hsm` | `cryptoki 0.7` (PKCS#11 via `dlopen`) | Dev and CI. `SOFTHSM2_MODULE` env var or well-known paths. |
| `YubiHsmBackend` / `YubiHsmSession` | `HsmBackend` + `Hsm` | `yubihsm 0.42` (native USB HID) | Production. No PKCS#11 wrapper or connector daemon. |
| `HsmActor` | `Hsm` | — | `Send + Sync + Clone` wrapper. Serialises all calls onto a dedicated thread via rendezvous channel. |

### HsmActor

Some HSM backends are `!Sync` (e.g., `cryptoki`'s `Session` contains a raw pointer). The actor pattern resolves this without `unsafe`:

```
caller thread ──SyncSender<HsmRequest>──► hsm-actor thread (owns Box<dyn Hsm>)
              ◄──SyncSender<Result<T>>───
```

`HsmActor::spawn(hsm)` takes ownership of the `Box<dyn Hsm>`. `Clone` gives a second handle to the same session — all requests are serialised on the actor thread.

### Factory functions

```rust
fn create_backend(kind: HsmBackendKind) -> Result<Box<dyn HsmBackend>>;
fn create_inventory(kind: HsmBackendKind) -> Result<Box<dyn HsmInventory>>;
fn create_backup(kind: HsmBackendKind) -> Result<Box<dyn HsmBackup>>;
```

---

## X.509 signing bridge

The `x509-cert` builder requires `signature::Keypair` + `spki::DynSignatureAlgorithmIdentifier`. `P384HsmSigner` bridges the gap:

- Stores a `p384::ecdsa::VerifyingKey` parsed from `hsm.public_key_der()` at construction.
- `try_sign(msg)` pre-hashes with SHA-384, calls `hsm.sign(key, EcdsaSha384, digest)`. Returns DER-encoded ECDSA signature (P1363 → DER conversion).
- For SoftHSM, `CKM_ECDSA_SHA384` is tried first; falls back to pre-hash + raw `CKM_ECDSA` if the mechanism is unsupported.
- For YubiHSM, always pre-hashes in Rust and calls `sign_ecdsa_prehash_raw`.

### CRL construction

`x509-cert 0.2` has no `CrlBuilder`. `issue_crl` manually constructs `TbsCertList`, DER-encodes it, signs the raw bytes with `P384HsmSigner`, and assembles the final `CertificateList`.

### CSR signature verification

`verify_csr_signature()` identifies key type and hash algorithm independently from the SPKI and outer signature OID. Supported matrix:

| Key type | Hash | OID |
|---|---|---|
| EC P-256/P-384 | SHA-256/384/512 | 1.2.840.10045.4.3.{2,3,4} |
| RSA PKCS#1 v1.5 | SHA-256/384/512 | 1.2.840.113549.1.1.{11,12,13} |
| Ed25519 | — | 1.3.101.112 |

---

## Configuration

### profile.toml

```toml
[ca]
common_name  = "Example Root CA"
organization = "Example Corp"
country      = "US"
cdp_url      = "http://crl.example.com/root.crl"

[hsm]
backend      = "yubihsm"     # or "softhsm"
token_label  = "anodize-root-2026"
key_label    = "root-key"
key_spec     = "ecdsa-p384"

[[cert_profiles]]
name          = "sub-ca"
validity_days = 1825
path_len      = 0

[[cert_profiles]]
name          = "ocsp-signer"
validity_days = 365
```

The `cert_profiles` array defines named certificate issuance profiles. Each profile specifies validity period and optional pathLen constraint. The operator selects a profile during `SignCsr`.

---

## Crate selections and rationale

| Need | Crate | Rationale |
|---|---|---|
| PKCS#11 (SoftHSM) | `cryptoki 0.7` | Maintained, real `dlopen`, production-proven |
| YubiHSM native | `yubihsm 0.42` | Official Yubico SDK, USB HID via `libusb` |
| X.509 building | `x509-cert 0.2` + `der 0.7` + `spki 0.7` | Construct TbsCertificate and hand bytes to HSM. `rcgen` wants to own the signing key. |
| ECDSA | `p384 0.13` | VerifyingKey from SPKI DER for signer; PrehashVerifier for CSR verification |
| RSA | `rsa 0.9` | PKCS#1 v1.5 CSR signature verification |
| Ed25519 | `ed25519-dalek 2` | Ed25519 CSR signature verification |
| Config | `serde` + `toml` | Standard |
| Secrets | `secrecy 0.8` | `SecretString` for PINs, zeroizes on drop |
| Audit hashing | `sha2 0.10` | SHA-256 — boring is good for a CA |
| TUI | `ratatui 0.29` + `crossterm` | Terminal UI framework |
| Errors | `thiserror 2` in libs, `anyhow 1` in binaries | |
| SSS | `anodize-sss` (internal) | Shamir over GF(256), 256-word wordlist, CRC-8 |

### Algorithm defaults

- **ECDSA P-384**: safer enterprise pick for relying-party compatibility. Supported by both YubiHSM 2 and SoftHSM2.
- **Root validity**: configurable; ceremony tooling defaults to 7305 days (20 years).
- **Token identification**: by label, not slot index (YubiHSM slot indices are unstable across USB reconnects).

---

## Related documents

- **[Overview](README.md)** — project summary, crate map, operation list
- **[Ceremony Pipeline](ceremony-pipeline.md)** — ceremony state machine
- **[Security](security.md)** — invariants, threat model, findings
