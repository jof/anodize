# Anodize — Design Documentation

Anodize is an offline root-CA ceremony tool written in Rust. It runs air-gapped from a verified NixOS live ISO, stores its signing key in a hardware HSM (YubiHSM 2 in production, SoftHSM2 in dev/CI), and records every CA operation on a write-once optical disc.

## Key properties

- **Air-gapped**: no network stack on the production ISO; ephemeral tmpfs root
- **HSM-backed**: P-384 private key never leaves the hardware trust boundary
- **Write-once audit**: every operation is committed to optical disc (BD-R / M-Disc) before artifacts reach USB
- **Reproducible**: Nix flake produces byte-identical ISOs from the same source
- **Quorum-gated**: HSM PIN is a 32-byte random value split via Shamir Secret Sharing; a threshold of custodians must be present to sign
- **Multi-HSM fleet**: signing key can be backed up across multiple YubiHSM 2 devices with fleet-aware login and automatic PIN propagation

## Crate map

| Crate | Role |
|---|---|
| `anodize-hsm` | HSM abstraction — `Hsm` + `HsmBackend` traits, SoftHSM + YubiHSM backends, `HsmActor`, fleet inventory, key backup |
| `anodize-ca` | X.509 cert/CRL generation, CSR validation, `P384HsmSigner` bridge |
| `anodize-audit` | Hash-chained JSONL audit log, disc validation functions |
| `anodize-config` | TOML profile loader (`profile.toml`), `SessionState` / `STATE.JSON`, fleet + SSS metadata |
| `anodize-sss` | Shamir over GF(256), 256-word wordlist encoding, CRC-8 checksums, share commitments |
| `anodize-shuttle` | CLI tool for shuttle USB preparation and linting |
| `anodize-tui` | Ceremony binary (`anodize-ceremony`), terminal gatekeeper (`anodize-sentinel`), disc validator (`anodize-validate`), all TUI modes |

## Ceremony operations

| # | Operation | Description |
|---|---|---|
| 1 | **InitRoot** | Generate root CA keypair, create self-signed cert, split PIN into SSS shares |
| 2 | **SignCsr** | Sign an intermediate CA CSR from the shuttle |
| 3 | **RevokeCert** | Add revocation entry + issue new CRL |
| 4 | **IssueCrl** | Re-sign the current revocation list |
| 5 | **RekeyShares** | Rotate HSM PIN, re-split to new custodians, propagate to fleet |
| 6 | **MigrateDisc** | Copy all sessions to a new optical disc |
| 7 | **KeyBackup** | Pair + backup signing key to a second HSM device |
| 8 | **ValidateDisc** | Verify disc integrity, audit chain, and HSM log consistency |

## Detailed documentation

### Design & architecture
- **[Architecture](architecture.md)** — crate structure, HSM traits, actor pattern, X.509 signing bridge, crate rationale
- **[Ceremony Pipeline](ceremony-pipeline.md)** — setup phases, operation lifecycle, state machine, crash recovery
- **[Optical Disc Archive](optical-disc.md)** — multi-session SAO format, ISO 9660, SG_IO MMC, WAL pattern
- **[SSS & PIN Management](sss-pin-management.md)** — Shamir splitting, wordlist encoding, share commitments, PIN rotation
- **[HSM Fleet & Key Backup](hsm-fleet.md)** — multi-device fleet, inventory, wrap-export/import, PIN propagation
- **[Security](security.md)** — security invariants, threat model, known findings
- **[Builds & ISO](builds-and-iso.md)** — Nix flake, reproducible builds, prod vs dev ISO, CI

### Operational runbooks
- **[Root Ceremony Init](ceremony-init.md)** — printable runbook for the root CA key ceremony
- **[Signing Ceremony](ceremony-sign.md)** — printable runbook for intermediate signing / CRL issuance
- **[Disc Validation](ceremony-validate.md)** — offline and HSM-cross-check validation procedures

### Testing
- **[E2E Test Plan](e2e-test-plan.md)** — full 8-phase ceremony lifecycle test plan
- **[Multi-Session Test](ceremony-multisession-test.md)** — InitRoot → reboot → SignCsr cross-session validation

## Hardware model

| Environment | HSM | Optical archive |
|---|---|---|
| Dev / CI | SoftHSM2 (PKCS#11) | `--skip-disc` or cdemu SCSI passthrough |
| Production | YubiHSM 2 (native USB) | BD-R / DVD-R / M-Disc via SG_IO SAO |
