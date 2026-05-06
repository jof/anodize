# Anodize — Threat Model

This document describes the trust boundaries, attack surface, and mitigations for Anodize. It assumes familiarity with the [overview](overview.md).

---

## Trust boundaries

| Boundary | Inside | Outside |
|---|---|---|
| HSM PKCS#11 interface | Private key material, PIN-gated signing | Anodize binary, ceremony operator |
| Air-gapped machine | Ceremony binary, RAM state, mounted shuttle | Network, external hosts |
| Write-once disc | Committed audit sessions, `STATE.JSON` | RAM-resident artifacts pre-commit |
| Shuttle USB | `profile.toml`, CSRs, signed artifacts | Operator's source environment |
| Custodian boundary | Individual SSS share (paper) | All other custodians, digital systems |

---

## Threats and mitigations

### Compromised ceremony operator

**Threat**: An operator who ignores the paper checklist or acts maliciously can make errors that no software can catch — issuing unauthorized intermediates, skipping verification, or misrepresenting share distribution.

**Mitigations**:
- Every CA operation is recorded on the write-once disc with a hash-chained audit log; the log cannot be retroactively edited.
- Quorum (threshold SSS) prevents a single operator from signing without custodian participation.
- The TUI enforces the ceremony pipeline structurally — operators cannot skip phases or reorder steps.

**Residual risk**: A colluding quorum of custodians can authorize any operation. Ceremony discipline is ultimately a governance problem.

### Compromised ISO build host

**Threat**: If the machine running `nix build` is compromised, the ISO may contain backdoors.

**Mitigations**:
- Reproducible builds: any party with the same source revision and flake lock file can independently rebuild the ISO and verify byte-for-byte identity.
- Release artifacts include `sha256` and detached signatures; the commit-hash-to-ISO-hash mapping is documented.

**Residual risk**: Reproducibility lets you *detect* a tampered build — it does not prevent one. The verifier must actually perform the comparison.

### Stolen HSM with known PIN

**Threat**: Physical theft of the YubiHSM combined with knowledge of the PIN gives full signing capability.

**Mitigations**:
- The PIN is a 32-byte random value, never stored digitally. Reconstruction requires a quorum of custodians presenting paper shares.
- Share commitments prevent share-index spoofing; the PIN verification hash avoids wasting retry attempts.
- Physical security of the HSM and the ceremony machine is an operational requirement outside software scope.

**Residual risk**: If an attacker obtains both the HSM and enough paper shares (or brute-forces the PIN, which is infeasible for 32 random bytes), the root is compromised.

### Supply-chain attack on dependencies

**Threat**: A malicious crate version could exfiltrate key material or subvert signing.

**Mitigations**:
- `cargo-deny` enforces license and advisory policies; `cargo-vet` tracks audit status of crate versions.
- The air-gapped ISO has no network stack at runtime — exfiltration requires physical channel.
- The crate set is intentionally small and from well-known RustCrypto / Mozilla families.

**Residual risk**: `cargo-deny` and `cargo-vet` reduce but do not eliminate supply-chain risk. A compromised crate could behave normally until a specific trigger condition.

### Covert channel via signing output

**Threat**: Malicious code could encode secrets (e.g., key material) in the nonce of ECDSA signatures or in certificate fields.

**Mitigations**:
- ECDSA signing uses `CKM_ECDSA` with a pre-computed digest — nonce generation is performed inside the HSM, not in Rust code.
- Certificate and CRL fields are constructed from explicit, auditable parameters; extension policy is conservative and hardcoded.
- The audit log records every operation with enough detail to reconstruct what was signed and why.

**Residual risk**: The HSM firmware itself is a trust anchor. A compromised HSM could leak material through biased nonces.

### Disc integrity and media failure

**Threat**: Optical media degrades over time or a session burn fails mid-write.

**Mitigations**:
- WAL intent/record pairs: if a burn fails after intent but before record, the next ceremony session detects and can resume.
- Each session's ISO image contains all prior sessions (copy-in), so the last session is always the complete archive. Earlier sessions provide redundancy.
- `SEND OPC INFORMATION` performs laser power calibration before writing; `SYNCHRONIZE CACHE` flushes the drive buffer.
- M-Disc media is recommended for long-term archival (rated >1000 years).

**Residual risk**: All copies of the disc could be lost or damaged. Maintaining multiple independent disc copies is an operational responsibility.

### Rogue shuttle USB

**Threat**: A malicious USB device presented as the shuttle could exploit kernel USB drivers or mount vulnerabilities.

**Mitigations**:
- The shuttle is mounted with `MS_NOEXEC | MS_NOSUID | MS_NODEV` — no executable content, no setuid, no device nodes.
- The ISO has no network stack, so a malicious shuttle cannot phone home.
- Shuttle discovery uses sysfs enumeration and `nix::mount::mount(2)` directly — no automount daemon or udisks2.

**Residual risk**: Kernel-level USB exploits are out of scope for userspace mitigations. The air-gap limits blast radius.

### Terminal screenshot leaking secrets

**Threat**: An operator photographing the ceremony screen (common during witnessed ceremonies) captures displayed secrets.

**Mitigations**:
- **Design invariant**: sensitive values and secrets are never printed to the terminal. PIN entry uses masked input with random-length noise.
- SSS share display is the one controlled exception: shares are shown one at a time, hidden by default, revealed on explicit key press, and cleared before the next custodian steps forward.
- The TUI mirrors its status log to tty2 as a scrollable audit trail — secrets are excluded from this mirror.

**Residual risk**: A custodian photographing their own share display window is an operational risk managed by ceremony policy, not software.

### Clock manipulation

**Threat**: A wrong system clock produces certificates and CRLs with incorrect validity periods, potentially enabling back-dating attacks.

**Mitigations**:
- The TUI's `ClockCheck` screen displays the current UTC time and requires explicit operator confirmation before any timestamped session can be written.
- The air-gapped machine has no NTP — the operator is responsible for setting the clock correctly from a trusted reference.

**Residual risk**: A malicious operator can confirm an intentionally wrong clock. Witnessed ceremonies and the audit log provide after-the-fact detection.

---

## Out of scope

These are explicitly not addressed by Anodize:

- **Online CA / OCSP / ACME**: Anodize signs intermediates and CRLs only.
- **Key backup and disaster recovery**: YubiHSM wrapped-export to a second device is a planned extension (see open questions in the design doc).
- **Entropy quality on the ISO**: `jitterentropy` + hardware TRNG is assumed; confirming the target hardware's TRNG availability is an operational step.

---

## Related documents

- [Overview](overview.md) — project goals, domain concepts, ceremony pipeline
- [Detailed Design](design.md) — architectural decisions, implementation details, crate rationale
