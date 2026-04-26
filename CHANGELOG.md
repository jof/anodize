# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.0.1] — 2026-04-26

Initial proof-of-concept release. All core subsystems are implemented and
integrated into a bootable NixOS appliance ISO. The key ceremony workflow
runs end-to-end against SoftHSM2 in development and is structured to run
against a YubiHSM 2 in production.

### Added

- **`anodize-hsm`** — PKCS#11 abstraction layer. `Pkcs11Hsm` opens any
  PKCS#11 module at runtime via `dlopen` and finds tokens by label (not slot
  index, which is unstable across USB reconnects). `HsmActor` wraps it in a
  dedicated thread + rendezvous channel so the `!Sync` session handle is safe
  to use from async or multi-threaded callers. Works against SoftHSM2 in dev
  and YubiHSM 2 in production with no code changes — only the module path in
  the config differs.

- **`anodize-ca`** — X.509 operations. Issues root certificates, signs
  intermediate CSRs, and produces CRLs via P-384/ECDSA. Private key material
  never leaves the HSM. CSR self-signature is verified before any field is
  parsed; only a fixed extension allowlist (BasicConstraints, KeyUsage, SKID,
  AKID, CDP) is copied; all others are rejected.

- **`anodize-audit`** — Hash-chained JSONL audit log. Each entry's
  `prev_hash` commits to the previous entry; the genesis entry's `prev_hash`
  is `SHA-256(root_cert_DER)`, binding the log irreversibly to the ceremony
  that produced it. Arithmetic and chain-verification helpers included.

- **`anodize-config`** — TOML profile loader (`profile.toml` on the USB
  stick). Emits a runtime warning when `pin_source` is `env:` or `file:`;
  `prompt` is the only safe value for a real ceremony.

- **`anodize-tui`** — ratatui ceremony binary. Full flow: HSM login (with
  randomised display length to prevent PIN-length disclosure), key
  generation vs. reuse selection, root certificate issuance, audit log
  genesis, disc burn, USB export. Runs on both tty1 (framebuffer) and
  ttyS0 (serial, 115200 baud).

- **Disc lifecycle** (`media/` inside `anodize-tui`) — pure-Rust SG_IO
  SCSI/MMC driver, ISO 9660 Level 2 writer, Sequential Access Only (SAO)
  burn to write-once optical media without depending on any external tool.
  Disc capacity is detected and a session limit is enforced before the first
  write.

- **Write-ahead log** — an intent session record is written to disc before
  the HSM key operation. This establishes the disc-before-USB ordering
  invariant at the software level.

- **`anodize-sentinel`** — terminal gatekeeper. Acquires an `flock` on
  `/run/anodize/ceremony.lock` before exec-ing the ceremony binary,
  preventing two terminals from running a ceremony simultaneously. Holds
  `CAP_SYS_BOOT` (via a capability wrapper) for the power-off option;
  emits an ANSI RIS reset before display to clear any prior terminal state.

- **NixOS appliance ISO** — air-gapped bootable image. No network stack,
  ephemeral `tmpfs` root (nothing survives reboot), read-only squashfs,
  instant GRUB timeout, auto-login to the ceremony shell on both tty1 and
  ttyS0, udev rules for YubiHSM 2 and optical drives, minimal capability
  wrappers (no setuid). Built via `nix build .#iso`.

- **Dev ISO** (`nix build .#dev-iso`) — identical NixOS configuration with
  `dev-usb-disc` and `dev-softhsm-usb` features enabled. USB sticks
  substitute for the optical disc and the YubiHSM, making the full ceremony
  flow testable in QEMU without specialised hardware. A red warning banner
  in the TUI header distinguishes dev builds from production.

- **CI** — GitHub Actions pipeline: `cargo fmt --check`, `cargo clippy`,
  `cargo test` (with SoftHSM2 integration), `cargo deny` (license +
  advisory audit), `nix build` + `nix flake check`, and automated ISO
  release upload on semver-tagged commits.

[0.0.1]: https://github.com/jof/anodize/releases/tag/v0.0.1
