# TODO

## Audit disc migration utility

When a disc approaches its session limit (≤10 sessions remaining), the ceremony warns the
operator. A future migration flow would let them carry the audit chain to a fresh disc:

1. Read all sessions from the nearly-full disc via `read_disc_sessions()`
2. Write a migration session to the new disc:
   - `MIGRATION.JSON`: source disc fingerprint, session count, migration timestamp
   - `AUDIT.LOG`: `audit.disc.migrate` event with `source_disc_fingerprint`
3. Chain continuity: new disc's audit log genesis = SHA-256(last cert DER from source disc)
4. Store old disc as immutable archive; continue ceremonies on new disc

Separate TUI state or `--migrate-disc` CLI flag. Plan when multi-cert ceremony flow matures.

## ~~State machine: intent burn → cert generation transition~~ (FIXED)

Fixed: added `PostCommitError` phase to `CeremonyPhase`. `do_bootstrap_hsm`,
`do_login_with_pin`, `do_generate_and_build`, `do_find_and_build`, and
`do_build_cert` now return `Result<(), String>`. Extracted `post_intent_init_root`
helper. `tick_intent_burn` transitions to `PostCommitError` on failure instead of
silently advancing to `Execute`. Operator sees the error and can `[1]` retry or
`[Esc]` abort. Safety-net removed.

## Clock drift guard blocks disc write

The "Clock drift > 5 min since ClockCheck" warning appears in the status bar after
the ceremony takes several minutes (e.g. typing 34-word shares twice). Once the
drift guard fires, the cert preview shows `[1] Proceed to disc write` but the
write modal's confirm step doesn't advance. Either:
- Relax the drift threshold for dev builds, or
- Let the operator re-confirm the clock without restarting the entire ceremony.

## ~~TUI: add j/k scroll hint to share display panel~~ ✅

Done. Key hints (`[j/k] Scroll`, `[Enter]`, `[S]`, `[Esc]`) now render in a
fixed 2-line footer pinned to the bottom of the share reveal panel, always
visible regardless of scroll position. Scroll offset is also clamped.

## TUI: share panel height

Consider making the share panel expand to fill available terminal height, or
auto-paginate shares into groups that fit the panel. Currently the panel is a fixed
12-row box regardless of terminal size.

## InitRoot: escape during share validation can leave half-initialized state

During InitRoot, after shares have been generated and the operator is validating
them (re-entering words), it is possible to press Escape or quit. This leaves
the ceremony in a half-initialized state: the HSM key material may already exist
and shares may have been partially distributed, but no cert or disc write has
occurred. On the next boot the appliance may not recognize the incomplete state
cleanly. Need to either:
- Prevent escape/quit during the share validation phase, or
- Detect and recover from the half-initialized state on next launch.

## ~~InitRoot: share validation should verify all shares, not just a quorum~~ (FIXED)

Fixed: `ShareInput` now has a `verify_all` flag. When set (during `ShareVerify`
and `RekeyShareVerify` phases), every custodian must re-enter their share—not
just a threshold quorum. The UI title, remaining-count, completion message, and
instruction panels all reflect the all-shares requirement.

## TUI: revoke cert input should accept Escape in serial field

The revoke-certificate input dialog should allow the operator to press Escape to
cancel even while the cursor is in the serial number field.

## TUI: certificate picker for revocation

The revoke flow currently drops the operator into a blank serial-number text field,
which requires out-of-band knowledge of the target certificate. Replace (or precede)
this with a selection screen that lists every previously-signed certificate found on
the audit disc.

### Data source

`prior_sessions` already contains all `.CRT` files. Walk the sessions, parse each
`.CRT` with `Certificate::from_der`, and collect into a
`Vec<CertSummary { serial: u64, subject: String, not_after: String, session_dir: String, already_revoked: bool }>`.
Cross-reference against the current `revocation_list` to mark already-revoked
entries. `ROOT.CRT` should be included but visually distinguished (root certs are
almost never revoked in practice).

### UX flow

1. **New phase `RevokeSelect`** inserted before `RevokeInput`. Display a scrollable
   list similar to the disc inspector's session list:
   ```
     #  Serial    Subject                     Expires      Session             Status
     1  12345678  CN=Intermediate CA 2026,...  2027-06-01   20260508T...record  active
     2  1         CN=Dev Root CA 2026,...      2036-05-08   20260508T...record  active
   ```
   - `[j/k]` or `[↑/↓]` to navigate, `[Enter]` to select, `[Esc]` to cancel.
   - Already-revoked certs shown grayed out / struck-through with "(revoked)" tag.
   - Selecting an already-revoked cert shows an inline warning and stays on the list.

2. On `[Enter]`, auto-populate `revoke_serial_buf` with the selected serial and
   advance to the existing `RevokeInput` phase with the serial field pre-filled and
   cursor in the reason field (phase 1). The operator can still edit the serial if
   needed.

3. Add a `[m]` ("manual") keybind on the `RevokeSelect` screen to skip straight to
   `RevokeInput` with an empty serial field, preserving the current workflow for
   operators who already know the serial.

### Implementation sketch

- Add `RevokeSelect` variant to `PlanningState`.
- Add `cert_list: Vec<CertSummary>` and `cert_list_cursor: usize` to `CeremonyData`.
- `do_load_revocation()` already runs before phase entry — extend it to populate
  `cert_list` by iterating `prior_sessions`, filtering `.CRT` files, parsing, and
  cross-referencing `revocation_list`.
- Render function mirrors `disc_inspector::render_session_list` pattern.
- Keybindings: `j/k/↑/↓` scroll, `Enter` selects, `m` manual, `Esc` cancels.

## anodize-shuttle: add `list-usb` top-level command

Add a command to enumerate USB devices that could be discs (e.g. USB mass-storage
devices, optical drives). Useful for operator discovery before ceremony start.
The `lint --list-usb` help text references this but it doesn't exist yet.

## TUI: clock re-confirm screen shows nanosecond precision

The clock re-confirm screen displays the timestamp with nanosecond granularity.
Seconds is sufficient—truncate the display to whole seconds.

## TUI: signing review should show the resulting certificate structure, not just CSR + profile name

The CSR-signing review screen currently displays the raw CSR fields alongside the
certificate profile name. This gives reviewers insufficient information to
understand what the final signed certificate will actually contain. The review
screen should instead present the *compiled* certificate document structure—i.e.
the result of applying the selected profile to the CSR—so that custodians can
verify the exact extensions, key usages, validity period, issuer chain, and any
profile-injected fields before authorizing the signature. Showing the certificate
as it will be signed (rather than its two inputs separately) eliminates guesswork
and makes the approval decision meaningful.

## CSR signature verification: flexible algorithm support

`verify_csr_signature()` in `anodize-ca/src/lib.rs` currently hard-codes two
combinations: P-256/SHA-256 and P-384/SHA-384. It assumes the signature algorithm
OID implies a specific curve—e.g. `ecdsa-with-SHA256` → P-256—so a CSR that pairs
a P-384 key with a SHA-256 signature (perfectly valid, and what OpenSSL produces by
default for `ecparam -name secp384r1`) is rejected as corrupt.

The fix should decouple curve detection from the hash algorithm OID:

1. **Parse the SPKI to determine the actual curve** (from the algorithm parameters
   OID inside SubjectPublicKeyInfo), independent of the signature algorithm.
2. **Match the signature hash from the outer algorithm OID** (SHA-256, SHA-384,
   SHA-512).
3. **Verify using the correct (curve, hash) pair.** This gives a matrix of
   supported combinations rather than a 1:1 mapping.

Target combinations to support:

| Curve   | Hash    | OID (sigAlg)              | Status   |
|---------|---------|---------------------------|----------|
| P-256   | SHA-256 | 1.2.840.10045.4.3.2       | ✅ works |
| P-256   | SHA-384 | 1.2.840.10045.4.3.3       | missing  |
| P-384   | SHA-256 | 1.2.840.10045.4.3.2       | ❌ broken|
| P-384   | SHA-384 | 1.2.840.10045.4.3.3       | ✅ works |
| P-384   | SHA-512 | 1.2.840.10045.4.3.4       | missing  |
| Ed25519 | —       | 1.3.101.112               | missing  |
| Ed448   | —       | 1.3.101.113               | missing  |
| RSA-PSS | SHA-256 | 1.2.840.113549.1.1.10     | missing  |
| RSA-PSS | SHA-384 | 1.2.840.113549.1.1.10     | missing  |

EdDSA and RSA-PSS are lower priority but worth supporting since subordinate CAs
from other PKI stacks may use them. The `spki` and `signature` crates already
provide the building blocks; the main work is restructuring the match to dispatch
on (curve, hash) rather than assuming OID ↔ curve.

## cdemu: verify multi-session append after CLOSE SESSION

The intent session write confirmed `sessions=0 → write → CLOSE TRACK → CLOSE
SESSION` all succeed. The disc reported `status=Incomplete sessions=1` on the
second open, confirming the first session was committed and the disc remained
appendable. Full end-to-end test (two complete session writes in one ceremony run)
is blocked by the state machine bug above.
