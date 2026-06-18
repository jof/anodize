//! LandingPad ceremony — initialize a blank disc as a known anodize audit disc.
//!
//! Generic OSes (macOS, Windows) only ever mount the *first* session of an
//! appendable multisession disc. We therefore make session 0 a deliberate,
//! self-describing "Track 1 landing pad": a magic marker file, a human-readable
//! README, the macOS last-session mounter, and (when bundled into the ISO) a
//! tarball of the anodize source that built the ceremony. The superset
//! invariant carries these files forward into every later session, so the
//! disc explains itself no matter which session a future reader lands on.
//!
//! This is not a state mutation, so — like MigrateDisc — it bypasses the
//! intent/record typestate and writes a single session via
//! [`Archive::write_landing_pad`].

use sha2::{Digest, Sha256};

use crate::ceremony::io::*;

/// Run the LandingPad ceremony: confirm, then burn the Track 1 session.
pub fn landing_pad(
    op: &mut dyn Operator,
    arc: &mut dyn Archive,
    env: &Env<LandingPadPlan>,
) -> Result<Outcome, Abort> {
    let plan = &env.plan;
    let src = match &plan.source_archive {
        Some(b) => format!("bundled source ({} KiB)", b.len() / 1024),
        None => "no source bundled (not present on this ISO)".to_string(),
    };
    let body = vec![
        "This blank disc will be initialized as an anodize audit disc.".into(),
        String::new(),
        "Track 1 records what the disc is and how to read it:".into(),
        format!(
            "  {}  (disc identity marker)",
            anodize_audit::LANDING_PAD_MARKER
        ),
        "  README.TXT      (human-readable explanation)".into(),
        "  MOUNT_MAC.command    (mount the newest session on macOS)".into(),
        format!("  SOURCE.TGZ      ({src})"),
        "  BUILD_INFO.TXT  (build provenance)".into(),
        String::new(),
        "These files are carried into every later session.".into(),
    ];
    op.confirm("Initialize Anodize Disc", &body)?;

    let files = assemble_landing_pad(plan);
    arc.write_landing_pad(&files)?;

    Ok(Outcome {
        headline: "Disc initialized as anodize audit disc".into(),
        detail: vec![
            format!("Track 1 session: {}-landing", plan.dir_name),
            format!("{} files written; restart to begin a ceremony", files.len()),
        ],
    })
}

/// Build the Track 1 file set from the plan. Pure (no I/O) so it is unit
/// testable. Always includes the marker, README, and mounter; includes the
/// source tarball and build-info only when the ISO bundled them.
pub fn assemble_landing_pad(plan: &LandingPadPlan) -> Vec<MigrationFile> {
    let mut files = Vec::new();

    let source_line = match &plan.source_archive {
        Some(bytes) => format!("source-archive: SOURCE.TGZ (sha256 {})", sha256_hex(bytes)),
        None => "source-archive: (not bundled on this ISO)".to_string(),
    };
    let marker = format!(
        "{magic}\n\
         format-version: 1\n\
         created: {created}\n\
         {source_line}\n\
         build-info: BUILD_INFO.TXT\n",
        magic = anodize_audit::LANDING_PAD_MAGIC,
        created = plan.dir_name,
    );
    files.push(MigrationFile {
        name: anodize_audit::LANDING_PAD_MARKER.to_string(),
        data: marker.into_bytes(),
    });

    files.push(MigrationFile {
        name: "README.TXT".into(),
        data: README_TXT.as_bytes().to_vec(),
    });
    files.push(MigrationFile {
        name: "MOUNT_MAC.command".into(),
        data: MOUNT_MAC_COMMAND.as_bytes().to_vec(),
    });

    if let Some(bytes) = &plan.source_archive {
        files.push(MigrationFile {
            name: "SOURCE.TGZ".into(),
            data: bytes.clone(),
        });
    }

    let build_info = plan
        .build_info
        .clone()
        .unwrap_or_else(|| "build provenance not recorded on this ISO\n".to_string());
    files.push(MigrationFile {
        name: "BUILD_INFO.TXT".into(),
        data: build_info.into_bytes(),
    });

    files
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Human-readable explanation burned into every disc. Written for a reader who
/// may know nothing about anodize and only has the disc in hand.
const README_TXT: &str = r##"ANODIZE AUDIT DISC
==================

This write-once optical disc is the append-only audit log of a root
certificate-authority key ceremony produced by "anodize". Each ceremony
(key generation, CSR signing, CRL issuance, key backup, ...) appended one
or more ISO 9660 sessions. Sessions are never modified or deleted.

YOU ARE PROBABLY LOOKING AT THE OLDEST SESSION
----------------------------------------------
Most operating systems mount only the FIRST session of an appendable
multisession disc, which is this Track 1 landing pad. The CURRENT state of
the CA (latest certificates, revocation list, audit log) lives in the
NEWEST session. To see everything:

  * Linux: mounts the last session automatically. If not, use
        mount -o session=N /dev/sr0 /mnt   (N = highest session number)

  * macOS: run the bundled helper (no admin rights needed):
        sh MOUNT_MAC.command
    It images the disc, relocates the newest session's volume descriptor,
    and mounts a read-only view showing every session's files.

  * Windows / other: read the disc with an ISO 9660 multisession-aware
    tool and open the last session.

DISC LAYOUT
-----------
Every session is a self-contained ISO 9660 image written at its own track.
Each session directory is named with a UTC timestamp and a suffix:
  -landing  this Track 1 file (disc identity + provenance)
  -intent   a write-ahead-log entry committed before an HSM key operation
  -record   the result of an operation (certificates, CRL, audit log, state)
By the "superset invariant" each session carries forward all prior files, so
the newest session contains the full history. AUDIT.LOG is a hash-chained
log whose genesis is anchored to the ceremony profile; any break is evident.

PROVENANCE / REBUILDING
-----------------------
SOURCE.TGZ is a tarball of the exact anodize source that built the ceremony
software, and BUILD_INFO.TXT records the git commit and build identity. With
those you can rebuild the tools and independently verify this disc. ANODIZE.ID
carries the format version and the SHA-256 of SOURCE.TGZ.

This is reproducible provenance, not a self-modifying program: the archive is
the source that produced the ISO, sufficient to rebuild and audit it.
"##;

/// macOS helper to mount the newest session, embedded verbatim from
/// scripts/mount-last-session-macos.sh. Kept in sync with that host copy.
const MOUNT_MAC_COMMAND: &str = r##"#!/bin/sh
# MOUNT_MAC.command — mount the newest session of this anodize multisession
# optical disc on macOS, read-only, without sudo.
#
# macOS's cd9660 driver only reads the volume descriptor at absolute sector
# 16 (the OLDEST session) and does not perform last-session lookup for BD/DVD
# media. This images the recorded area, relocates the newest session's PVD +
# terminator to sectors 16/17, widens the PVD's volume-space-size so the
# disc-absolute LBAs are in bounds, then hdiutil-attaches the patched image
# read-only. The physical disc is never written.
#
# Usage:  sh MOUNT_MAC.command [diskN | /dev/diskN]
# With no argument the optical drive is auto-detected via drutil.
# Detach later with:  hdiutil detach <mountpoint>

set -eu

SECT=2048

dev=${1:-}
if [ -z "$dev" ]; then
    dev=$(drutil status | awk '{for(i=1;i<NF;i++) if($i=="Name:") print $(i+1)}')
    if [ -z "$dev" ]; then
        echo "error: no optical disc found (drutil status reports no media)" >&2
        exit 1
    fi
fi
case $dev in
    /dev/*) ;;
    *) dev=/dev/$dev ;;
esac
rdev=$(printf '%s' "$dev" | sed 's|/dev/|/dev/r|')

# Newest fully-recorded track (skip the open/invisible track on an appendable disc).
trackinfo=$(drutil trackinfo)
session=$(printf '%s\n' "$trackinfo" | awk '
    /blank:/               { blank = $2 }
    /trackStartAddress:/   { start = $2 }
    /lastRecordedAddress:/ { lra = $2; valid = ($3 == "(valid)") }
    /freeBlocks:/          { if (blank == "false" && valid) { S = start; L = lra } }
    END { if (L == "") exit 1; print S, L }
') || { echo "error: no recorded tracks found on $dev" >&2; exit 1; }

start=${session% *}
last=${session#* }
count=$((last + 1))
pvd=$((start + 16))

echo "device:       $dev"
echo "last session: starts at LBA $start, recorded through LBA $last"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/anodize-last.XXXXXX")
img="$tmp/last-session-view.iso"

echo "imaging $count sectors from $rdev ..."
dd if="$rdev" of="$img" bs="$SECT" count="$count" 2>/dev/null

magic=$(dd if="$img" bs=1 skip=$((pvd * SECT)) count=6 2>/dev/null | od -An -tx1 | tr -d ' ')
if [ "$magic" != "014344303031" ]; then
    echo "error: no ISO 9660 PVD at LBA $pvd (found bytes: $magic)" >&2
    exit 1
fi

dd if="$img" of="$img" bs="$SECT" skip="$pvd" seek=16 count=2 conv=notrunc 2>/dev/null

b0=$((count & 255)); b1=$((count >> 8 & 255))
b2=$((count >> 16 & 255)); b3=$((count >> 24 & 255))
le=$(printf '\\%03o\\%03o\\%03o\\%03o' "$b0" "$b1" "$b2" "$b3")
be=$(printf '\\%03o\\%03o\\%03o\\%03o' "$b3" "$b2" "$b1" "$b0")
printf "$le" | dd of="$img" bs=1 seek=$((16 * SECT + 80)) conv=notrunc 2>/dev/null
printf "$be" | dd of="$img" bs=1 seek=$((16 * SECT + 84)) conv=notrunc 2>/dev/null

echo "attaching patched image read-only ..."
out=$(hdiutil attach "$img" -readonly)
mnt=$(printf '%s\n' "$out" | sed -n 's/.*\t//p' | tail -1)

echo
echo "mounted last-session view at: $mnt"
echo
echo "when done:  hdiutil detach \"$mnt\" && rm -rf \"$tmp\""
"##;

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(source: Option<Vec<u8>>) -> LandingPadPlan {
        LandingPadPlan {
            dir_name: "20260616T120000_000000000Z".into(),
            source_archive: source,
            build_info: Some("git-commit: abc123\n".into()),
        }
    }

    #[test]
    fn assembles_full_set_with_source() {
        let files = assemble_landing_pad(&plan(Some(b"fake-tarball".to_vec())));
        let names: Vec<&str> = files.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                anodize_audit::LANDING_PAD_MARKER,
                "README.TXT",
                "MOUNT_MAC.command",
                "SOURCE.TGZ",
                "BUILD_INFO.TXT",
            ]
        );
        // Marker begins with the magic line and records the source hash.
        let marker = &files[0].data;
        let text = std::str::from_utf8(marker).unwrap();
        assert!(text.starts_with(anodize_audit::LANDING_PAD_MAGIC));
        assert!(text.contains("sha256 "));
    }

    #[test]
    fn degrades_gracefully_without_source() {
        let files = assemble_landing_pad(&plan(None));
        let names: Vec<&str> = files.iter().map(|f| f.name.as_str()).collect();
        // No SOURCE.TGZ, but marker + README + mounter + build-info still present.
        assert!(!names.contains(&"SOURCE.TGZ"));
        assert!(names.contains(&anodize_audit::LANDING_PAD_MARKER));
        assert!(names.contains(&"README.TXT"));
        assert!(names.contains(&"MOUNT_MAC.command"));
        let marker = std::str::from_utf8(&files[0].data).unwrap();
        assert!(marker.contains("not bundled"));
    }

    #[test]
    fn mount_helper_is_a_posix_script() {
        assert!(MOUNT_MAC_COMMAND.starts_with("#!/bin/sh"));
        assert!(README_TXT.contains("MOUNT_MAC.command"));
    }

    // ── Transcript tests (drive the script through the effect traits) ────

    /// Archive fake that captures the landing-pad files; all other operations
    /// are unreachable for this ceremony.
    struct CapturingArchive {
        landing: Option<Vec<MigrationFile>>,
    }

    impl Archive for CapturingArchive {
        fn commit_intent(&mut self, _: IntentEvent) -> Result<IntentCommitted, Abort> {
            Err(Abort::new("unexpected commit_intent"))
        }
        fn commit_record(
            &mut self,
            _: IntentCommitted,
            _: RecordSession,
        ) -> Result<RecordCommitted, Abort> {
            Err(Abort::new("unexpected commit_record"))
        }
        fn export_shuttle(
            &mut self,
            _: &RecordCommitted,
            _: &[(&str, &[u8])],
        ) -> Result<(), Abort> {
            Err(Abort::new("unexpected export_shuttle"))
        }
        fn write_landing_pad(&mut self, files: &[MigrationFile]) -> Result<(), Abort> {
            self.landing = Some(files.to_vec());
            Ok(())
        }
    }

    fn env(source: Option<Vec<u8>>) -> Env<LandingPadPlan> {
        Env {
            sss: anodize_config::state::SssMetadata {
                generation: 0,
                threshold: 0,
                total: 0,
                custodians: vec![],
                pin_verify_hash: String::new(),
                share_commitments: vec![],
            },
            plan: plan(source),
        }
    }

    #[test]
    fn confirms_then_writes_marked_session() {
        use crate::ceremony::scripts::init_root::tests::FakeOperator;
        let mut op = FakeOperator::new();
        let mut arc = CapturingArchive { landing: None };
        let outcome = landing_pad(&mut op, &mut arc, &env(Some(b"src".to_vec()))).unwrap();
        assert!(op.transcript.contains(&"confirm".to_string()));
        let written = arc.landing.expect("write_landing_pad must be called");
        assert!(written
            .iter()
            .any(|f| f.name == anodize_audit::LANDING_PAD_MARKER));
        assert!(outcome.headline.contains("anodize audit disc"));
    }

    #[test]
    fn declined_confirm_writes_nothing() {
        use crate::ceremony::scripts::init_root::tests::FakeOperator;
        let mut op = FakeOperator::new();
        op.abort_at = Some("confirm");
        let mut arc = CapturingArchive { landing: None };
        assert!(landing_pad(&mut op, &mut arc, &env(None)).is_err());
        assert!(arc.landing.is_none(), "no disc write on declined confirm");
    }
}
