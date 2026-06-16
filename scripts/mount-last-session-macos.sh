#!/bin/sh
# mount-last-session-macos.sh — mount the newest session of an anodize
# multisession optical disc on macOS, read-only, without sudo.
#
# Background: anodize burns each ceremony as a self-contained ISO 9660
# session whose PVD sits at <session_start>+16 and references files by
# disc-absolute LBA. The superset invariant means the newest session's
# tree describes every file on the disc. macOS's cd9660 driver, however,
# only reads the volume descriptor at absolute sector 16 — the *oldest*
# session — and does not perform last-session lookup for BD/DVD media
# (that kernel behaviour is CD-only; see mount_cd9660(8)).
#
# Strategy: image the recorded area with dd (the console user owns
# /dev/rdiskN, so no privileges are needed), copy the newest session's
# PVD + terminator over sectors 16/17 of the image, widen the PVD's
# volume-space-size field so the disc-absolute LBAs are in bounds, then
# hdiutil-attach the patched image read-only.
#
# The physical disc is never written. The auto-mounted first-session
# volume (e.g. /Volumes/ANODIZE) can stay mounted; raw reads coexist.
#
# Usage:
#   scripts/mount-last-session-macos.sh [diskN | /dev/diskN]
#
# With no argument, the optical drive is auto-detected via drutil.
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

# Find the newest fully-recorded track: last one that is not blank and has
# a valid lastRecordedAddress (skips the open/invisible track on an
# appendable disc).
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

# Verify there really is a PVD (0x01 "CD001") at the expected location.
magic=$(dd if="$img" bs=1 skip=$((pvd * SECT)) count=6 2>/dev/null | od -An -tx1 | tr -d ' ')
if [ "$magic" != "014344303031" ]; then
    echo "error: no ISO 9660 PVD at LBA $pvd (found bytes: $magic)" >&2
    exit 1
fi

# Relocate the newest session's PVD + terminator to absolute sectors 16/17,
# where macOS looks. Regions do not overlap, so in-place dd is safe.
dd if="$img" of="$img" bs="$SECT" skip="$pvd" seek=16 count=2 conv=notrunc 2>/dev/null

# The per-session PVD declares volume_space_size = sectors in that session
# only, but its file LBAs are disc-absolute. Widen it (both-endian u32 at
# PVD offset 80) to the imaged size so every referenced LBA is in bounds.
b0=$((count & 255)); b1=$((count >> 8 & 255))
b2=$((count >> 16 & 255)); b3=$((count >> 24 & 255))
le=$(printf '\\%03o\\%03o\\%03o\\%03o' "$b0" "$b1" "$b2" "$b3")
be=$(printf '\\%03o\\%03o\\%03o\\%03o' "$b3" "$b2" "$b1" "$b0")
# shellcheck disable=SC2059  # octal escapes intentionally come from variables
printf "$le" | dd of="$img" bs=1 seek=$((16 * SECT + 80)) conv=notrunc 2>/dev/null
# shellcheck disable=SC2059
printf "$be" | dd of="$img" bs=1 seek=$((16 * SECT + 84)) conv=notrunc 2>/dev/null

echo "attaching patched image read-only ..."
out=$(hdiutil attach "$img" -readonly)
mnt=$(printf '%s\n' "$out" | sed -n 's/.*\t//p' | tail -1)

echo
echo "mounted last-session view at: $mnt"
echo
echo "when done:"
echo "  hdiutil detach \"$mnt\""
echo "  rm -rf \"$tmp\""
