#!/usr/bin/env bash
# Initialize a SoftHSM2 token and write it into a FAT image.
# Called by the Makefile fake-shuttle.img target.
#
# Usage: init-softhsm-shuttle.sh <fat-image>
#
# Requires: softhsm2-util, mmd, mcopy (mtools)
#
# The token label and PIN must match what is in the profile.toml written into
# the same image:
#   token_label = "anodize-root-2026"
#   Dev PIN: 123456   (SO-PIN: 12345678)
set -euo pipefail

IMG=$1

STMP=$(mktemp -d /tmp/anodize-softhsm-XXXXXXXX)
trap 'rm -rf "$STMP"' EXIT

# Write a minimal SoftHSM2 conf pointing at the temp token dir.
cat > "$STMP/softhsm2.conf" <<EOF
directories.tokendir = $STMP/tokens
objectstore.backend = file
log.level = ERROR
slots.removable = false
EOF
mkdir -p "$STMP/tokens"

# Initialize the token.
SOFTHSM2_CONF="$STMP/softhsm2.conf" softhsm2-util \
    --init-token --free \
    --label  "anodize-root-2026" \
    --so-pin "12345678" \
    --pin    "123456"

# Copy the token directory tree into the FAT image under softhsm2/tokens/.
mmd -i "$IMG" ::softhsm2
mmd -i "$IMG" ::softhsm2/tokens

for uuid_dir in "$STMP"/tokens/*/; do
    uuid=$(basename "$uuid_dir")
    mmd -i "$IMG" "::softhsm2/tokens/$uuid"
    for obj in "$uuid_dir"*; do
        [ -f "$obj" ] || continue
        mcopy -i "$IMG" "$obj" "::softhsm2/tokens/$uuid/$(basename "$obj")"
    done
done
