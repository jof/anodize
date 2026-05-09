#!/usr/bin/env bash
# cdemu-swap-disc.sh — Unload the current BD-R from cdemu, archive old ISOs,
# and create a fresh blank BD-R.
#
# Designed to run on the dev VM (NixOS guest) as the debug user.  The script
# must run inside the ceremony user's D-Bus session to communicate with the
# cdemu-daemon.
#
# Usage (from host):
#   ssh debug@<VM_IP> 'bash -s' < scripts/cdemu-swap-disc.sh
#   # or via make:
#   DEV_VM_IP=192.168.178.76 make cdemu-swap-disc
#
# Can also be run directly on the guest:
#   bash /path/to/cdemu-swap-disc.sh

set -euo pipefail

SHARE=/run/anodize/share
DISC_BASE=test-bdr

# Locate gdbus — Nix paths may not be in PATH for a raw SSH command.
GDBUS="${GDBUS:-$(command -v gdbus 2>/dev/null || echo /run/current-system/sw/bin/gdbus)}"
if [ ! -x "$GDBUS" ]; then
    echo "ERROR: gdbus not found" >&2
    exit 1
fi

# Find the ceremony user's D-Bus session address.
# cdemu-daemon runs as a user service under the ceremony user.
CEREMONY_UID=$(id -u ceremony 2>/dev/null || echo "")
if [ -z "$CEREMONY_UID" ]; then
    echo "ERROR: ceremony user not found" >&2
    exit 1
fi

DBUS_ADDR=""
for f in /run/user/"$CEREMONY_UID"/bus; do
    if [ -S "$f" ]; then
        DBUS_ADDR="unix:path=$f"
        break
    fi
done
if [ -z "$DBUS_ADDR" ]; then
    echo "ERROR: no D-Bus session socket for ceremony user (uid=$CEREMONY_UID)" >&2
    exit 1
fi
export DBUS_SESSION_BUS_ADDRESS="$DBUS_ADDR"

echo "Using D-Bus: $DBUS_SESSION_BUS_ADDRESS"

# 1. Unload the current disc from cdemu slot 0.
echo "Unloading cdemu slot 0..."
"$GDBUS" call --session \
    --dest net.sf.cdemu.CDEmuDaemon \
    --object-path /Daemon \
    --method net.sf.cdemu.CDEmuDaemon.DeviceUnload \
    0

# 2. Archive old ISO files.
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
ARCHIVED=0
for f in "$SHARE"/${DISC_BASE}.iso "$SHARE"/${DISC_BASE}-*.iso; do
    if [ -f "$f" ]; then
        ARCHIVE_NAME="${f%.iso}-${TIMESTAMP}.iso.bak"
        mv "$f" "$ARCHIVE_NAME"
        echo "Archived: $(basename "$f") → $(basename "$ARCHIVE_NAME")"
        ARCHIVED=$((ARCHIVED + 1))
    fi
done
echo "Archived $ARCHIVED file(s)."

# 3. Create a fresh blank BD-R.
echo "Creating new blank BD-R at $SHARE/$DISC_BASE.iso..."
"$GDBUS" call --session \
    --dest net.sf.cdemu.CDEmuDaemon \
    --object-path /Daemon \
    --method net.sf.cdemu.CDEmuDaemon.DeviceCreateBlank \
    0 "$SHARE/$DISC_BASE.iso" \
    "{'writer-id': <'WRITER-ISO'>, 'medium-type': <'bdr'>}"

echo "Done — fresh blank BD-R loaded in cdemu slot 0."
