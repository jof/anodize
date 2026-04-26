.PHONY: ci nix-check qemu qemu-sdl qemu-curses qemu-dev qemu-dev-sdl qemu-dev-curses clean test fmt lint deny build-dev

# Run the full GitHub Actions CI job locally via act + Docker
ci:
	act push --job check

# Run the Nix build job locally via act + Docker (same philosophy as 'make ci')
nix-check:
	act push --job nix

# Shared helper: runs a Nix build inside Docker and copies the ISO to a local path.
# Usage: $(call nix-iso-build, <flake-output>, <dest-file>)
define nix-iso-build
	docker volume create nix-store 2>/dev/null || true
	docker run --rm --privileged \
		-v nix-store:/nix \
		-v "$(CURDIR):/src" \
		-w /src \
		nixos/nix \
		sh -c 'git config --global --add safe.directory /src && \
		       nix --extra-experimental-features "nix-command flakes" build .#$(1) && \
		       cp -L result/iso/*.iso /src/$(2)'
	@echo "ISO ready: $(CURDIR)/$(2)"
endef

# Production ceremony ISO (optical M-Disc write path).
# This is a release-only step; first run takes 10-30 minutes.
anodize.iso:
	$(call nix-iso-build,iso,anodize.iso)

# Development ISO with dev-usb-disc feature (USB stick as disc substitute).
# Faster to iterate on than the production ISO; never use in a real ceremony.
anodize-dev.iso:
	$(call nix-iso-build,dev-iso,anodize-dev.iso)

dev-iso: anodize-dev.iso

# Create a 64 MiB FAT USB image pre-loaded with a SoftHSM2 profile and a
# pre-initialized SoftHSM2 token for dev-softhsm-usb testing.
# Requires: mtools (mcopy, mmd), softhsm2-util.
# Only built once — delete to recreate.
#
# Dev credentials written into this image:
#   token label : anodize-root-2026
#   user PIN    : 123456
#   SO PIN      : 12345678
fake-usb.img:
	truncate -s 64M $@
	mkfs.vfat $@
	printf '%s\n' \
	    '[ca]' \
	    'common_name  = "Example Root CA"' \
	    'organization = "Example Corp"' \
	    'country      = "US"' \
	    '' \
	    '[hsm]' \
	    'module_path = "/run/current-system/sw/lib/softhsm/libsofthsm2.so"' \
	    'token_label = "anodize-root-2026"' \
	    'key_label   = "root-key"' \
	    'key_spec    = "ecdsa-p384"' \
	    'pin_source  = "prompt"' \
	    | mcopy -i $@ - ::profile.toml
	bash scripts/init-softhsm-usb.sh $@
	@echo "$@ ready (dev PIN: 123456)"

# Boot anodize.iso in QEMU via EFI (OVMF) with a fake USB stick.
# EFI boot uses GRUB (timeout=0 → instant boot) rather than legacy BIOS/ISOLINUX
# where TIMEOUT 0 means "wait forever for user input".
# Requires: ovmf package (OVMF_CODE_4M.fd), mtools (for fake-usb.img).
# OVMF vars are copied to a temp file so boot entries are not persisted.
#
# The ISO kernel params include video=efifb:off so Linux uses the VGA text
# console rather than the EFI framebuffer (efifb breaks SDL VGA capture).
OVMF_CODE ?= /usr/share/OVMF/OVMF_CODE_4M.fd
OVMF_VARS ?= /usr/share/OVMF/OVMF_VARS_4M.fd
QEMU_BASE = qemu-system-x86_64 -enable-kvm -machine pc -cpu host -m 2G -smp 2 \
	  -drive if=pflash,format=raw,readonly=on,file=$(OVMF_CODE) \
	  -drive if=pflash,format=raw,file=/tmp/anodize-ovmf-vars.fd \
	  -cdrom anodize.iso -no-reboot \
	  -drive file=fake-usb.img,format=raw,if=none,id=usb0 \
	  -device usb-ehci,id=ehci \
	  -device usb-storage,drive=usb0,bus=ehci.0 \
	  -serial stdio

# QEMU base with a second USB stick for dev-usb-disc testing.
# fake-usb.img  → profile USB (/dev/sda in guest)
# fake-disc-usb.img → disc USB (/dev/sdb in guest)
QEMU_DEV_BASE = $(QEMU_BASE) \
	  -drive file=fake-disc-usb.img,format=raw,if=none,id=usb1 \
	  -device usb-storage,drive=usb1,bus=ehci.0

qemu: qemu-sdl

# SDL graphical window.  Serial console output also appears in the terminal
# that launched make (via -serial stdio) — useful when SDL shows nothing.
qemu-sdl: anodize.iso fake-usb.img
	cp $(OVMF_VARS) /tmp/anodize-ovmf-vars.fd
	$(QEMU_BASE) -display sdl -vga std

# Curses mode — renders VGA text content in the terminal.  Press Ctrl-A X to
# quit QEMU.  Only shows VGA text-mode output; framebuffer content is invisible
# here — compare with SDL or serial stdio output to check boot progress.
qemu-curses: anodize.iso fake-usb.img
	cp $(OVMF_VARS) /tmp/anodize-ovmf-vars.fd
	$(QEMU_BASE) -display curses -vga std

# Dev-mode QEMU targets: boot the dev ISO with both profile USB and disc USB attached.
QEMU_DEV_BASE_ISO = $(subst -cdrom anodize.iso,-cdrom anodize-dev.iso,$(QEMU_DEV_BASE))

qemu-dev: qemu-dev-sdl

qemu-dev-sdl: anodize-dev.iso fake-usb.img fake-disc-usb.img
	cp $(OVMF_VARS) /tmp/anodize-ovmf-vars.fd
	$(QEMU_DEV_BASE_ISO) -display sdl -vga std

qemu-dev-curses: anodize-dev.iso fake-usb.img fake-disc-usb.img
	cp $(OVMF_VARS) /tmp/anodize-ovmf-vars.fd
	$(QEMU_DEV_BASE_ISO) -display curses -vga std

# 64 MiB FAT image pre-marked as a disc USB for dev-usb-disc testing.
# Requires mtools (mcopy).  Only built once — delete to recreate.
fake-disc-usb.img:
	truncate -s 64M $@
	mkfs.vfat $@
	printf 'disc-usb-dev' | mcopy -i $@ - ::ANODIZE_DISC_ID
	@echo "$@ ready"

# Build anodize-ceremony and anodize-sentinel with all dev features enabled
# (never use in a real ceremony).
# dev-usb-disc:    USB stick as M-Disc substitute
# dev-softhsm-usb: SoftHSM2 token directory on profile USB as HSM backend
#
# To run the sentinel locally without a full ISO boot:
#   mkdir -p /tmp/anodize
#   ./target/debug/anodize-sentinel --lock-file /tmp/anodize/ceremony.lock
build-dev:
	cargo build -p anodize-tui --features dev-usb-disc,dev-softhsm-usb

clean:
	rm -f anodize.iso anodize-dev.iso fake-usb.img fake-disc-usb.img /tmp/anodize-ovmf-vars.fd

# Inner-loop shortcuts (no Docker overhead)
fmt:
	cargo fmt --all -- --check

lint:
	cargo clippy --all-targets --all-features -- -D warnings

test:
	cargo test --all -- --test-threads=1

deny:
	cargo deny check
