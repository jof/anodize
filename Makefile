.PHONY: ci nix-check qemu qemu-sdl qemu-curses test fmt lint deny

# Run the full GitHub Actions CI job locally via act + Docker
ci:
	act push --job check

# Run the Nix build job locally via act + Docker (same philosophy as 'make ci')
nix-check:
	act push --job nix

# Build the bootable ceremony ISO via Docker and copy it to ./anodize.iso.
# Requires --privileged for squashfs/bootloader tooling.
# This is a release-only step; it takes 10-30 minutes on first run.
# A named volume (nix-store) persists the Nix store across runs so repeated
# builds don't re-download everything and the container doesn't run out of space.
anodize.iso:
	docker volume create nix-store 2>/dev/null || true
	docker run --rm --privileged \
		-v nix-store:/nix \
		-v "$(CURDIR):/src" \
		-w /src \
		nixos/nix \
		sh -c 'git config --global --add safe.directory /src && \
		       nix --extra-experimental-features "nix-command flakes" build .#iso && \
		       cp -L result/iso/anodize.iso /src/anodize.iso'
	@echo "ISO ready: $(CURDIR)/anodize.iso"

# Create a 64 MiB FAT USB image pre-loaded with a SoftHSM2 profile for QEMU testing.
# Requires mtools (mcopy).  Only built once — delete to recreate.
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
	@echo "$@ ready"

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

# Inner-loop shortcuts (no Docker overhead)
fmt:
	cargo fmt --all -- --check

lint:
	cargo clippy --all-targets --all-features -- -D warnings

test:
	cargo test --all -- --test-threads=1

deny:
	cargo deny check
