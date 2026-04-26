.PHONY: ci nix-check nix-iso iso qemu test fmt lint deny

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
nix-iso:
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

# Alias — same as nix-iso but reads more naturally in CI/CD contexts
iso: nix-iso

# Boot anodize.iso in QEMU via EFI (OVMF) with a fake USB stick.
# Requires: anodize.iso, fake-usb.img (see below), and ovmf package.
# Create fake USB:
#   truncate -s 64M fake-usb.img && mkfs.vfat fake-usb.img
#   mcopy -i fake-usb.img /etc/anodize/profile.example.toml ::/profile.toml
# OVMF vars are copied to a temp file so UEFI boot entries are not persisted.
# The ISO uses EFI GRUB (timeout=0 → instant boot, no splash).
OVMF_CODE ?= /usr/share/OVMF/OVMF_CODE_4M.fd
OVMF_VARS ?= /usr/share/OVMF/OVMF_VARS_4M.fd
qemu: anodize.iso fake-usb.img
	cp $(OVMF_VARS) /tmp/anodize-ovmf-vars.fd
	qemu-system-x86_64 -enable-kvm -machine q35 -cpu host -m 2G -smp 2 \
	  -drive if=pflash,format=raw,readonly=on,file=$(OVMF_CODE) \
	  -drive if=pflash,format=raw,file=/tmp/anodize-ovmf-vars.fd \
	  -cdrom anodize.iso \
	  -display sdl -vga std -no-reboot \
	  -drive file=fake-usb.img,format=raw,if=none,id=usb0 \
	  -device usb-ehci,id=ehci \
	  -device usb-storage,drive=usb0,bus=ehci.0

# Inner-loop shortcuts (no Docker overhead)
fmt:
	cargo fmt --all -- --check

lint:
	cargo clippy --all-targets --all-features -- -D warnings

test:
	cargo test --all -- --test-threads=1

deny:
	cargo deny check
