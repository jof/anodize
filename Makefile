.PHONY: ci nix-check iso dev-iso dev-iso-aarch64 proddbg-iso qemu qemu-sdl qemu-nographic qemu-aarch64 qemu-aarch64-nographic qemu-dev qemu-dev-sdl qemu-dev-nographic list-usb write-usb write-usb-proddbg hash-iso verify-iso clean test fmt lint deny build-dev

# Run the full GitHub Actions CI job locally via act + Docker
ci:
	act push --job check

# Run the Nix build job locally via act + Docker (same philosophy as 'make ci')
nix-check:
	act push --job nix

# ---------------------------------------------------------------------------
# ISO builds via Docker + Nix (no local Nix installation required)
#
# A persistent Docker volume per architecture caches the Nix store across
# runs so the first build takes 10-30 minutes and subsequent builds are
# incremental.  Volumes are kept separate (nix-store-amd64 / nix-store-arm64)
# because Nix store paths are architecture-specific.
#
# On Apple Silicon the amd64 builds run under QEMU emulation inside Docker
# and will be slow.  Use dev-iso-aarch64 + qemu-aarch64 for fast iteration.
# ---------------------------------------------------------------------------

# Pin the Docker image so builds use the same Nix binary across machines.
# Bump this when you intentionally want a newer Nix; don't rely on :latest.
NIX_IMAGE ?= nixos/nix:2.28.3

# On macOS (Colima / Docker Desktop) the kernel inside the VM does not
# support the seccomp BPF filters that the Nix sandbox tries to load.
# Disabling filter-syscalls skips only the seccomp layer while keeping the
# namespace-based sandbox intact.  Build output is identical either way.
ifeq ($(shell uname -s),Darwin)
NIX_SANDBOX_FLAG := --option filter-syscalls false
else
NIX_SANDBOX_FLAG :=
endif

# Source files that affect the ISO build — changing any of these triggers a rebuild.
NIX_SOURCES := flake.nix flake.lock nix/iso.nix

# $(call nix-iso-build, <flake-output>, <dest-file>, <docker-platform>, <arch-tag>)
define nix-iso-build
	docker volume create nix-store-$(4) 2>/dev/null || true
	docker run --rm --privileged \
		--platform $(3) \
		-v nix-store-$(4):/nix \
		-v "$(CURDIR):/src" \
		-w /src \
		$(NIX_IMAGE) \
		sh -c 'rm -rf /homeless-shelter && \
		       git config --global --add safe.directory /src && \
		       nix --extra-experimental-features "nix-command flakes" \
		           --option build-users-group "" \
		           $(NIX_SANDBOX_FLAG) build .#$(1) && \
		       rm -f /src/$(2) && cp -L result/iso/*.iso /src/$(2)'
	@echo "ISO ready: $(2)"
endef

# Production ISO (x86_64).
# Requires a clean git tree for bit-for-bit reproducibility.  Override with
# ALLOW_DIRTY=1 during development.
anodize.iso: $(NIX_SOURCES)
ifeq ($(ALLOW_DIRTY),)
	@if ! git diff --quiet HEAD 2>/dev/null; then \
		echo "ERROR: Tracked files are modified.  Commit changes before building" >&2; \
		echo "       the production ISO, or set ALLOW_DIRTY=1 to override." >&2; \
		exit 1; \
	fi
endif
	$(call nix-iso-build,iso,anodize.iso,linux/amd64,amd64)

# Development ISO (x86_64), boots well in QEMU.
anodize-dev.iso: $(NIX_SOURCES)
	$(call nix-iso-build,dev-iso,anodize-dev.iso,linux/amd64,amd64)

# Development ISO (aarch64) — runs natively on Apple Silicon.
anodize-dev-aarch64.iso: $(NIX_SOURCES)
	$(call nix-iso-build,dev-iso-aarch64,anodize-dev-aarch64.iso,linux/arm64,arm64)

# Production debug ISO — real hardware + SSH/DHCP for remote debugging (x86_64).
anodize-proddbg.iso: $(NIX_SOURCES)
	$(call nix-iso-build,proddbg-iso,anodize-proddbg.iso,linux/amd64,amd64)

iso:             anodize.iso
dev-iso:         anodize-dev.iso
dev-iso-aarch64: anodize-dev-aarch64.iso
proddbg-iso:     anodize-proddbg.iso

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

# ---------------------------------------------------------------------------
# QEMU development targets — boot a dev ISO locally.
#
# Firmware paths are auto-detected across macOS (Homebrew) and Linux (distro
# packages).  Override OVMF_CODE / OVMF_VARS / AAVMF_CODE if your paths differ.
#
# x86_64 uses software emulation (tcg) on macOS and KVM on Linux by default.
# Prefer qemu-aarch64 for day-to-day testing on Apple Silicon.
# ---------------------------------------------------------------------------

OVMF_CODE ?= $(firstword $(wildcard \
  /opt/homebrew/share/qemu/edk2-x86_64-code.fd \
  /usr/local/share/qemu/edk2-x86_64-code.fd \
  /usr/share/OVMF/OVMF_CODE_4M.fd \
  /usr/share/OVMF/OVMF_CODE.fd \
  /usr/share/edk2/x64/OVMF_CODE.4m.fd))

OVMF_VARS ?= $(firstword $(wildcard \
  /opt/homebrew/share/qemu/edk2-i386-vars.fd \
  /usr/local/share/qemu/edk2-i386-vars.fd \
  /usr/share/OVMF/OVMF_VARS_4M.fd \
  /usr/share/OVMF/OVMF_VARS.fd \
  /usr/share/edk2/x64/OVMF_VARS.4m.fd))

AAVMF_CODE ?= $(firstword $(wildcard \
  /opt/homebrew/share/qemu/edk2-aarch64-code.fd \
  /usr/local/share/qemu/edk2-aarch64-code.fd \
  /usr/share/AAVMF/AAVMF_CODE.fd \
  /usr/share/edk2/aarch64/QEMU_EFI.fd))

ifeq ($(shell uname -s),Darwin)
QEMU_ACCEL   ?= tcg
QEMU_CPU     ?= qemu64
QEMU_DISPLAY ?= cocoa
else
QEMU_ACCEL   ?= kvm
QEMU_CPU     ?= host
QEMU_DISPLAY ?= sdl
endif

QEMU_BASE = qemu-system-x86_64 \
	  -machine pc,accel=$(QEMU_ACCEL) \
	  -cpu $(QEMU_CPU) \
	  -m 2G -smp 2 \
	  -drive if=pflash,format=raw,readonly=on,file=$(OVMF_CODE) \
	  -drive if=pflash,format=raw,file=/tmp/anodize-ovmf-vars.fd \
	  -cdrom anodize.iso -no-reboot \
	  -drive file=fake-usb.img,format=raw,if=none,id=usb0 \
	  -device usb-ehci,id=ehci \
	  -device usb-storage,drive=usb0,bus=ehci.0 \
	  -serial stdio

# aarch64 with HVF hardware acceleration — near-native speed on Apple Silicon.
QEMU_AARCH64_BASE = qemu-system-aarch64 \
	  -machine virt,accel=hvf \
	  -cpu host \
	  -m 2G -smp 2 \
	  -bios $(AAVMF_CODE) \
	  -device nec-usb-xhci,id=xhci \
	  -drive if=none,id=usbiso,format=raw,readonly=on,file=anodize-dev-aarch64.iso \
	  -device usb-storage,bus=xhci.0,drive=usbiso \
	  -drive file=fake-usb.img,format=raw,if=none,id=usb0 \
	  -device usb-storage,bus=xhci.0,drive=usb0 \
	  -no-reboot \
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
	$(QEMU_BASE) -display $(QEMU_DISPLAY) -vga std

# No-graphic mode — serial console only, no VGA rendering.  Ctrl-A X to quit.
qemu-nographic: anodize.iso fake-usb.img
	cp $(OVMF_VARS) /tmp/anodize-ovmf-vars.fd
	$(subst -serial stdio,-nographic,$(QEMU_BASE))

# aarch64 with graphical window — near-native speed via HVF on Apple Silicon.
qemu-aarch64: anodize-dev-aarch64.iso fake-usb.img
	$(QEMU_AARCH64_BASE) -display cocoa -device virtio-gpu-pci

# aarch64 serial console only.  Ctrl-A X to quit.
qemu-aarch64-nographic: anodize-dev-aarch64.iso fake-usb.img
	$(subst -serial stdio,-nographic,$(QEMU_AARCH64_BASE))

# Dev-mode QEMU targets: boot the dev ISO with both profile USB and disc USB attached.
QEMU_DEV_BASE_ISO = $(subst -cdrom anodize.iso,-cdrom anodize-dev.iso,$(QEMU_DEV_BASE))

qemu-dev: qemu-dev-sdl

qemu-dev-sdl: anodize-dev.iso fake-usb.img fake-disc-usb.img
	cp $(OVMF_VARS) /tmp/anodize-ovmf-vars.fd
	$(QEMU_DEV_BASE_ISO) -display $(QEMU_DISPLAY) -vga std

# No-graphic mode — serial console only, no VGA rendering.  Ctrl-A X to quit.
qemu-dev-nographic: anodize-dev.iso fake-usb.img fake-disc-usb.img
	cp $(OVMF_VARS) /tmp/anodize-ovmf-vars.fd
	$(subst -serial stdio,-nographic,$(QEMU_DEV_BASE_ISO))

# 64 MiB FAT image pre-marked as a disc USB for dev-usb-disc testing.
# Requires mtools (mcopy).  Only built once — delete to recreate.
fake-disc-usb.img:
	truncate -s 64M $@
	mkfs.vfat $@
	printf 'disc-usb-dev' | mcopy -i $@ - ::ANODIZE_DISC_ID
	@echo "$@ ready"

# ---------------------------------------------------------------------------
# USB write target — write anodize.iso to a USB stick identified by serial
# number.  This avoids hardcoding /dev/diskN which can shift between plugs.
# macOS only (uses ioreg + diskutil).
#
# Usage:
#   make write-usb USB_SERIAL=ABCD1234
#
# Find your stick's serial with:
#   make list-usb
# ---------------------------------------------------------------------------

USB_SERIAL ?=

list-usb:
	@python3 -c '\
	import subprocess, re, sys; \
	data = subprocess.check_output(["ioreg", "-r", "-c", "IOUSBHostDevice", "-l"]).decode(); \
	serials = {m.group(1): m.start() for m in re.finditer(r"\"USB Serial Number\"\s*=\s*\"(\w+)\"", data)}; \
	rows = []; \
	[rows.append((s, \
	  (lambda blk, fwd: ( \
	    (lambda v, p, b: ((v.group(1) + " " if v else "") + (p.group(1) if p else "Unknown"), b.group(1) if b else "no disk")) \
	    (re.search(r"\"USB Vendor Name\"\s*=\s*\"([^\"]+)\"", blk), \
	     re.search(r"\"USB Product Name\"\s*=\s*\"([^\"]+)\"", blk), \
	     re.search(r"\"BSD Name\"\s*=\s*\"(disk\d+)\"", fwd)))) \
	  (data[data.rfind("+-o ", 0, pos):pos], data[pos:]))) for s, pos in serials.items()]; \
	(lambda: [print(f"  {s:<{max(len(x) for x,_ in rows)}}  {d:<{max(len(y) for _,(_, y) in rows)}}  {n}") for s, (n, d) in rows])() if rows else print("No USB storage devices found.")'

write-usb: anodize.iso
ifndef USB_SERIAL
	$(error USB_SERIAL is required — set it to your USB stick serial number)
endif
	@disk=$$(ioreg -r -c IOUSBHostDevice -l | \
		python3 -c 'import sys, re; \
		data = sys.stdin.read(); \
		serial = "$(USB_SERIAL)"; \
		pos = data.find("\"USB Serial Number\" = \"" + serial + "\""); \
		match = re.search(r"\"BSD Name\"\s*=\s*\"(disk\d+)\"", data[pos:]) if pos >= 0 else None; \
		print(match.group(1)) if match else sys.exit(1)') && \
	if [ -z "$$disk" ]; then \
		echo "No disk found with serial $(USB_SERIAL)" >&2; exit 1; \
	fi && \
	echo "Found serial $(USB_SERIAL) at /dev/$$disk" && \
	diskutil unmountDisk /dev/$$disk && \
	sudo dd if=anodize.iso of=/dev/r$$disk bs=1m && \
	diskutil eject /dev/$$disk && \
	echo "Done — safe to remove the USB stick."

write-usb-proddbg: anodize-proddbg.iso
ifndef USB_SERIAL
	$(error USB_SERIAL is required — set it to your USB stick serial number)
endif
	@disk=$$(ioreg -r -c IOUSBHostDevice -l | \
		python3 -c 'import sys, re; \
		data = sys.stdin.read(); \
		serial = "$(USB_SERIAL)"; \
		pos = data.find("\"USB Serial Number\" = \"" + serial + "\""); \
		match = re.search(r"\"BSD Name\"\s*=\s*\"(disk\d+)\"", data[pos:]) if pos >= 0 else None; \
		print(match.group(1)) if match else sys.exit(1)') && \
	if [ -z "$$disk" ]; then \
		echo "No disk found with serial $(USB_SERIAL)" >&2; exit 1; \
	fi && \
	echo "Found serial $(USB_SERIAL) at /dev/$$disk" && \
	diskutil unmountDisk /dev/$$disk && \
	sudo dd if=anodize-proddbg.iso of=/dev/r$$disk bs=1m && \
	diskutil eject /dev/$$disk && \
	echo "Done — safe to remove the USB stick."

# ---------------------------------------------------------------------------
# ISO hash and verification — for reproducibility assurance.
#
# hash-iso:   Record the ISO checksum + git commit to anodize.iso.sha256.
# verify-iso: Rebuild from the same commit and compare checksums.
# ---------------------------------------------------------------------------

hash-iso: anodize.iso
	@commit=$$(git rev-parse --short HEAD 2>/dev/null || echo unknown); \
	sha=$$(shasum -a 256 anodize.iso | cut -d' ' -f1); \
	echo "$$sha  anodize.iso  # git:$$commit" | tee anodize.iso.sha256

verify-iso: anodize.iso.sha256
	@expected=$$(awk '{print $$1}' anodize.iso.sha256); \
	actual=$$(shasum -a 256 anodize.iso | cut -d' ' -f1); \
	if [ "$$expected" = "$$actual" ]; then \
		echo "PASS: anodize.iso matches anodize.iso.sha256"; \
	else \
		echo "FAIL: expected $$expected, got $$actual" >&2; exit 1; \
	fi

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
	rm -f anodize.iso anodize-dev.iso anodize-dev-aarch64.iso anodize-proddbg.iso anodize.iso.sha256 fake-usb.img fake-disc-usb.img /tmp/anodize-ovmf-vars.fd

# Inner-loop shortcuts (no Docker overhead)
fmt:
	cargo fmt --all -- --check

lint:
	cargo clippy --all-targets --all-features -- -D warnings

test:
	cargo test --all -- --test-threads=1

deny:
	cargo deny check
