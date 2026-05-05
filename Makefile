.PHONY: ci nix-check prod-amd64 prod-arm64 dev-amd64 dev-arm64 qemu qemu-sdl qemu-nographic qemu-aarch64 qemu-aarch64-nographic qemu-dev qemu-dev-sdl qemu-dev-nographic ssh-dev list-usb write-usb hash-iso verify-iso clean test fmt lint deny build-dev

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
# and will be slow.  Use dev-arm64 + qemu-aarch64 for fast iteration.
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
NIX_SOURCES := flake.nix flake.lock nix/iso.nix nix/cdemu.nix

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

# Production ISO (amd64).
# Requires a clean git tree for bit-for-bit reproducibility.  Override with
# ALLOW_DIRTY=1 during development.
anodize-prod-amd64.iso: $(NIX_SOURCES)
ifeq ($(ALLOW_DIRTY),)
	@if ! git diff --quiet HEAD 2>/dev/null; then \
		echo "ERROR: Tracked files are modified.  Commit changes before building" >&2; \
		echo "       the production ISO, or set ALLOW_DIRTY=1 to override." >&2; \
		exit 1; \
	fi
endif
	$(call nix-iso-build,prod-amd64,anodize-prod-amd64.iso,linux/amd64,amd64)

# Production ISO (arm64).
anodize-prod-arm64.iso: $(NIX_SOURCES)
ifeq ($(ALLOW_DIRTY),)
	@if ! git diff --quiet HEAD 2>/dev/null; then \
		echo "ERROR: Tracked files are modified.  Commit changes before building" >&2; \
		echo "       the production ISO, or set ALLOW_DIRTY=1 to override." >&2; \
		exit 1; \
	fi
endif
	$(call nix-iso-build,prod-arm64,anodize-prod-arm64.iso,linux/arm64,arm64)

# Development ISO (amd64) — cdemu, SSH, DHCP, 9p share.
anodize-dev-amd64.iso: $(NIX_SOURCES)
	$(call nix-iso-build,dev-amd64,anodize-dev-amd64.iso,linux/amd64,amd64)

# Development ISO (arm64) — runs natively on Apple Silicon via HVF.
anodize-dev-arm64.iso: $(NIX_SOURCES)
	$(call nix-iso-build,dev-arm64,anodize-dev-arm64.iso,linux/arm64,arm64)

prod-amd64: anodize-prod-amd64.iso
prod-arm64: anodize-prod-arm64.iso
dev-amd64:  anodize-dev-amd64.iso
dev-arm64:  anodize-dev-arm64.iso

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
# QEMU targets — boot ISOs locally for testing and development.
#
# Firmware paths are auto-detected across macOS (Homebrew) and Linux (distro
# packages).  Override OVMF_CODE / OVMF_VARS / AAVMF_CODE if your paths differ.
#
# x86_64 uses software emulation (tcg) on macOS and KVM on Linux by default.
# Prefer qemu-aarch64 for day-to-day testing on Apple Silicon.
#
# Prod targets (qemu-sdl, qemu-nographic): boot the production ISO.
# Dev targets  (qemu-dev-*, qemu-aarch64): boot the dev ISO with cdemu,
#   SSH (port 2222), and a 9p share at dev-disc/.
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

# Host directory shared into the guest via virtio-9p (dev ISOs only).
# Inspect dev-disc/test-bdr.img after a ceremony session.
DEV_DISC_DIR ?= $(CURDIR)/dev-disc

# SSH port forwarded from host localhost to guest sshd (dev ISOs only).
DEV_SSH_PORT ?= 2222

# Prod amd64 QEMU base command.
QEMU_BASE = qemu-system-x86_64 \
	  -machine pc,accel=$(QEMU_ACCEL) \
	  -cpu $(QEMU_CPU) \
	  -m 2G -smp 2 \
	  -drive if=pflash,format=raw,readonly=on,file=$(OVMF_CODE) \
	  -drive if=pflash,format=raw,file=/tmp/anodize-ovmf-vars.fd \
	  -cdrom anodize-prod-amd64.iso -no-reboot \
	  -drive file=fake-usb.img,format=raw,if=none,id=usb0 \
	  -device usb-ehci,id=ehci \
	  -device usb-storage,drive=usb0,bus=ehci.0 \
	  -serial stdio

# Dev amd64 QEMU: dev ISO + SoftHSM USB + 9p share + user-mode networking.
# The cdemu stack runs inside the guest — no host setup required.
QEMU_DEV_BASE = qemu-system-x86_64 -enable-kvm -machine pc -cpu host -m 2G -smp 2 \
	  -drive if=pflash,format=raw,readonly=on,file=$(OVMF_CODE) \
	  -drive if=pflash,format=raw,file=/tmp/anodize-ovmf-vars.fd \
	  -cdrom anodize-dev-amd64.iso -no-reboot \
	  -drive file=fake-usb.img,format=raw,if=none,id=usb0 \
	  -device usb-ehci,id=ehci \
	  -device usb-storage,drive=usb0,bus=ehci.0 \
	  -fsdev local,security_model=none,id=devdisc,path=$(DEV_DISC_DIR) \
	  -device virtio-9p-pci,id=fs0,fsdev=devdisc,mount_tag=dev-disc \
	  -netdev user,id=net0,hostfwd=tcp::$(DEV_SSH_PORT)-:22 \
	  -device virtio-net-pci,netdev=net0 \
	  -serial stdio

# Dev arm64 QEMU with HVF — near-native speed on Apple Silicon.
# Includes 9p share and SSH port forwarding (same as amd64 dev QEMU).
QEMU_AARCH64_BASE = qemu-system-aarch64 \
	  -machine virt,accel=hvf \
	  -cpu host \
	  -m 2G -smp 2 \
	  -bios $(AAVMF_CODE) \
	  -device nec-usb-xhci,id=xhci \
	  -drive if=none,id=usbiso,format=raw,readonly=on,file=anodize-dev-arm64.iso \
	  -device usb-storage,bus=xhci.0,drive=usbiso \
	  -drive file=fake-usb.img,format=raw,if=none,id=usb0 \
	  -device usb-storage,bus=xhci.0,drive=usb0 \
	  -fsdev local,security_model=none,id=devdisc,path=$(DEV_DISC_DIR) \
	  -device virtio-9p-pci,id=fs0,fsdev=devdisc,mount_tag=dev-disc \
	  -netdev user,id=net0,hostfwd=tcp::$(DEV_SSH_PORT)-:22 \
	  -device virtio-net-pci,netdev=net0 \
	  -no-reboot \
	  -serial stdio

qemu: qemu-sdl

# Boot production ISO in SDL graphical window.
qemu-sdl: anodize-prod-amd64.iso fake-usb.img
	cp $(OVMF_VARS) /tmp/anodize-ovmf-vars.fd
	$(QEMU_BASE) -display $(QEMU_DISPLAY) -vga std

# Boot production ISO — serial console only.  Ctrl-A X to quit.
qemu-nographic: anodize-prod-amd64.iso fake-usb.img
	cp $(OVMF_VARS) /tmp/anodize-ovmf-vars.fd
	$(subst -serial stdio,-nographic,$(QEMU_BASE))

# Dev arm64 with graphical window — near-native speed via HVF on Apple Silicon.
qemu-aarch64: anodize-dev-arm64.iso fake-usb.img
	mkdir -p $(DEV_DISC_DIR) && chmod 777 $(DEV_DISC_DIR)
	$(QEMU_AARCH64_BASE) -display cocoa -device virtio-gpu-pci

# Dev arm64 serial console only.  Ctrl-A X to quit.
qemu-aarch64-nographic: anodize-dev-arm64.iso fake-usb.img
	mkdir -p $(DEV_DISC_DIR) && chmod 777 $(DEV_DISC_DIR)
	$(subst -serial stdio,-nographic,$(QEMU_AARCH64_BASE))

# ---------------------------------------------------------------------------
# USB write target — write a production ISO to a USB stick identified by
# serial number.  This avoids hardcoding /dev/diskN which can shift between
# plugs.
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

write-usb: anodize-prod-amd64.iso
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
	sudo dd if=anodize-prod-amd64.iso of=/dev/r$$disk bs=1m && \
	diskutil eject /dev/$$disk && \
	echo "Done — safe to remove the USB stick."

# ---------------------------------------------------------------------------
# ISO hash and verification — for reproducibility assurance.
#
# hash-iso:   Record the ISO checksum + git commit to anodize-prod-amd64.iso.sha256.
# verify-iso: Rebuild from the same commit and compare checksums.
# ---------------------------------------------------------------------------

hash-iso: anodize-prod-amd64.iso
	@commit=$$(git rev-parse --short HEAD 2>/dev/null || echo unknown); \
	sha=$$(shasum -a 256 anodize-prod-amd64.iso | cut -d' ' -f1); \
	echo "$$sha  anodize-prod-amd64.iso  # git:$$commit" | tee anodize-prod-amd64.iso.sha256

verify-iso: anodize-prod-amd64.iso.sha256
	@expected=$$(awk '{print $$1}' anodize-prod-amd64.iso.sha256); \
	actual=$$(shasum -a 256 anodize-prod-amd64.iso | cut -d' ' -f1); \
	if [ "$$expected" = "$$actual" ]; then \
		echo "PASS: anodize-prod-amd64.iso matches anodize-prod-amd64.iso.sha256"; \
	else \
		echo "FAIL: expected $$expected, got $$actual" >&2; exit 1; \
	fi

# ── Dev amd64 QEMU targets ─────────────────────────────────────────────────────
#
# Primary dev/CI testing path.  The entire cdemu stack (vhba kernel module +
# cdemu-daemon + blank BD-R setup) runs *inside* the QEMU guest — no host
# modifications or daemons required.
#
# QEMU user-mode networking forwards host localhost:2222 → guest :22 so the
# dev ISO's SSH server is reachable without any host tap/bridge setup.
# Connect with: make ssh-dev  (or: ssh -p 2222 ceremony@localhost)
#
# The BD-R image is stored on a virtio-9p share: dev-disc/test-bdr.img
#
# One-time setup:
#   make fake-usb.img     # SoftHSM2 profile USB (PIN: 123456)
#   make dev-amd64        # dev ISO — first build slow, cached after
#
# Each dev session:
#   make qemu-dev         # start VM in SDL window
#   make ssh-dev          # (separate terminal) SSH into the running VM

qemu-dev: qemu-dev-sdl

qemu-dev-sdl: anodize-dev-amd64.iso fake-usb.img
	mkdir -p $(DEV_DISC_DIR) && chmod 777 $(DEV_DISC_DIR)
	cp $(OVMF_VARS) /tmp/anodize-ovmf-vars.fd
	$(QEMU_DEV_BASE) -display sdl -vga std

qemu-dev-nographic: anodize-dev-amd64.iso fake-usb.img
	mkdir -p $(DEV_DISC_DIR) && chmod 777 $(DEV_DISC_DIR)
	cp $(OVMF_VARS) /tmp/anodize-ovmf-vars.fd
	$(subst -serial stdio,-nographic,$(QEMU_DEV_BASE))

# Wait for SSH to be ready, then open an interactive session as the ceremony user.
# Run this in a second terminal while qemu-dev or qemu-aarch64 is running.
# Uses scripts/dev-ssh-key (committed dev-only keypair, localhost access only).
ssh-dev:
	@echo "Waiting for SSH on localhost:$(DEV_SSH_PORT)..."
	@until nc -z localhost $(DEV_SSH_PORT) 2>/dev/null; do sleep 1; done
	@echo "Connected."
	ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
	    -i $(CURDIR)/scripts/dev-ssh-key \
	    -p $(DEV_SSH_PORT) ceremony@localhost

# Build anodize-ceremony with dev-softhsm-usb (never use in a real ceremony).
build-dev:
	cargo build -p anodize-tui --features dev-softhsm-usb

clean:
	rm -rf anodize-prod-amd64.iso anodize-prod-arm64.iso anodize-dev-amd64.iso anodize-dev-arm64.iso anodize-prod-amd64.iso.sha256 fake-usb.img dev-disc /tmp/anodize-ovmf-vars.fd

# Inner-loop shortcuts (no Docker overhead)
fmt:
	cargo fmt --all -- --check

lint:
	cargo clippy --all-targets --all-features -- -D warnings

test:
	cargo test --all -- --test-threads=1

deny:
	cargo deny check
