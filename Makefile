.PHONY: ci nix-check nix-reset prod-amd64 prod-arm64 dev-amd64 dev-arm64 qemu qemu-sdl qemu-nographic qemu-aarch64 qemu-aarch64-nographic qemu-dev qemu-dev-sdl qemu-dev-nographic ssh-dev ssh-dev-vm ceremony-dev-vm list-usb write-usb write-usb-dev hash-iso verify-iso deploy-dev cdemu-swap-disc cdemu-swap-disc-local clean test fmt lint deny build-dev build-shuttle shuttle-lint setup

# Run the full GitHub Actions CI job locally via act + Docker
ci:
	act push --job check

# Run the Nix build job locally via act + Docker (same philosophy as 'make ci')
nix-check:
	act push --job nix

# ---------------------------------------------------------------------------
# ISO builds via Nix
#
# Two modes, selected automatically by whether NIX_BUILDER is set:
#
#   Local (default) — Docker + Nix
#     Runs Nix inside a Docker container with a persistent volume for the
#     Nix store.  Works on any machine with Docker.  On Apple Silicon the
#     amd64 builds run under Rosetta/QEMU emulation and may be slow; use
#     dev-arm64 + qemu-aarch64 for fast iteration.
#
#   Remote — SSH + Nix on a remote x86_64-linux host
#     The source tree is rsynced to the builder, Nix runs there natively,
#     and the ISO is copied back.  Much faster than emulation on macOS.
#     The remote host needs: Nix with flakes enabled, current user as a
#     trusted-user, rsync, and git.
#
#     Bootstrap a fresh Debian/Ubuntu builder:
#       sudo apt update && sudo apt install -y build-essential rsync git
#       sh <(curl -L https://nixos.org/nix/install) --daemon
#       sudo mkdir -p /etc/nix
#       echo 'experimental-features = nix-command flakes' | sudo tee -a /etc/nix/nix.conf
#       echo "trusted-users = root $(whoami)" | sudo tee -a /etc/nix/nix.conf
#       sudo systemctl restart nix-daemon
#       # Log out/in or: . /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
#
# Environment variables:
#   NIX_BUILDER       SSH destination (user@host or host).  When set,
#                     the remote path is used.  Unset = local Docker.
#   NIX_BUILDER_DIR   Remote working directory (default: /tmp/anodize-build).
#   NIX_IMAGE         Docker image for local builds (default: nixos/nix:2.28.3).
#   ALLOW_DIRTY       Set to 1 to skip the clean-tree check on prod ISOs.
#
# Examples:
#   make prod-amd64                          # local Docker build
#   NIX_BUILDER=10.0.0.5 make prod-amd64    # remote build
# ---------------------------------------------------------------------------

NIX_BUILDER ?=
NIX_BUILDER_DIR ?= /tmp/anodize-build
SSH_OPTS := -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null

# Pin the Docker image so local builds use the same Nix binary across machines.
NIX_IMAGE ?= nixos/nix:2.28.3

# Sandbox is disabled in Docker (--option sandbox false) because builds run as
# root without build-users-group.  On macOS, also disable filter-syscalls since
# the Docker VM kernel does not support the seccomp BPF filters.
ifeq ($(shell uname -s),Darwin)
NIX_SANDBOX_FLAG := --option filter-syscalls false
else
NIX_SANDBOX_FLAG :=
endif

# Source files that affect the ISO build — changing any of these triggers a rebuild.
NIX_SOURCES := flake.nix flake.lock nix/iso.nix nix/dev-iso.nix

# $(call nix-iso-build, <flake-output>, <dest-file>, <docker-platform>, <arch-tag>)
ifdef NIX_BUILDER
define nix-iso-build
	rsync -az --delete \
		-e 'ssh $(SSH_OPTS)' \
		--filter=':- .gitignore' \
		--exclude='.git' \
		$(CURDIR)/ $(NIX_BUILDER):$(NIX_BUILDER_DIR)/
	ssh $(SSH_OPTS) $(NIX_BUILDER) \
		'. /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh && \
		 cd $(NIX_BUILDER_DIR) && \
		 nix build .#$(1) -L'
	rsync -az --progress \
		-e 'ssh $(SSH_OPTS)' \
		'$(NIX_BUILDER):$(NIX_BUILDER_DIR)/result/iso/*.iso' $(2)
	@echo "ISO ready: $(2)"
endef
else
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
		           --option sandbox false \
		           $(NIX_SANDBOX_FLAG) build .#$(1) && \
		       rm -f /src/$(2) && cp -L result/iso/*.iso /src/$(2)'
	@echo "ISO ready: $(2)"
endef
endif

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

# Reset the build cache.  Remote mode: wipe the remote directory.
# Local mode: remove Docker Nix store volumes.
nix-reset:
ifdef NIX_BUILDER
	ssh $(SSH_OPTS) $(NIX_BUILDER) 'rm -rf $(NIX_BUILDER_DIR)'
	@echo "Remote build directory removed."
else
	@for arch in amd64 arm64; do \
	  vol="nix-store-$$arch"; \
	  if docker volume inspect "$$vol" >/dev/null 2>&1; then \
	    echo "Removing $$vol"; \
	    docker volume rm "$$vol"; \
	  fi; \
	done
endif

prod-amd64: anodize-prod-amd64.iso
prod-arm64: anodize-prod-arm64.iso
dev-amd64:  anodize-dev-amd64.iso
dev-arm64:  anodize-dev-arm64.iso

# Create a 64 MiB FAT shuttle image with a profile.toml and an empty
# SoftHSM2 token directory.  The actual token is initialized during the
# ceremony's InitRoot phase via C_InitToken — no pre-seeded credentials.
# Requires: mtools (mcopy, mmd).
# Only built once — delete to recreate.
fake-shuttle.img:
	truncate -s 64M $@
	mkfs.vfat $@
	printf '%s\n' \
	    '[ca]' \
	    'common_name  = "Example Root CA"' \
	    'organization = "Example Corp"' \
	    'country      = "US"' \
	    'cdp_url      = "http://crl.example.com/root.crl"' \
	    '' \
	    '[hsm]' \
	    'backend     = "softhsm"' \
	    'token_label = "anodize-root-2026"' \
	    'key_label   = "root-key"' \
	    'key_spec    = "ecdsa-p384"' \
	    '' \
	    '[[cert_profiles]]' \
	    'name          = "sub-ca"' \
	    'validity_days = 1825' \
	    'path_len      = 0' \
	    | mcopy -i $@ - ::profile.toml
	mmd -i $@ ::softhsm2
	mmd -i $@ ::softhsm2/tokens
	@echo "$@ ready"

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
	  -drive file=fake-shuttle.img,format=raw,if=none,id=usb0 \
	  -device usb-ehci,id=ehci \
	  -device usb-storage,drive=usb0,bus=ehci.0 \
	  -serial stdio

# Dev amd64 QEMU: dev ISO + SoftHSM shuttle + 9p share + user-mode networking.
# The cdemu stack runs inside the guest — no host setup required.
QEMU_DEV_BASE = qemu-system-x86_64 -enable-kvm -machine pc -cpu host -m 2G -smp 2 \
	  -drive if=pflash,format=raw,readonly=on,file=$(OVMF_CODE) \
	  -drive if=pflash,format=raw,file=/tmp/anodize-ovmf-vars.fd \
	  -cdrom anodize-dev-amd64.iso -no-reboot \
	  -drive file=fake-shuttle.img,format=raw,if=none,id=usb0 \
	  -device usb-ehci,id=ehci \
	  -device usb-storage,drive=usb0,bus=ehci.0 \
	  -fsdev local,security_model=mapped-xattr,id=devdisc,path=$(DEV_DISC_DIR) \
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
	  -drive file=fake-shuttle.img,format=raw,if=none,id=usb0 \
	  -device usb-storage,bus=xhci.0,drive=usb0 \
	  -fsdev local,security_model=mapped-xattr,id=devdisc,path=$(DEV_DISC_DIR) \
	  -device virtio-9p-pci,id=fs0,fsdev=devdisc,mount_tag=dev-disc \
	  -netdev user,id=net0,hostfwd=tcp::$(DEV_SSH_PORT)-:22 \
	  -device virtio-net-pci,netdev=net0 \
	  -no-reboot \
	  -serial stdio

qemu: qemu-sdl

# Boot production ISO in SDL graphical window.
qemu-sdl: anodize-prod-amd64.iso fake-shuttle.img
	cp $(OVMF_VARS) /tmp/anodize-ovmf-vars.fd
	$(QEMU_BASE) -display $(QEMU_DISPLAY) -vga std

# Boot production ISO — serial console only.  Ctrl-A X to quit.
qemu-nographic: anodize-prod-amd64.iso fake-shuttle.img
	cp $(OVMF_VARS) /tmp/anodize-ovmf-vars.fd
	$(subst -serial stdio,-nographic,$(QEMU_BASE))

# Dev arm64 with graphical window — near-native speed via HVF on Apple Silicon.
qemu-aarch64: anodize-dev-arm64.iso fake-shuttle.img
	mkdir -p $(DEV_DISC_DIR) && chmod 777 $(DEV_DISC_DIR)
	@# 9p mapped-xattr leaves 0600 perms; strip so cdemu can read on next boot
	@for f in $(DEV_DISC_DIR)/*.iso; do [ -f "$$f" ] && xattr -c "$$f" && chmod 666 "$$f"; done 2>/dev/null || true
	$(QEMU_AARCH64_BASE) -display cocoa -device virtio-gpu-pci

# Dev arm64 serial console only.  Ctrl-A X to quit.
qemu-aarch64-nographic: anodize-dev-arm64.iso fake-shuttle.img
	mkdir -p $(DEV_DISC_DIR) && chmod 777 $(DEV_DISC_DIR)
	@for f in $(DEV_DISC_DIR)/*.iso; do [ -f "$$f" ] && xattr -c "$$f" && chmod 666 "$$f"; done 2>/dev/null || true
	$(subst -serial stdio,-nographic,$(QEMU_AARCH64_BASE))

# ---------------------------------------------------------------------------
# USB write target — write a production ISO to a USB stick identified by
# serial number.  This avoids hardcoding /dev/diskN which can shift between
# plugs.
# Cross-platform: macOS (ioreg + diskutil) and Linux (lsblk).
#
# Usage:
#   make write-usb USB_SERIAL=ABCD1234
#
# Find your stick's serial with:
#   make list-usb
# ---------------------------------------------------------------------------

USB_SERIAL ?=

ifeq ($(shell uname),Darwin)
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
else
list-usb:
	@lsblk -J -d -o NAME,SERIAL,VENDOR,MODEL,SIZE,TRAN 2>/dev/null | \
	python3 -c '\
	import json, sys; \
	devs = json.load(sys.stdin).get("blockdevices", []); \
	usb = [(d["serial"], "/dev/" + d["name"], ((d.get("vendor") or "") + " " + (d.get("model") or "Unknown")).strip(), d.get("size", "")) for d in devs if (d.get("tran") or "") == "usb" and d.get("serial")]; \
	[print(f"  {s:<{max(len(r[0]) for r in usb)}}  {p:<{max(len(r[1]) for r in usb)+2}}  {n:<{max(len(r[2]) for r in usb)}}  {z}") for s,p,n,z in usb] if usb else print("No USB storage devices found.")'
endif

# $(call write-usb-iso, <iso-file>)
ifeq ($(shell uname),Darwin)
define write-usb-iso
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
	sudo dd if=$(1) of=/dev/r$$disk bs=1m && \
	diskutil eject /dev/$$disk && \
	echo "Done — safe to remove the USB stick."
endef
else
define write-usb-iso
	@dev=$$(lsblk -J -d -o NAME,SERIAL,TRAN | \
		python3 -c 'import json, sys; \
		devs = json.loads(sys.stdin.read()).get("blockdevices", []); \
		hits = [d["name"] for d in devs if d.get("tran") == "usb" and d.get("serial") == "$(USB_SERIAL)"]; \
		print(hits[0]) if hits else sys.exit(1)') && \
	if [ -z "$$dev" ]; then \
		echo "No disk found with serial $(USB_SERIAL)" >&2; exit 1; \
	fi && \
	echo "Found serial $(USB_SERIAL) at /dev/$$dev" && \
	udisksctl unmount -b /dev/$${dev}1 2>/dev/null || true && \
	sudo dd if=$(1) of=/dev/$$dev bs=1M status=progress && \
	sync && \
	udisksctl power-off -b /dev/$$dev 2>/dev/null && \
	echo "Done — safe to remove the USB stick."
endef
endif

write-usb: anodize-prod-amd64.iso
ifndef USB_SERIAL
	$(error USB_SERIAL is required — set it to your USB stick serial number)
endif
	$(call write-usb-iso,anodize-prod-amd64.iso)

write-usb-dev: anodize-dev-amd64.iso
ifndef USB_SERIAL
	$(error USB_SERIAL is required — set it to your USB stick serial number)
endif
	$(call write-usb-iso,anodize-dev-amd64.iso)

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
#   make fake-shuttle.img  # SoftHSM2 profile shuttle (token init'd during ceremony)
#   make dev-amd64        # dev ISO — first build slow, cached after
#
# Each dev session:
#   make qemu-dev         # start VM in SDL window
#   make ssh-dev          # (separate terminal) SSH into the running VM
#   make save-disc        # flush cdemu BD-R image to dev-disc/ for inspection

qemu-dev: qemu-dev-sdl

qemu-dev-sdl: anodize-dev-amd64.iso fake-shuttle.img
	mkdir -p $(DEV_DISC_DIR) && chmod 777 $(DEV_DISC_DIR)
	@for f in $(DEV_DISC_DIR)/*.iso; do [ -f "$$f" ] && xattr -c "$$f" && chmod 666 "$$f"; done 2>/dev/null || true
	cp $(OVMF_VARS) /tmp/anodize-ovmf-vars.fd
	$(QEMU_DEV_BASE) -display sdl -vga std

qemu-dev-nographic: anodize-dev-amd64.iso fake-shuttle.img
	mkdir -p $(DEV_DISC_DIR) && chmod 777 $(DEV_DISC_DIR)
	@for f in $(DEV_DISC_DIR)/*.iso; do [ -f "$$f" ] && xattr -c "$$f" && chmod 666 "$$f"; done 2>/dev/null || true
	cp $(OVMF_VARS) /tmp/anodize-ovmf-vars.fd
	$(subst -serial stdio,-nographic,$(QEMU_DEV_BASE))

# ── SSH into dev environments ───────────────────────────────────────────
#
#                  Local QEMU              Remote VM (DEV_VM_IP)
#  ceremony user   make ssh-dev            make ssh-vm
#  debug user      make ssh-dev-debug      make ssh-vm-debug
#
# All targets use scripts/dev-ssh-key (committed dev-only keypair).
# Remote targets require: DEV_VM_IP=10.0.0.5 make ssh-vm

SSH_OPTS = -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
	   -i $(CURDIR)/scripts/dev-ssh-key

# Local QEMU — ceremony user (sentinel TUI).
ssh-dev:
	@echo "Waiting for SSH on localhost:$(DEV_SSH_PORT)..."
	@until nc -z localhost $(DEV_SSH_PORT) 2>/dev/null; do sleep 1; done
	@echo "Connected."
	ssh $(SSH_OPTS) -p $(DEV_SSH_PORT) ceremony@localhost

# List per-session ISO files saved by the dev build to the 9p share.
# The ceremony binary (with feature dev-softhsm-usb) writes each session's
# ISO image to /run/anodize/share/session-NN.iso automatically.
save-disc:
	@echo "Session ISOs in $(DEV_DISC_DIR)/:"
	@ls -lh $(DEV_DISC_DIR)/session-*.iso 2>/dev/null \
	  || echo "  (none — run a ceremony first)"

# Local QEMU — debug user (bash shell).
ssh-dev-debug:
	@echo "Waiting for SSH on localhost:$(DEV_SSH_PORT)..."
	@until nc -z localhost $(DEV_SSH_PORT) 2>/dev/null; do sleep 1; done
	@echo "Connected."
	ssh $(SSH_OPTS) -p $(DEV_SSH_PORT) debug@localhost

# Remote VM — ceremony user (sentinel TUI via sudo).
# Sources /etc/set-environment so PKCS#11 env vars are available.
ssh-vm:
ifndef DEV_VM_IP
	$(error DEV_VM_IP is required — set it to the dev VM's IP address)
endif
	ssh -t $(SSH_OPTS) debug@$(DEV_VM_IP) \
	    'sudo -u ceremony sh -c ". /etc/set-environment && exec anodize-sentinel"'

# Remote VM — debug user (bash shell).
ssh-vm-debug:
ifndef DEV_VM_IP
	$(error DEV_VM_IP is required — set it to the dev VM's IP address)
endif
	ssh $(SSH_OPTS) debug@$(DEV_VM_IP)

# ── Disc swap for MigrateDisc testing ─────────────────────────────────
#
# Unload the current BD-R from cdemu, archive old ISOs, and create a
# fresh blank BD-R.  The script runs on the guest via SSH.
#
# Usage (remote VM):  DEV_VM_IP=192.168.178.76 make cdemu-swap-disc
# Usage (local QEMU): make cdemu-swap-disc-local

cdemu-swap-disc:
ifndef DEV_VM_IP
	$(error DEV_VM_IP is required — set it to the dev VM's IP address)
endif
	ssh $(SSH_OPTS) debug@$(DEV_VM_IP) 'sudo bash -s' < $(CURDIR)/scripts/cdemu-swap-disc.sh

cdemu-swap-disc-local:
	@until nc -z localhost $(DEV_SSH_PORT) 2>/dev/null; do sleep 1; done
	ssh $(SSH_OPTS) -p $(DEV_SSH_PORT) debug@localhost 'sudo bash -s' < $(CURDIR)/scripts/cdemu-swap-disc.sh

# Build anodize-ceremony with dev-softhsm-usb (never use in a real ceremony).
build-dev:
	cargo build -p anodize-tui --features dev-softhsm-usb

# ── Hot-deploy binary to running dev VM ─────────────────────────────────
#
# Builds the dev ceremony binary via Nix (x86_64-linux), scps it to the
# remote host, and replaces the Nix store binary in-place.  The sentinel
# detects the ceremony process exit and restarts it automatically.
#
# This is MUCH faster than a full ISO rebuild for Rust-only changes.
# The Nix store on a live ISO boots into a tmpfs overlay, so it's writable.
#
# Usage:  DEV_VM_IP=192.168.178.76 make deploy-dev

# $(call nix-build-bin, <flake-output>, <dest-file>)
# Build a single Nix package and extract its binary.  Uses the same
# Docker / remote-builder strategy as the ISO builds.
ifdef NIX_BUILDER
define nix-build-bin
	rsync -az --delete \
		-e 'ssh $(SSH_OPTS)' \
		--filter=':- .gitignore' \
		--exclude='.git' \
		$(CURDIR)/ $(NIX_BUILDER):$(NIX_BUILDER_DIR)/
	ssh $(SSH_OPTS) $(NIX_BUILDER) \
		'. /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh && \
		 cd $(NIX_BUILDER_DIR) && \
		 nix build .#$(1) -L && \
		 cat result/bin/anodize-ceremony' > $(2)
	chmod +x $(2)
endef
else
define nix-build-bin
	docker volume create nix-store-amd64 2>/dev/null || true
	docker run --rm --privileged \
		--platform linux/amd64 \
		-v nix-store-amd64:/nix \
		-v "$(CURDIR):/src" \
		-w /src \
		$(NIX_IMAGE) \
		sh -c 'rm -rf /homeless-shelter && \
		       git config --global --add safe.directory /src && \
		       nix --extra-experimental-features "nix-command flakes" \
		           --option build-users-group "" \
		           --option sandbox false \
		           $(NIX_SANDBOX_FLAG) build .#$(1) && \
		       rm -f /src/$(2) && cp -L result/bin/anodize-ceremony /src/$(2)'
endef
endif

deploy-dev: .FORCE
ifndef DEV_VM_IP
	$(error DEV_VM_IP is required)
endif
	@echo "Building anodize-ceremony-dev binary..."
	$(call nix-build-bin,anodize-ceremony-dev,anodize-ceremony-dev.bin)
	@echo "Copying binary to $(DEV_VM_IP)..."
	ssh $(SSH_OPTS) debug@$(DEV_VM_IP) 'rm -f /tmp/anodize-ceremony-new'
	scp $(SSH_OPTS) \
		anodize-ceremony-dev.bin debug@$(DEV_VM_IP):/tmp/anodize-ceremony-new
	@echo "Replacing binary on remote..."
	ssh $(SSH_OPTS) debug@$(DEV_VM_IP) ' \
		set -e; \
		STORE_PKG=$$(for d in /nix/store/*-anodize-ceremony-*/bin; do \
			[ -f "$$d/anodize-ceremony" ] && [ -f "$$d/anodize-sentinel" ] && dirname "$$d" && break; \
		done); \
		if [ -z "$$STORE_PKG" ]; then echo "Cannot find anodize-ceremony package in nix store"; exit 1; fi; \
		STORE_BIN=$$STORE_PKG/bin/anodize-ceremony; \
		echo "Nix store binary: $$STORE_BIN"; \
		sudo cp /tmp/anodize-ceremony-new /run/anodize-ceremony-hot; \
		sudo chmod 555 /run/anodize-ceremony-hot; \
		sudo mount --bind /run/anodize-ceremony-hot $$STORE_BIN; \
		echo "Bind-mounted over $$STORE_BIN"; \
		WRAP=/run/wrappers/bin/anodize-ceremony; \
		if [ -f "$$WRAP" ]; then \
			sudo cp /tmp/anodize-ceremony-new $$WRAP; \
			sudo chmod 755 $$WRAP; \
			sudo chown root:wheel $$WRAP; \
			sudo setcap cap_sys_admin=ep $$WRAP; \
			echo "Updated wrapper: $$WRAP"; \
		fi; \
		rm /tmp/anodize-ceremony-new; \
		echo "Killing ceremony TUI (sentinel will restart)..."; \
		sudo pkill -9 -x anodize-ceremony 2>/dev/null || true; \
		sleep 1; \
		echo "Done."'
	@rm -f anodize-ceremony-dev.bin

.FORCE:

clean:
	rm -rf anodize-prod-amd64.iso anodize-prod-arm64.iso anodize-dev-amd64.iso anodize-dev-arm64.iso anodize-prod-amd64.iso.sha256 fake-shuttle.img anodize-ceremony-dev.bin dev-disc /tmp/anodize-ovmf-vars.fd

# One-time repo setup — configures git to use the committed hooks directory.
setup:
	git config core.hooksPath .githooks
	@echo "Git hooks configured (.githooks/)."

# ---------------------------------------------------------------------------
# Shuttle USB preparation — build and run the shuttle CLI tool.
#
# The shuttle is the USB stick that carries profile.toml and artifacts
# between the operator's workstation and the air-gapped ceremony machine.
#
# Build:        make build-shuttle
# Lint a USB:   make shuttle-lint SHUTTLE_PATH=/Volumes/ANODIZE
# Init a USB:   cargo run -p anodize-shuttle -- init --help
# ---------------------------------------------------------------------------

SHUTTLE_PATH ?=

build-shuttle:
	cargo build -p anodize-shuttle

shuttle-lint:
ifndef SHUTTLE_PATH
	$(error SHUTTLE_PATH is required — set it to the mounted shuttle volume)
endif
	cargo run -p anodize-shuttle -- lint --path $(SHUTTLE_PATH)

# Inner-loop shortcuts (no Docker overhead)
fmt:
	cargo fmt --all -- --check

lint:
	cargo clippy --all-targets --all-features -- -D warnings

test:
	cargo test --all -- --test-threads=1

deny:
	cargo deny check
