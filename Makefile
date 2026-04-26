.PHONY: ci nix-check nix-iso iso test fmt lint deny

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

# Inner-loop shortcuts (no Docker overhead)
fmt:
	cargo fmt --all -- --check

lint:
	cargo clippy --all-targets --all-features -- -D warnings

test:
	cargo test --all -- --test-threads=1

deny:
	cargo deny check
