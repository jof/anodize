.PHONY: ci test fmt lint deny

# Run the full GitHub Actions CI job locally via act + Docker
ci:
	act push --job check

# Inner-loop shortcuts (no Docker overhead)
fmt:
	cargo fmt --all -- --check

lint:
	cargo clippy --all-targets --all-features -- -D warnings

test:
	cargo test --all -- --test-threads=1

deny:
	cargo deny check
