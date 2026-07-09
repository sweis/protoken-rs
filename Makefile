.PHONY: all test fmt clippy audit check fuzz mutants

# Run all checks (format, clippy, test)
all: check test

# Run tests
test:
	cargo test

# Check formatting (dry run)
fmt:
	cargo fmt -- --check

# Run clippy with warnings as errors
clippy:
	cargo clippy --all-targets -- -D warnings

# Audit dependencies for known vulnerabilities
audit:
	cargo audit

# Run all static checks (fmt + clippy)
check: fmt clippy

# Run mutation testing (requires `cargo install cargo-mutants`).
mutants:
	cargo mutants -j 2 --no-shuffle

# Run fuzz targets (requires nightly). Example:
#   make fuzz TARGET=parse_claims DURATION=60
TARGET ?= parse_claims
DURATION ?= 60
fuzz:
	cargo +nightly fuzz run $(TARGET) -- -dict=fuzz/proto3.dict -max_total_time=$(DURATION)
