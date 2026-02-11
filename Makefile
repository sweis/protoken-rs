.PHONY: all test fmt clippy audit check fuzz

# Run all checks (format, clippy, test)
all: check test

# Run tests
test:
	cargo test --all-targets

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

# Run fuzz targets (requires nightly). Example:
#   make fuzz TARGET=parse_payload DURATION=60
TARGET ?= parse_payload
DURATION ?= 60
fuzz:
	cargo +nightly fuzz run $(TARGET) -- -dict=fuzz/proto3.dict -max_total_time=$(DURATION)
