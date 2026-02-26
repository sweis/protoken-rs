.PHONY: all test test-snark fmt clippy audit check fuzz

# Run all checks (format, clippy, test)
all: check test

# Run tests (excluding slow SNARK tests)
test:
	cargo test --all-targets -- --skip snark

# Run slow SNARK tests (requires ~4 min, 64MB stack)
test-snark:
	RUST_MIN_STACK=67108864 cargo test --lib snark::tests -- --test-threads=1

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
