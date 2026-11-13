.PHONY: all test fmt clippy check audit vectors vectors-check python mutants fuzz lean lean-conformance

# Run all static checks and tests
all: check test

test:
	cargo test

# Check formatting (dry run)
fmt:
	cargo fmt --all -- --check

# Clippy over every workspace crate and target, plus the library-only build
clippy:
	cargo clippy --workspace --all-targets -- -D warnings
	cargo clippy --no-default-features --lib -- -D warnings

check: fmt clippy

# Audit dependencies for known vulnerabilities (requires `cargo install cargo-audit`)
audit:
	cargo audit

# Regenerate the stored test vectors (only needed after a wire format change)
vectors:
	cargo run -q --example gen_test_vectors > testdata/vectors.json
	cargo run -q --example gen_reference_vectors > testdata/reference_vectors.json

# Confirm the stored vectors match what the generators produce
vectors-check:
	cargo run -q --example gen_test_vectors | diff - testdata/vectors.json
	cargo run -q --example gen_reference_vectors | diff - testdata/reference_vectors.json

# Build the Python bindings into the active virtualenv and run their tests
# (requires maturin and pytest)
python:
	cd bindings/python && maturin develop && pytest

# Check the Lean proofs and the axiom audit, then replay the proofs through a
# fresh kernel (requires elan)
lean:
	cd lean && lake build --wfail && lake env leanchecker Protoken

# Replay Rust-generated cases through the Lean model. Example:
#   make lean-conformance SEED=7
SEED ?= 1
lean-conformance:
	cd lean && lake build conformance
	cargo build -q --release --example gen_lean_cases
	target/release/examples/gen_lean_cases $(SEED) | lean/.lake/build/bin/conformance

# Mutation testing (requires `cargo install cargo-mutants`)
mutants:
	cargo mutants -j 2 --no-shuffle

# Fuzz one target (requires nightly and `cargo install cargo-fuzz`). The
# corpus is first seeded with the reference keys, tokens, and payloads so the
# fuzzers start from inputs the decoders accept. max_len is just above the
# largest token. Example:
#   make fuzz TARGET=verify_token DURATION=120
TARGET ?= parse_claims
DURATION ?= 60
fuzz:
	cargo run -q --example gen_fuzz_seeds fuzz/corpus/$(TARGET)
	cargo +nightly fuzz run $(TARGET) -- -dict=fuzz/proto3.dict -max_len=37000 -max_total_time=$(DURATION)
