# protoken-rs

Minimal signed tokens using canonical proto3 wire encoding. Supports three signature algorithms:

- **HMAC-SHA256** — symmetric, 56-byte tokens
- **Ed25519** — asymmetric, 88-byte tokens
- **ML-DSA-44** — post-quantum (FIPS 204), ~2,500-byte tokens

## Build

```sh
cargo build --release
```

## Install

```sh
cargo install --path .
```

## Usage

All keys are encoded as canonical proto3 messages (`SigningKey` / `VerifyingKey`). The CLI accepts hex or base64-encoded proto bytes for key files and token inputs. Output from `generate-key` and `extract-verifying-key` is a base64-encoded proto that any protobuf decoder can parse.

### Generate keys

```sh
# Ed25519 (default) — outputs base64-encoded SigningKey proto
protoken generate-key > my.key

# HMAC-SHA256
protoken generate-key -a hmac > my.key

# ML-DSA-44 (post-quantum)
protoken generate-key -a ml-dsa-44 > my.key

# Output as hex instead of base64
protoken generate-key -o hex > my.key
```

### Extract verifying key

For asymmetric algorithms (Ed25519, ML-DSA-44), extract the verifying key to share with verifiers:

```sh
protoken extract-verifying-key -k my.key > my.pub
```

### Sign a token

```sh
# Sign with a 1-hour expiry
protoken sign -k my.key -d 1h

# With claims
protoken sign -k my.key -d 4d --subject "user:alice" --audience "api" --scope read --scope write

# Output as hex instead of base64
protoken sign -k my.key -d 30m -o hex
```

### Verify a token

```sh
# HMAC (uses signing key)
protoken verify -k my.key -t <token>

# Ed25519 / ML-DSA-44 (uses verifying key)
protoken verify -k my.pub -t <token>
```

On success, prints the verified claims as JSON. On failure, exits with a non-zero status.

### Inspect a token

```sh
# Decode without verifying (no key needed)
protoken inspect -t <token>

# Pipe from stdin
echo "<token>" | protoken inspect
```

## Wire Format

Payloads use canonical proto3 encoding: fields in ascending order, minimal varints, default values omitted. Output is valid proto3 that any protobuf library can decode.

```proto
message Payload {
  uint32 version = 1;      // reserved, always 0 (omitted on wire)
  uint32 algorithm = 2;    // 1 = HMAC-SHA256, 2 = Ed25519, 3 = ML-DSA-44
  uint32 key_id_type = 3;  // 1 = key_hash, 2 = public_key
  bytes  key_id = 4;       // 8 B (key_hash) or variable (32 B Ed25519, 1312 B ML-DSA-44)
  uint64 expires_at = 5;   // Unix seconds
  uint64 not_before = 6;   // optional
  uint64 issued_at = 7;    // optional
  string subject = 8;      // optional, max 255 bytes
  string audience = 9;     // optional, max 255 bytes
  repeated string scope = 10; // sorted, max 32 entries
}

message SignedToken {
  Payload payload = 1;
  bytes   signature = 2;   // HMAC-SHA256 (32 B), Ed25519 (64 B), or ML-DSA-44 (2420 B)
}

message SigningKey {
  uint32 algorithm = 1;
  bytes secret_key = 2;    // HMAC: raw key; Ed25519: 32 B seed; ML-DSA-44: 2560 B
  bytes public_key = 3;    // Ed25519: 32 B; ML-DSA-44: 1312 B; empty for HMAC
}

message VerifyingKey {
  uint32 algorithm = 1;
  bytes public_key = 2;    // Ed25519: 32 B; ML-DSA-44: 1312 B
}
```

### Token sizes

| Configuration | Payload | Sig | Total |
|---|---|---|---|
| HMAC + key_hash (minimal) | ~20 B | 32 B | ~56 B |
| Ed25519 + key_hash (minimal) | ~20 B | 64 B | ~88 B |
| ML-DSA-44 + key_hash (minimal) | ~20 B | 2420 B | ~2,450 B |
| Ed25519 + public_key + claims | ~70 B | 64 B | ~138 B |

## Test vectors

Stored in `testdata/vectors.json` (wire format regression) and `testdata/reference_vectors.json` (long-lived keys and tokens expiring 2036). All binary data is URL-safe base64 (no padding).

```sh
# Regenerate wire format vectors
cargo run --bin gen_test_vectors > testdata/vectors.json

# Run all tests
cargo test
```

## Benchmarks

```sh
cargo bench
```

See [PERFORMANCE.md](PERFORMANCE.md) for benchmark results and automated CSV tracking.

## Fuzzing

```sh
cargo install cargo-fuzz
cargo fuzz list                    # show targets
cargo fuzz run parse_payload       # fuzz payload parser
cargo fuzz run parse_signed_token  # fuzz token parser
cargo fuzz run roundtrip           # fuzz roundtrip invariant
cargo fuzz run parse_keys          # fuzz key deserialization
cargo fuzz run exercise_token      # exercise all fields of parsed tokens
```

## License

See [LICENSE](LICENSE) for details.
