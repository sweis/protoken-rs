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

All keys are canonical proto3 messages, stored as base64 (or hex). Use `-` as the keyfile to read from stdin.

### Generate a key and sign a token

```sh
# Generate an Ed25519 signing key
protoken generate-key > my.key

# Sign a token valid for 1 hour
protoken sign my.key 1h

# Pipe directly: generate and sign in one step
protoken generate-key | protoken sign - 1h
```

### Extract verifying key and verify

```sh
# Extract the verifying (public) key
protoken extract-verifying-key my.key > my.pub

# Verify a token (reads token from stdin)
protoken sign my.key 1h | protoken verify my.pub

# Or pass the token explicitly
protoken verify my.pub -t <token>
```

### Other algorithms

```sh
# HMAC-SHA256 (symmetric — use signing key to verify)
protoken generate-key -a hmac > hmac.key
protoken sign hmac.key 4d | protoken verify hmac.key

# ML-DSA-44 (post-quantum)
protoken generate-key -a ml-dsa-44 > pq.key
protoken extract-verifying-key pq.key > pq.pub
protoken sign pq.key 1h | protoken verify pq.pub
```

### Sign with claims

```sh
protoken sign my.key 4d --subject "user:alice" --audience "api" --scope read --scope write
```

### Inspect a token (no key needed)

```sh
protoken inspect -t <token>
echo "<token>" | protoken inspect
```

### Output formats

All commands that produce binary output default to base64. Use `-o hex` for hex:

```sh
protoken generate-key -o hex > my.key
protoken sign my.key 1h -o hex
```

### Verify stdin rules

`verify` reads the token from stdin by default. If keyfile is `-` (stdin), pass the token explicitly with `--token`:

```sh
protoken verify - -t <token> < my.pub
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
cargo run --bin gen_test_vectors > testdata/vectors.json
cargo test
```

## Benchmarks

```sh
cargo bench
```

See [PERFORMANCE.md](PERFORMANCE.md) for benchmark results.

## Fuzzing

```sh
cargo install cargo-fuzz
cargo fuzz run parse_payload
cargo fuzz run parse_signed_token
cargo fuzz run roundtrip
cargo fuzz run parse_keys
cargo fuzz run exercise_token
```

## License

See [LICENSE](LICENSE) for details.
