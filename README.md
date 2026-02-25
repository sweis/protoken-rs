# protoken-rs: Expreimental Protobuf signed tokens in Rust

Compact, signed binary tokens using canonical proto3 wire encoding. An HMAC-SHA256 protoken is ~56 bytes versus ~300-400 bytes for a typical JWT. The format avoids algorithm confusion attacks by design: the algorithm is fixed per key, not per token.

**Warning**: This code is experimental and not ready for production. It is mostly AI generated and has not had human review.

Supports three signature algorithms:

- **HMAC-SHA256** -- symmetric, ~56-byte tokens
- **Ed25519** -- asymmetric, ~88-byte tokens
- **ML-DSA-44** -- post-quantum (FIPS 204), ~2,500-byte tokens

## Build

```sh
cargo build --release
```

## Install

```sh
cargo install --path .
```

## Quick start

```sh
# Generate an Ed25519 signing key
protoken generate-key > my.key

# Extract the public (verifying) key
protoken get-verifying-key my.key > my.pub

# Sign a token valid for 1 hour with claims
protoken sign my.key 1h \
  --subject "user:alice" \
  --audience "api.example.com" \
  --scope read --scope write > token.txt

# Verify the token
protoken verify my.pub < token.txt
```

Example output from `verify` (keys and timestamps will differ):

```
OK
     Algorithm  Ed25519
        Key ID  nsaAwNyxZac (key_hash)
       Expires  2026-02-24T23:21:39Z
    Not Before  2026-02-24T22:21:39Z
     Issued At  2026-02-24T22:21:39Z
       Subject  user:alice
      Audience  api.example.com
        Scopes  read, write
```

Example output from `inspect --json` (no key needed):

```json
{
  "type": "SignedToken",
  "payload": {
    "metadata": {
      "version": "V0",
      "algorithm": "Ed25519",
      "key_identifier": { "KeyHash": [158, 198, 128, 192, 220, 177, 101, 167] }
    },
    "claims": {
      "expires_at": 1771975299,
      "not_before": 1771971699,
      "issued_at": 1771971699,
      "subject": "user:alice",
      "audience": "api.example.com",
      "scopes": ["read", "write"]
    }
  },
  "signature_base64": "HGsm4IgMB8uDg...",
  "total_bytes": 142
}
```

## Usage

All keys and tokens are base64-encoded canonical proto3 messages. Use `-` as the keyfile to read from stdin.

### Generate a key and sign a token

```sh
# Generate an Ed25519 signing key (default algorithm)
protoken generate-key > my.key

# Sign a token valid for 1 hour
protoken sign my.key 1h

# Pipe directly: generate and sign in one step
protoken generate-key | protoken sign - 1h
```

### Extract verifying key and verify

```sh
# Extract the verifying (public) key
protoken get-verifying-key my.key > my.pub

# Verify a token (reads token from stdin)
protoken sign my.key 1h | protoken verify my.pub

# Or pass the token explicitly
protoken verify my.pub <token>
```

### Other algorithms

```sh
# HMAC-SHA256 (symmetric -- use signing key to verify)
protoken generate-key -a hmac > hmac.key
protoken sign hmac.key 4d | protoken verify hmac.key

# ML-DSA-44 (post-quantum)
protoken generate-key -a ml-dsa-44 > pq.key
protoken get-verifying-key pq.key > pq.pub
protoken sign pq.key 1h | protoken verify pq.pub
```

### Sign with claims

```sh
protoken sign my.key 4d --subject "user:alice" --audience "api" --scope read --scope write
```

### Inspect a token (no key needed)

```sh
protoken inspect <token>
echo "<token>" | protoken inspect
echo "<token>" | protoken inspect --json   # machine-readable JSON
```

### Verify stdin rules

`verify` reads the token from stdin by default. If keyfile is `-` (stdin), the token must be given as a positional argument:

```sh
protoken verify - <token> < my.pub
```

## Security considerations

- **Key hash is an identifier, not a security binding.** The 8-byte truncated SHA-256 key hash (~2^32 collision resistance at birthday bound) is used for key selection. Security relies on full signature verification.
- **Secret keys are zeroized on drop** using the `zeroize` crate, preventing key material from lingering in memory.
- **Single algorithm per key** avoids the algorithm confusion attacks that affect JWT.
- **No unknown fields** -- the parser rejects any unexpected protobuf fields, preventing extension-based attacks.

## Wire format

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
cargo run --example gen_test_vectors > testdata/vectors.json
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
