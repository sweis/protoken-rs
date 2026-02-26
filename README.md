# protoken-rs: Experimental Protobuf-based tokens in Rust

Compact, signed binary tokens using canonical proto3 wire encoding. Encoding is deterministic with our own serializer, and decoding can use standard protobuf deserialization.

Warning: This is experimental and largely AI generated. It is not production ready and has not been audited by a human.

**Warning**: This code is experimental and not ready for production. It is mostly AI generated and has not had human review.

Supports four algorithms:

- **HMAC-SHA256** -- symmetric MAC, ~56-byte tokens
- **Ed25519** -- asymmetric signature, ~88-byte tokens
- **ML-DSA-44** -- post-quantum signature (FIPS 204), ~2,500-byte tokens
- **Groth16-SHA256** -- zero-knowledge SNARK proof of symmetric key knowledge, ~250-byte tokens

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

# Groth16-SHA256 (SNARK, library API only -- see below)
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

### Groth16-SHA256 (library API)

Groth16 tokens prove knowledge of a symmetric key without revealing it, using a zero-knowledge SNARK. The circuit proves: `SHA-256(K) = key_hash` and `HMAC-SHA256(K, SHA-256(payload)) = signature`. Verifiers only need the SNARK verifying key -- no symmetric key required.

Because Groth16 requires a trusted setup (circuit-specific proving/verifying keys), it is only available via the library API, not the CLI.

```rust
use protoken::snark;
use protoken::sign::sign_groth16;
use protoken::verify::verify_groth16;
use protoken::types::Claims;

// One-time trusted setup (slow -- cache the keys)
let (proving_key, verifying_key) = snark::setup().unwrap();

// Sign: prover has the 32-byte symmetric key
let key = [0x42u8; 32];
let claims = Claims {
    expires_at: 1800000000,
    subject: "user:alice".into(),
    ..Default::default()
};
let token_bytes = sign_groth16(&proving_key, &key, claims).unwrap();

// Verify: verifier has only the SNARK verifying key (no symmetric key)
let now = 1799999000;
let verified = verify_groth16(&verifying_key, &token_bytes, now).unwrap();
assert_eq!(verified.claims.subject, "user:alice");
```

Serializing keys for storage:

```rust
// Save keys
let vk_bytes = snark::serialize_verifying_key(&verifying_key).unwrap();
let pk_bytes = snark::serialize_proving_key(&proving_key).unwrap();

// Load keys
let vk = snark::deserialize_verifying_key(&vk_bytes).unwrap();
let pk = snark::deserialize_proving_key(&pk_bytes).unwrap();
```

## Wire format

Payloads use canonical proto3 encoding: fields in ascending order, minimal varints, default values omitted. Output is valid proto3 that any protobuf library can decode.

```proto
message Payload {
  uint32 version = 1;      // reserved, always 0 (omitted on wire)
  uint32 algorithm = 2;    // 1 = HMAC-SHA256, 2 = Ed25519, 3 = ML-DSA-44, 4 = Groth16-SHA256
  uint32 key_id_type = 3;  // 1 = key_hash, 2 = public_key, 3 = full_key_hash
  bytes  key_id = 4;       // 8 B (key_hash), 32 B (full_key_hash/Ed25519), 1312 B (ML-DSA-44)
  uint64 expires_at = 5;   // Unix seconds
  uint64 not_before = 6;   // optional
  uint64 issued_at = 7;    // optional
  string subject = 8;      // optional, max 255 bytes
  string audience = 9;     // optional, max 255 bytes
  repeated string scope = 10; // sorted, max 32 entries
}

message SignedToken {
  Payload payload = 1;
  bytes   signature = 2;   // HMAC-SHA256 (32 B), Ed25519 (64 B), ML-DSA-44 (2420 B)
  bytes   proof = 3;       // Groth16 proof (128 B), empty for other algorithms
}

message SigningKey {
  uint32 algorithm = 1;
  bytes secret_key = 2;    // HMAC: raw key (≥32 B); Ed25519: 32 B seed; ML-DSA-44: 2560 B
  bytes public_key = 3;    // Ed25519: 32 B; ML-DSA-44: 1312 B; empty for HMAC
}

message VerifyingKey {
  uint32 algorithm = 1;    // 2 = Ed25519, 3 = ML-DSA-44
  bytes public_key = 2;    // Ed25519: 32 B; ML-DSA-44: 1312 B
}
```

### Token sizes

| Configuration | Payload | Sig | Total |
|---|---|---|---|
| HMAC + key_hash (minimal) | ~20 B | 32 B | ~56 B |
| Ed25519 + key_hash (minimal) | ~20 B | 64 B | ~88 B |
| ML-DSA-44 + key_hash (minimal) | ~20 B | 2420 B | ~2,450 B |
| Groth16 + full_key_hash (minimal) | ~40 B | 32 B + 128 B proof | ~210 B |
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
