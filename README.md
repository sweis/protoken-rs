# protoken-rs: Experimental Protobuf-based tokens in Rust

Compact, signed binary tokens using canonical proto3 wire encoding. Encoding is deterministic with our own serializer, and decoding can use standard protobuf deserialization.

**Warning**: This code is experimental and not ready for production. It is mostly AI generated and has not had human review.

Supports three algorithms:

- **HMAC-SHA256** -- symmetric MAC, ~56-byte tokens
- **Ed25519** -- asymmetric signature, ~88-byte tokens
- **ML-DSA-44** -- post-quantum signature (FIPS 204), ~2,500-byte tokens

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
  "algorithm": "Ed25519",
  "key_identifier": { "type": "key_hash", "base64": "nsaAwNyxZac" },
  "claims": {
    "expires_at": 1771975299,
    "not_before": 1771971699,
    "issued_at": 1771971699,
    "subject": "user:alice",
    "audience": "api.example.com",
    "scopes": ["read", "write"]
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

## Wire format

A token is a signed envelope. The envelope carries the signing metadata
(algorithm and key identifier), the payload as opaque bytes, and the
signature. The payload is itself a canonical proto3 message -- `Claims` for
tokens -- so the envelope can carry other message types.

```proto
message SignedToken {
  uint32 version = 1;      // reserved, always 0 (omitted on wire)
  uint32 algorithm = 2;    // 1 = HMAC-SHA256, 2 = Ed25519, 3 = ML-DSA-44
  uint32 key_id_type = 3;  // 1 = key_hash, 2 = public_key
  bytes  key_id = 4;       // 8 B (key_hash) or public key (Ed25519: 32 B, ML-DSA-44: 1312 B)
  bytes  payload = 5;      // canonical proto3 encoding of Claims
  bytes  signature = 6;    // HMAC-SHA256 (32 B), Ed25519 (64 B), ML-DSA-44 (2420 B)
}

message Claims {
  uint64 expires_at = 1;   // Unix seconds, required
  uint64 not_before = 2;   // optional
  uint64 issued_at = 3;    // optional
  string subject = 4;      // optional, max 255 bytes
  string audience = 5;     // optional, max 255 bytes
  repeated string scope = 6; // sorted, no duplicates, max 32 entries
}

message SigningKey {
  uint32 algorithm = 1;
  bytes secret_key = 2;    // HMAC: raw key (>=32 B); Ed25519/ML-DSA-44: 32 B seed
  bytes public_key = 3;    // Ed25519: 32 B; ML-DSA-44: 1312 B; empty for HMAC
}

message VerifyingKey {
  uint32 algorithm = 1;    // 2 = Ed25519, 3 = ML-DSA-44
  bytes public_key = 2;    // Ed25519: 32 B; ML-DSA-44: 1312 B
}
```

All messages use canonical proto3 encoding: fields in ascending order, minimal
varints, default values omitted, no unknown or duplicate fields. Decoders
reject non-canonical input. Output is valid proto3 that any protobuf library
can decode.

### Signature construction

The signature is computed over the canonical encoding of envelope fields 1-5
(everything except the trailing signature field). Because the encoding is
canonical, the signed bytes are exactly the token bytes minus the signature
field. Binding the algorithm and key identifier into the signature prevents
algorithm-confusion and key-substitution attacks.

Signing is deterministic for all three algorithms; ML-DSA-44 uses the
FIPS 204 deterministic variant with an empty context string.

The 8-byte key hash is `SHA-256(key_material)[0..8]`. It is a key selection
identifier, not a security binding: security rests on full signature
verification. Verifiers additionally compare the key identifier against their
own key in constant time before verifying the signature.

Keys used with protoken should not be reused to sign other formats.

### Token sizes

| Configuration | Total |
|---|---|
| HMAC + key_hash (minimal) | ~56 B |
| Ed25519 + key_hash (minimal) | ~88 B |
| Ed25519 + embedded public key | ~112 B |
| ML-DSA-44 + key_hash (minimal) | ~2,450 B |
| ML-DSA-44 + embedded public key | ~3,760 B |

## Library API

```rust
use protoken::sign::{generate_ed25519_key, compute_key_hash, sign_ed25519};
use protoken::verify::verify_ed25519;
use protoken::types::{Claims, KeyIdentifier};

let (seed, public_key) = generate_ed25519_key().unwrap();
let claims = Claims {
    expires_at: 1800000000,
    subject: "user:alice".into(),
    ..Default::default()
};
let key_id = KeyIdentifier::KeyHash(compute_key_hash(&public_key));
let token_bytes = sign_ed25519(&seed, &claims, key_id).unwrap();

let now = 1799999000;
let verified = verify_ed25519(&public_key, &token_bytes, now).unwrap();
assert_eq!(verified.claims.subject, "user:alice");
```

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
cargo fuzz run parse_claims
cargo fuzz run parse_signed_token
cargo fuzz run roundtrip
cargo fuzz run parse_keys
cargo fuzz run exercise_token
```

## License

See [LICENSE](LICENSE) for details.
