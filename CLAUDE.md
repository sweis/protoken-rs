# protoken-rs: Protobuf based Tokens in Rust

Protokens are designed to be a simple, fast replacemenmt for JWTs, ad hoc tokens, or in some cases x509 certificates.

## Notes for Claude
* Use this file, CLAUDE.md, to record decisions or lessons along the way. Create new .md files if necessary to record research findings. Take good notes and include links to references, but do not be overly wordy.
* Try to be concicse and clear in all documentation and comments.
* Use care chosing dependencies and try to use the most widely used, common tools for the job. Do not reinvent new code if it is not necessary.
* Since this is security-focused software, be especially cognizant and aware of security decisions. This software will consume untrusted input and needs to be designed to be able to handle any malformed or malicious input given to it.

## Design Guidelines
1. The wire format uses canonical proto3 encoding. Payloads are valid proto3 messages.
2. These are signed tokens that support a symmetric MAC and asymmetric signature options.
3. The symmetric MAC is HMAC-SHA256.
4. The asymmetric signatures are Ed25519 and ML-DSA-44 (post-quantum, FIPS 204).
5. The implementation is in Rust.
6. The goal is a minimal token format. We start simple and add only fields essential to our use cases.

### Proto3 Schema
```proto
message Payload {
  uint32 version = 1;      // reserved, always 0 (omitted on wire)
  uint32 algorithm = 2;    // 1 = HMAC-SHA256, 2 = Ed25519, 3 = ML-DSA-44
  uint32 key_id_type = 3;  // 1 = key_hash, 2 = public_key
  bytes  key_id = 4;       // 8 bytes (key_hash) or variable (32 B Ed25519, 1312 B ML-DSA-44)
  uint64 expires_at = 5;   // Unix seconds
  uint64 not_before = 6;   // optional (0 = omitted)
  uint64 issued_at = 7;    // optional (0 = omitted)
  string subject = 8;      // optional (empty = omitted), max 255 bytes
  string audience = 9;     // optional (empty = omitted), max 255 bytes
  repeated string scope = 10; // optional, sorted, max 32 entries, each max 255 bytes
}

message SignedToken {
  Payload payload = 1;     // canonical-encoded Payload submessage
  bytes   signature = 2;   // HMAC-SHA256 (32 B), Ed25519 (64 B), or ML-DSA-44 (2420 B)
}

message SigningKey {
  uint32 algorithm = 1;    // 1 = HMAC-SHA256, 2 = Ed25519, 3 = ML-DSA-44
  bytes secret_key = 2;    // HMAC: raw key (≥32 B); Ed25519: 32 B seed; ML-DSA-44: 2560 B
  bytes public_key = 3;    // Ed25519: 32 B; ML-DSA-44: 1312 B; empty for HMAC
}

message VerifyingKey {
  uint32 algorithm = 1;    // 2 = Ed25519, 3 = ML-DSA-44
  bytes public_key = 2;    // Ed25519: 32 B; ML-DSA-44: 1312 B
}
```

7. Canonical encoding rules: fields in ascending order, minimal varints, default values (0/empty) omitted. Repeated fields (scope) appear consecutively, sorted lexicographically, no duplicates.
8. The version field is reserved and always 0. It will not appear on the wire until we finalize the format.
9. SignedToken wraps Payload as a submessage. The signature is computed over the canonical Payload bytes inside field 1.

## TODO

1. ~~Create a minimal version of this that we can build from.~~
2. ~~Start out with just serialization / deserialization~~
3. ~~Have a command line tool that can take byte string and attempt to deserialize it as either a Payload or a Signed Token. Display it to the screen as a JSON which can be piped to jq.~~
4. ~~We should have a signing interface that can take the constituent fields.~~
5. ~~We should have a command line tool that can take a signing key and a humantime value like "4d" interpreted as a duration to produce a token that is valid from the current time for the duration.~~
6. ~~We should have a verification interface that takes a signed token and a verification key, verifies that the key matches the key_hash, and returns the deserialized claims as JSON.~~
7. ~~Have the command line tool be able to take a verification key and validate a token against the current time.~~
8. ~~Set up test vectors and unit tests. Use mock clocks to test cases where tokens are expired. Also test corrupting every field of a signed token in isolation and verifying that they will be rejected as expected.~~

## Decisions

### Asymmetric Signature: Ed25519 (decided 2026-02-10)
Chose Ed25519 over P-256 after researching performance, token size, FIPS compliance,
security properties, Rust ecosystem, and adoption. Key factors: deterministic nonces
(eliminates nonce-reuse key compromise), FIPS 186-5 approval (Feb 2023), equivalent
performance and size, alignment with modern token designs (PASETO, Biscuit).
See [notes/research-p256-vs-ed25519.md](notes/research-p256-vs-ed25519.md) for full analysis.

### Canonical Proto3 Serialization (decided 2026-02-11)
Using canonical proto3 wire encoding with a custom ~200-line encoder/decoder (`src/proto3.rs`).
This produces valid proto3 that any library can decode, while guaranteeing deterministic output.
Rules: ascending field order, minimal varints, default values omitted, no unknown fields.
See [notes/research-protobuf-determinism.md](notes/research-protobuf-determinism.md).

### Post-Quantum Signature: ML-DSA-44 (decided 2026-02-18)
Added ML-DSA-44 (FIPS 204) as a third algorithm option. Chose over SLH-DSA (huge signatures),
XMSS, and LMS (both stateful — incompatible with distributed token issuance).
ML-DSA-44: stateless, ~200μs sign, 2,420 B signatures, 1,312 B public keys.
Token sizes: ~2,500 B (KeyHash) or ~3,800 B (PublicKey).
See [notes/research-pq-signatures.md](notes/research-pq-signatures.md) for full analysis.

### Dependencies: RustCrypto (migrated 2026-02-18, originally ring 2026-02-10)
Migrated from `ring` to RustCrypto ecosystem to unify with `ml-dsa` crate:
- `ed25519-dalek` for Ed25519 signing/verification (raw 32-byte seeds, no PKCS#8)
- `hmac` + `sha2` for HMAC-SHA256 and SHA-256 key hashing
- `ml-dsa` for ML-DSA-44 (post-quantum), chosen over `fips204` crate (~1,100 dependents vs ~1)
- `rand` for key generation
- `clap` (derive) for CLI, `serde`/`serde_json` for JSON, `humantime`, `base64`, `thiserror`

### Key Serialization: Proto3 (decided 2026-02-19)
All key types use canonical proto3 encoding (same as token format). Ed25519 uses raw 32-byte
seeds (not PKCS#8 DER). SigningKey includes the public key for asymmetric algorithms so
`extract_verifying_key()` can derive the VerifyingKey without re-deriving from secret material.
CLI stores keys as base64-encoded proto bytes. See `src/keys.rs`.

## Implementation Status

All TODO items 1-8 are implemented, plus ML-DSA-44 post-quantum support:
- `src/types.rs` - Core types (Version, Algorithm incl. MlDsa44, KeyIdentifier, Payload, SignedToken, Claims)
- `src/proto3.rs` - Canonical proto3 wire encoder/decoder
- `src/serialize.rs` - Deterministic serialization/deserialization for Payload and SignedToken
- `src/keys.rs` - Proto3 key serialization (SigningKey, VerifyingKey) with validation
- `src/sign.rs` - HMAC-SHA256, Ed25519, and ML-DSA-44 signing (raw seeds, RustCrypto)
- `src/verify.rs` - Verification with key hash matching, expiry and not_before checking
- `src/main.rs` - CLI tool with `generate-key`, `get-verifying-key`, `sign`, `verify`, `inspect` commands (all 3 algorithms, proto key format)
- `src/error.rs` - Error types
- 101 tests (84 unit + 4 reference + 13 integration) including byte-level corruption tests for all algorithms
- `notes/` - Research documents (prior art, Ed25519 vs P-256, protobuf determinism, post-quantum, ML-DSA key formats, subject identifiers)

## Research Prior Art

Completed. See [notes/research-prior-art.md](notes/research-prior-art.md) for full comparison of
JWT, x509, Macaroons, Biscuit, and CWT. Key takeaways:
- `exp`, `nbf`, `iat` are universal temporal claims
- `iss`, `sub`, `aud` are the core identity triple (future additions)
- Binary encoding (CWT ~194B) significantly beats JSON (JWT ~300-400B)
- Our 56-88 byte tokens are competitive with the most compact formats
- Protoken's single-algorithm approach avoids JWT's algorithm confusion attacks
