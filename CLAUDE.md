# protoken-rs: Protobuf based Tokens in Rust

Protokens are designed to be a simple, fast replacement for JWTs, ad hoc tokens, or in some cases x509 certificates.

## Notes for Claude
* Use this file, CLAUDE.md, to record decisions or lessons along the way. Create new .md files if necessary to record research findings. Take good notes and include links to references, but do not be overly wordy.
* Try to be concise and clear in all documentation and comments.
* Use care choosing dependencies and try to use the most widely used, common tools for the job. Do not reinvent new code if it is not necessary.
* Since this is security-focused software, be especially cognizant and aware of security decisions. This software will consume untrusted input and needs to be designed to be able to handle any malformed or malicious input given to it.

## Design Guidelines
1. The wire format uses canonical proto3 encoding. Tokens and payloads are valid proto3 messages.
2. A token is a signed envelope: signing metadata plus opaque payload bytes plus a signature. The envelope is payload-agnostic; token payloads are Claims messages.
3. The symmetric MAC is HMAC-SHA256.
4. The asymmetric signatures are Ed25519 and ML-DSA-44 (post-quantum, FIPS 204).
5. The implementation is in Rust.
6. The goal is a minimal token format. We start simple and add only fields essential to our use cases.

### Proto3 Schema
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
  uint64 expires_at = 1;   // Unix seconds, required (non-zero)
  uint64 not_before = 2;   // optional (0 = omitted)
  uint64 issued_at = 3;    // optional (0 = omitted)
  string subject = 4;      // optional (empty = omitted), max 255 bytes
  string audience = 5;     // optional (empty = omitted), max 255 bytes
  repeated string scope = 6; // optional, sorted, no duplicates, max 32 entries, each max 255 bytes
}

message SigningKey {
  uint32 algorithm = 1;    // 1 = HMAC-SHA256, 2 = Ed25519, 3 = ML-DSA-44
  bytes secret_key = 2;    // HMAC: raw key (>=32 B); Ed25519: 32 B seed; ML-DSA-44: 2560 B
  bytes public_key = 3;    // Ed25519: 32 B; ML-DSA-44: 1312 B; empty for HMAC
}

message VerifyingKey {
  uint32 algorithm = 1;    // 2 = Ed25519, 3 = ML-DSA-44
  bytes public_key = 2;    // Ed25519: 32 B; ML-DSA-44: 1312 B
}
```

7. Canonical encoding rules: fields in ascending order, minimal varints, default values (0/empty) omitted, no unknown or duplicate fields. Repeated fields (scope) appear consecutively, sorted lexicographically, no duplicates. Decoders reject non-canonical input.
8. The version field is reserved and always 0. It will not appear on the wire until we finalize the format.
9. The signature is computed over the canonical encoding of envelope fields 1-5. Because the encoding is canonical, the signed bytes are exactly the token bytes minus the trailing signature field. This binds the algorithm and key identifier into the signature, preventing algorithm-confusion and key-substitution attacks.
10. Verification order: parse envelope (structure and size checks) → check algorithm matches the key → constant-time compare key identifier → verify signature → parse payload as Claims → check temporal claims. Payload bytes are not interpreted before the signature verifies.

## Decisions

### Signed envelope with opaque payload
The envelope carries signing metadata (algorithm, key_id_type, key_id) and the payload as `bytes`. This is the traditional way to sign protobufs: the exact signed bytes travel on the wire, so no re-serialization ambiguity exists, and the envelope can carry payload types other than Claims. Verifiers must know the expected payload type; for tokens it is always Claims.

### Asymmetric Signature: Ed25519
Chose Ed25519 over P-256: deterministic nonces (eliminates nonce-reuse key compromise), FIPS 186-5 approval, equivalent performance and size, alignment with modern token designs (PASETO, Biscuit).
See [notes/research-p256-vs-ed25519.md](notes/research-p256-vs-ed25519.md).

### Canonical Proto3 Serialization
Canonical proto3 wire encoding with a custom ~360-line encoder/decoder (`src/proto3.rs`). This produces valid proto3 that any library can decode, while guaranteeing deterministic output.
See [notes/research-protobuf-determinism.md](notes/research-protobuf-determinism.md).

### Post-Quantum Signature: ML-DSA-44
ML-DSA-44 (FIPS 204) chosen over SLH-DSA (huge signatures) and XMSS/LMS (stateful — incompatible with distributed token issuance). Stateless, ~200μs sign, 2,420 B signatures, 1,312 B public keys.
See [notes/research-pq-signatures.md](notes/research-pq-signatures.md).

### Dependencies: RustCrypto ecosystem
- `ed25519-dalek` for Ed25519 (raw 32-byte seeds, no PKCS#8)
- `hmac` + `sha2` for HMAC-SHA256 and SHA-256 key hashing
- `ml-dsa` for ML-DSA-44, chosen over `fips204` crate (~1,100 dependents vs ~1)
- `subtle` for constant-time comparisons
- `rand` for key generation
- `zeroize` for secret key memory wiping
- `clap` (derive) for CLI, `serde`/`serde_json` for JSON, `humantime`, `base64`, `thiserror`

### Key Serialization: Proto3
All key types use canonical proto3 encoding (same as the token format). Ed25519 uses raw 32-byte seeds (not PKCS#8 DER). SigningKey includes the public key for asymmetric algorithms so `extract_verifying_key()` can derive the VerifyingKey without re-deriving from secret material. CLI stores keys as base64-encoded proto bytes. See `src/keys.rs`.

### Secret Key Zeroization
`SigningKey.secret_key` uses `Zeroizing<Vec<u8>>` so secret key material is automatically zeroed from memory when dropped. The CLI also zeroizes key material read from files or stdin.

### Key Hash Collision Resistance
The 8-byte key hash (SHA-256[0..8]) gives ~2^32 collision resistance at the birthday bound. It is a key *identifier* for key selection, not a security binding. Security relies on full signature verification. Documented in the code and README.

### Key Reuse
Keys used with protoken should not sign other formats. The signing input has no domain-separation prefix; the envelope structure itself (proto3 fields 1-5) is the only framing.

## Implementation Status

- `src/types.rs` - Core types (Version, Algorithm, KeyIdType, KeyIdentifier, Claims, SignedToken) and size limits
- `src/proto3.rs` - Canonical proto3 wire encoder/decoder
- `src/serialize.rs` - Serialization for Claims and the SignedToken envelope, including the signing-input construction
- `src/keys.rs` - Proto3 key serialization (SigningKey, VerifyingKey) with validation
- `src/sign.rs` - HMAC-SHA256, Ed25519, and ML-DSA-44 signing; key generation; key hashing
- `src/verify.rs` - Verification with algorithm and key checks, signature verification, expiry and not_before checking
- `src/main.rs` - CLI tool with `generate-key`, `get-verifying-key`, `sign`, `verify`, `inspect` commands
- `src/error.rs` - Error types
- `tests/` - Test vector and reference vector regression tests
- `testdata/` - Stored vectors; regenerate with `cargo run --example gen_test_vectors > testdata/vectors.json` (and `gen_reference_vectors`)
- `fuzz/` - cargo-fuzz targets: parse_claims, parse_signed_token, parse_keys, roundtrip, exercise_token
- `benches/` - Criterion benchmarks; results in PERFORMANCE.md
- `notes/` - Research documents (prior art, Ed25519 vs P-256, protobuf determinism, post-quantum, ML-DSA key formats, subject identifiers)

## Research Prior Art

See [notes/research-prior-art.md](notes/research-prior-art.md) for a comparison of JWT, x509, Macaroons, Biscuit, and CWT. Key takeaways:
- `exp`, `nbf`, `iat` are universal temporal claims
- `iss`, `sub`, `aud` are the core identity triple
- Binary encoding (CWT ~194B) significantly beats JSON (JWT ~300-400B)
- Our 56-88 byte tokens are competitive with the most compact formats
- Protoken's single-algorithm approach avoids JWT's algorithm confusion attacks
