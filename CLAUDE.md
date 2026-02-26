# protoken-rs: Protobuf based Tokens in Rust

Protokens are designed to be a simple, fast replacement for JWTs, ad hoc tokens, or in some cases x509 certificates.

## Notes for Claude
* Use this file, CLAUDE.md, to record decisions or lessons along the way. Create new .md files if necessary to record research findings. Take good notes and include links to references, but do not be overly wordy.
* Try to be concise and clear in all documentation and comments.
* Use care choosing dependencies and try to use the most widely used, common tools for the job. Do not reinvent new code if it is not necessary.
* Since this is security-focused software, be especially cognizant and aware of security decisions. This software will consume untrusted input and needs to be designed to be able to handle any malformed or malicious input given to it.

## Design Guidelines
1. The wire format uses canonical proto3 encoding. Payloads are valid proto3 messages.
2. These are signed tokens that support a symmetric MAC, asymmetric signatures, and SNARK proofs.
3. The symmetric MAC is HMAC-SHA256.
4. The asymmetric signatures are Ed25519 and ML-DSA-44 (post-quantum, FIPS 204).
4b. Groth16-SHA256 proves knowledge of a symmetric key via a zero-knowledge SNARK proof.
5. The implementation is in Rust.
6. The goal is a minimal token format. We start simple and add only fields essential to our use cases.

### Proto3 Schema
```proto
message Payload {
  uint32 version = 1;      // reserved, always 0 (omitted on wire)
  uint32 algorithm = 2;    // 1 = HMAC-SHA256, 2 = Ed25519, 3 = ML-DSA-44, 4 = Groth16-SHA256
  uint32 key_id_type = 3;  // 1 = key_hash, 2 = public_key, 3 = full_key_hash
  bytes  key_id = 4;       // 8 B (key_hash), 32 B (Ed25519/full_key_hash), 1312 B (ML-DSA-44)
  uint64 expires_at = 5;   // Unix seconds
  uint64 not_before = 6;   // optional (0 = omitted)
  uint64 issued_at = 7;    // optional (0 = omitted)
  string subject = 8;      // optional (empty = omitted), max 255 bytes
  string audience = 9;     // optional (empty = omitted), max 255 bytes
  repeated string scope = 10; // optional, sorted, max 32 entries, each max 255 bytes
}

message SignedToken {
  Payload payload = 1;     // canonical-encoded Payload submessage
  bytes   signature = 2;   // HMAC-SHA256 (32 B), Ed25519 (64 B), ML-DSA-44 (2420 B)
  bytes   proof = 3;       // Groth16 SNARK proof (128 B), empty for other algorithms
}

message SigningKey {
  uint32 algorithm = 1;    // 1 = HMAC-SHA256, 2 = Ed25519, 3 = ML-DSA-44, 4 = Groth16-SHA256
  bytes secret_key = 2;    // HMAC/Groth16: raw key (≥32 B); Ed25519: 32 B seed; ML-DSA-44: 2560 B
  bytes public_key = 3;    // Ed25519: 32 B; ML-DSA-44: 1312 B; empty for HMAC/Groth16
}

message VerifyingKey {
  uint32 algorithm = 1;    // 2 = Ed25519, 3 = ML-DSA-44
  bytes public_key = 2;    // Ed25519: 32 B; ML-DSA-44: 1312 B
}
// Note: Groth16-SHA256 verification uses a separate SNARK verifying key, not VerifyingKey proto.
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

### Dependencies: RustCrypto + arkworks (migrated 2026-02-18, originally ring 2026-02-10)
Migrated from `ring` to RustCrypto ecosystem to unify with `ml-dsa` crate:
- `ed25519-dalek` for Ed25519 signing/verification (raw 32-byte seeds, no PKCS#8)
- `hmac` + `sha2` for HMAC-SHA256 and SHA-256 key hashing
- `ml-dsa` for ML-DSA-44 (post-quantum), chosen over `fips204` crate (~1,100 dependents vs ~1)
- `rand` for key generation
- `zeroize` for secret key memory wiping
- arkworks v0.5 ecosystem for Groth16 SNARK proofs (ark-ff, ark-bn254, ark-groth16, etc.)
- `clap` (derive) for CLI, `serde`/`serde_json` for JSON, `humantime`, `base64`, `thiserror`

### Key Serialization: Proto3 (decided 2026-02-19)
All key types use canonical proto3 encoding (same as token format). Ed25519 uses raw 32-byte
seeds (not PKCS#8 DER). SigningKey includes the public key for asymmetric algorithms so
`extract_verifying_key()` can derive the VerifyingKey without re-deriving from secret material.
CLI stores keys as base64-encoded proto bytes. See `src/keys.rs`.

### Secret Key Zeroization (added 2026-02-24)
`SigningKey.secret_key` uses `Zeroizing<Vec<u8>>` (from the `zeroize` crate, already a transitive
dependency) so secret key material is automatically zeroed from memory when dropped.

### Key Hash Collision Resistance (documented 2026-02-24)
The 8-byte key hash (SHA-256[0..8]) gives ~2^32 collision resistance at the birthday bound.
It is a key *identifier* for key selection, not a security binding. Security relies on full
signature verification. This is documented in the code and README.

### ECVRF Removed (decided 2026-02-26)
ECVRF (RFC 9381) was originally added as algorithm 4. Removed because VRF verification
still requires the full public key — making it functionally identical to Ed25519, which
we already support. The original motivation was "verification with only a key hash," but
VRFs don't achieve that. Research notes kept in
[notes/research-symmetric-key-proofs.md](notes/research-symmetric-key-proofs.md).

### Groth16-SHA256 SNARK (added 2026-02-26)
Added Groth16-SHA256 as algorithm 4, replacing the removed ECVRF. This is a true symmetric
key proof: the prover demonstrates knowledge of a key K such that SHA-256(K) = key_hash
and HMAC-SHA256(K, SHA-256(payload)) = signature, without revealing K.

**Circuit design**: Fixed-size R1CS circuit using arkworks ecosystem (BN254 curve).
Public inputs: key_hash (32B) + payload_hash (32B) + hmac_output (32B) = 96 bytes
encoded as 768 Boolean field elements. Private witness: key K (32B).
The circuit computes SHA-256 in-circuit for both the key hash and HMAC.

**Properties**: 128-byte compressed proof (2×G1 + 1×G2 on BN254), ~30s prove time (debug),
<1s verify. Requires trusted setup (circuit-specific CRS). The SNARK verifying key is
separate from the proto VerifyingKey (it's an arkworks-specific ~25KB structure).

**Dependencies**: arkworks ecosystem v0.5 — ark-ff, ark-bn254, ark-groth16, ark-relations,
ark-r1cs-std, ark-crypto-primitives (SHA-256 gadget), ark-snark, ark-serialize, ark-std.

## Implementation Status

All TODO items 1-8 are implemented, plus ML-DSA-44 and Groth16-SHA256 support:
- `src/types.rs` - Core types (Version, Algorithm incl. MlDsa44/Groth16Sha256, KeyIdentifier incl. FullKeyHash, Payload, SignedToken, Claims)
- `src/proto3.rs` - Canonical proto3 wire encoder/decoder
- `src/serialize.rs` - Deterministic serialization/deserialization for Payload and SignedToken (incl. proof field)
- `src/keys.rs` - Proto3 key serialization (SigningKey, VerifyingKey) with validation for all 4 algorithms
- `src/sign.rs` - HMAC-SHA256, Ed25519, ML-DSA-44, and Groth16-SHA256 signing
- `src/verify.rs` - Verification with key hash matching, expiry and not_before checking, Groth16 SNARK verification
- `src/snark.rs` - Groth16 SNARK circuit (HMAC-SHA256 key proof), setup/prove/verify, key serialization
- `src/main.rs` - CLI tool with `generate-key`, `get-verifying-key`, `snark-setup`, `sign`, `verify`, `inspect` commands (all 4 algorithms)
- `src/error.rs` - Error types
- 110 tests (89 unit + 11 SNARK + 10 Groth16 e2e) including byte-level corruption tests for all algorithms
- `notes/` - Research documents (prior art, Ed25519 vs P-256, protobuf determinism, post-quantum, ML-DSA key formats, subject identifiers, symmetric key proofs)

## Research Prior Art

Completed. See [notes/research-prior-art.md](notes/research-prior-art.md) for full comparison of
JWT, x509, Macaroons, Biscuit, and CWT. Key takeaways:
- `exp`, `nbf`, `iat` are universal temporal claims
- `iss`, `sub`, `aud` are the core identity triple (future additions)
- Binary encoding (CWT ~194B) significantly beats JSON (JWT ~300-400B)
- Our 56-88 byte tokens are competitive with the most compact formats
- Protoken's single-algorithm approach avoids JWT's algorithm confusion attacks
