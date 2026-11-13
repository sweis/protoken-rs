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
3. The symmetric MAC is HMAC-SHA384.
4. The asymmetric signatures are post-quantum only: ML-DSA (FIPS 204), SLH-DSA (FIPS 205), and FN-DSA (FIPS 206, experimental).
5. The implementation is in Rust.
6. The goal is a minimal token format. We start simple and add only fields essential to our use cases.

### Algorithms
| ID | Name | Standard | NIST level | Secret key | Public key | Signature |
|---|---|---|---|---|---|---|
| 3 | `ml-dsa-44` | FIPS 204 | 2 | 32 (seed) | 1,312 | 2,420 |
| 4 | `ml-dsa-65` | FIPS 204 | 3 | 32 (seed) | 1,952 | 3,309 |
| 5 | `ml-dsa-87` | FIPS 204 | 5 | 32 (seed) | 2,592 | 4,627 |
| 6 | `hmac-sha384` | FIPS 198-1 | n/a | 48-128 | none | 48 |
| 7 | `slh-dsa-sha2-128s` | FIPS 205 | 1 | 64 | 32 | 7,856 |
| 8 | `slh-dsa-sha2-192s` | FIPS 205 | 3 | 96 | 48 | 16,224 |
| 9 | `slh-dsa-sha2-256s` | FIPS 205 | 5 | 128 | 64 | 29,792 |
| 10 | `fn-dsa-512` | FIPS 206 (unpublished) | 1 | 1,345 | 897 | 666 |
| 11 | `fn-dsa-1024` | FIPS 206 (unpublished) | 5 | 2,369 | 1,793 | 1,280 |

Sizes are in bytes. IDs 1 (HMAC-SHA256) and 2 (Ed25519) are retired and must not be reused.

### Proto3 Schema
```proto
message SignedToken {
  uint32 version = 1;      // reserved, always 0 (omitted on wire)
  uint32 algorithm = 2;    // see the algorithm table
  uint32 key_id_type = 3;  // 1 = key_hash, 2 = public_key
  bytes  key_id = 4;       // 8 B (key_hash) or the public key
  bytes  payload = 5;      // canonical proto3 encoding of Claims
  bytes  signature = 6;    // over fields 1-5
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
  uint32 algorithm = 1;
  bytes secret_key = 2;    // HMAC key, ML-DSA seed, or encoded SLH-DSA/FN-DSA private key
  bytes public_key = 3;    // empty for HMAC
}

message VerifyingKey {
  uint32 algorithm = 1;    // any but HMAC
  bytes public_key = 2;
}
```

7. Canonical encoding rules: fields in ascending order, minimal varints, default values (0/empty) omitted, no unknown or duplicate fields. Repeated fields (scope) appear consecutively, sorted lexicographically, no duplicates. Decoders reject non-canonical input.
8. The version field is reserved and always 0. It will not appear on the wire until we finalize the format.
9. The signature is computed over the canonical encoding of envelope fields 1-5. Because the encoding is canonical, the signed bytes are exactly the token bytes minus the trailing signature field. This binds the algorithm and key identifier into the signature, preventing algorithm-confusion and key-substitution attacks.
10. Verification order: parse envelope (structure and size checks) → check algorithm matches the key → constant-time compare key identifier → verify signature → parse payload as Claims → `Claims::validate()` → check temporal claims. Payload bytes are not interpreted before the signature verifies.

## Decisions

### Signed envelope with opaque payload
The envelope carries signing metadata (algorithm, key_id_type, key_id) and the payload as `bytes`. This is the traditional way to sign protobufs: the exact signed bytes travel on the wire, so no re-serialization ambiguity exists, and the envelope can carry payload types other than Claims. Verifiers must know the expected payload type; for tokens it is always Claims.

### HMAC-SHA384
Keys are 48 bytes (the output size) to 128 bytes (the block size). HMAC hashes a longer key first, so it adds no strength. The key hash stays SHA-256: it keeps ML-DSA-44 tokens from before the change valid, and it must differ from the HMAC hash. With HMAC-SHA256, the identifier of a key over 64 bytes was the first 8 bytes of the effective HMAC key.

### Canonical Proto3 Serialization
Canonical proto3 wire encoding with a small custom encoder/decoder (`src/proto3.rs`). This produces valid proto3 that any library can decode, while guaranteeing deterministic output.
See [notes/research-protobuf-determinism.md](notes/research-protobuf-determinism.md).

### Post-Quantum Signatures
Ed25519 was removed in November 2026. All schemes use pure mode and an empty context. See [notes/research-pq-signatures.md](notes/research-pq-signatures.md).
- **ML-DSA** is the default (`ml-dsa-44`). Keys are 32-byte seeds. Signing is deterministic. Public keys with `t1 = 0` are rejected because anyone can sign for them.
- **SLH-DSA** uses only the SHA2 "s" sets: tokens are sent and verified more often than signed, so size and verify time matter most. Keys use the FIPS 205 encoding (`SK.seed || SK.prf || PK.seed || PK.root`); loading recomputes the root with the crate's hidden `slh_keygen_internal`. Signing is deterministic and takes about a second, so the dev profile uses `opt-level = 2` and tests, fuzzers, and generators use these keys sparingly.
- **FN-DSA** is randomized and stores the encoded key, not a seed, as NIST plans to require. Loading checks the embedded public key hash and must never sign: the sampler can run without bound on a crafted key. See [notes/research-fn-dsa.md](notes/research-fn-dsa.md).

### Dependencies
- `hmac` 0.13 + `sha2` 0.11, both with `zeroize` (without it on `sha2`, the keyed HMAC state is not wiped)
- `ml-dsa` 0.1 and `slh-dsa` 0.2.0-rc.5 (RustCrypto; the release candidate is pinned because it is the only one on this `digest`/`signature` generation, and its `alloc` feature needs the default features)
- `fn-dsa` 0.4.0 (Thomas Pornin), pinned together with its four sub-crates, which are direct dependencies only for the pin and to enable `no_avx2` on `fn-dsa-sign`. It brings second copies of `rand_core` and `cpufeatures`.
- `getrandom` for key generation (reports RNG failure as an error instead of panicking)
- `subtle` for constant-time comparisons, `zeroize` for secret wiping
- `serde`, `base64`, `thiserror`
- CLI only, behind the default `cli` feature: `clap` (derive), `colored`, `humantime`, `serde_json`. Library users and the Python bindings build with `default-features = false`.
- `base64` stays on 0.22: 0.23 adds default-on unsafe SIMD code that buys nothing for token-sized inputs.

### Key API: `SigningKey` and `VerifyingKey`
Key fields are private and every constructor validates, so a key that exists is well formed. `from_secret_key` is the one place the public key is derived; `generate` and `from_bytes` go through it. `crypto.rs` holds the `Scheme` trait and the only `match` from `Algorithm` to an implementation; sizes and names come from one table in `types.rs`. `sign_token` and `verify_token` take an algorithm and raw key bytes, so they stay `pub(crate)`: a public version would let a caller pass a token's algorithm with a public key, which is the JWT confusion attack. To add an algorithm: one enum variant, one table row, one `Scheme` arm, and the same rows in `lean/Protoken/Types.lean`.

### Key Serialization: Proto3
All key types use canonical proto3 encoding (same as the token format). SigningKey stores the public key; decoding re-derives it and rejects a mismatch, so a corrupted key file cannot issue tokens its own verifying key rejects. CLI stores keys as base64-encoded proto bytes.

### Structural Decoding vs. Semantic Validation
`deserialize_claims` enforces canonical form and size limits only. The semantic rules (`expires_at` set, `not_before <= expires_at`, no duplicate scopes) live in `Claims::validate()`, which signing applies before encoding and verification applies after the signature check (`finish_verification`). Keeping them out of the decoder lets `inspect` and Python's `inspect_token` display a token from another issuer even when its claims are unusable, which is what those diagnostic tools are for. Both vector generators use fixed keys (and a fixed random stream for FN-DSA), so `make vectors-check` (also run in CI) proves the stored vectors are reproducible; regenerate them only for an intentional format change.

### Secret Key Zeroization
`SigningKey.secret_key` and `to_bytes()` use `Zeroizing<Vec<u8>>`, and the primitive crates zeroize their key objects on drop. This is best effort: stack copies left by moves inside those crates are not wiped. The decoders borrow field bytes and copy them only once accepted, which matters because the CLI's `verify` tries the verifying-key decoder first even when handed a signing key. The CLI reads and base64-decodes keys into zeroizing buffers allocated once at full size. Python `bytes` cannot be zeroized; the bindings document this.

### CLI Output
Claim strings come from untrusted tokens, so text output prints them with `{:?}` and JSON output escapes everything outside printable ASCII.

### Python Bindings: PyO3 + maturin
`bindings/python` is a workspace member producing the `protoken._protoken` abi3 extension (Python 3.10+), wrapped by a small pure-Python package with type stubs. PyO3 was chosen over UniFFI (heavier, aimed at Kotlin/Swift too) and a hand-written C ABI (needs `unsafe`, which this crate denies). The binding only converts types and errors and releases the GIL only for slow calls; every parser and check is the Rust one. Its tests re-verify and re-sign the stored reference vectors, which doubles as an interop test with the CLI. Token problems raise `VerificationFailed` (or `TokenExpired`/`TokenNotYetValid`); key and claims problems raise the base `ProtokenError`.

### Producers Enforce the Decoders' Size Limits
Anything the library produces must be accepted by its own decoders. `sign_token` rejects a payload over `MAX_PAYLOAD_BYTES`, because `Claims::validate()` alone allows about 8 KB (32 scopes of 255 bytes). The key and signature field limits are the largest sizes in the algorithm table. The Lean round-trip theorems depend on both.

### Formal Verification: Lean 4 Model plus Differential Test
`lean/` holds a hand-written Lean 4 model of `proto3`, `types`, `serialize`, `crypto` (dispatch only), `sign`, `verify`, and `keys`, with proofs about the model. It uses only Lean's standard library (no Mathlib), so it builds in under a minute. The primitives are parameters of a `Crypto` structure and no theorem assumes unforgeability. See [lean/README.md](lean/README.md) for the theorems and their limits.
- The proofs do not read the Rust source. `make lean-conformance` is what ties the model to the code, and it is a test, not a proof. **Any change to the logic in those modules needs the matching change in `lean/Protoken/`.** A changed limit, check, check order, or error variant should make the conformance run fail until the model follows.
- `Audit.lean` fails the build on `sorry` or any axiom beyond `propext`, `Classical.choice`, and `Quot.sound`. Avoid `bv_decide` and `native_decide`, which add axioms that trust compiled code. Add new headline theorems to the audit list.
- New size limits or ordering rules need cases on both sides of the boundary in `examples/gen_lean_cases.rs`. Random inputs rarely land on a boundary. Plant the bug in a scratch copy of the model to confirm the cases catch it.
- Keep Lean at 4.34 or later: earlier kernels have soundness bugs (for example CVE-2026-72844).
- [notes/research-lean-extraction.md](notes/research-lean-extraction.md) has the plan for proving the Rust source against the model with Charon and Aeneas. It has not been run yet.

### Key Hash Collision Resistance
The 8-byte key hash (SHA-256[0..8]) gives ~2^32 collision resistance at the birthday bound. It is a key *identifier* for key selection, not a security binding. Security relies on full signature verification. Documented in the code and README.

### Key Reuse
Keys used with protoken should not sign other formats. The signing input has no domain-separation prefix; the envelope structure itself (proto3 fields 1-5) is the only framing.

## Implementation Status

- `src/types.rs` - Core types (Version, Algorithm, KeyIdType, KeyIdentifier, Claims, SignedToken) and size limits
- `src/proto3.rs` - Canonical proto3 encoders and the `Reader` that the message decoders are built from
- `src/serialize.rs` - Serialization for Claims and the SignedToken envelope, and the signing-input construction
- `src/crypto.rs` - The `Scheme` trait and its HMAC, ML-DSA, SLH-DSA, and FN-DSA implementations (private)
- `src/keys.rs` - SigningKey and VerifyingKey: construction, validation, serialization, sign and verify
- `src/sign.rs` - Token signing and key hashing
- `src/verify.rs` - Token verification: algorithm, key identity, and signature length checks, signature verification, expiry and not_before checking
- `src/main.rs` - CLI (`cli` feature) with `generate-key`, `get-verifying-key`, `sign`, `verify`, `inspect` commands
- `src/error.rs` - Error types
- `src/lib.rs` - Re-exports the key types, Claims, Algorithm, and ProtokenError at the crate root; doctest shows the intended usage
- `tests/` - Test vector and reference vector regression tests (vector files are deserialized into typed structs via serde)
- `testdata/` - Stored vectors; `make vectors-check` verifies them, `make vectors` regenerates them. `acvp_vectors.json` is copied from NIST ACVP
- `bindings/python/` - PyO3 bindings, Python package, stubs, and pytest suite (`make python` inside a virtualenv)
- `fuzz/` - cargo-fuzz targets: parse_claims, parse_signed_token, parse_keys, roundtrip, exercise_token, verify_token, verify_untrusted_key. `make fuzz` first seeds the corpus from the reference vectors (`examples/gen_fuzz_seeds.rs`); without seeds the fuzzers cannot construct an acceptable asymmetric signing key
- `lean/` - Lean 4 model, proofs, axiom audit, and conformance runner (`make lean`, `make lean-conformance`); `examples/gen_lean_cases.rs` generates the conformance cases
- `benches/` - Criterion benchmarks (sign, verify, keygen, envelope parse); results in PERFORMANCE.md
- There is deliberately no LICENSE file or license metadata yet; do not add one or refer to one
- `notes/` - Research documents (prior art, Ed25519 vs P-256, protobuf determinism, post-quantum, ML-DSA key formats, FN-DSA, subject identifiers, Lean extraction) and the November 2026 audit

## Research Prior Art

See [notes/research-prior-art.md](notes/research-prior-art.md) for a comparison of JWT, x509, Macaroons, Biscuit, and CWT. Key takeaways:
- `exp`, `nbf`, `iat` are universal temporal claims
- `iss`, `sub`, `aud` are the core identity triple
- Binary encoding (CWT ~194B) significantly beats JSON (JWT ~300-400B)
- Our 72-byte HMAC tokens are competitive with the most compact formats; post-quantum tokens are dominated by the signature
- Binding each key to one algorithm avoids JWT's algorithm confusion attacks
