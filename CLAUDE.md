# protoken-rs: Protobuf based Tokens in Rust

Protokens are designed to be a simple, fast replacemenmt for JWTs, ad hoc tokens, or in some cases x509 certificates.

## Notes for Claude
* Use this file, CLAUDE.md, to record decisions or lessons along the way. Create new .md files if necessary to record research findings. Take good notes and include links to references, but do not be overly wordy.
* Try to be concicse and clear in all documentation and comments.
* Use care chosing dependencies and try to use the most widely used, common tools for the job. Do not reinvent new code if it is not necessary.
* Since this is security-focused software, be especially cognizant and aware of security decisions. This software will consume untrusted input and needs to be designed to be able to handle any malformed or malicious input given to it.

## Design Guidelines
1. The wire format uses canonical proto3 encoding. Payloads are valid proto3 messages.
2. These are signed tokens that support a single symmetric MAC and a single asymmetric signature option.
3. The symmetric MAC is HMAC-SHA256.
4. The asymmetric signature is Ed25519.
5. The implementation is in Rust.
6. The goal is a minimal token format. We start simple and add only fields essential to our use cases.

### Proto3 Schema
```proto
message Payload {
  uint32 version = 1;      // reserved, always 0 (omitted on wire)
  uint32 algorithm = 2;    // 1 = HMAC-SHA256, 2 = Ed25519
  uint32 key_id_type = 3;  // 1 = key_hash, 2 = public_key
  bytes  key_id = 4;       // 8 bytes (key_hash) or 32 bytes (Ed25519 public_key)
  uint64 expires_at = 5;   // Unix seconds
  uint64 not_before = 6;   // optional (0 = omitted)
  uint64 issued_at = 7;    // optional (0 = omitted)
  bytes  subject = 8;      // optional (empty = omitted), max 255 bytes
  bytes  audience = 9;     // optional (empty = omitted), max 255 bytes
  repeated string scope = 10; // optional, sorted, max 32 entries, each max 255 bytes
}

message SignedToken {
  Payload payload = 1;     // canonical-encoded Payload submessage
  bytes   signature = 2;   // HMAC-SHA256 (32 bytes) or Ed25519 (64 bytes)
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
See [research-p256-vs-ed25519.md](research-p256-vs-ed25519.md) for full analysis.

### Canonical Proto3 Serialization (decided 2026-02-11)
Using canonical proto3 wire encoding with a custom ~200-line encoder/decoder (`src/proto3.rs`).
This produces valid proto3 that any library can decode, while guaranteeing deterministic output.
Rules: ascending field order, minimal varints, default values omitted, no unknown fields.
See [design-serialization.md](design-serialization.md) and [research-protobuf-determinism.md](research-protobuf-determinism.md).

### Dependencies (decided 2026-02-10)
- `ring` for all cryptography (HMAC-SHA256, Ed25519, SHA-256). Battle-tested BoringSSL backend.
- `clap` (derive) for CLI parsing.
- `serde` + `serde_json` for JSON output.
- `humantime` for duration parsing.
- `base64`, `hex` for encoding.
- `thiserror` for error types.

## Implementation Status

All TODO items 1-8 are implemented:
- `src/types.rs` - Core types (Version, Algorithm, KeyIdentifier, Payload, SignedToken, Claims)
- `src/proto3.rs` - Canonical proto3 wire encoder/decoder
- `src/serialize.rs` - Deterministic serialization/deserialization for Payload and SignedToken
- `src/sign.rs` - HMAC-SHA256 and Ed25519 signing
- `src/verify.rs` - Verification with key hash matching, expiry and not_before checking
- `src/main.rs` - CLI tool with `inspect`, `sign`, `verify`, `generate-key` commands
- `src/error.rs` - Error types
- 51 tests (39 unit + 12 integration) including byte-level corruption tests

## Research Prior Art

Completed. See [research-prior-art.md](research-prior-art.md) for full comparison of
JWT, x509, Macaroons, Biscuit, and CWT. Key takeaways:
- `exp`, `nbf`, `iat` are universal temporal claims
- `iss`, `sub`, `aud` are the core identity triple (future additions)
- Binary encoding (CWT ~194B) significantly beats JSON (JWT ~300-400B)
- Our 56-88 byte tokens are competitive with the most compact formats
- Protoken's single-algorithm approach avoids JWT's algorithm confusion attacks
