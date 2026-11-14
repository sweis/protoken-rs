# protoken-rs: Post-quantum tokens in Rust using protobufs

**Experimental**: Compact, signed binary tokens using canonical proto3 wire encoding and post-quantum algorithms.

**Warning**: This code is experimental and not ready for production. It is mostly AI generated and has not had human review.

Supports a NIST MAC and the NIST post-quantum signatures:

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

**FN-DSA is experimental.** FIPS 206 has not been published, so FN-DSA keys and
tokens may stop working in a later release. FN-DSA has no level 3 parameter set.

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
# Generate an ML-DSA-44 signing key
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
     Algorithm  ml-dsa-44
        Key ID  nsaAwNyxZac (key_hash)
       Expires  2026-02-24T23:21:39Z
    Not Before  2026-02-24T22:21:39Z
     Issued At  2026-02-24T22:21:39Z
       Subject  "user:alice"
      Audience  "api.example.com"
        Scopes  ["read", "write"]
```

Example output from `inspect --json` (no key needed):

```json
{
  "type": "SignedToken",
  "algorithm": "ml-dsa-44",
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
  "total_bytes": 2499
}
```

## Usage

All keys and tokens are base64-encoded canonical proto3 messages. Use `-` as the keyfile to read from stdin.

### Generate a key and sign a token

```sh
# Generate an ML-DSA-44 signing key (default algorithm)
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
# HMAC-SHA384 (symmetric -- use signing key to verify); "hmac" is accepted as an alias
protoken generate-key -a hmac-sha384 > hmac.key
protoken sign hmac.key 4d | protoken verify hmac.key

# Any other name from the table above
protoken generate-key -a slh-dsa-sha2-128s > slh.key
protoken get-verifying-key slh.key > slh.pub
protoken sign slh.key 1h | protoken verify slh.pub
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
  uint32 algorithm = 2;    // see the algorithm table
  uint32 key_id_type = 3;  // 1 = key_hash, 2 = public_key
  bytes  key_id = 4;       // 8 B (key_hash) or the public key
  bytes  payload = 5;      // canonical proto3 encoding of Claims
  bytes  signature = 6;    // over fields 1-5
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
  bytes secret_key = 2;    // HMAC key, ML-DSA seed, or encoded SLH-DSA/FN-DSA private key
  bytes public_key = 3;    // empty for HMAC
}

message VerifyingKey {
  uint32 algorithm = 1;    // any but HMAC
  bytes public_key = 2;
}
```

All messages use canonical proto3 encoding: fields in ascending order, minimal
varints, default values omitted, no unknown or duplicate fields. Decoders
reject non-canonical input. Output is valid proto3 that any protobuf library
can decode.

Serialized `Claims` may be at most 4096 bytes. Signing rejects larger claims.

Loading a `SigningKey` re-derives the public key from the secret and rejects the
key if the stored `public_key` differs. Loading a `VerifyingKey`
rejects malformed FN-DSA keys and ML-DSA keys whose `t1` is zero.

### Signature construction

The signature is computed over the canonical encoding of envelope fields 1-5
(everything except the trailing signature field). Because the encoding is
canonical, the signed bytes are exactly the token bytes minus the signature
field. Binding the algorithm and key identifier into the signature prevents
algorithm-confusion and key-substitution attacks.

All signatures use the pure (no pre-hash) mode with an empty context string.
ML-DSA and SLH-DSA use their deterministic variants. FN-DSA is always randomized.

The 8-byte key hash is `SHA-256(key_material)[0..8]`. It is a key selection
identifier, not a security binding: security rests on full signature
verification. Verifiers additionally compare the key identifier against their
own key in constant time before verifying the signature.

Keys used with protoken should not be reused to sign other formats.

Verification checks the signature and the time window (`not_before <= now <=
expires_at`). The caller must check `audience` and `scope`.

### Token sizes

A minimal token (only `expires_at`) is the signature plus 24 to 26 bytes: 72 B for
HMAC-SHA384, 691 B for FN-DSA-512, 2,445 B for ML-DSA-44, and 29,818 B for
SLH-DSA-SHA2-256s. Embedding the public key replaces the 8-byte hash with the key.

## Library API

Add the crate with `default-features = false` to skip the CLI's dependencies.

```rust
use protoken::{Algorithm, Claims, SigningKey, VerifyingKey};

let key = SigningKey::generate(Algorithm::MlDsa44)?;
let claims = Claims {
    expires_at: 1800000000,
    subject: "user:alice".into(),
    ..Default::default()
};
let token_bytes = key.sign(&claims)?;

// Verifiers only need the serialized verifying key.
let verifying_key = VerifyingKey::from_bytes(&key.verifying_key()?.to_bytes())?;
let now = 1799999000;
let verified = verifying_key.verify(&token_bytes, now)?;
assert_eq!(verified.claims.subject, "user:alice");
```

`SigningKey::sign_with_key_id(&claims, KeyIdType::PublicKey)` embeds the
public key in the token instead of its hash. HMAC keys verify with
`SigningKey::verify`. `SigningKey::from_secret_key` and `VerifyingKey::new` build
keys from raw bytes, and `serialize` exposes the wire format.

The signature crates keep large values on the stack. In release builds, allow
512 KB for signing and key loading and 192 KB for verification.

## Python

`bindings/python` contains [PyO3](https://pyo3.rs) bindings with the same
API shape (`SigningKey`, `VerifyingKey`, `Claims`, `inspect_token`), built
with [maturin](https://www.maturin.rs). See
[bindings/python/README.md](bindings/python/README.md).

```python
from protoken import Claims, SigningKey

key = SigningKey.generate("ml-dsa-44")
token = key.sign(Claims(expires_at=1_800_000_000, subject="user:alice"))
key.verifying_key().verify(token).claims.subject   # 'user:alice'
```

## Test vectors

Stored in `testdata/vectors.json` (wire format regression) and
`testdata/reference_vectors.json` (long-lived keys and tokens expiring 2036).
All binary data is URL-safe base64 (no padding). Both files are generated from
fixed seeds, so `make vectors-check` confirms the code still reproduces them
exactly; `make vectors` rewrites them after an intentional format change. The
Python tests also verify and re-sign the reference vectors.
`testdata/acvp_vectors.json` holds NIST ACVP known-answer tests for ML-DSA and SLH-DSA.

## Benchmarks

```sh
cargo bench
```

See [PERFORMANCE.md](PERFORMANCE.md) for benchmark results.

## Fuzzing

```sh
cargo install cargo-fuzz
make fuzz TARGET=parse_claims        # or: parse_signed_token, roundtrip, parse_keys,
                                     # exercise_token, verify_token, verify_untrusted_key
```

`roundtrip` and `parse_keys` assert that anything the decoders accept re-encodes to
identical bytes. `verify_token` mutates the reference tokens under their own keys and
asserts that no other byte string verifies. `verify_untrusted_key` feeds arbitrary
public keys and signatures to the primitives.

## Formal verification

`lean/` holds a Lean 4 model of the parsers, serializers, key handling, and the
sign and verify logic, with machine-checked proofs about it. Among them: decoders
accept only canonical encodings, the signed bytes determine everything a verifier
returns, no token is accepted under two algorithms, and every token that signing
returns will verify.

```sh
make lean               # check the proofs (requires elan)
make lean-conformance   # compare the model with the Rust library
```

The proofs are about a hand-written model, not the Rust source. A differential
test over about 170,000 inputs ties the two together. The cryptographic primitives
are assumed rather than verified. See [lean/README.md](lean/README.md) for the
theorem list and the limits of what is proved, and
[notes/research-lean-extraction.md](notes/research-lean-extraction.md) for how to
extend the proofs to the Rust source.
