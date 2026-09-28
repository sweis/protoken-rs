# Lean verification of protoken

This directory holds a Lean 4 model of the protoken library, machine-checked
theorems about that model, and a differential test that compares the model with
the Rust code.

```sh
make lean               # check every proof and the axiom audit
make lean-conformance   # compare the model with the Rust library
```

Both need [elan](https://github.com/leanprover/elan). The Lean version is pinned in
`lean-toolchain`. There are no dependencies beyond Lean's own standard library.

## What is and is not verified

**The theorems are about a hand-written model, not about the Rust source.** Lean
checks that the theorems follow from the model. It does not read `src/*.rs`. The
link between the two is:

1. The model follows the Rust code function by function, with the same checks in
   the same order. Each definition names the Rust function it models.
2. `make lean-conformance` runs about 150,000 inputs through both and requires the
   same result, including the error variant and its fields.

Step 2 is testing, not proof. A difference that no case reaches would go
unnoticed. When you change `src/`, change the model to match.

**The cryptographic primitives are assumed, not verified.** SHA-256, HMAC, Ed25519,
and ML-DSA-44 are parameters (`Crypto.lean`), so each theorem holds for any
implementation of them. No theorem assumes unforgeability. The theorems say which
bytes a signature was checked over and that those bytes determine the result.
The step from there to "an attacker cannot forge a token" rests on the security of
the primitives.

Also outside the model:

- Timing. The model records the result of a constant-time comparison, not its cost.
- Memory. Zeroization has no counterpart.
- Panics and integer overflow in Rust. The model uses natural numbers for positions
  and lengths, and repeats each range check that Rust makes.
- Error message strings. Only the variant and its numeric fields are kept.
- The CLI, base64, JSON, key generation, and the Python bindings.
- 32-bit targets. `usize` is taken to be 64 bits.

## Main theorems

Every name below is checked by `Audit.lean`, which fails the build if a theorem
uses `sorry` or any axiom other than `propext`, `Classical.choice`, and
`Quot.sound`. Those three are the standard axioms of Lean.

### Canonical encoding (design guideline 7)

| Theorem | Statement |
| --- | --- |
| `decodeVarint_sound` | The bytes an accepted varint consumed are `encodeVarint` of its value. |
| `decodeVarint_complete` | Every `encodeVarint` output decodes to its value. |
| `deserializeClaims_canonical` | Accepted bytes equal `serializeClaims` of the decoded claims. |
| `deserializeSignedTokenAt_canonical` | Accepted bytes equal `serializeSignedToken` of the decoded token. |
| `deserializeSigningKey_canonical`, `deserializeVerifyingKey_canonical` | The same for keys, and the decoded key passes `validate`. |
| `deserializeClaims_injective`, `deserializeSignedTokenAt_injective` | A value has only one accepted encoding. |

### Round trips

| Theorem | Statement |
| --- | --- |
| `deserializeClaims_serializeClaims` | Valid claims that fit in `MAX_PAYLOAD_BYTES` decode to themselves with sorted scopes. |
| `deserializeSignedTokenAt_serialize` | A well-formed token decodes to itself. |
| `deserializeSigningKey_serialize`, `deserializeVerifyingKey_serialize` | Every key that passes `validate` decodes to itself. |
| `serializeSignedToken_length_le` | Every well-formed token fits in `MAX_SIGNED_TOKEN_BYTES`. |

### What the signature covers (design guideline 9)

| Theorem | Statement |
| --- | --- |
| `deserializeSignedTokenAt_canonical` | The first `signed_len` bytes are `serializeSigningInput` of the decoded fields. |
| `serializeSigningInput_injective` | Equal signing inputs have equal algorithm, key identifier, and payload. |
| `serializeClaims_injective` | Equal payloads have equal claims. |

### Verification (design guideline 10)

| Theorem | Statement |
| --- | --- |
| `verifyHmac_sound`, `verifyEd25519_sound`, `verifyMldsa44_sound` | An accepted token is the encoding of the returned algorithm, key identifier, and claims, followed by a signature that the primitive accepted over exactly those bytes under the caller's key. The identifier names the caller's key. The claims are valid and inside their time window. |
| `accepted_result_determined_by_signing_input` | The signed bytes determine the whole result, across algorithms and keys. |
| `accepted_same_token` | A byte string accepted twice, under any keys, was accepted under one algorithm with one result. So there is no algorithm confusion. |
| `verifyHmac_unique_token` | Under one HMAC key, a result has exactly one accepted token. |
| `accepted_tokens_differ_only_in_signature` | For the signature algorithms, two tokens with one result differ only in the signature field. |
| `verify*_bad_signature` | A well-formed envelope with a bad signature gets `VerificationFailed` whatever its payload holds. So the payload is not interpreted first. |

### Sign then verify

| Theorem | Statement |
| --- | --- |
| `verifyHmac_signHmac`, `verifyEd25519_signEd25519`, `verifyMldsa44_signMldsa44` | Every token that signing returns is accepted inside its time window. |
| `SigningKey.verify_signWithKeyId`, `VerifyingKey.verify_signWithKeyId` | The same through the key API, for both key identifier types. |

The Ed25519 and ML-DSA-44 versions assume `Crypto.Correct`: honest signatures verify.

### Keys

| Theorem | Statement |
| --- | --- |
| `signing_key_is_not_verifying_key` | No byte string decodes as both key types. |
| `SigningKey.fromSecretKey_valid` | `from_secret_key` only returns keys that pass `validate`. |
| `SigningKey.verifyingKey_valid` | The verifying key of a valid signing key passes `validate`. |
| `Claims.validate_eq_ok_iff`, `SigningKey.validate_eq_ok_iff`, `VerifyingKey.validate_eq_ok_iff` | Each `validate` accepts exactly the values described by a plain list of rules. |

## Bugs this found

Two round-trip theorems could not be proved as first stated. Both failures were real
bugs in the Rust code, now fixed with regression tests.

- **Unverifiable tokens.** `Claims::validate` allows up to 32 scopes of 255 bytes,
  about 8 KB, but verifiers reject payloads over 4096 bytes. Signing accepted such
  claims and returned a token that no verifier would take. `sign_claims` now rejects
  a payload over `MAX_PAYLOAD_BYTES`.
- **Unloadable HMAC keys.** HMAC keys had no maximum length, but the key decoder
  rejects a `secret_key` field over 4096 bytes. A longer key could be built, used,
  and saved, but not loaded again. `check_hmac_key_len` now enforces
  `HMAC_MAX_KEY_LEN`.

## Layout

| File | Rust source | Contents |
| --- | --- | --- |
| `Protoken/Basic.lean` | `error.rs` | Bytes, errors, shared lemmas |
| `Protoken/Varint.lean` | `proto3.rs` | Varint model and proofs |
| `Protoken/Proto3.lean` | `proto3.rs` | Tags, field encoders, readers, and their lemmas |
| `Protoken/FieldLoop.lean` | | The `while pos < data.len()` loop and its invariant rule |
| `Protoken/Types.lean` | `types.rs` | Limits, enums, `Claims`, `validate`, UTF-8, sorting |
| `Protoken/Serialize.lean` | `serialize.rs` | Claims and SignedToken model |
| `Protoken/ClaimsProofs.lean`, `TokenProofs.lean` | | Theorems about `Serialize.lean` |
| `Protoken/Crypto.lean` | | The assumed primitives |
| `Protoken/Sign.lean`, `Verify.lean` | `sign.rs`, `verify.rs` | Signing and verification model |
| `Protoken/VerifyProofs.lean` | | Theorems about verification |
| `Protoken/Keys.lean`, `KeysProofs.lean` | `keys.rs` | Key model and theorems |
| `Audit.lean` | | Axiom check for the theorems above |
| `Conformance/` | | Differential test runner |

## The differential test

`examples/gen_lean_cases.rs` writes one case per line: an operation, its inputs, and
what the Rust library returned. `lake exe conformance` replays each line through the
model and exits non-zero on any difference. Byte strings are hex, with `-` for the
empty string. The generator takes a seed, so failures can be reproduced:

```sh
cargo run --release --example gen_lean_cases 7 | (cd lean && lake exe conformance)
```

The cases cover every decoder, `validate`, both serializers, signing, and
verification. They include the stored reference vectors, mutated valid inputs, random
field sequences, correctly signed envelopes around invalid payloads, and inputs on
each side of every size limit. The runner prints how many cases each operation
accepted and rejected. Both numbers should stay well above zero.

SHA-256 and HMAC run in Lean (`Conformance/Sha256.lean`) and are themselves compared
with the Rust crates. Ed25519 and ML-DSA-44 are not implemented in Lean. For those,
each case carries the primitive's answer, which the generator obtains by calling the
primitive directly on fields found by its own small wire parser.

To check that the test can fail, 28 single-line bugs were planted in the model one
at a time: off-by-one limits, swapped error variants, missing checks, and reordered
checks. The proofs or the test caught 27. The other raises the field number bound in
`decodeTag` from 2^32 to 2^33, which cannot be observed because every field number
above 6 gets the same error. The first run caught only 22, and the misses led to the
limit cases the generator has now.
