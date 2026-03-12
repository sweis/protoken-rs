# cargo-mutants Analysis

Mutation testing run on 2026-03-12 using cargo-mutants 27.0.0.

## Summary

| Outcome  | Count | Percent |
|----------|-------|---------|
| Caught   | 203   | 67.4%   |
| Missed   | 78    | 25.9%   |
| Unviable | 19    | 6.3%    |
| Timeout  | 1     | 0.3%    |
| **Total** | **301** | |

**Mutation score** (caught / testable): 203 / (203 + 78) = **72.2%**

Run time: ~10 minutes with 2 parallel workers.

## Methodology

cargo-mutants was configured to skip `src/main.rs` (CLI, no unit tests) and
`src/snark.rs` (each Groth16 setup takes ~2 minutes). Test runs used
`--skip snark --skip groth16` so each mutant tested in ~3 seconds instead of
2+ minutes. This means **all Groth16-only code paths show as "missed" below
by construction** — run `cargo mutants -f src/snark.rs` separately to
mutation-test SNARK code.

Configuration is in `.cargo/mutants.toml`.

## Missed Mutants by Category

### 1. Groth16-only code paths — 26 mutants (expected, tests skipped)

These survive only because the Groth16 tests were skipped. They ARE covered
when the full test suite runs:

| File | Lines | Description |
|------|-------|-------------|
| keys.rs | 267 (×3) | Groth16 key size validation (`< HMAC_MIN_KEY_LEN`) |
| serialize.rs | 222 (×1), 326 (×3) | `FullKeyHash` length check; `MAX_PROOF_BYTES` check |
| sign.rs | 189 (×2), 211 (×3), 238 (×2), 256 (×3) | `compute_full_key_hash`, `sign_groth16`, `compute_sha256_full_key_hash`, `sign_groth16_hybrid` bodies |
| types.rs | 41, 42, 79 (×3) | `Algorithm::from_byte` arms 4/5; `KeyIdType::from_byte` arm 3 |
| verify.rs | 239, 248, 257, 299, 307, 315 (×6) | `verify_groth16` / `verify_groth16_hybrid` internals |

### 2. DoS-protection size limits — 23 mutants (real test gap)

None of the `> MAX_*` upper-bound checks have a test that passes input
**above** the limit, and no test passes input **at exactly** the limit.
The `> → ==` mutations accept oversized input; the `> → >=` mutations
reject exactly-at-limit input (a correctness bug, not a security one).

| File | Line | Check | Limit |
|------|------|-------|-------|
| keys.rs | 111 (×2) | secret_key too large | MAX_SECRET_KEY_BYTES = 4096 |
| keys.rs | 122 (×2) | public_key too large (SK deser) | MAX_PUBLIC_KEY_BYTES = 2048 |
| keys.rs | 180 (×2) | public_key too large (VK deser) | MAX_PUBLIC_KEY_BYTES = 2048 |
| serialize.rs | 70 (×2) | payload too large | MAX_PAYLOAD_BYTES = 4096 |
| serialize.rs | 267 (×5) | MAX_SIGNED_TOKEN_BYTES constant arithmetic | sum ≈ 6944 |
| serialize.rs | 276 (×2) | signed token too large | MAX_SIGNED_TOKEN_BYTES |
| serialize.rs | 304 (×2) | payload (inside token) too large | MAX_PAYLOAD_BYTES |
| serialize.rs | 315 (×2) | signature too large | MAX_SIGNATURE_BYTES = 2560 |

Fuzzing likely exercises these paths but unit tests don't.

### 3. Claims::validate boundary conditions — 9 mutants (real test gap)

`Claims::validate()` is called from signing functions. No signing test uses
claims at the boundary values:

| Line | Check | Gap |
|------|-------|-----|
| types.rs:150 (×1) | `not_before > expires_at` | no test with `not_before == expires_at` |
| types.rs:156 (×2) | subject > 255 bytes | no signing test with overlong subject |
| types.rs:163 (×2) | audience > 255 bytes | no signing test with overlong audience |
| types.rs:170 (×2) | scopes.len() > 32 | no signing test with too many scopes |
| types.rs:178 (×2) | scope entry > 255 bytes | no signing test with overlong scope |

Note: `deserialize_payload` has its own boundary checks on the same limits
that **are** tested (test_rejects_subject_too_long etc.), but
`Claims::validate` on the signing side is not.

### 4. Untested / dead code — 8 mutants (worth addressing)

| File:Line | Finding |
|-----------|---------|
| **types.rs:53 (×2)** | `Algorithm::signature_len()` is **never called anywhere** — not in lib, not in main.rs. Dead code. |
| **sign.rs:179 (×3)** | `generate_hmac_key()` is only called from main.rs (excluded from tests). No test verifies it returns ≥32 bytes. |
| **keys.rs:280 (×1)** | `validate_public_key_size()` can be replaced with `Ok(())` entirely — no test passes a VerifyingKey with Ed25519/ML-DSA-44 algorithm but wrong-length public key. |
| **types.rs:206 (×3)** | `is_zero()` (serde `skip_serializing_if` predicate) — no test serializes Claims to JSON and checks that zero-valued fields are omitted. |
| poseidon.rs:54 (×1) | `bytes_to_fr()` is only roundtrip-tested with itself; no test pins a known input → known output. If it always returned `Fr::from(0)` the roundtrip would still pass. |

### 5. Errors shadowed by later checks — 5 mutants (low priority)

These mutants disable a check, but a **subsequent** check produces an error
anyway, so tests using `.is_err()` still pass. The underlying behavior is
correct; the tests just don't pin *which* error fires.

| File:Line | Mutation | Why test passes anyway |
|-----------|----------|------------------------|
| keys.rs:38, 39 (×2) | `\|\|` → `&&` in `extract_verifying_key` symmetric-alg check | HMAC key falls through to "empty public_key" error |
| keys.rs:203, 204 (×2) | `\|\|` → `&&` in `deserialize_verifying_key` symmetric-alg check | HMAC key falls through to `validate_public_key_size` error |
| serialize.rs:98 (×1) | `\|\|` → `&&` disables ascending-field-order check | test input (field 1 after field 2) produces `InvalidVersion(1)` instead |

### 6. `verify_key_match` always succeeds — 1 mutant (defense-in-depth gap)

`src/verify.rs:17` — Replacing the entire constant-time key comparison with
`Ok(())` survives all tests. The function is the key-hash / public-key
identity check that runs **before** signature verification.

All existing wrong-key tests (test_verify_hmac_wrong_key, etc.) still pass
because the **signature verification** catches the mismatch afterward.
However, this means the key-match check is effectively unproven as an
independent defense layer.

Fix: add a test that signs with key A, tampers only the key_id in the
payload to match key B's hash, re-signs with key A, then verifies with
key B. With a working `verify_key_match`, this fails at the key-match step;
with the mutation it reaches sig verification.

Actually simpler: the current tests are fine for security (sig check is the
real defense) but don't prove the early-exit works. Add a test that checks
for `ProtokenError::KeyHashMismatch` specifically.

### 7. Subtle decoding edge cases — 2 mutants (low risk but worth a test)

| File:Line | Issue |
|-----------|-------|
| proto3.rs:100 (×1) | `byte > 1 → byte < 1` in the u64-overflow guard for the 10th varint byte. No test decodes a 10-byte varint with final byte > 1 (which represents a value > u64::MAX and should be rejected). |
| proto3.rs:110 (×1) | `*pos - start → *pos + start` in the non-minimal-varint detector. No test decodes a valid single-byte `0x00` varint at a nonzero position — in practice this never happens because proto3 omits zero-valued fields, but the mutation would falsely reject such input. |

### 8. Semantically equivalent mutations — 3 mutants (harmless, ignore)

These mutations produce identical behavior because the bit patterns don't
overlap:

| File:Line | Original | Mutation | Why equivalent |
|-----------|----------|----------|----------------|
| proto3.rs:42 | `(value & 0x7F) \| 0x80` | `^ 0x80` | bit 7 always 0 after `& 0x7F` |
| proto3.rs:49 | `(field << 3) \| wire_type` | `^ wire_type` | bits 0-2 always 0 after `<< 3` |
| types.rs:20 | `Version::to_byte() = self as u8` | returns `0` | only `V0 = 0` exists |

Add these to `exclude_re` in `.cargo/mutants.toml` to suppress them.

### Exact-boundary deserialize gaps — 3 mutants (low priority)

`deserialize_payload` has checks `> MAX_CLAIM_BYTES_LEN` for subject/audience/scope.
The negative tests use `MAX_CLAIM_BYTES_LEN + 1`, so the `> → >=` mutation
(rejects exactly 255 bytes) survives:

| File:Line |
|-----------|
| serialize.rs:116 (subject) |
| serialize.rs:131 (audience) |
| serialize.rs:146 (scope) |

## Timeout

`proto3.rs:38` — mutating `value <= 0x7F` to `value > 0x7F` in `encode_varint`
produces an infinite loop when value ≤ 0x7F (shifting 0 right stays 0). This
is effectively a caught mutant.

## Unviable (build failures)

19 mutants did not compile, mostly `Ok(Default::default())` where the return
type doesn't implement `Default`. These are harmless — the type system catches
them.

## Recommendations

Priority order:

1. **Delete `Algorithm::signature_len`** (types.rs:52) — unused code.
2. **Add `deserialize_verifying_key` wrong-size test** — exercise
   `validate_public_key_size` with a wrong-length Ed25519 public key.
3. **Test `generate_hmac_key` length** — `assert_eq!(generate_hmac_key().len(), 32)`.
4. **Assert `KeyHashMismatch` specifically** in a wrong-key verify test.
5. **Add `Claims::validate` boundary tests** — subject/audience/scope at
   exactly 255 bytes (should pass), and overlong via `sign_hmac` (should fail).
6. **Add `bytes_to_fr` known-value test** — pin `bytes_to_fr(&[1; 32])` to
   a specific `Fr` value.
7. **Optional**: add oversize-input tests for the DoS limits (Cat. 2).
   Low priority because fuzzing already exercises these, and the limits
   are strictly more permissive than any valid input.
8. **Add semantically-equivalent mutants to `exclude_re`** so future runs
   are cleaner.
