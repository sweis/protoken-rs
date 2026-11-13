# FN-DSA (FIPS 206)

Written 2026-11-13.

## Status

No FIPS 206 draft was found as of this date. The `fn-dsa` 0.4.0 README says it implements a
"best guess" at the draft and that keys and signatures may break before 1.0. The signing key
encoding already changed between 0.3 and 0.4. The crate version is pinned for that reason.

There are two parameter sets: FN-DSA-512 (level 1) and FN-DSA-1024 (level 5). Nothing matches
ML-DSA-65 at level 3.

## Crate choice

| Crate | Notes |
|---|---|
| [`fn-dsa`](https://github.com/pornin/rust-fn-dsa) | Chosen. Pure Rust, by a Falcon author, tracks the FIPS 206 changes, fixed-size canonical signatures. |
| `pqcrypto-falcon` | C bindings to round 3 Falcon, not FN-DSA. |
| `falcon-rust` | Round 3 Falcon. |

## Decisions

- **Randomized signing only.** [NIST's plan](https://csrc.nist.gov/presentations/2025/fips-206-fn-dsa-falcon)
  allows no deterministic mode: floating-point differences could give two signatures for one
  hash, which reveals the key. Only the test generators use a fixed random stream.
- **Store the encoded key, not a seed.** The same plan forbids exporting seeds, because key
  generation is not specified bit for bit. Expanding a seed also costs 3-25 ms.
- **Check the embedded hash when a key is loaded, and never sign there.** Decoding does not
  check the public key hash, and a wrong one gives invalid signatures. A sign-and-verify check
  was tried and removed: decoding does not check the NTRU equation either, and the sampler's
  rejection loop runs without bound on a degenerate basis such as `F = f`.
- **Known limit.** A deliberately degenerate signing key loads, and `sign` then fails or does
  not return. Accidental corruption is rejected on load. Do not sign with keys from an untrusted
  source.
- **No independent test vectors exist yet.** The reference vectors only detect regressions.

## Upstream issues in 0.4.0

- `mq_avx2::mqpoly_int_to_small` never rejects. It tests bit 15 of each value with
  `_mm256_movemask_epi8`, but the values are below 2^14; the portable version tests `x >> 8`.
  With AVX2, a signing key with one flipped bit decodes, and FN-DSA-1024 then spends 10 to over
  30 seconds failing to sign. protoken enables `no_avx2` on `fn-dsa-sign` to avoid this.
- The `no_avx2` feature of the `fn-dsa` crate is not forwarded to its sub-crates.
- `sign` has no iteration bound in its sampler (see above).
- The seeds drawn in `keygen` and `sign`, and copies of the key moved out of `decode`, are left
  on the stack without zeroization.
