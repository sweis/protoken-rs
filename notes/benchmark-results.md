# Protoken Benchmark Results

Date: 2026-02-27
Build: `cargo run --release --example benchmark`
Environment: Linux 4.4.0, release mode (optimized)

## Test Payload

All benchmarks use the same claims:
- `subject`: "user:alice"
- `audience`: "api.example.com"
- `scopes`: ["read", "write"]
- `expires_at`: u64::MAX
- `issued_at`: 1,000,000

## Signing & Verification Performance

| Algorithm        | Sign               | Verify             |
|------------------|--------------------|--------------------|
| HMAC-SHA256      | 428,845 ops/s (2.3 us) | 406,736 ops/s (2.5 us) |
| Ed25519          | 25,953 ops/s (38.5 us) | 23,716 ops/s (42.2 us) |
| ML-DSA-44        | 2,848 ops/s (351 us)   | 6,584 ops/s (152 us)   |
| Groth16-Poseidon | 38.4 ops/s (26.0 ms)   | 296 ops/s (3.4 ms)     |
| Groth16-Hybrid   | 2.7 ops/s (370 ms)     | 293 ops/s (3.4 ms)     |

Benchmark durations: 10s for HMAC/Ed25519/ML-DSA, 30s sign / 10s verify for Groth16 variants.

## Token & Key Sizes

| Algorithm        | Token (B) | Signing Key (B) | Verify Key (B) |
|------------------|-----------|-----------------|----------------|
| HMAC-SHA256      | 107       | 36              | N/A (symmetric) |
| Ed25519          | 139       | 70              | 36             |
| ML-DSA-44        | 2,496     | 3,880           | 1,317          |
| Groth16-Poseidon | 262       | 36              | N/A (symmetric) |
| Groth16-Hybrid   | 262       | 36              | N/A (symmetric) |

Groth16 signing/verifying system keys (CRS) are excluded from key sizes.
The CRS is a circuit-specific trusted setup artifact, not a per-user key.

## Observations

- **HMAC-SHA256** is the fastest: ~430K sign/s, ~410K verify/s, 107-byte tokens.
- **Ed25519** is ~17x slower than HMAC but still very fast at ~26K sign/s.
- **ML-DSA-44** (post-quantum) has the largest tokens (2,496 B) and keys (3,880 B signing key)
  but still achieves ~2,800 sign/s and ~6,600 verify/s. Verify is faster than sign.
- **Groth16-Poseidon** proving is ~38 ops/s (26 ms/op) with a compact 262-byte token.
  The small Poseidon-only circuit (~480 constraints) keeps proving fast.
- **Groth16-Hybrid** proving is ~14x slower than Poseidon (370 ms/op) due to the
  in-circuit SHA-256 computation (~26K constraints). This is the cost of SHA-256
  key hash compatibility with existing HMAC key infrastructure.
- **Groth16 verification** is the same speed for both variants (~293-296 ops/s, 3.4 ms)
  since both produce identical 128-byte BN254 Groth16 proofs.
- Groth16 trusted setup takes <0.1s for Poseidon and ~2.5s for Hybrid (one-time cost).
