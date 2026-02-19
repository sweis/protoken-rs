# Post-Quantum Signature Schemes for Short-Lived Tokens

Research conducted 2026-02-18. Evaluated ML-DSA, SLH-DSA, XMSS, and LMS for use in protoken-rs.

## Quick Comparison

| | ML-DSA-44 | SLH-DSA-SHA2-128s | XMSS-SHA2_10_256 | LMS-SHA256_H20 |
|---|---|---|---|---|
| **Standard** | FIPS 204 (Aug 2024) | FIPS 205 (Aug 2024) | RFC 8391 / SP 800-208 | RFC 8554 / SP 800-208 |
| **Basis** | Lattice (Module-LWE) | Hash (WOTS+/Merkle) | Hash (WOTS+/Merkle) | Hash (LM-OTS/Merkle) |
| **Stateful** | No | No | **Yes** | **Yes** |
| **Signature** | **2,420 B** | 7,856 B | ~2,500 B | ~2,500 B |
| **Public key** | 1,312 B | 32 B | 32-68 B | 32 B |
| **Sign time** | ~200 us | ~100 ms | ~ms | ~4 ms |
| **Verify time** | ~100 us | ~180 us | ~ms | ~2.6 ms |
| **Max sigs/key** | Unlimited | Unlimited | 2^h (e.g. 1,024) | 2^h (e.g. 1M) |
| **Keygen time** | ~ms | ~ms-sec | sec to hours | sec to hours |

## ML-DSA-44 (FIPS 204) — Lattice-Based

**Pros:**
- Stateless — no state coordination, safe for distributed token issuers
- Fast — ~200 us sign, ~100 us verify
- Smallest PQ signatures at 128-bit security (2,420 B)
- FIPS 204 finalized Aug 2024
- Best Rust support: `ml-dsa` (RustCrypto, ~69K downloads, ~1,100 dependents), `fips204` (IntegrityChain, ~56K downloads)

**Cons:**
- Large public keys (1,312 B) — impractical for inline embedding in compact tokens
- Lattice assumption is newer than hash-based schemes
- 2,420 B signatures are ~38x larger than Ed25519's 64 B
- No independently audited Rust crate yet

## SLH-DSA (FIPS 205) — Stateless Hash-Based

**Pros:**
- Stateless
- Conservative — relies only on hash function preimage resistance
- Tiny public keys (32 B)
- FIPS 205 finalized Aug 2024

**Cons:**
- Huge signatures: 7,856 B minimum ("small" variant), up to 49,856 B ("fast" 256-bit)
- Slow signing: ~100 ms for the "small" variant
- Painful trade-off between signature size and signing speed

## XMSS (RFC 8391 / SP 800-208) — Stateful Hash-Based

**Pros:**
- Conservative hash-based security
- Small public keys (32-68 B)
- Signatures (~2,500 B) competitive with ML-DSA

**Cons:**
- **Stateful**: reusing a one-time key index enables complete forgery. State must be atomically persisted after every signature.
- Limited signatures per key: 2^h (e.g. h=10 → 1,024)
- Key generation takes seconds to hours
- Poor Rust support — no mature pure Rust crate
- Incompatible with distributed/HA token issuers

## LMS (RFC 8554 / SP 800-208) — Stateful Hash-Based

**Pros:**
- Conservative hash-based security
- HSS hierarchical mode scales to billions of signatures
- Better Rust support than XMSS: `hbs-lms` (pure Rust, no_std)

**Cons:**
- **Stateful** — same forgery risk as XMSS on index reuse
- Same state management problems: disk sync per signature, backup/restore risks
- Slow verification (~2.6 ms)
- Key generation seconds to hours

## Why Stateful Schemes Don't Work for Tokens

1. **Throughput**: Each signature requires fsync to persist state. ~1K sigs/sec max per key.
2. **Distributed issuers**: Cannot share a stateful key without distributed consensus.
3. **Crash recovery**: Must assume all "possibly used" indices are burned after a crash.
4. **VM cloning/backups**: Restoring old state = catastrophic forgery vulnerability.

These schemes are designed for firmware signing and CA certificates, not token issuance.

## Decision: ML-DSA-44

ML-DSA-44 is the only scheme that is simultaneously stateless, fast, NIST standardized, and well-supported in Rust. The main trade-off is token size (~2,500 B vs 56-88 B for HMAC/Ed25519).

Implementation uses the `ml-dsa` crate (RustCrypto): ~1,100 dependents, 69K downloads, actively maintained with security hardening (Barrett reduction for timing side-channels). Neither `ml-dsa` nor `fips204` has been independently audited.

## References

- [FIPS 204 — ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205 — SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [RFC 8391 — XMSS](https://datatracker.ietf.org/doc/html/rfc8391)
- [RFC 8554 — LMS/HSS](https://datatracker.ietf.org/doc/html/rfc8554)
- [NIST SP 800-208 — Stateful HBS](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-208.pdf)
- [ml-dsa crate (RustCrypto)](https://crates.io/crates/ml-dsa)
- [fips204 crate (IntegrityChain)](https://crates.io/crates/fips204)
