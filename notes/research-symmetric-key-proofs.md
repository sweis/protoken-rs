# Research: Symmetric Key Proofs for Protoken

## Problem Statement

We want a new token type where the verifier only needs a key hash (not the full key) to
verify tokens. The bearer of the symmetric key proves:
1. They know the preimage of the key_id hash
2. The signature was generated with that preimage

This turns symmetric verification into "public verification."

## Approaches Researched

### 1. SNARKs (Groth16, PLONK, Halo2)

The natural approach is a SNARK circuit proving:
`∃ K: SHA-256(K) = key_hash ∧ HMAC-SHA256(K, payload) = signature`

**Circuit complexity:** SHA-256 ≈ 30K R1CS constraints per block. HMAC-SHA256 requires
~3 SHA-256 calls (ipad, opad, key_hash) ≈ 90K–150K constraints depending on payload size.

| System | Proof Size | Proving Time | Verify | Trusted Setup | Rust Crate |
|--------|-----------|-------------|--------|---------------|------------|
| Groth16 | 128–192 B | 5–15s | ~1ms | YES (per-circuit) | ark-groth16, bellman |
| PLONK | 400–900 B | 5–15s | 2–5ms | YES (universal) | dusk-plonk, zk-garage |
| Halo2 | 5–10 KB | 30–60s | 5–20ms | No | halo2_proofs (zcash) |
| Spartan | 10–50 KB | 0.5–2s | 5–20ms | No | microsoft/Spartan |
| STARKs | 15–300 KB | 0.1–1s | 2–6ms | No | winterfell (Meta) |
| Bulletproofs | 1–2 KB | 10–30s | 5–15s | No | dalek bulletproofs |

**Key concern:** SHA-256 is expensive in arithmetic circuits (~30K constraints/block).
The ZK community uses Poseidon (~250 constraints) but it's less "boring."

**References:**
- SHA-256 in Circom: 29,380 non-linear R1CS constraints
- Groth16 proof = 2 G₁ points + 1 G₂ point on BN254 = 128–256 bytes
- bellman (Zcash Rust Groth16): ~25s for SHA-256 with 16KB preimage
- arkworks ecosystem: ~46M crates.io downloads for core crates
- [ark-groth16](https://crates.io/crates/ark-groth16)
- [bellman](https://crates.io/crates/bellman)
- [halo2_proofs](https://crates.io/crates/halo2_proofs)
- [Poseidon hash](https://eprint.iacr.org/2019/458.pdf)

### 2. Verifiable Random Functions (VRFs) — CHOSEN

A VRF is the public-key analogue of a keyed hash (HMAC). The secret key holder computes
`VRF(sk, message) → (output, proof)`, and anyone with the public key can verify.

**RFC 9381** standardizes ECVRF with multiple cipher suites including
ECVRF-RISTRETTO255-SHA512.

| Property | Value |
|----------|-------|
| Secret key | 32 bytes (EC scalar) |
| Public key | 32 bytes (ristretto255 point) |
| VRF output | 64 bytes (deterministic, pseudorandom) |
| Proof | 80 bytes |
| Proving time | <1ms |
| Verification time | ~1ms |
| Trusted setup | None |
| Standard | RFC 9381 |

**Rust crate:** [`vrf-r255`](https://crates.io/crates/vrf-r255) by str4d (Zcash core dev)
- Implements ECVRF-RISTRETTO255-SHA512
- Dependencies: `curve25519-dalek` v4, `sha2`, `subtle`, `rand_core` (all overlap with existing protoken deps)
- ~5K downloads, MIT/Apache-2.0

**Why VRF over SNARK:**
- 1000× faster proving (<1ms vs seconds)
- Simpler implementation (no circuit development)
- No trusted setup
- Standardized (RFC 9381)
- Lighter dependencies (single crate vs entire ZK stack)
- 80-byte proof vs 128+ byte SNARK proof

**Trade-off:** The "symmetric key" is technically an EC private key (scalar), not a raw
symmetric key. But functionally it behaves the same: only the issuer has it, it's 32 bytes,
and verification uses only the public key hash.

### 3. ZK-Friendly Hashes (Poseidon)

Replace SHA-256 with Poseidon (~250 constraints vs ~30K). Makes any SNARK feasible with
ms-level proving. But Poseidon is field-specific and less studied outside ZK.

**Not chosen:** Less "boring," field-specific parameters, limited standardization.

### 4. Sigma Protocols

Traditional Sigma protocols (Schnorr-like) work for discrete log proofs but not for
hash preimage proofs. SHA-256 is not algebraically structured, so there's no efficient
Sigma protocol for SHA-256 preimage knowledge without embedding it in a circuit (→ SNARK).

**Not applicable** as a standalone approach.

## Decision: ECVRF (RFC 9381) via vrf-r255

**Rationale:** Most boring, standardized, and lightweight option. Provides exactly the
properties needed with minimal complexity. SNARK approach remains available for future
exploration if a true symmetric-key proof is desired (see Groth16 option above).

**Token design:**
- New algorithm: `EcVrf = 4`
- New key_id_type: `FullKeyHash = 3` (32-byte SHA-256 of public key)
- `signature` field: VRF output (64 bytes)
- New `proof` field: VRF proof (80 bytes)
- SigningKey: 32B EC scalar + 32B public key
- VerifyingKey: 32B public key

**Verification flow:**
1. Deserialize token → payload_bytes, signature (VRF output), proof
2. Parse payload → check algorithm = EcVrf
3. Compute SHA-256(public_key), verify matches key_id (full 32 bytes)
4. `pk.verify(payload_bytes, &proof)` → returns computed VRF output
5. Constant-time compare computed output with signature field
6. Check temporal claims
