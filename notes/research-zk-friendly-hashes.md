# Research: ZK-Friendly Hash Functions and Proof Systems

Researched 2026-02-26. Context: our current Groth16+SHA-256 SNARK circuit for algorithm 4
(Groth16-SHA256) is expensive. The circuit proves:

```
∃ K: SHA-256(K) = key_hash ∧ HMAC-SHA256(K, SHA-256(payload)) = signature
```

SHA-256 costs ~30K R1CS constraints per block. Our circuit has 3 SHA-256 invocations
(key hash + HMAC inner + HMAC outer) totaling ~90K–150K constraints. Proving takes ~30s,
requires a per-circuit trusted setup, and the proving key is tens of MB.

This document evaluates alternatives that could dramatically reduce circuit size and
proving time.

---

## 1. Poseidon Hash

### Constraint Count

Poseidon with t=3 (width 3, rate 2, capacity 1) over BN254 scalar field:
**~240 R1CS constraints** per permutation. Compare SHA-256: **~29,380 constraints**.
That is a **~120x reduction** in circuit size.

Source: [Poseidon paper (USENIX Security 2021)](https://eprint.iacr.org/2019/458.pdf),
confirmed by [Circom benchmarks (hash-circuits)](https://github.com/bkomuves/hash-circuits).

### Poseidon-Based Key Proof Circuit

Replace the entire SHA-256/HMAC construction with Poseidon native operations:

```
Public inputs:  key_hash (1 field element), payload_hash (1 field element), mac (1 field element)
Private witness: K (1 field element)

Constraint 1: Poseidon(K) = key_hash                    (~240 constraints)
Constraint 2: Poseidon(K, payload_hash) = mac            (~240 constraints)
```

Total: **~480 R1CS constraints** (vs ~150K for SHA-256/HMAC). That is a **~300x reduction**.

The "MAC" here is simply `Poseidon(K, payload_hash)` — a keyed hash. Since Poseidon uses a
sponge construction, absorbing `K` then `payload_hash` and squeezing produces a
pseudorandom output that is unforgeable without `K`. This is functionally equivalent to
HMAC but dramatically cheaper in-circuit.

Note: `payload_hash` would still be `SHA-256(payload_bytes)` computed **outside** the circuit
(see Hybrid Approach, Section 4). The circuit itself never touches SHA-256.

### Expected Proving Time

Groth16 proving time scales roughly linearly with constraint count. At ~200μs per
constraint (arkworks on modern hardware):

| Circuit | Constraints | Estimated Prove Time |
|---------|-------------|---------------------|
| SHA-256 HMAC (current) | ~150K | ~30s |
| Poseidon key proof | ~480 | **~100ms** |

This is a **~300x speedup** — from 30 seconds to sub-second proving.

Setup time also drops proportionally. The proving key would shrink from tens of MB to
tens of KB.

### Arkworks Support

Poseidon is **natively supported** in `ark-crypto-primitives` (the crate we already use
for SHA-256 gadgets):

```toml
ark-crypto-primitives = { version = "0.5", default-features = false, features = ["crh", "sponge", "r1cs"] }
```

Key modules:
- `ark_crypto_primitives::sponge::poseidon::PoseidonConfig` — parameter configuration
- `ark_crypto_primitives::crh::poseidon::CRH` — native Poseidon hash
- `ark_crypto_primitives::crh::poseidon::constraints::CRHGadget` — R1CS constraint gadget

The `sponge` feature (merged from the archived `ark-sponge` crate) provides the full
Poseidon sponge with absorb/squeeze, which is what we need for the keyed hash construction.

Source: [ark-crypto-primitives repo](https://github.com/arkworks-rs/crypto-primitives),
[Sonobe docs (usage example)](https://sonobe.pse.dev/usage/frontend-arkworks.html)

### Other Poseidon Crates

| Crate | Downloads | Notes |
|-------|-----------|-------|
| `light-poseidon` | 7M+ | Solana ecosystem, native only (no R1CS) |
| `poseidon-rs` | 26K | Standalone, small |
| `poseidon377` (Penumbra) | audited | BLS12-377 specific, audited by NCC Group |
| `arkworks-r1cs-gadgets` (Webb/Tangle) | — | Poseidon R1CS for arkworks, with Merkle tree support |

**Recommendation:** Use `ark-crypto-primitives` directly (already a dependency).
The Poseidon CRH gadget and sponge are built in. No new crates needed.

### Parameters / Instances

There is no single "standard" Poseidon parameterization. Common choices:

- **t=3, d=5 (alpha=5), BN254 scalar field**: Used by Zcash, most Ethereum ZK projects.
  8 full rounds + 57 partial rounds for 128-bit security.
- **Filecoin (Neptune)**: t=9 for arity-8 Merkle trees. Audited. Different round constants.
- **Penumbra (Poseidon377)**: BLS12-377, audited by NCC Group (2022).

For our use case (t=3, BN254), we can use the parameter generation from
`ark-crypto-primitives` or adopt well-known constants (e.g., from circomlib/circom).

Source: [Poseidon parameter info](https://www.poseidon-hash.info/),
[Penumbra blog](https://www.penumbra.zone/blog/poseidon377)

### Security Analysis

- **128-bit security**: Achieved with appropriate round counts (8 full + 57 partial for
  t=3, d=5 over ~254-bit fields). This is the standard recommendation.
- **Cryptanalysis bounty**: The Ethereum Foundation runs a
  [Poseidon Cryptanalysis 2024-2026 bounty](https://www.poseidon-initiative.info/),
  paying $4K–$10K for attacks on reduced-round instances. Several bounties have been
  claimed on heavily reduced variants (4–6 full rounds, 0–4 partial rounds), but **no
  attacks on full-round instances** have been found.
- **Gröbner basis attacks** (2025): [Grassi, Koschatko, Rechberger](https://eprint.iacr.org/2025/954.pdf)
  revisited algebraic attacks and found some inaccuracies in the original security
  evaluation's model description, but the corrected analysis does not break full-round
  Poseidon. The authors recommend verifying round requirements.
- **Bottom line**: Poseidon with recommended round counts provides 128-bit security.
  The main risk is that it has ~5 years of cryptanalysis vs ~20+ years for SHA-256.
  However, the security margin is conservative and no practical attacks exist.

### Output Size

Poseidon over BN254 outputs **1 field element = 32 bytes** (254 bits of entropy, zero-padded
to 32 bytes in little-endian encoding). This is the same size as SHA-256 output, so
`key_hash` and `mac` fields remain 32 bytes.

### Production Usage

Poseidon is deployed in production by major projects:

| Project | Usage | Field |
|---------|-------|-------|
| **Zcash (Orchard)** | Note commitment, nullifier derivation | Pallas |
| **Filecoin** | Proof-of-Replication Merkle trees | BLS12-381 |
| **Mina Protocol** | Entire protocol state hash | Pasta curves |
| **Dusk Network** | Zcash-like privacy for securities | BLS12-381 |
| **Polygon (Plonky2)** | Recursive proof hashing | Goldilocks |
| **Aztec** | Note hashing, nullifiers | BN254 |
| **Tornado Cash** | Deposit/withdrawal commitments | BN254 |

Source: [EIP-5988 (Poseidon precompile proposal)](https://eips.ethereum.org/EIPS/eip-5988),
[USENIX paper](https://www.usenix.org/conference/usenixsecurity21/presentation/grassi),
[Filecoin spec](https://spec.filecoin.io/algorithms/crypto/poseidon/)

---

## 2. Rescue / Griffin / Anemoi

### Rescue-Prime

Older algebraic hash (2020). ~250–300 R1CS constraints, similar to Poseidon. Less
adopted, superseded by newer designs. No significant advantage over Poseidon.

### Griffin

96 R1CS constraints for t=3 over BN254 — **2.5x fewer than Poseidon**. Uses a different
nonlinear layer design. Published 2022.

However: less deployed, less analyzed, fewer Rust implementations. No production usage
found.

Source: [hash-circuits benchmarks](https://github.com/bkomuves/hash-circuits)

### Anemoi

~120 R1CS constraints for the permutation (t=3) — **~2x fewer than Poseidon**. Published
at CRYPTO 2023. Introduces the "Flystel" S-box and "Jive" compression mode.

**Rust crate:** [`anemoi-rust`](https://github.com/anemoi-hash/anemoi-rust) — native
implementation backed by arkworks field types. Supports BN254, BLS12-381, BLS12-377,
Vesta, Pallas, Ed25519.

**Limitation:** No R1CS gadget/constraint crate exists. The `anemoi-rust` crate provides
native evaluation only. Building R1CS constraints would require writing a custom gadget
(the Flystel S-box is more complex than Poseidon's x^5 S-box).

Source: [Anemoi paper](https://eprint.iacr.org/2022/840),
[Anemoi project page](https://anemoi-hash.github.io/),
[TACEO blog comparison](https://blog.taceo.io/how-to-choose-your-zk-friendly-hash-function/)

### Poseidon2

Improved version of Poseidon (2023). ~240 constraints in R1CS (same as Poseidon), but
**up to 70% fewer Plonk constraints** and much faster native performance.

**Rust crate:** [HorizenLabs/poseidon2](https://github.com/HorizenLabs/poseidon2) —
reference implementation with plain evaluation. **No arkworks R1CS gadget** available.

Poseidon2 is becoming the default in modern ZK stacks (SP1, RISC Zero recursion) but
those use Plonkish arithmetization, not R1CS.

For R1CS/Groth16, **Poseidon v1 and Poseidon2 have the same constraint count** (~240).
The advantages of Poseidon2 only appear in Plonk-style systems.

Source: [Poseidon2 paper](https://eprint.iacr.org/2023/323.pdf)

### Summary Table: Algebraic Hash Comparison

| Hash | R1CS Constraints (t=3, BN254) | Rust/Arkworks R1CS Gadget | Production Use | Standardization |
|------|-------------------------------|---------------------------|----------------|-----------------|
| **Poseidon** | ~240 | YES (ark-crypto-primitives) | Extensive | De facto ZK standard |
| **Poseidon2** | ~240 (R1CS same) | NO | Emerging (Plonk stacks) | Newer |
| **Griffin** | ~96 | NO | None found | Academic |
| **Anemoi** | ~120 | NO (native only) | None found | CRYPTO 2023 |
| **Rescue-Prime** | ~250-300 | NO | Limited | Older |

**Recommendation:** Poseidon is the clear choice for R1CS/Groth16. It has the only
production-ready arkworks R1CS gadget, extensive deployment, and 5+ years of
cryptanalysis. Griffin/Anemoi are theoretically superior but lack R1CS tooling.

---

## 3. Transparent Proof Systems (No Trusted Setup)

With a ~480 constraint Poseidon circuit, the choice of proof system becomes more flexible.
Smaller circuits reduce the cost of systems that have worse asymptotic scaling.

### Groth16 + Poseidon (Baseline Comparison)

| Property | Value |
|----------|-------|
| Proof size | 128 bytes (compressed BN254) |
| Proving time | ~100ms (estimated for ~480 constraints) |
| Verification time | ~1.2ms |
| Trusted setup | YES (per-circuit) |
| Rust crate | `ark-groth16` (already used) |

The trusted setup is the main downside. However, for ~480 constraints, setup is fast
(seconds, not minutes) and the proving key is small (KB, not MB).

### Spartan + Poseidon

| Property | Value |
|----------|-------|
| Proof size | ~1–5 KB (DL-based, scales O(√n)) |
| Proving time | ~50–200ms (estimated, ~2x faster prover than Groth16) |
| Verification time | ~5–20ms (sub-linear in circuit size) |
| Trusted setup | **NO** (transparent) |
| Rust crate | [`spartan`](https://github.com/microsoft/Spartan), [`arkworks-rs/spartan`](https://github.com/arkworks-rs/spartan) |

Spartan eliminates the trusted setup with a modest increase in proof size (1–5 KB vs 128 B)
and verification time (~10ms vs ~1ms). The prover is actually faster than Groth16 (2x for
arbitrary R1CS). For our small circuit, both should be sub-200ms.

**Concern:** The `spartan` crate uses ristretto255 (curve25519), not BN254. The
`arkworks-rs/spartan` port exists but may not be production-ready. Integration effort
would be higher than staying with `ark-groth16`.

Source: [Spartan paper (CRYPTO 2020)](https://eprint.iacr.org/2019/550.pdf),
[Microsoft/Spartan](https://github.com/microsoft/Spartan)

### Bulletproofs + Poseidon

| Property | Value |
|----------|-------|
| Proof size | ~700 bytes (logarithmic) |
| Proving time | ~1–5s |
| Verification time | ~100ms–1s (linear in circuit size) |
| Trusted setup | **NO** |
| Rust crate | [`bulletproofs`](https://github.com/dalek-cryptography/bulletproofs) |

**Verdict: Still too slow to verify.** Bulletproofs verification is linear in circuit size.
Even with ~480 constraints, verification would be orders of magnitude slower than Groth16.
Not suitable for token verification.

### Halo2 + Poseidon

| Property | Value |
|----------|-------|
| Proof size | ~400–5000 bytes (depending on variant) |
| Proving time | ~200ms–1s (IPA-based is slower; KZG variant is faster) |
| Verification time | ~5–20ms |
| Trusted setup | **NO** (IPA variant) / YES-universal (KZG variant) |
| Rust crate | [`halo2_proofs`](https://crates.io/crates/halo2_proofs) |

Halo2 uses PLONKish arithmetization (not R1CS), so Poseidon constraints are different
(potentially fewer due to custom gates). The IPA variant has no trusted setup but larger
proofs. The KZG variant has a universal (not per-circuit) trusted setup.

**Concern:** Halo2 is a much larger dependency than `ark-groth16`. The circuit would need
to be rewritten for PLONKish. Given that Poseidon+Groth16 already achieves ~100ms proving
with 128-byte proofs, the complexity of Halo2 seems hard to justify for our use case.

Source: [The Halo2 Book](https://zcash.github.io/halo2/),
[halo2_proofs crate](https://crates.io/crates/halo2_proofs)

### Summary Table: Proof Systems with ~480-Constraint Poseidon Circuit

| System | Proof Size | Prove | Verify | Setup | Practical? |
|--------|-----------|-------|--------|-------|------------|
| **Groth16** | 128 B | ~100ms | ~1ms | Per-circuit | **YES** (recommended) |
| **Spartan** | 1–5 KB | ~100ms | ~10ms | None | Maybe (integration effort) |
| **Halo2 (IPA)** | ~3–5 KB | ~500ms | ~10ms | None | Too complex |
| **Halo2 (KZG)** | ~400 B | ~200ms | ~5ms | Universal | Too complex |
| **Bulletproofs** | ~700 B | ~2s | ~500ms | None | NO (verify too slow) |

---

## 4. Hybrid Approach (Recommended)

Use Poseidon **inside** the circuit for algebraic operations on field elements, and
SHA-256 **outside** the circuit for byte-oriented hashing.

### Design

```
Outside circuit (native):
  payload_hash = SHA-256(payload_bytes)    // standard, fast (~1μs)

Inside circuit (R1CS):
  Public inputs:  key_hash, payload_hash, mac    (3 field elements)
  Private witness: K                              (1 field element)

  Constraint 1: Poseidon(K) = key_hash            (~240 constraints)
  Constraint 2: Poseidon(K, payload_hash) = mac   (~240 constraints)
  Total: ~480 constraints
```

### Why This Works

- **Payload binding**: `payload_hash = SHA-256(payload_bytes)` is a public input. The
  verifier computes this independently from the raw payload. The circuit proves that the
  MAC was computed over this exact hash. Tampering with the payload changes `payload_hash`,
  which invalidates the proof.

- **Key binding**: `key_hash = Poseidon(K)` binds the proof to a specific key. The key
  hash in the token identifies the key, and the proof shows knowledge of its preimage.

- **MAC security**: `Poseidon(K, payload_hash)` is a keyed hash — unforgeable without K.
  The sponge construction absorbs K first (into the capacity), then payload_hash, and
  squeezes the output. This provides PRF-like security.

### Advantages over Current Design

| Property | Current (SHA-256) | Hybrid (Poseidon) | Improvement |
|----------|-------------------|-------------------|-------------|
| Circuit constraints | ~150K | ~480 | **~300x** |
| Proving time | ~30s | ~100ms | **~300x** |
| Proof size | 128 B | 128 B | Same |
| Verification time | ~1ms | ~1ms | Same |
| Setup time | ~minutes | ~seconds | **Much faster** |
| Proving key size | ~50 MB | ~100 KB | **~500x** |
| New dependencies | None | None (ark-crypto-primitives sponge feature) | Same |

### What Changes in the Token Format

If we adopt the hybrid approach, the token format changes:

1. **`key_hash`** (key_id field): Changes from `SHA-256(K)[0..32]` to `Poseidon(K)`
   (1 BN254 field element, 32 bytes). Same wire size, different computation.

2. **`signature`** field: Changes from `HMAC-SHA256(K, SHA-256(payload))` (32 bytes)
   to `Poseidon(K, SHA-256(payload))` (1 field element, 32 bytes). Same wire size.

3. **`proof`** field: Stays at 128 bytes (still Groth16 on BN254).

4. **`key_id_type = FullKeyHash`**: Still 32 bytes. The hash function changes but the
   wire format does not.

5. **Algorithm enum**: Stays `Groth16Sha256 = 4` or could be renamed to
   `Groth16Poseidon = 4` (or a new value `5`).

6. **SNARK verifying key**: Changes (different circuit), but the serialization format
   stays the same (arkworks compressed). Size drops dramatically (~100 KB to ~1–2 KB).

### Token Size Impact

No change. Both `key_hash` and `mac` remain 32 bytes. The proof remains 128 bytes.
Total Groth16 token size is unchanged.

---

## 5. Practical Trade-offs

### "Non-standard" Concern

Poseidon is not NIST-standardized and is not widely deployed outside ZK systems. But:

1. Our entire Groth16 approach is already non-standard (there is no NIST standard for
   SNARK-based token authentication).
2. Poseidon is the de facto standard within the ZK ecosystem, with billions of dollars
   secured by it (Zcash, Filecoin, Tornado Cash, etc.).
3. The alternative (SHA-256 in-circuit) is standard but makes the system impractically
   slow for many use cases.
4. For algorithm 1 (HMAC-SHA256), we still use standard SHA-256. Poseidon is only used
   inside the SNARK circuit for algorithm 4.

### Compatibility / Migration

Switching to Poseidon means:

- **Key hashes change**: A key `K` will have a different `key_hash` under Poseidon vs
  SHA-256. Existing Groth16-SHA256 tokens are not compatible with Groth16-Poseidon tokens.
- **Standard tooling**: You cannot verify the key hash with `openssl dgst -sha256` or
  similar. But you also cannot verify the Groth16 proof with standard tooling, so this
  is not a meaningful regression.
- **Migration path**: Assign a new algorithm number (e.g., `5 = Groth16Poseidon`) and
  support both during transition. Eventually deprecate algorithm 4.

### Performance Summary

The hybrid Poseidon approach transforms the Groth16 SNARK from a "batch/offline use only"
feature (~30s proving) into a practical "online" feature (~100ms proving). This is the
single biggest improvement available without changing the proof system itself.

---

## 6. Recommendation

**Switch to Poseidon for the in-circuit hash, keeping SHA-256 for external payload
hashing (hybrid approach).**

Specific plan:

1. **Keep Groth16 on BN254** — smallest proofs (128 B), fastest verification (~1 ms),
   and we already have the arkworks dependency. The trusted setup downside is minimal for
   a ~480 constraint circuit (fast setup, small keys).

2. **Use `ark-crypto-primitives` Poseidon sponge** — already a dependency. Enable the
   `sponge` feature flag. Use `PoseidonConfig` with standard BN254 parameters (t=3, d=5,
   8 full + 57 partial rounds).

3. **Circuit**: `Poseidon(K) = key_hash ∧ Poseidon(K, SHA-256(payload)) = mac`. ~480
   constraints. ~100ms proving. 128-byte proof.

4. **New algorithm**: `Groth16Poseidon = 5` (keep `Groth16Sha256 = 4` for backward
   compatibility during any transition, or replace 4 since it is not yet widely deployed).

5. **Do NOT switch proof systems** (Spartan, Halo2, etc.) — the marginal benefit of
   eliminating the trusted setup does not justify the integration cost, larger proofs,
   and slower verification. Groth16 with a tiny circuit is practical and well-understood.

6. **Do NOT use Griffin or Anemoi** — theoretically better (~2x fewer constraints) but
   no R1CS gadgets exist in Rust. Not worth building custom gadgets for a 2x improvement
   when Poseidon already gives a 300x improvement over SHA-256.

---

## References

- [Poseidon paper (ePrint 2019/458)](https://eprint.iacr.org/2019/458.pdf)
- [Poseidon2 paper (ePrint 2023/323)](https://eprint.iacr.org/2023/323.pdf)
- [Poseidon cryptanalysis bounty (Ethereum Foundation)](https://www.poseidon-initiative.info/)
- [Gröbner basis cryptanalysis (2025)](https://eprint.iacr.org/2025/954.pdf)
- [Anemoi paper (ePrint 2022/840)](https://eprint.iacr.org/2022/840)
- [Anemoi project page](https://anemoi-hash.github.io/)
- [Griffin/Anemoi comparison (TACEO blog)](https://blog.taceo.io/how-to-choose-your-zk-friendly-hash-function/)
- [ark-crypto-primitives (GitHub)](https://github.com/arkworks-rs/crypto-primitives)
- [Sonobe docs (Poseidon usage)](https://sonobe.pse.dev/usage/frontend-arkworks.html)
- [Penumbra Poseidon377 (audited)](https://www.penumbra.zone/blog/poseidon377)
- [Spartan paper (CRYPTO 2020)](https://eprint.iacr.org/2019/550.pdf)
- [Microsoft/Spartan (GitHub)](https://github.com/microsoft/Spartan)
- [Halo2 Book](https://zcash.github.io/halo2/)
- [Filecoin Poseidon spec](https://spec.filecoin.io/algorithms/crypto/poseidon/)
- [EIP-5988 (Poseidon precompile)](https://eips.ethereum.org/EIPS/eip-5988)
- [hash-circuits benchmarks (Circom)](https://github.com/bkomuves/hash-circuits)
- [Groth16 overview (Lambda Class)](https://blog.lambdaclass.com/groth16/)
- [light-poseidon crate](https://crates.io/crates/light-poseidon)
- [anemoi-rust crate](https://github.com/anemoi-hash/anemoi-rust)
- [HorizenLabs/poseidon2](https://github.com/HorizenLabs/poseidon2)
- [Webb/Tangle arkworks-gadgets](https://github.com/tangle-network/zero-knowledge-gadgets)
- [FuzzingLabs Poseidon sponge bugs](https://fuzzinglabs.com/poseidon-sponge-bugs-arkworks-cryptography-zkp/)
- [Benchmarking ZK-Circuits in Circom (ePrint 2023/681)](https://eprint.iacr.org/2023/681.pdf)
- [Current state of SNARKs (Alpen Labs)](https://www.alpenlabs.io/blog/current-state-of-snarks)
