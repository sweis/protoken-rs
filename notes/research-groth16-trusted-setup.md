# Research: Groth16 Trusted Setup and Ceremony Reuse

## 1. Two-Phase Setup Explained

Groth16 requires a Common Reference String (CRS) containing "toxic waste" -- random field
elements that, if known, allow forging proofs. The setup uses the BGM17 MPC protocol
(Bowe-Gabizon-Miers, 2017) split into two phases:

### Phase 1: Powers of Tau (Circuit-Independent)

Generates a universal SRS: encrypted powers of a secret tau on the elliptic curve.
Concretely, the output is `{g^tau^0, g^tau^1, ..., g^tau^n}` on G1 and G2.

- **Circuit-independent**: works for any circuit up to 2^n constraints.
- **Reusable**: one Phase 1 output can feed many different Phase 2 ceremonies.
- **MPC**: each participant multiplies by their own random secret. Security holds if
  at least 1 of N participants honestly destroys their contribution.
- **Perpetual**: participants can join/leave at any time; no coordination needed.

### Phase 2: Circuit-Specific

Takes Phase 1 output + the circuit's R1CS/QAP description and produces the final
`ProvingKey` and `VerifyingKey`. This phase introduces additional toxic waste
(alpha, beta, gamma, delta) specific to the circuit structure.

- **Must be re-run** for every distinct circuit (different constraint system).
- **Also MPC-able**: can be run as another multi-party ceremony.
- **Much smaller**: only needs to handle the circuit's specific polynomial evaluations.

**Key point**: Phase 1 can absolutely be reused across different circuits. Only Phase 2
needs to be circuit-specific.

References:
- [BGM17 paper (MMORPG)](https://eprint.iacr.org/2017/1050)
- [ZKProof setup ceremonies](https://zkproof.org/2021/06/30/setup-ceremonies/)
- [ZoKrates trusted setup docs](https://zokrates.github.io/toolbox/trusted_setup.html)

## 2. Existing Powers of Tau Ceremonies

### Perpetual Powers of Tau (PSE/Ethereum) -- BN254

| Property | Value |
|----------|-------|
| Curve | **BN254** (bn128) |
| Max constraints | **2^28** (~268M) |
| Participants | 71+ (ongoing) |
| Organizer | Privacy & Scaling Explorations (Ethereum Foundation) |
| Status | Perpetual (still accepting contributions) |
| Used by | Tornado Cash, Hermez/Polygon, Loopring, Semaphore |

**Download (Hermez-prepared .ptau files)**:
```
https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_{NN}.ptau
```
Where `{NN}` = power of 2 (08, 10, 12, ..., 28). For our ~150K-200K constraint circuit,
we need `powersOfTau28_hez_final_18.ptau` (supports 2^18 = 262,144 constraints).

Alternative S3 mirror:
```
https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_18.ptau
```

**Repository**: https://github.com/privacy-scaling-explorations/perpetualpowersoftau

### Zcash Sapling Ceremony -- BLS12-381

| Property | Value |
|----------|-------|
| Curve | **BLS12-381** (NOT BN254) |
| Participants | 87 (Phase 1), 91 (Phase 2) |
| Status | Complete |

**Not usable**: wrong curve. Zcash switched from BN254 to BLS12-381 for Sapling.
Ethereum-based projects cannot use these parameters.

### Perpetual Powers of Tau (Gabizon) -- BLS12-381

| Property | Value |
|----------|-------|
| Curve | **BLS12-381** |
| Max constraints | 2^27 (~130M) |
| Participants | 18 (Phase 1 only) |

**Not usable**: wrong curve (BLS12-381, not BN254).

### Aztec Ignition -- BN254

| Property | Value |
|----------|-------|
| Curve | **BN254** |
| Points | 100.8 million G1 + 2 G2 |
| Participants | 176 |
| Date | Oct 2019 - Jan 2020 |
| Used by | zkSync, Aztec PLONK, Brevis |

**Download**: 20 transcript files (~307 MB each), accessible via `ark-srs` crate or scripts.
**Repository**: https://github.com/AztecProtocol/Setup

**Caveat**: Aztec Ignition was designed for PLONK (universal SRS), not Groth16. The SRS
structure is KZG-style (powers of tau on G1), which overlaps with what Groth16 Phase 1
needs, but the tooling around it targets KZG polynomial commitments, not Groth16.

### a16z EVM Powers of Tau -- BN254

| Property | Value |
|----------|-------|
| Curve | BN254 |
| Implementation | On-chain Ethereum ceremony |
| Backend | arkworks-rs |

**Repository**: https://github.com/a16z/evm-powers-of-tau
Interesting because it uses arkworks natively, but is more experimental.

### Summary Table

| Ceremony | Curve | Max Size | Participants | Groth16 Phase 1? | BN254? |
|----------|-------|----------|--------------|-------------------|--------|
| PPoT (PSE) | BN254 | 2^28 | 71+ | YES | YES |
| Zcash Sapling | BLS12-381 | - | 87+91 | n/a | NO |
| PPoT (Gabizon) | BLS12-381 | 2^27 | 18 | YES | NO |
| Aztec Ignition | BN254 | ~100M pts | 176 | KZG (partial) | YES |
| a16z EVM | BN254 | varies | varies | YES | YES |

**Winner for our use case**: Perpetual Powers of Tau (PSE/Ethereum) on BN254 with
Hermez-prepared .ptau files.

## 3. arkworks (ark-groth16 v0.5) API Analysis

### Current Setup API

The ark-groth16 crate provides two setup functions in `src/generator.rs`:

1. **`generate_random_parameters_with_reduction`**: Samples fresh random alpha, beta,
   gamma, delta (toxic waste) + random generators, then delegates to (2).

2. **`generate_parameters_with_qap`**: Accepts explicit toxic waste (alpha, beta, gamma,
   delta) and group generators. Computes the full ProvingKey and VerifyingKey.

**Neither function accepts pre-computed Powers of Tau**. The functions compute tau powers
internally via scalar multiplication, not by loading pre-computed curve points from a
ceremony. The `circuit_specific_setup` method (which we currently call) just wraps
`generate_random_parameters_with_reduction`.

### What This Means

arkworks ark-groth16 **does not natively support loading Phase 1 parameters** from an
existing ceremony and running only Phase 2. The `circuit_specific_setup` always generates
ALL toxic waste (including tau) fresh from random. This is fine for testing but not for
production, since there's no MPC -- a single machine knows the toxic waste.

### Known Phase 2 / MPC Implementations for arkworks

| Project | Repo | Status | Notes |
|---------|------|--------|-------|
| penumbra-zone/aleo-setup | [GitHub](https://github.com/penumbra-zone/aleo-setup) | Used for Penumbra mainnet | BGM17 MPC, phase1+phase2 crates |
| LaplaceKorea/trusted-setup-ceremony | [GitHub](https://github.com/LaplaceKorea/trusted-setup-ceremony) | Unknown maintenance | BGM17 MPC, Rust crates |
| kobigurk/phase2-bn254 | [GitHub](https://github.com/kobigurk/phase2-bn254) | Mature (Tornado Cash) | Uses bellman, NOT arkworks |
| quadratic-funding/mpc-phase2-suite | [GitHub](https://github.com/quadratic-funding/mpc-phase2-suite) | Firebase-based | JS/TS MPC coordinator |

The **penumbra-zone/aleo-setup** fork is the closest to our needs: it has `phase1` and
`phase2` Rust crates that implement the BGM17 MPC protocol and produce Groth16 parameters.
However, Penumbra uses BLS12-377, not BN254, so we'd need to verify BN254 compatibility
or adapt it.

## 4. snarkjs/circom Compatibility with arkworks

### .ptau File Format

The `.ptau` files from snarkjs/Hermez contain Phase 1 Powers of Tau in snarkjs's binary
format. These are **not directly loadable** by arkworks.

### .zkey File Format

After Phase 2, snarkjs produces `.zkey` files containing the circuit-specific proving key.
The `ark-circom` crate (arkworks-rs/circom-compat) can parse `.zkey` files into arkworks
`ProvingKey<Bn254>`, BUT:

**Critical difference**: snarkjs/circom uses Lagrange-basis representation of powers of tau
(`L_i(s).G` instead of `s^i.G`). This requires using `CircomReduction` instead of arkworks'
default `LibsnarkReduction` for the R1CS-to-QAP mapping. If you generate a `.zkey` via
snarkjs and load it with ark-circom, you MUST use `CircomReduction`.

### Conversion Tools

| Tool | From | To | Notes |
|------|------|----|-------|
| ark-circom | .zkey (snarkjs) | arkworks ProvingKey | Must use CircomReduction |
| ptau-deserializer (Worldcoin) | .ptau | gnark Phase 1 | Not arkworks |
| gnark-ptau | .ptau | gnark KZG SRS | Not arkworks |
| ark-srs | Aztec transcripts | arkworks KZG10 SRS | KZG only, not Groth16 |

**Bottom line**: There is no turnkey `.ptau -> arkworks Groth16 ProvingKey` pipeline.
The circom path (.ptau -> snarkjs Phase 2 -> .zkey -> ark-circom) works but requires
rewriting the circuit in circom and using CircomReduction.

## 5. Practical Recommendation

### Our Circuit

- ~150K-200K R1CS constraints (3x SHA-256 for HMAC + 1x SHA-256 for key hash)
- BN254 curve (arkworks `ark-bn254`)
- Fixed circuit (same for all protoken deployments)
- Current setup: `Groth16::circuit_specific_setup` (single-party, not MPC)

### Option A: Single-Party Setup with Committed Parameters (Pragmatic)

**What**: Run `circuit_specific_setup` once, publish the ProvingKey and VerifyingKey as
committed artifacts (e.g., checked into the repo or published as a release asset).

**Pros**: Zero additional dependencies, works today, deterministic for all users.
**Cons**: Single-party toxic waste. Users must trust the setup runner.
**Mitigation**: Document exactly how parameters were generated so anyone can audit the
process. The proving key can be verified against the circuit.

**This is what we do today** and is acceptable for initial deployment.

### Option B: snarkjs Phase 2 Pipeline (Medium Effort)

**What**:
1. Write the same HMAC-SHA256 circuit in circom
2. Use Hermez `.ptau` file for Phase 1 (download `powersOfTau28_hez_final_18.ptau`)
3. Run `snarkjs groth16 setup` for Phase 2 (single-party or small MPC)
4. Export `.zkey` file
5. Load in Rust via `ark-circom` with `CircomReduction`

**Pros**: Reuses the 71-participant PPoT ceremony for Phase 1.
**Cons**: Requires maintaining a parallel circom circuit. Phase 2 is still single-party
unless you also run a Phase 2 MPC. Different R1CS-to-QAP reduction (CircomReduction).

### Option C: Rust MPC Ceremony (High Effort, Best Security)

**What**:
1. Fork `penumbra-zone/aleo-setup` or `LaplaceKorea/trusted-setup-ceremony`
2. Adapt the `phase1` crate to load PPoT ceremony output (or run a new Phase 1)
3. Run Phase 2 as a multi-party ceremony for our specific circuit
4. Extract arkworks-compatible ProvingKey/VerifyingKey

**Pros**: Full MPC for both phases, native arkworks, no circom dependency.
**Cons**: Significant engineering effort. Need to recruit ceremony participants.

### Option D: Hybrid -- PPoT Phase 1 + Custom Rust Phase 2 (Recommended Future Path)

**What**:
1. Write a `.ptau` parser that extracts BN254 G1/G2 powers into arkworks types
2. Implement Phase 2 (circuit-specific specialization) in Rust, taking Phase 1 output
3. This is essentially a custom implementation of the BGM17 Phase 2 for arkworks

**Pros**: Reuses 71-participant PPoT ceremony, stays in Rust/arkworks ecosystem.
**Cons**: Requires implementing .ptau parsing and Phase 2 specialization.

### Recommendation

**Short term (now)**: Stay with Option A. Document the setup process, publish parameters.
This is what every arkworks-based project does during development.

**Medium term**: Option B (snarkjs pipeline) if we want to leverage PPoT Phase 1 with
minimal effort. The circom SHA-256 circuit already exists in the circom standard library.

**Long term**: Option D if we want a pure-Rust solution with ceremony support. The
`penumbra-zone/aleo-setup` codebase is the best starting point.

## .ptau Download Reference (for future use)

For our ~200K constraint circuit on BN254:
```bash
# 2^18 = 262,144 max constraints (sufficient)
wget https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_18.ptau

# 2^20 = 1,048,576 max constraints (generous headroom)
wget https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_20.ptau
```

## References

- [BGM17: Scalable MPC for zk-SNARK parameters](https://eprint.iacr.org/2017/1050)
- [Perpetual Powers of Tau (PSE)](https://github.com/privacy-scaling-explorations/perpetualpowersoftau)
- [Hermez .ptau files (snarkjs)](https://github.com/iden3/snarkjs)
- [phase2-bn254 (Tornado Cash)](https://github.com/kobigurk/phase2-bn254)
- [ark-groth16](https://github.com/arkworks-rs/groth16)
- [ark-circom (circom-compat)](https://github.com/arkworks-rs/circom-compat)
- [penumbra-zone/aleo-setup](https://github.com/penumbra-zone/aleo-setup)
- [ark-srs (ceremony SRS loader)](https://github.com/alxiong/ark-srs)
- [Aztec Ignition ceremony](https://github.com/AztecProtocol/Setup)
- [a16z EVM Powers of Tau](https://github.com/a16z/evm-powers-of-tau)
- [Worldcoin ptau-deserializer](https://github.com/worldcoin/ptau-deserializer)
- [Penumbra setup ceremony notes](https://hackmd.io/@tdHalYMZQBem3nIR74evcQ/S1k-xyrwh)
- [Groth16 explained (RareSkills)](https://rareskills.io/post/groth16)
- [Groth16 deep dive (Alin Tomescu)](https://alinush.github.io/groth16)
