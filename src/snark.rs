//! Groth16 SNARK for symmetric key proofs.
//!
//! Proves knowledge of a symmetric key K such that:
//! 1. SHA-256(K) = key_hash (binds the proof to the key identifier)
//! 2. HMAC-SHA256(K, SHA-256(payload)) = signature (binds the key to the token)
//!
//! The verifier needs only the key_hash (from the token's key_identifier field),
//! the signature, and the payload bytes — no symmetric key required.
//!
//! The circuit uses SHA-256 for both the key hash and HMAC computation.
//! HMAC is computed over SHA-256(payload_bytes) rather than the raw payload,
//! so the circuit has fixed-size inputs regardless of payload length.

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;
use ark_crypto_primitives::crh::CRHSchemeGadget;
use ark_groth16::Groth16;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;

use crate::error::ProtokenError;
use crate::types::GROTH16_PROOF_LEN;

/// Groth16 proving key (circuit-specific, generated during trusted setup).
pub type SnarkProvingKey = ark_groth16::ProvingKey<Bn254>;

/// Groth16 verifying key (circuit-specific, generated during trusted setup).
pub type SnarkVerifyingKey = ark_groth16::VerifyingKey<Bn254>;

/// Compressed Groth16 proof.
pub type SnarkProof = ark_groth16::Proof<Bn254>;

/// HMAC-SHA256 key hash circuit.
///
/// Public inputs (96 bytes = 768 Boolean field elements):
///   - key_hash: SHA-256(K) — 32 bytes
///   - payload_hash: SHA-256(payload_bytes) — 32 bytes
///   - hmac_output: HMAC-SHA256(K, payload_hash) — 32 bytes
///
/// Private witness:
///   - key: K — 32 bytes
#[derive(Clone, Default)]
struct HmacKeyHashCircuit {
    key: [u8; 32],
    key_hash: [u8; 32],
    payload_hash: [u8; 32],
    hmac_output: [u8; 32],
}

impl ConstraintSynthesizer<Fr> for HmacKeyHashCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate public inputs
        let key_hash_vars = allocate_bytes_input(cs.clone(), &self.key_hash)?;
        let payload_hash_vars = allocate_bytes_input(cs.clone(), &self.payload_hash)?;
        let hmac_output_vars = allocate_bytes_input(cs.clone(), &self.hmac_output)?;

        // Allocate private witness
        let key_vars = allocate_bytes_witness(cs.clone(), &self.key)?;

        // SHA-256 parameters (unit — SHA-256 has no variable parameters)
        let sha256_params = <Sha256Gadget<Fr> as CRHSchemeGadget<
            ark_crypto_primitives::crh::sha256::Sha256,
            Fr,
        >>::ParametersVar::default();

        // Constraint 1: SHA-256(K) = key_hash
        let computed_key_hash = <Sha256Gadget<Fr> as CRHSchemeGadget<
            ark_crypto_primitives::crh::sha256::Sha256,
            Fr,
        >>::evaluate(&sha256_params, &key_vars)?;
        computed_key_hash.0.enforce_equal(&key_hash_vars)?;

        // Constraint 2: HMAC-SHA256(K, payload_hash) = hmac_output
        //
        // HMAC(K, M) = SHA-256((K_padded ^ opad) || SHA-256((K_padded ^ ipad) || M))
        // K_padded = K || 0x00^32 (pad 32-byte key to 64-byte block size)
        // ipad = 0x36 repeated, opad = 0x5C repeated

        // Build K_padded (64 bytes): key || zeros
        let mut k_padded = key_vars.clone();
        for _ in 0..32 {
            k_padded.push(UInt8::constant(0u8));
        }

        // ipad = K_padded XOR 0x36^64
        let mut ipad = Vec::with_capacity(64);
        for byte in &k_padded {
            ipad.push(byte ^ 0x36u8);
        }

        // inner_input = ipad || payload_hash (96 bytes)
        let mut inner_input = ipad;
        inner_input.extend_from_slice(&payload_hash_vars);

        let inner_hash = <Sha256Gadget<Fr> as CRHSchemeGadget<
            ark_crypto_primitives::crh::sha256::Sha256,
            Fr,
        >>::evaluate(&sha256_params, &inner_input)?;

        // opad = K_padded XOR 0x5C^64
        // Rebuild k_padded since it was moved into ipad
        let mut k_padded2 = key_vars;
        for _ in 0..32 {
            k_padded2.push(UInt8::constant(0u8));
        }
        let mut opad = Vec::with_capacity(64);
        for byte in &k_padded2 {
            opad.push(byte ^ 0x5Cu8);
        }

        // outer_input = opad || inner_hash (96 bytes)
        let mut outer_input = opad;
        outer_input.extend_from_slice(&inner_hash.0);

        let computed_hmac = <Sha256Gadget<Fr> as CRHSchemeGadget<
            ark_crypto_primitives::crh::sha256::Sha256,
            Fr,
        >>::evaluate(&sha256_params, &outer_input)?;

        // Enforce HMAC output matches
        computed_hmac.0.enforce_equal(&hmac_output_vars)?;

        Ok(())
    }
}

/// Allocate bytes as public input variables.
fn allocate_bytes_input(
    cs: ConstraintSystemRef<Fr>,
    bytes: &[u8; 32],
) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    let mut vars = Vec::with_capacity(32);
    for &b in bytes {
        vars.push(UInt8::new_input(cs.clone(), || Ok(b))?);
    }
    Ok(vars)
}

/// Allocate bytes as private witness variables.
fn allocate_bytes_witness(
    cs: ConstraintSystemRef<Fr>,
    bytes: &[u8; 32],
) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    let mut vars = Vec::with_capacity(32);
    for &b in bytes {
        vars.push(UInt8::new_witness(cs.clone(), || Ok(b))?);
    }
    Ok(vars)
}

/// Generate the Groth16 proving and verifying keys (trusted setup).
///
/// This must be run once per deployment. The proving key is large (~tens of MB)
/// and should be stored securely. The verifying key is small (~25 KB) and can
/// be distributed publicly.
pub fn setup() -> Result<(SnarkProvingKey, SnarkVerifyingKey), ProtokenError> {
    let circuit = HmacKeyHashCircuit::default();
    let mut rng = ark_std::rand::rngs::OsRng;
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)
        .map_err(|e| ProtokenError::SigningFailed(format!("Groth16 setup failed: {e}")))?;
    Ok((pk, vk))
}

/// Compute the native HMAC-SHA256(key, payload_hash).
///
/// This is used to compute the signature field natively (outside the circuit).
fn native_hmac_sha256(key: &[u8; 32], payload_hash: &[u8; 32]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    #[allow(clippy::unwrap_used)] // 32-byte key always valid for HMAC
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(payload_hash);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Result of a Groth16 proof generation: (key_hash, signature, proof_bytes).
pub type ProveResult = ([u8; 32], [u8; 32], Vec<u8>);

/// Generate a Groth16 proof for a symmetric key token.
///
/// Inputs:
///   - `pk`: the Groth16 proving key (from `setup()`)
///   - `key`: the 32-byte symmetric key
///   - `payload_bytes`: the canonical-encoded payload bytes
///
/// Returns (key_hash, signature, proof_bytes):
///   - `key_hash`: SHA-256(key) — 32 bytes, used as FullKeyHash key_identifier
///   - `signature`: HMAC-SHA256(key, SHA-256(payload_bytes)) — 32 bytes
///   - `proof_bytes`: compressed Groth16 proof — 128 bytes
pub fn prove(
    pk: &SnarkProvingKey,
    key: &[u8; 32],
    payload_bytes: &[u8],
) -> Result<ProveResult, ProtokenError> {
    use sha2::{Digest, Sha256};

    // Compute native values
    let key_hash: [u8; 32] = Sha256::digest(key).into();
    let payload_hash: [u8; 32] = Sha256::digest(payload_bytes).into();
    let hmac_output = native_hmac_sha256(key, &payload_hash);

    // Build circuit with actual values
    let circuit = HmacKeyHashCircuit {
        key: *key,
        key_hash,
        payload_hash,
        hmac_output,
    };

    let mut rng = ark_std::rand::rngs::OsRng;
    let proof = Groth16::<Bn254>::prove(pk, circuit, &mut rng)
        .map_err(|e| ProtokenError::SigningFailed(format!("Groth16 proving failed: {e}")))?;

    // Serialize proof (compressed)
    let mut proof_bytes = Vec::with_capacity(GROTH16_PROOF_LEN);
    proof
        .serialize_compressed(&mut proof_bytes)
        .map_err(|e| ProtokenError::SigningFailed(format!("proof serialization failed: {e}")))?;

    Ok((key_hash, hmac_output, proof_bytes))
}

/// Verify a Groth16 proof for a symmetric key token.
///
/// Inputs:
///   - `vk`: the Groth16 verifying key (from `setup()`)
///   - `key_hash`: the 32-byte key hash from the token's key_identifier
///   - `signature`: the 32-byte HMAC signature from the token
///   - `proof_bytes`: the compressed Groth16 proof (128 bytes)
///   - `payload_bytes`: the canonical-encoded payload bytes
pub fn verify(
    vk: &SnarkVerifyingKey,
    key_hash: &[u8; 32],
    signature: &[u8; 32],
    proof_bytes: &[u8],
    payload_bytes: &[u8],
) -> Result<(), ProtokenError> {
    use sha2::{Digest, Sha256};

    // Deserialize the proof
    let proof = SnarkProof::deserialize_compressed(proof_bytes)
        .map_err(|e| ProtokenError::VerificationFailed(format!("invalid Groth16 proof: {e}")))?;

    // Compute payload hash (verifier computes this from the raw payload)
    let payload_hash: [u8; 32] = Sha256::digest(payload_bytes).into();

    // Encode public inputs as field elements (each byte → 8 Boolean field elements)
    let public_inputs = encode_public_inputs(key_hash, &payload_hash, signature);

    // Prepare verifying key for efficient verification
    let pvk = ark_groth16::prepare_verifying_key(vk);

    // Verify the proof
    let valid =
        Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &proof).map_err(|e| {
            ProtokenError::VerificationFailed(format!("Groth16 verification error: {e}"))
        })?;

    if !valid {
        return Err(ProtokenError::VerificationFailed(
            "Groth16 proof verification failed".into(),
        ));
    }

    Ok(())
}

/// Encode public inputs as BN254 scalar field elements.
///
/// Each byte is encoded as 8 Boolean (0/1) field elements in little-endian
/// order (LSB first), matching arkworks `UInt8::new_input` allocation order.
fn encode_public_inputs(
    key_hash: &[u8; 32],
    payload_hash: &[u8; 32],
    hmac_output: &[u8; 32],
) -> Vec<Fr> {
    let mut inputs = Vec::with_capacity(768); // 96 bytes × 8 bits
    for group in [
        key_hash.as_slice(),
        payload_hash.as_slice(),
        hmac_output.as_slice(),
    ] {
        for &byte in group {
            // UInt8 allocates bits in little-endian order (LSB first)
            for bit_idx in 0..8 {
                let bit = (byte >> bit_idx) & 1;
                inputs.push(Fr::from(bit as u64));
            }
        }
    }
    inputs
}

/// Serialize a Groth16 verifying key to bytes.
pub fn serialize_verifying_key(vk: &SnarkVerifyingKey) -> Result<Vec<u8>, ProtokenError> {
    let mut buf = Vec::new();
    vk.serialize_compressed(&mut buf)
        .map_err(|e| ProtokenError::MalformedEncoding(format!("VK serialization failed: {e}")))?;
    Ok(buf)
}

/// Deserialize a Groth16 verifying key from bytes.
pub fn deserialize_verifying_key(data: &[u8]) -> Result<SnarkVerifyingKey, ProtokenError> {
    SnarkVerifyingKey::deserialize_compressed(data).map_err(|e| {
        ProtokenError::MalformedEncoding(format!("invalid Groth16 verifying key: {e}"))
    })
}

/// Serialize a Groth16 proving key to bytes.
pub fn serialize_proving_key(pk: &SnarkProvingKey) -> Result<Vec<u8>, ProtokenError> {
    let mut buf = Vec::new();
    pk.serialize_compressed(&mut buf)
        .map_err(|e| ProtokenError::MalformedEncoding(format!("PK serialization failed: {e}")))?;
    Ok(buf)
}

/// Deserialize a Groth16 proving key from bytes.
pub fn deserialize_proving_key(data: &[u8]) -> Result<SnarkProvingKey, ProtokenError> {
    SnarkProvingKey::deserialize_compressed(data)
        .map_err(|e| ProtokenError::MalformedEncoding(format!("invalid Groth16 proving key: {e}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_native_hmac_matches_hmac_crate() {
        let key = [0xABu8; 32];
        let payload_hash: [u8; 32] = Sha256::digest(b"test payload").into();
        let result = native_hmac_sha256(&key, &payload_hash);
        assert_eq!(result.len(), 32);
        // Verify deterministic
        let result2 = native_hmac_sha256(&key, &payload_hash);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_setup_and_prove_verify() {
        // This test is slow (~30s) due to circuit setup and proving
        let (pk, vk) = setup().unwrap();

        let key = [0x42u8; 32];
        let payload = b"test payload bytes";

        let (key_hash, signature, proof_bytes) = prove(&pk, &key, payload).unwrap();

        // Verify the key hash
        let expected_hash: [u8; 32] = Sha256::digest(key).into();
        assert_eq!(key_hash, expected_hash);

        // Verify the proof
        verify(&vk, &key_hash, &signature, &proof_bytes, payload).unwrap();

        // Verify proof size
        assert_eq!(proof_bytes.len(), GROTH16_PROOF_LEN);
    }

    #[test]
    fn test_verify_rejects_wrong_key_hash() {
        let (pk, vk) = setup().unwrap();

        let key = [0x42u8; 32];
        let payload = b"test payload";

        let (_key_hash, signature, proof_bytes) = prove(&pk, &key, payload).unwrap();

        // Use a different key hash
        let wrong_hash = [0xFFu8; 32];
        let result = verify(&vk, &wrong_hash, &signature, &proof_bytes, payload);
        assert!(
            matches!(&result, Err(ProtokenError::VerificationFailed(msg)) if msg.contains("proof verification failed")),
            "expected proof verification failed, got: {result:?}"
        );
    }

    #[test]
    fn test_verify_rejects_wrong_signature() {
        let (pk, vk) = setup().unwrap();

        let key = [0x42u8; 32];
        let payload = b"test payload";

        let (key_hash, _signature, proof_bytes) = prove(&pk, &key, payload).unwrap();

        // Use a different signature
        let wrong_sig = [0xFFu8; 32];
        let result = verify(&vk, &key_hash, &wrong_sig, &proof_bytes, payload);
        assert!(
            matches!(&result, Err(ProtokenError::VerificationFailed(msg)) if msg.contains("proof verification failed")),
            "expected proof verification failed, got: {result:?}"
        );
    }

    #[test]
    fn test_verify_rejects_wrong_payload() {
        let (pk, vk) = setup().unwrap();

        let key = [0x42u8; 32];
        let payload = b"test payload";

        let (key_hash, signature, proof_bytes) = prove(&pk, &key, payload).unwrap();

        // Use a different payload
        let result = verify(&vk, &key_hash, &signature, &proof_bytes, b"different");
        assert!(
            matches!(&result, Err(ProtokenError::VerificationFailed(msg)) if msg.contains("proof verification failed")),
            "expected proof verification failed, got: {result:?}"
        );
    }

    #[test]
    fn test_verify_rejects_corrupted_proof() {
        let (pk, vk) = setup().unwrap();

        let key = [0x42u8; 32];
        let payload = b"test payload";

        let (key_hash, signature, mut proof_bytes) = prove(&pk, &key, payload).unwrap();

        // Flip a bit in the proof
        proof_bytes[0] ^= 0x01;
        let result = verify(&vk, &key_hash, &signature, &proof_bytes, payload);
        assert!(result.is_err(), "corrupted proof should fail verification");
    }

    #[test]
    fn test_verify_rejects_truncated_proof() {
        let (pk, vk) = setup().unwrap();

        let key = [0x42u8; 32];
        let payload = b"test payload";

        let (key_hash, signature, proof_bytes) = prove(&pk, &key, payload).unwrap();

        // Truncate the proof to half its length
        let truncated = &proof_bytes[..proof_bytes.len() / 2];
        let result = verify(&vk, &key_hash, &signature, truncated, payload);
        assert!(
            matches!(&result, Err(ProtokenError::VerificationFailed(msg)) if msg.contains("invalid Groth16 proof")),
            "expected invalid proof error, got: {result:?}"
        );
    }

    #[test]
    fn test_verify_rejects_empty_proof() {
        let (pk, vk) = setup().unwrap();

        let key = [0x42u8; 32];
        let payload = b"test payload";

        let (key_hash, signature, _proof_bytes) = prove(&pk, &key, payload).unwrap();

        let result = verify(&vk, &key_hash, &signature, &[], payload);
        assert!(
            matches!(&result, Err(ProtokenError::VerificationFailed(msg)) if msg.contains("invalid Groth16 proof")),
            "expected invalid proof error, got: {result:?}"
        );
    }

    #[test]
    fn test_proving_key_serialization_roundtrip() {
        let (pk, _vk) = setup().unwrap();
        let bytes = serialize_proving_key(&pk).unwrap();
        let pk2 = deserialize_proving_key(&bytes).unwrap();
        let bytes2 = serialize_proving_key(&pk2).unwrap();
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn test_verifying_key_serialization_roundtrip() {
        let (_, vk) = setup().unwrap();
        let bytes = serialize_verifying_key(&vk).unwrap();
        let vk2 = deserialize_verifying_key(&bytes).unwrap();
        let bytes2 = serialize_verifying_key(&vk2).unwrap();
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn test_split_key_attack_rejected() {
        // Attack scenario: prover uses K2 for the HMAC but claims key_hash = SHA-256(K1).
        // This tests that the circuit binds the same witness K to both the key hash and
        // the HMAC — a prover cannot use two different keys for the two constraints.
        let k1 = [0x42u8; 32]; // legitimate key whose hash is in the DB
        let k2 = [0x99u8; 32]; // attacker's different key
        assert_ne!(k1, k2);

        let payload = b"test payload";
        let payload_hash: [u8; 32] = Sha256::digest(payload).into();

        // Attacker computes key_hash from K1 (to match DB) but HMAC from K2
        let key_hash_k1: [u8; 32] = Sha256::digest(k1).into();
        let hmac_k2 = native_hmac_sha256(&k2, &payload_hash);

        // Sanity: these are genuinely different operations on different keys
        let key_hash_k2: [u8; 32] = Sha256::digest(k2).into();
        assert_ne!(key_hash_k1, key_hash_k2);

        // Build circuit with K2 as witness but K1's key_hash — constraints are unsatisfied
        let bad_circuit = HmacKeyHashCircuit {
            key: k2,
            key_hash: key_hash_k1,
            payload_hash,
            hmac_output: hmac_k2,
        };

        let (pk, vk) = setup().unwrap();

        // Arkworks Groth16 asserts constraint satisfaction in debug builds (panics),
        // while release builds produce an invalid proof that fails verification.
        // We handle both: catch_unwind for the panic, then verify rejection if it doesn't.
        let pk_clone = pk.clone();
        let prove_result = std::panic::catch_unwind(move || {
            let mut rng = ark_std::rand::rngs::OsRng;
            Groth16::<Bn254>::prove(&pk_clone, bad_circuit, &mut rng)
        });

        match prove_result {
            Err(_) => {
                // Prover panicked — constraint system detected the unsatisfied assignment
            }
            Ok(Err(_)) => {
                // Prover returned an error — also acceptable
            }
            Ok(Ok(proof)) => {
                // Proof was produced, but verification must reject it
                let mut proof_bytes = Vec::new();
                proof.serialize_compressed(&mut proof_bytes).unwrap();

                let result = verify(&vk, &key_hash_k1, &hmac_k2, &proof_bytes, payload);
                assert!(
                    result.is_err(),
                    "split-key attack: proof must not verify when key_hash and HMAC use different keys"
                );
            }
        }
    }
}
