//! Groth16 SNARK for symmetric key proofs using Poseidon hash.
//!
//! Proves knowledge of a symmetric key K such that:
//! 1. Poseidon(K) = key_hash (binds the proof to the key identifier)
//! 2. Poseidon(K, SHA-256(payload)) = mac (binds the key to the token)
//!
//! The verifier needs only the key_hash (from the token's key_identifier field),
//! the mac, and the payload bytes — no symmetric key required.
//!
//! Hybrid approach: Poseidon inside the circuit (~480 constraints), SHA-256 outside
//! for payload hashing. This gives ~300x speedup over the pure SHA-256 circuit.

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_groth16::Groth16;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;

use crate::error::ProtokenError;
use crate::poseidon;
use crate::types::GROTH16_PROOF_LEN;

/// Groth16 proving key (circuit-specific, generated during trusted setup).
pub type SnarkProvingKey = ark_groth16::ProvingKey<Bn254>;

/// Groth16 verifying key (circuit-specific, generated during trusted setup).
pub type SnarkVerifyingKey = ark_groth16::VerifyingKey<Bn254>;

/// Compressed Groth16 proof.
pub type SnarkProof = ark_groth16::Proof<Bn254>;

/// Poseidon key proof circuit.
///
/// Public inputs (3 field elements):
///   - key_hash: Poseidon(K)
///   - payload_hash: Fr::from_le_bytes_mod_order(SHA-256(payload_bytes))
///   - mac: Poseidon(K, payload_hash)
///
/// Private witness:
///   - key: K (1 field element)
#[derive(Clone)]
struct PoseidonKeyProofCircuit {
    config: PoseidonConfig<Fr>,
    key: Fr,
    key_hash: Fr,
    payload_hash: Fr,
    mac: Fr,
}

impl PoseidonKeyProofCircuit {
    fn new_default(config: PoseidonConfig<Fr>) -> Self {
        Self {
            config,
            key: Fr::from(0u64),
            key_hash: Fr::from(0u64),
            payload_hash: Fr::from(0u64),
            mac: Fr::from(0u64),
        }
    }
}

impl ConstraintSynthesizer<Fr> for PoseidonKeyProofCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate public inputs
        let key_hash_var = FpVar::<Fr>::new_input(cs.clone(), || Ok(self.key_hash))?;
        let payload_hash_var = FpVar::<Fr>::new_input(cs.clone(), || Ok(self.payload_hash))?;
        let mac_var = FpVar::<Fr>::new_input(cs.clone(), || Ok(self.mac))?;

        // Allocate private witness
        let key_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(self.key))?;

        // Constraint 1: Poseidon(K) = key_hash
        let mut sponge1 = PoseidonSpongeVar::<Fr>::new(cs.clone(), &self.config);
        sponge1.absorb(&key_var)?;
        let computed_key_hash = sponge1.squeeze_field_elements(1)?;
        // squeeze_field_elements(1) always returns exactly 1 element
        let computed_key_hash = computed_key_hash
            .into_iter()
            .next()
            .ok_or(SynthesisError::Unsatisfiable)?;
        computed_key_hash.enforce_equal(&key_hash_var)?;

        // Constraint 2: Poseidon(K, payload_hash) = mac
        let mut sponge2 = PoseidonSpongeVar::<Fr>::new(cs, &self.config);
        sponge2.absorb(&key_var)?;
        sponge2.absorb(&payload_hash_var)?;
        let computed_mac = sponge2.squeeze_field_elements(1)?;
        let computed_mac = computed_mac
            .into_iter()
            .next()
            .ok_or(SynthesisError::Unsatisfiable)?;
        computed_mac.enforce_equal(&mac_var)?;

        Ok(())
    }
}

/// Generate the Groth16 proving and verifying keys (trusted setup).
///
/// This must be run once per deployment. With Poseidon (~480 constraints),
/// setup is fast (seconds) and the proving key is small (~100s of KB).
pub fn setup() -> Result<(SnarkProvingKey, SnarkVerifyingKey), ProtokenError> {
    let config = poseidon::poseidon_config();
    let circuit = PoseidonKeyProofCircuit::new_default(config);
    let mut rng = ark_std::rand::rngs::OsRng;
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)
        .map_err(|e| ProtokenError::SigningFailed(format!("Groth16 setup failed: {e}")))?;
    Ok((pk, vk))
}

/// Result of a Groth16 proof generation: (key_hash, mac, proof_bytes).
pub type ProveResult = ([u8; 32], [u8; 32], Vec<u8>);

/// Generate a Groth16 proof for a symmetric key token.
///
/// Inputs:
///   - `pk`: the Groth16 proving key (from `setup()`)
///   - `key`: the 32-byte symmetric key
///   - `payload_bytes`: the canonical-encoded payload bytes
///
/// Returns (key_hash_bytes, mac_bytes, proof_bytes):
///   - `key_hash_bytes`: Poseidon(K) serialized — 32 bytes, used as FullKeyHash key_identifier
///   - `mac_bytes`: Poseidon(K, SHA-256(payload) as Fr) — 32 bytes, stored as signature
///   - `proof_bytes`: compressed Groth16 proof — 128 bytes
pub fn prove(
    pk: &SnarkProvingKey,
    key: &[u8; 32],
    payload_bytes: &[u8],
) -> Result<ProveResult, ProtokenError> {
    use sha2::{Digest, Sha256};

    let config = poseidon::poseidon_config();

    // Convert key to field element
    let key_fr = poseidon::bytes_to_fr(key);

    // Compute native values
    let key_hash = poseidon::poseidon_hash(&config, &[key_fr]);
    let payload_sha256: [u8; 32] = Sha256::digest(payload_bytes).into();
    let payload_hash_fr = poseidon::bytes_to_fr(&payload_sha256);
    let mac = poseidon::poseidon_hash(&config, &[key_fr, payload_hash_fr]);

    // Build circuit with actual values
    let circuit = PoseidonKeyProofCircuit {
        config,
        key: key_fr,
        key_hash,
        payload_hash: payload_hash_fr,
        mac,
    };

    let mut rng = ark_std::rand::rngs::OsRng;
    let proof = Groth16::<Bn254>::prove(pk, circuit, &mut rng)
        .map_err(|e| ProtokenError::SigningFailed(format!("Groth16 proving failed: {e}")))?;

    // Serialize
    let key_hash_bytes = poseidon::fr_to_bytes(&key_hash);
    let mac_bytes = poseidon::fr_to_bytes(&mac);

    let mut proof_bytes = Vec::with_capacity(GROTH16_PROOF_LEN);
    proof
        .serialize_compressed(&mut proof_bytes)
        .map_err(|e| ProtokenError::SigningFailed(format!("proof serialization failed: {e}")))?;

    Ok((key_hash_bytes, mac_bytes, proof_bytes))
}

/// Verify a Groth16 proof for a symmetric key token.
///
/// Inputs:
///   - `vk`: the Groth16 verifying key (from `setup()`)
///   - `key_hash_bytes`: the 32-byte Poseidon key hash from the token's key_identifier
///   - `mac_bytes`: the 32-byte Poseidon MAC from the token's signature
///   - `proof_bytes`: the compressed Groth16 proof (128 bytes)
///   - `payload_bytes`: the canonical-encoded payload bytes
pub fn verify(
    vk: &SnarkVerifyingKey,
    key_hash_bytes: &[u8; 32],
    mac_bytes: &[u8; 32],
    proof_bytes: &[u8],
    payload_bytes: &[u8],
) -> Result<(), ProtokenError> {
    use sha2::{Digest, Sha256};

    // Deserialize the proof
    let proof = SnarkProof::deserialize_compressed(proof_bytes)
        .map_err(|e| ProtokenError::VerificationFailed(format!("invalid Groth16 proof: {e}")))?;

    // Reconstruct public inputs as field elements
    let key_hash_fr = poseidon::bytes_to_fr(key_hash_bytes);
    let payload_sha256: [u8; 32] = Sha256::digest(payload_bytes).into();
    let payload_hash_fr = poseidon::bytes_to_fr(&payload_sha256);
    let mac_fr = poseidon::bytes_to_fr(mac_bytes);

    // Public inputs: [key_hash, payload_hash, mac]
    let public_inputs = vec![key_hash_fr, payload_hash_fr, mac_fr];

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

    #[test]
    fn test_setup_and_prove_verify() {
        let (pk, vk) = setup().unwrap();

        let key = [0x42u8; 32];
        let payload = b"test payload bytes";

        let (key_hash, mac, proof_bytes) = prove(&pk, &key, payload).unwrap();

        // Verify the key hash matches native computation
        let config = poseidon::poseidon_config();
        let key_fr = poseidon::bytes_to_fr(&key);
        let expected_hash = poseidon::poseidon_hash(&config, &[key_fr]);
        assert_eq!(key_hash, poseidon::fr_to_bytes(&expected_hash));

        // Verify the proof
        verify(&vk, &key_hash, &mac, &proof_bytes, payload).unwrap();

        // Verify proof size
        assert_eq!(proof_bytes.len(), GROTH16_PROOF_LEN);
    }

    #[test]
    fn test_verify_rejects_wrong_key_hash() {
        let (pk, vk) = setup().unwrap();

        let key = [0x42u8; 32];
        let payload = b"test payload";

        let (_key_hash, mac, proof_bytes) = prove(&pk, &key, payload).unwrap();

        let wrong_hash = [0xFFu8; 32];
        let result = verify(&vk, &wrong_hash, &mac, &proof_bytes, payload);
        assert!(
            matches!(&result, Err(ProtokenError::VerificationFailed(msg)) if msg.contains("proof verification failed")),
            "expected proof verification failed, got: {result:?}"
        );
    }

    #[test]
    fn test_verify_rejects_wrong_mac() {
        let (pk, vk) = setup().unwrap();

        let key = [0x42u8; 32];
        let payload = b"test payload";

        let (key_hash, _mac, proof_bytes) = prove(&pk, &key, payload).unwrap();

        let wrong_mac = [0xFFu8; 32];
        let result = verify(&vk, &key_hash, &wrong_mac, &proof_bytes, payload);
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

        let (key_hash, mac, proof_bytes) = prove(&pk, &key, payload).unwrap();

        let result = verify(&vk, &key_hash, &mac, &proof_bytes, b"different");
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

        let (key_hash, mac, mut proof_bytes) = prove(&pk, &key, payload).unwrap();

        proof_bytes[0] ^= 0x01;
        let result = verify(&vk, &key_hash, &mac, &proof_bytes, payload);
        assert!(result.is_err(), "corrupted proof should fail verification");
    }

    #[test]
    fn test_verify_rejects_truncated_proof() {
        let (pk, vk) = setup().unwrap();

        let key = [0x42u8; 32];
        let payload = b"test payload";

        let (key_hash, mac, proof_bytes) = prove(&pk, &key, payload).unwrap();

        let truncated = &proof_bytes[..proof_bytes.len() / 2];
        let result = verify(&vk, &key_hash, &mac, truncated, payload);
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

        let (key_hash, mac, _proof_bytes) = prove(&pk, &key, payload).unwrap();

        let result = verify(&vk, &key_hash, &mac, &[], payload);
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
        // Attack: prover uses K2 for the MAC but claims key_hash = Poseidon(K1).
        // The circuit binds the same witness K to both constraints.
        let k1 = [0x42u8; 32];
        let k2 = [0x99u8; 32];
        assert_ne!(k1, k2);

        let config = poseidon::poseidon_config();
        let payload = b"test payload";

        use sha2::{Digest, Sha256};
        let payload_sha256: [u8; 32] = Sha256::digest(payload).into();
        let payload_hash_fr = poseidon::bytes_to_fr(&payload_sha256);

        // Attacker computes key_hash from K1 but MAC from K2
        let k1_fr = poseidon::bytes_to_fr(&k1);
        let k2_fr = poseidon::bytes_to_fr(&k2);
        let key_hash_k1 = poseidon::poseidon_hash(&config, &[k1_fr]);
        let mac_k2 = poseidon::poseidon_hash(&config, &[k2_fr, payload_hash_fr]);

        // Sanity: these use different keys
        let key_hash_k2 = poseidon::poseidon_hash(&config, &[k2_fr]);
        assert_ne!(key_hash_k1, key_hash_k2);

        // Build circuit with K2 as witness but K1's key_hash — constraints unsatisfied
        let bad_circuit = PoseidonKeyProofCircuit {
            config: config.clone(),
            key: k2_fr,
            key_hash: key_hash_k1,
            payload_hash: payload_hash_fr,
            mac: mac_k2,
        };

        let (pk, vk) = setup().unwrap();

        // Arkworks Groth16 panics on unsatisfied constraints in debug builds,
        // or produces an invalid proof in release builds.
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

                let key_hash_bytes = poseidon::fr_to_bytes(&key_hash_k1);
                let mac_bytes = poseidon::fr_to_bytes(&mac_k2);
                let result = verify(&vk, &key_hash_bytes, &mac_bytes, &proof_bytes, payload);
                assert!(
                    result.is_err(),
                    "split-key attack: proof must not verify when key_hash and MAC use different keys"
                );
            }
        }
    }
}
