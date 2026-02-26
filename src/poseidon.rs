//! Poseidon hash configuration and native helpers for BN254.
//!
//! Provides:
//! - Standard Poseidon parameters (t=3, rate=2, alpha=5, 8 full + 57 partial rounds)
//! - Native hash: `poseidon_hash(&[Fr]) -> Fr`
//! - Byte-to-field conversion: `bytes_to_fr(&[u8]) -> Fr`
//! - Field-to-bytes conversion: `fr_to_bytes(Fr) -> [u8; 32]`

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::traits::find_poseidon_ark_and_mds;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use ark_ff::PrimeField;

/// Standard Poseidon parameters for BN254 scalar field.
///
/// t=3 (rate=2, capacity=1), alpha=5, 8 full rounds + 57 partial rounds.
/// Parameters are deterministically derived from the Grain LFSR (Poseidon paper).
/// This matches the standard configuration used by Tornado Cash, circomlib, and
/// most Ethereum ZK projects.
pub fn poseidon_config() -> PoseidonConfig<Fr> {
    let rate = 2;
    let full_rounds: usize = 8;
    let partial_rounds: usize = 57;
    let alpha: u64 = 5;
    let skip_matrices: u64 = 0;

    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
        Fr::MODULUS_BIT_SIZE as u64,
        rate,
        full_rounds as u64,
        partial_rounds as u64,
        skip_matrices,
    );

    PoseidonConfig::new(full_rounds, partial_rounds, alpha, mds, ark, rate, 1)
}

/// Compute Poseidon hash of field elements natively (outside a circuit).
#[allow(clippy::expect_used)] // squeeze(1) always returns exactly 1 element
pub fn poseidon_hash(config: &PoseidonConfig<Fr>, inputs: &[Fr]) -> Fr {
    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    let mut sponge = PoseidonSponge::<Fr>::new(config);
    sponge.absorb(&inputs.to_vec());
    let result = sponge.squeeze_native_field_elements(1);
    result.into_iter().next().expect("squeeze returned empty")
}

/// Convert a byte slice to a BN254 scalar field element (little-endian, mod order).
///
/// Since BN254 scalar field is ~2^254, a 32-byte value (256 bits) may wrap.
/// This is standard practice in ZK applications and negligibly affects collision resistance.
pub fn bytes_to_fr(bytes: &[u8]) -> Fr {
    Fr::from_le_bytes_mod_order(bytes)
}

/// Serialize a BN254 scalar field element to 32 bytes (little-endian).
#[allow(clippy::expect_used)] // BN254 Fr bigint is always exactly 32 bytes
pub fn fr_to_bytes(elem: &Fr) -> [u8; 32] {
    use ark_ff::BigInteger;
    let bigint = elem.into_bigint();
    let le_bytes = bigint.to_bytes_le();
    let mut out = [0u8; 32];
    // BN254 Fr bigint is always exactly 32 bytes in little-endian
    let len = le_bytes.len().min(out.len());
    out.get_mut(..len)
        .expect("len <= 32")
        .copy_from_slice(le_bytes.get(..len).expect("len <= le_bytes.len()"));
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_config_consistent() {
        let c1 = poseidon_config();
        let c2 = poseidon_config();
        assert_eq!(c1.full_rounds, c2.full_rounds);
        assert_eq!(c1.partial_rounds, c2.partial_rounds);
        assert_eq!(c1.alpha, c2.alpha);
        assert_eq!(c1.rate, c2.rate);
        assert_eq!(c1.capacity, c2.capacity);
        assert_eq!(c1.ark, c2.ark);
        assert_eq!(c1.mds, c2.mds);
    }

    #[test]
    fn test_poseidon_hash_deterministic() {
        let config = poseidon_config();
        let input = vec![Fr::from(42u64)];
        let h1 = poseidon_hash(&config, &input);
        let h2 = poseidon_hash(&config, &input);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_poseidon_hash_different_inputs() {
        let config = poseidon_config();
        let h1 = poseidon_hash(&config, &[Fr::from(1u64)]);
        let h2 = poseidon_hash(&config, &[Fr::from(2u64)]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_poseidon_hash_two_inputs() {
        let config = poseidon_config();
        let h = poseidon_hash(&config, &[Fr::from(1u64), Fr::from(2u64)]);
        assert_ne!(h, Fr::from(0u64));
    }

    #[test]
    fn test_bytes_fr_roundtrip() {
        let original = [0x42u8; 32];
        let fr = bytes_to_fr(&original);
        let back = fr_to_bytes(&fr);
        // Not necessarily identical due to mod reduction, but re-converting should be stable
        let fr2 = bytes_to_fr(&back);
        assert_eq!(fr, fr2);
    }

    #[test]
    fn test_fr_to_bytes_deterministic() {
        let fr = Fr::from(123456789u64);
        let b1 = fr_to_bytes(&fr);
        let b2 = fr_to_bytes(&fr);
        assert_eq!(b1, b2);
    }
}
