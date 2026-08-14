//! Token signing and key generation: HMAC-SHA256, Ed25519, and ML-DSA-44.
//!
//! The functions here take raw key material. `keys::SigningKey` wraps them
//! with algorithm dispatch and key serialization.

use ed25519_dalek::Signer as _;
use hmac::{Hmac, KeyInit as _, Mac as _};
use ml_dsa::MlDsa44;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::ProtokenError;
use crate::serialize::{append_signature, serialize_claims, serialize_signing_input};
use crate::types::*;

pub(crate) type HmacSha256 = Hmac<Sha256>;

/// Compute the 8-byte key hash: SHA-256(key_material)[0..8].
///
/// This is a key *identifier*, not a security binding. The 8-byte truncation
/// gives ~2^32 collision resistance at the birthday bound. Security relies on
/// full signature verification, not on the key hash being unique.
#[must_use]
#[allow(clippy::indexing_slicing)] // SHA-256 output is 32 bytes, longer than KEY_HASH_LEN
pub fn compute_key_hash(key_material: &[u8]) -> [u8; KEY_HASH_LEN] {
    let digest = Sha256::digest(key_material);
    let mut truncated = [0u8; KEY_HASH_LEN];
    truncated.copy_from_slice(&digest[..KEY_HASH_LEN]);
    truncated
}

/// Fill `dest` from the operating system's random number generator.
pub fn fill_random(dest: &mut [u8]) -> Result<(), ProtokenError> {
    getrandom::fill(dest).map_err(|e| ProtokenError::RngFailed(e.to_string()))
}

/// Check that an HMAC key meets the minimum length. Shared with verification.
pub(crate) fn check_hmac_key_len(key: &[u8]) -> Result<(), ProtokenError> {
    if key.len() < HMAC_MIN_KEY_LEN {
        return Err(ProtokenError::InvalidKey(format!(
            "HMAC key too short: {} bytes (minimum {HMAC_MIN_KEY_LEN})",
            key.len()
        )));
    }
    Ok(())
}

/// Return an HMAC-SHA256 instance keyed with `key` and updated with `input`.
/// Signing finalizes it; verification compares it against a received tag.
/// Callers check the key length first with `check_hmac_key_len`.
pub(crate) fn hmac_sha256(key: &[u8], input: &[u8]) -> Result<HmacSha256, ProtokenError> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| ProtokenError::InvalidKey(format!("invalid HMAC key: {e}")))?;
    mac.update(input);
    Ok(mac)
}

/// Copy a seed slice into a fixed-size array that is zeroized on drop.
fn seed_array<const N: usize>(seed: &[u8]) -> Result<Zeroizing<[u8; N]>, ProtokenError> {
    if seed.len() != N {
        return Err(ProtokenError::InvalidKeyLength {
            expected: N,
            actual: seed.len(),
        });
    }
    let mut out = Zeroizing::new([0u8; N]);
    out.copy_from_slice(seed);
    Ok(out)
}

/// Both key types zeroize their own copy of the seed on drop.
fn ed25519_signing_key(seed: &[u8]) -> Result<ed25519_dalek::SigningKey, ProtokenError> {
    let seed = seed_array::<ED25519_SEED_LEN>(seed)?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}

fn mldsa44_signing_key(seed: &[u8]) -> Result<ml_dsa::SigningKey<MlDsa44>, ProtokenError> {
    let seed = seed_array::<MLDSA44_SEED_LEN>(seed)?;
    let seed_ref: &ml_dsa::Seed = (&*seed).into();
    Ok(ml_dsa::SigningKey::<MlDsa44>::from_seed(seed_ref))
}

/// Validate the claims, build the signing input for `algorithm` and `key_id`,
/// and append the signature produced by `sign`.
fn sign_claims(
    algorithm: Algorithm,
    key_id: &KeyIdentifier,
    claims: &Claims,
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, ProtokenError>,
) -> Result<Vec<u8>, ProtokenError> {
    claims.validate()?;
    let payload = serialize_claims(claims);
    let signing_input = serialize_signing_input(Version::V0, algorithm, key_id, &payload);
    let signature = sign(&signing_input)?;
    Ok(append_signature(signing_input, &signature))
}

/// Sign a token with HMAC-SHA256, identified by the hash of the key.
/// Returns the serialized SignedToken wire bytes.
///
/// `key` must be at least 32 bytes of cryptographically random material.
pub fn sign_hmac(key: &[u8], claims: &Claims) -> Result<Vec<u8>, ProtokenError> {
    check_hmac_key_len(key)?;
    let key_id = KeyIdentifier::KeyHash(compute_key_hash(key));
    sign_claims(Algorithm::HmacSha256, &key_id, claims, |input| {
        Ok(hmac_sha256(key, input)?.finalize().into_bytes().to_vec())
    })
}

/// Sign a token with Ed25519. Returns the serialized SignedToken wire bytes.
///
/// `seed` is the raw 32-byte Ed25519 private key seed. `key_id` must identify
/// the corresponding public key (its hash or the key itself); verifiers reject
/// tokens whose identifier does not match their key.
pub fn sign_ed25519(
    seed: &[u8],
    claims: &Claims,
    key_id: &KeyIdentifier,
) -> Result<Vec<u8>, ProtokenError> {
    let signing_key = ed25519_signing_key(seed)?;
    sign_claims(Algorithm::Ed25519, key_id, claims, |input| {
        Ok(signing_key.sign(input).to_bytes().to_vec())
    })
}

/// Sign a token with ML-DSA-44 (FIPS 204 deterministic variant, empty
/// context). Returns the serialized SignedToken wire bytes.
///
/// `seed` is the raw 32-byte ML-DSA-44 seed. `key_id` must identify the
/// corresponding public key (its hash or the key itself).
pub fn sign_mldsa44(
    seed: &[u8],
    claims: &Claims,
    key_id: &KeyIdentifier,
) -> Result<Vec<u8>, ProtokenError> {
    let signing_key = mldsa44_signing_key(seed)?;
    sign_claims(Algorithm::MlDsa44, key_id, claims, |input| {
        let sig = signing_key
            .try_sign(input)
            .map_err(|e| ProtokenError::SigningFailed(format!("ML-DSA-44: {e}")))?;
        Ok(sig.encode().to_vec())
    })
}

/// Derive the public key for an asymmetric algorithm from its seed.
/// Returns an error for HMAC, which has no public key.
pub fn derive_public_key(algorithm: Algorithm, seed: &[u8]) -> Result<Vec<u8>, ProtokenError> {
    match algorithm {
        Algorithm::HmacSha256 => Err(ProtokenError::InvalidKey(
            "symmetric algorithm has no public key".into(),
        )),
        Algorithm::Ed25519 => Ok(ed25519_signing_key(seed)?
            .verifying_key()
            .to_bytes()
            .to_vec()),
        Algorithm::MlDsa44 => {
            let signing_key = mldsa44_signing_key(seed)?;
            let verifying_key: &ml_dsa::VerifyingKey<MlDsa44> = signing_key.as_ref();
            Ok(verifying_key.encode().to_vec())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod tests {
    use super::*;
    use crate::keys::SigningKey;
    use crate::serialize::{deserialize_claims, deserialize_signed_token};

    const TEST_HMAC_KEY: &[u8; 32] = &[0xAB; 32];

    /// Fresh (seed, public key) raw material for an asymmetric algorithm.
    pub(crate) fn key_pair(algorithm: Algorithm) -> (Zeroizing<Vec<u8>>, Vec<u8>) {
        let key = SigningKey::generate(algorithm).unwrap();
        (key.secret_key, key.public_key)
    }

    fn claims_expiring(expires_at: u64) -> Claims {
        Claims {
            expires_at,
            ..Default::default()
        }
    }

    fn key_hash_id(public_key: &[u8]) -> KeyIdentifier {
        KeyIdentifier::KeyHash(compute_key_hash(public_key))
    }

    #[test]
    fn test_sign_hmac_produces_valid_token() {
        let token_bytes = sign_hmac(TEST_HMAC_KEY, &claims_expiring(1700000000)).unwrap();
        let token = deserialize_signed_token(&token_bytes).unwrap();
        let decoded = deserialize_claims(&token.payload).unwrap();

        assert_eq!(token.version, Version::V0);
        assert_eq!(token.algorithm, Algorithm::HmacSha256);
        assert_eq!(token.signature.len(), HMAC_SHA256_SIG_LEN);
        assert_eq!(decoded.expires_at, 1700000000);
        assert_eq!(token.key_identifier, key_hash_id(TEST_HMAC_KEY));
    }

    #[test]
    fn test_key_hash_deterministic() {
        assert_eq!(compute_key_hash(b"some-key"), compute_key_hash(b"some-key"));
    }

    #[test]
    fn test_key_hash_different_keys() {
        assert_ne!(compute_key_hash(b"key-a"), compute_key_hash(b"key-b"));
    }

    #[test]
    fn test_key_hash_known_value() {
        // First 8 bytes of SHA-256("").
        assert_eq!(
            compute_key_hash(b""),
            [0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14]
        );
    }

    #[test]
    fn test_sign_ed25519_produces_valid_token() {
        let (seed, pk) = key_pair(Algorithm::Ed25519);
        let token_bytes =
            sign_ed25519(&seed, &claims_expiring(1800000000), &key_hash_id(&pk)).unwrap();
        let token = deserialize_signed_token(&token_bytes).unwrap();
        let decoded = deserialize_claims(&token.payload).unwrap();

        assert_eq!(token.algorithm, Algorithm::Ed25519);
        assert_eq!(token.signature.len(), ED25519_SIG_LEN);
        assert_eq!(decoded.expires_at, 1800000000);
    }

    #[test]
    fn test_ed25519_signing_deterministic() {
        let (seed, pk) = key_pair(Algorithm::Ed25519);
        let key_id = key_hash_id(&pk);
        let claims = Claims {
            expires_at: 1800000000,
            not_before: 1799990000,
            issued_at: 1799990000,
            subject: "test".into(),
            ..Default::default()
        };

        let t1 = sign_ed25519(&seed, &claims, &key_id).unwrap();
        let t2 = sign_ed25519(&seed, &claims, &key_id).unwrap();
        assert_eq!(t1, t2);
    }

    #[test]
    fn test_sign_hmac_rejects_short_key() {
        let err = sign_hmac(b"too-short", &claims_expiring(1700000000)).unwrap_err();
        assert!(matches!(err, ProtokenError::InvalidKey(_)), "got {err:?}");
    }

    #[test]
    fn test_sign_rejects_zero_expires_at() {
        assert!(sign_hmac(TEST_HMAC_KEY, &claims_expiring(0)).is_err());
    }

    #[test]
    fn test_sign_rejects_not_before_after_expires_at() {
        let claims = Claims {
            expires_at: 1000,
            not_before: 2000,
            ..Default::default()
        };
        assert!(sign_hmac(TEST_HMAC_KEY, &claims).is_err());
    }

    #[test]
    fn test_sign_hmac_with_claims() {
        let claims = Claims {
            expires_at: 1700000000,
            not_before: 1699990000,
            issued_at: 1699990000,
            ..Default::default()
        };

        let token_bytes = sign_hmac(TEST_HMAC_KEY, &claims).unwrap();
        let token = deserialize_signed_token(&token_bytes).unwrap();
        assert_eq!(deserialize_claims(&token.payload).unwrap(), claims);
    }

    #[test]
    fn test_sign_ed25519_with_claims() {
        let (seed, pk) = key_pair(Algorithm::Ed25519);
        let claims = Claims {
            expires_at: 1800000000,
            subject: "user:alice".into(),
            audience: "api.example.com".into(),
            ..Default::default()
        };

        let token_bytes = sign_ed25519(&seed, &claims, &key_hash_id(&pk)).unwrap();
        let token = deserialize_signed_token(&token_bytes).unwrap();
        assert_eq!(token.version, Version::V0);
        assert_eq!(token.algorithm, Algorithm::Ed25519);
        assert_eq!(deserialize_claims(&token.payload).unwrap(), claims);
    }

    #[test]
    fn test_sign_ed25519_rejects_bad_seed_length() {
        let key_id = KeyIdentifier::KeyHash([0; 8]);
        let err = sign_ed25519(&[0; 16], &claims_expiring(1800000000), &key_id).unwrap_err();
        assert!(matches!(
            err,
            ProtokenError::InvalidKeyLength {
                expected: ED25519_SEED_LEN,
                actual: 16
            }
        ));
    }

    #[test]
    fn test_sign_mldsa44_produces_valid_token() {
        let (seed, pk) = key_pair(Algorithm::MlDsa44);
        let token_bytes =
            sign_mldsa44(&seed, &claims_expiring(1900000000), &key_hash_id(&pk)).unwrap();
        let token = deserialize_signed_token(&token_bytes).unwrap();
        let decoded = deserialize_claims(&token.payload).unwrap();

        assert_eq!(token.algorithm, Algorithm::MlDsa44);
        assert_eq!(token.signature.len(), MLDSA44_SIG_LEN);
        assert_eq!(decoded.expires_at, 1900000000);
    }

    #[test]
    fn test_sign_mldsa44_with_claims() {
        let (seed, pk) = key_pair(Algorithm::MlDsa44);
        let claims = Claims {
            expires_at: 1900000000,
            subject: "pq-user".into(),
            audience: "pq-api.example.com".into(),
            scopes: vec!["admin".into(), "read".into()],
            ..Default::default()
        };

        let token_bytes = sign_mldsa44(&seed, &claims, &key_hash_id(&pk)).unwrap();
        let token = deserialize_signed_token(&token_bytes).unwrap();
        assert_eq!(token.version, Version::V0);
        assert_eq!(token.algorithm, Algorithm::MlDsa44);
        assert_eq!(deserialize_claims(&token.payload).unwrap(), claims);
    }

    #[test]
    fn test_sign_mldsa44_deterministic() {
        let (seed, pk) = key_pair(Algorithm::MlDsa44);
        let key_id = key_hash_id(&pk);
        let claims = claims_expiring(1900000000);
        assert_eq!(
            sign_mldsa44(&seed, &claims, &key_id).unwrap(),
            sign_mldsa44(&seed, &claims, &key_id).unwrap()
        );
    }

    #[test]
    fn test_sign_mldsa44_rejects_bad_seed_length() {
        let key_id = KeyIdentifier::KeyHash([0; 8]);
        let err = sign_mldsa44(&[0; 100], &claims_expiring(1900000000), &key_id).unwrap_err();
        assert!(matches!(
            err,
            ProtokenError::InvalidKeyLength {
                expected: MLDSA44_SEED_LEN,
                actual: 100
            }
        ));
    }

    #[test]
    fn test_derive_public_key_known_ed25519_vector() {
        // RFC 8032 section 7.1, test 1.
        let seed = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap();
        let expected =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap();
        assert_eq!(
            derive_public_key(Algorithm::Ed25519, &seed).unwrap(),
            expected
        );
    }

    #[test]
    fn test_derive_public_key_rejects_hmac_and_bad_lengths() {
        assert!(matches!(
            derive_public_key(Algorithm::HmacSha256, &[0; 32]),
            Err(ProtokenError::InvalidKey(_))
        ));
        assert!(matches!(
            derive_public_key(Algorithm::Ed25519, &[0; 31]),
            Err(ProtokenError::InvalidKeyLength { .. })
        ));
        assert!(matches!(
            derive_public_key(Algorithm::MlDsa44, &[0; 33]),
            Err(ProtokenError::InvalidKeyLength { .. })
        ));
    }

    #[test]
    fn test_sign_rejects_overlong_subject() {
        let claims = Claims {
            expires_at: 1700000000,
            subject: "x".repeat(MAX_CLAIM_BYTES_LEN + 1),
            ..Default::default()
        };
        assert!(sign_hmac(TEST_HMAC_KEY, &claims).is_err());
    }

    #[test]
    fn test_sign_rejects_overlong_audience() {
        let claims = Claims {
            expires_at: 1700000000,
            audience: "x".repeat(MAX_CLAIM_BYTES_LEN + 1),
            ..Default::default()
        };
        assert!(sign_hmac(TEST_HMAC_KEY, &claims).is_err());
    }

    #[test]
    fn test_sign_rejects_too_many_scopes() {
        let claims = Claims {
            expires_at: 1700000000,
            scopes: (0..=MAX_SCOPES).map(|i| format!("s{i:03}")).collect(),
            ..Default::default()
        };
        assert!(sign_hmac(TEST_HMAC_KEY, &claims).is_err());
    }

    #[test]
    fn test_sign_rejects_overlong_scope_entry() {
        let claims = Claims {
            expires_at: 1700000000,
            scopes: vec!["x".repeat(MAX_CLAIM_BYTES_LEN + 1)],
            ..Default::default()
        };
        assert!(sign_hmac(TEST_HMAC_KEY, &claims).is_err());
    }

    #[test]
    fn test_sign_rejects_duplicate_scopes() {
        let claims = Claims {
            expires_at: 1700000000,
            scopes: vec!["read".into(), "read".into()],
            ..Default::default()
        };
        assert!(sign_hmac(TEST_HMAC_KEY, &claims).is_err());
    }

    #[test]
    fn test_sign_accepts_max_length_claims() {
        let claims = Claims {
            expires_at: 1700000000,
            subject: "s".repeat(MAX_CLAIM_BYTES_LEN),
            audience: "a".repeat(MAX_CLAIM_BYTES_LEN),
            scopes: vec!["x".repeat(MAX_CLAIM_BYTES_LEN)],
            ..Default::default()
        };
        assert!(sign_hmac(TEST_HMAC_KEY, &claims).is_ok());
    }

    #[test]
    fn test_sign_accepts_max_scopes() {
        let claims = Claims {
            expires_at: 1700000000,
            scopes: (0..MAX_SCOPES).map(|i| format!("s{i:03}")).collect(),
            ..Default::default()
        };
        assert!(sign_hmac(TEST_HMAC_KEY, &claims).is_ok());
    }

    #[test]
    fn test_sign_accepts_not_before_equal_expires_at() {
        let claims = Claims {
            expires_at: 5000,
            not_before: 5000,
            ..Default::default()
        };
        assert!(sign_hmac(TEST_HMAC_KEY, &claims).is_ok());
    }
}
