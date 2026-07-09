//! Token signing: HMAC-SHA256, Ed25519, and ML-DSA-44.

use ed25519_dalek::Signer as _;
use hmac::{Hmac, Mac};
use ml_dsa::signature::Signer as _;
use ml_dsa::MlDsa44;
use rand::rngs::OsRng;
use rand::RngCore as _;
use sha2::{Digest, Sha256};

use crate::error::ProtokenError;
use crate::serialize::{append_signature, serialize_claims, serialize_signing_input};
use crate::types::*;

/// Compute the 8-byte key hash: SHA-256(key_material)[0..8].
///
/// This is a key *identifier*, not a security binding. The 8-byte truncation
/// gives ~2^32 collision resistance at the birthday bound. Security relies on
/// full signature verification, not on the key hash being unique.
#[must_use]
#[allow(clippy::indexing_slicing)] // SHA-256 always produces 32 bytes >= KEY_HASH_LEN
pub fn compute_key_hash(key_material: &[u8]) -> [u8; KEY_HASH_LEN] {
    let hash = Sha256::digest(key_material);
    let mut truncated = [0u8; KEY_HASH_LEN];
    truncated.copy_from_slice(&hash[..KEY_HASH_LEN]);
    truncated
}

/// Convert a slice to a fixed-size seed array with a descriptive error.
fn to_seed<const N: usize>(seed: &[u8], what: &str) -> Result<[u8; N], ProtokenError> {
    seed.try_into().map_err(|_| {
        ProtokenError::SigningFailed(format!(
            "invalid {what}: expected {N} bytes, got {}",
            seed.len()
        ))
    })
}

/// Sign a token with HMAC-SHA256.
/// Returns the serialized SignedToken wire bytes.
///
/// For HMAC-SHA256, use at least 32 bytes of cryptographically random key material.
pub fn sign_hmac(key: &[u8], claims: &Claims) -> Result<Vec<u8>, ProtokenError> {
    if key.len() < HMAC_MIN_KEY_LEN {
        return Err(ProtokenError::SigningFailed(format!(
            "HMAC key too short: {} bytes (minimum {})",
            key.len(),
            HMAC_MIN_KEY_LEN
        )));
    }
    claims.validate()?;
    let key_id = KeyIdentifier::KeyHash(compute_key_hash(key));
    let payload = serialize_claims(claims);
    let signing_input =
        serialize_signing_input(Version::V0, Algorithm::HmacSha256, &key_id, &payload);

    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|e| ProtokenError::SigningFailed(format!("invalid HMAC key: {e}")))?;
    mac.update(&signing_input);
    let tag = mac.finalize().into_bytes();

    Ok(append_signature(signing_input, &tag))
}

/// Sign a token with Ed25519.
/// Returns the serialized SignedToken wire bytes.
///
/// `seed` is the raw 32-byte Ed25519 private key seed.
/// `key_id` must identify the corresponding public key (its hash or the key itself).
pub fn sign_ed25519(
    seed: &[u8],
    claims: &Claims,
    key_id: KeyIdentifier,
) -> Result<Vec<u8>, ProtokenError> {
    claims.validate()?;
    let seed_array = to_seed::<ED25519_SEED_LEN>(seed, "Ed25519 seed")?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed_array);

    let payload = serialize_claims(claims);
    let signing_input = serialize_signing_input(Version::V0, Algorithm::Ed25519, &key_id, &payload);
    let sig = signing_key.sign(&signing_input);

    Ok(append_signature(signing_input, &sig.to_bytes()))
}

/// Sign a token with ML-DSA-44 (deterministic variant, empty context).
/// Returns the serialized SignedToken wire bytes.
///
/// `seed` is the raw 32-byte ML-DSA-44 private key seed.
/// `key_id` must identify the corresponding public key (its hash or the key itself).
pub fn sign_mldsa44(
    seed: &[u8],
    claims: &Claims,
    key_id: KeyIdentifier,
) -> Result<Vec<u8>, ProtokenError> {
    claims.validate()?;
    let seed_array = to_seed::<MLDSA44_SEED_LEN>(seed, "ML-DSA-44 seed")?;
    let signing_key = ml_dsa::SigningKey::<MlDsa44>::from_seed(&seed_array.into());

    let payload = serialize_claims(claims);
    let signing_input = serialize_signing_input(Version::V0, Algorithm::MlDsa44, &key_id, &payload);
    let sig = signing_key
        .try_sign(&signing_input)
        .map_err(|e| ProtokenError::SigningFailed(format!("ML-DSA-44 signing failed: {e}")))?;

    Ok(append_signature(signing_input, &sig.encode()))
}

/// Generate a new Ed25519 key pair, returning (seed, public_key) as raw bytes.
pub fn generate_ed25519_key() -> (Vec<u8>, Vec<u8>) {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let seed = signing_key.to_bytes().to_vec();
    let pk = signing_key.verifying_key().to_bytes().to_vec();
    (seed, pk)
}

/// Generate a new ML-DSA-44 key pair, returning (seed, public_key_bytes).
pub fn generate_mldsa44_key() -> (Vec<u8>, Vec<u8>) {
    let mut seed = [0u8; MLDSA44_SEED_LEN];
    OsRng.fill_bytes(&mut seed);
    let signing_key = ml_dsa::SigningKey::<MlDsa44>::from_seed(&seed.into());
    let pk_bytes = signing_key.expanded_key().verifying_key().encode().to_vec();
    (seed.to_vec(), pk_bytes)
}

/// Generate a new HMAC key (32 bytes of cryptographically random data).
pub fn generate_hmac_key() -> Vec<u8> {
    let mut key = vec![0u8; HMAC_MIN_KEY_LEN];
    OsRng.fill_bytes(&mut key);
    key
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::serialize::{deserialize_claims, deserialize_signed_token};

    const TEST_HMAC_KEY: &[u8; 32] = &[0xAB; 32];

    #[test]
    fn test_sign_hmac_produces_valid_token() {
        let key: &[u8] = TEST_HMAC_KEY;
        let claims = Claims {
            expires_at: 1700000000,
            ..Default::default()
        };

        let token_bytes = sign_hmac(key, &claims).unwrap();
        let token = deserialize_signed_token(&token_bytes).unwrap();
        let decoded = deserialize_claims(&token.payload).unwrap();

        assert_eq!(token.version, Version::V0);
        assert_eq!(token.algorithm, Algorithm::HmacSha256);
        assert_eq!(decoded.expires_at, 1700000000);

        let expected_hash = compute_key_hash(key);
        assert_eq!(token.key_identifier, KeyIdentifier::KeyHash(expected_hash));
    }

    #[test]
    fn test_key_hash_deterministic() {
        let key = b"some-key";
        let h1 = compute_key_hash(key);
        let h2 = compute_key_hash(key);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_key_hash_different_keys() {
        let h1 = compute_key_hash(b"key-a");
        let h2 = compute_key_hash(b"key-b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_key_hash_known_value() {
        // SHA-256("") = e3b0c44298fc1c14... — first 8 bytes.
        let hash = compute_key_hash(b"");
        assert_eq!(hash, [0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14]);
    }

    #[test]
    fn test_sign_ed25519_produces_valid_token() {
        let (seed, pk) = generate_ed25519_key();
        let key_id = KeyIdentifier::KeyHash(compute_key_hash(&pk));
        let claims = Claims {
            expires_at: 1800000000,
            ..Default::default()
        };

        let token_bytes = sign_ed25519(&seed, &claims, key_id).unwrap();
        let token = deserialize_signed_token(&token_bytes).unwrap();
        let decoded = deserialize_claims(&token.payload).unwrap();

        assert_eq!(token.algorithm, Algorithm::Ed25519);
        assert_eq!(decoded.expires_at, 1800000000);
    }

    #[test]
    fn test_ed25519_signing_deterministic() {
        let (seed, pk) = generate_ed25519_key();
        let key_id = KeyIdentifier::KeyHash(compute_key_hash(&pk));
        let claims = Claims {
            expires_at: 1800000000,
            not_before: 1799990000,
            issued_at: 1799990000,
            subject: "test".into(),
            ..Default::default()
        };

        let t1 = sign_ed25519(&seed, &claims, key_id.clone()).unwrap();
        let t2 = sign_ed25519(&seed, &claims, key_id).unwrap();
        assert_eq!(t1, t2);
    }

    #[test]
    fn test_sign_hmac_rejects_short_key() {
        let short_key = b"too-short";
        let claims = Claims {
            expires_at: 1700000000,
            ..Default::default()
        };
        assert!(sign_hmac(short_key, &claims).is_err());
    }

    #[test]
    fn test_sign_rejects_zero_expires_at() {
        let key: &[u8] = TEST_HMAC_KEY;
        let claims = Claims {
            expires_at: 0,
            ..Default::default()
        };
        assert!(sign_hmac(key, &claims).is_err());
    }

    #[test]
    fn test_sign_rejects_not_before_after_expires_at() {
        let key: &[u8] = TEST_HMAC_KEY;
        let claims = Claims {
            expires_at: 1000,
            not_before: 2000,
            ..Default::default()
        };
        assert!(sign_hmac(key, &claims).is_err());
    }

    #[test]
    fn test_sign_hmac_with_claims() {
        let key: &[u8] = TEST_HMAC_KEY;
        let claims = Claims {
            expires_at: 1700000000,
            not_before: 1699990000,
            issued_at: 1699990000,
            ..Default::default()
        };

        let token_bytes = sign_hmac(key, &claims).unwrap();
        let token = deserialize_signed_token(&token_bytes).unwrap();
        let decoded = deserialize_claims(&token.payload).unwrap();

        assert_eq!(token.version, Version::V0);
        assert_eq!(token.algorithm, Algorithm::HmacSha256);
        assert_eq!(decoded, claims);
    }

    #[test]
    fn test_sign_ed25519_with_claims() {
        let (seed, pk) = generate_ed25519_key();
        let key_id = KeyIdentifier::KeyHash(compute_key_hash(&pk));
        let claims = Claims {
            expires_at: 1800000000,
            subject: "user:alice".into(),
            audience: "api.example.com".into(),
            ..Default::default()
        };

        let token_bytes = sign_ed25519(&seed, &claims, key_id).unwrap();
        let token = deserialize_signed_token(&token_bytes).unwrap();
        let decoded = deserialize_claims(&token.payload).unwrap();

        assert_eq!(token.version, Version::V0);
        assert_eq!(token.algorithm, Algorithm::Ed25519);
        assert_eq!(decoded, claims);
    }

    #[test]
    fn test_sign_ed25519_rejects_bad_seed_length() {
        let claims = Claims {
            expires_at: 1800000000,
            ..Default::default()
        };
        let key_id = KeyIdentifier::KeyHash([0; 8]);
        assert!(sign_ed25519(&[0; 16], &claims, key_id).is_err());
    }

    #[test]
    fn test_sign_mldsa44_produces_valid_token() {
        let (sk, pk) = generate_mldsa44_key();
        let key_id = KeyIdentifier::KeyHash(compute_key_hash(&pk));
        let claims = Claims {
            expires_at: 1900000000,
            ..Default::default()
        };

        let token_bytes = sign_mldsa44(&sk, &claims, key_id).unwrap();
        let token = deserialize_signed_token(&token_bytes).unwrap();
        let decoded = deserialize_claims(&token.payload).unwrap();

        assert_eq!(token.algorithm, Algorithm::MlDsa44);
        assert_eq!(decoded.expires_at, 1900000000);
    }

    #[test]
    fn test_sign_mldsa44_with_claims() {
        let (sk, pk) = generate_mldsa44_key();
        let key_id = KeyIdentifier::KeyHash(compute_key_hash(&pk));
        let claims = Claims {
            expires_at: 1900000000,
            subject: "pq-user".into(),
            audience: "pq-api.example.com".into(),
            scopes: vec!["admin".into(), "read".into()],
            ..Default::default()
        };

        let token_bytes = sign_mldsa44(&sk, &claims, key_id).unwrap();
        let token = deserialize_signed_token(&token_bytes).unwrap();
        let decoded = deserialize_claims(&token.payload).unwrap();

        assert_eq!(token.version, Version::V0);
        assert_eq!(token.algorithm, Algorithm::MlDsa44);
        assert_eq!(decoded, claims);
    }

    #[test]
    fn test_sign_mldsa44_rejects_bad_key_length() {
        let claims = Claims {
            expires_at: 1900000000,
            ..Default::default()
        };
        let key_id = KeyIdentifier::KeyHash([0; 8]);
        assert!(sign_mldsa44(&[0; 100], &claims, key_id).is_err());
    }

    #[test]
    fn test_mldsa44_key_sizes() {
        let (sk, pk) = generate_mldsa44_key();
        assert_eq!(sk.len(), MLDSA44_SEED_LEN);
        assert_eq!(pk.len(), MLDSA44_PUBLIC_KEY_LEN);
    }

    #[test]
    fn test_generate_hmac_key_length_and_entropy() {
        let k1 = generate_hmac_key();
        let k2 = generate_hmac_key();
        assert_eq!(k1.len(), 32, "HMAC key must be 32 bytes");
        assert_ne!(k1, k2, "two generated keys should differ");
        assert_ne!(k1, vec![0u8; 32], "key should not be all zeros");
    }

    #[test]
    fn test_sign_rejects_overlong_subject() {
        let key: &[u8] = TEST_HMAC_KEY;
        let claims = Claims {
            expires_at: 1700000000,
            subject: "x".repeat(MAX_CLAIM_BYTES_LEN + 1),
            ..Default::default()
        };
        assert!(sign_hmac(key, &claims).is_err());
    }

    #[test]
    fn test_sign_rejects_overlong_audience() {
        let key: &[u8] = TEST_HMAC_KEY;
        let claims = Claims {
            expires_at: 1700000000,
            audience: "x".repeat(MAX_CLAIM_BYTES_LEN + 1),
            ..Default::default()
        };
        assert!(sign_hmac(key, &claims).is_err());
    }

    #[test]
    fn test_sign_rejects_too_many_scopes() {
        let key: &[u8] = TEST_HMAC_KEY;
        let scopes: Vec<String> = (0..=MAX_SCOPES).map(|i| format!("s{i:03}")).collect();
        let claims = Claims {
            expires_at: 1700000000,
            scopes,
            ..Default::default()
        };
        assert!(sign_hmac(key, &claims).is_err());
    }

    #[test]
    fn test_sign_rejects_overlong_scope_entry() {
        let key: &[u8] = TEST_HMAC_KEY;
        let claims = Claims {
            expires_at: 1700000000,
            scopes: vec!["x".repeat(MAX_CLAIM_BYTES_LEN + 1)],
            ..Default::default()
        };
        assert!(sign_hmac(key, &claims).is_err());
    }

    #[test]
    fn test_sign_accepts_max_length_claims() {
        // Exact-boundary: subject/audience/scope of exactly 255 bytes.
        let key: &[u8] = TEST_HMAC_KEY;
        let claims = Claims {
            expires_at: 1700000000,
            subject: "s".repeat(MAX_CLAIM_BYTES_LEN),
            audience: "a".repeat(MAX_CLAIM_BYTES_LEN),
            scopes: vec!["x".repeat(MAX_CLAIM_BYTES_LEN)],
            ..Default::default()
        };
        assert!(sign_hmac(key, &claims).is_ok());
    }

    #[test]
    fn test_sign_accepts_max_scopes() {
        let key: &[u8] = TEST_HMAC_KEY;
        let scopes: Vec<String> = (0..MAX_SCOPES).map(|i| format!("s{i:03}")).collect();
        let claims = Claims {
            expires_at: 1700000000,
            scopes,
            ..Default::default()
        };
        assert!(sign_hmac(key, &claims).is_ok());
    }

    #[test]
    fn test_sign_accepts_not_before_equal_expires_at() {
        // Boundary: not_before == expires_at is a valid instantaneous token.
        let key: &[u8] = TEST_HMAC_KEY;
        let claims = Claims {
            expires_at: 5000,
            not_before: 5000,
            ..Default::default()
        };
        assert!(sign_hmac(key, &claims).is_ok());
    }
}
