//! Token signing: HMAC-SHA256, Ed25519, ML-DSA-44, and Groth16-SHA256.

use hmac::{Hmac, Mac};
use ml_dsa::signature::Signer as _;
use ml_dsa::{KeyGen, MlDsa44};
use sha2::{Digest, Sha256};

use crate::error::ProtokenError;
use crate::serialize::{serialize_payload, serialize_signed_token};
use crate::snark::SnarkProvingKey;
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

/// Sign a token with HMAC-SHA256.
/// Returns the serialized SignedToken wire bytes.
///
/// For HMAC-SHA256, use at least 32 bytes of cryptographically random key material.
pub fn sign_hmac(key: &[u8], claims: Claims) -> Result<Vec<u8>, ProtokenError> {
    if key.len() < HMAC_MIN_KEY_LEN {
        return Err(ProtokenError::SigningFailed(format!(
            "HMAC key too short: {} bytes (minimum {})",
            key.len(),
            HMAC_MIN_KEY_LEN
        )));
    }
    claims.validate()?;
    let key_hash = compute_key_hash(key);
    let payload = Payload {
        metadata: Metadata {
            version: Version::V0,
            algorithm: Algorithm::HmacSha256,
            key_identifier: KeyIdentifier::KeyHash(key_hash),
        },
        claims,
    };

    let payload_bytes = serialize_payload(&payload);
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|e| ProtokenError::SigningFailed(format!("invalid HMAC key: {e}")))?;
    mac.update(&payload_bytes);
    let tag = mac.finalize().into_bytes();

    let token = SignedToken {
        payload_bytes,
        signature: tag.to_vec(),
        proof: Vec::new(),
    };
    Ok(serialize_signed_token(&token))
}

/// Sign a token with Ed25519.
/// Returns the serialized SignedToken wire bytes.
///
/// `seed` is the raw 32-byte Ed25519 private key seed.
pub fn sign_ed25519(
    seed: &[u8],
    claims: Claims,
    key_id: KeyIdentifier,
) -> Result<Vec<u8>, ProtokenError> {
    claims.validate()?;
    let seed_array: [u8; ED25519_SEED_LEN] = seed.try_into().map_err(|_| {
        ProtokenError::SigningFailed(format!(
            "invalid Ed25519 seed: expected {} bytes, got {}",
            ED25519_SEED_LEN,
            seed.len()
        ))
    })?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed_array);

    let payload = Payload {
        metadata: Metadata {
            version: Version::V0,
            algorithm: Algorithm::Ed25519,
            key_identifier: key_id,
        },
        claims,
    };

    let payload_bytes = serialize_payload(&payload);
    let sig = signing_key.sign(&payload_bytes);

    let token = SignedToken {
        payload_bytes,
        signature: sig.to_bytes().to_vec(),
        proof: Vec::new(),
    };
    Ok(serialize_signed_token(&token))
}

/// Sign a token with ML-DSA-44.
/// Returns the serialized SignedToken wire bytes.
///
/// `signing_key_bytes` is the raw 2,560-byte ML-DSA-44 signing key.
pub fn sign_mldsa44(
    signing_key_bytes: &[u8],
    claims: Claims,
    key_id: KeyIdentifier,
) -> Result<Vec<u8>, ProtokenError> {
    claims.validate()?;

    let encoded: &ml_dsa::EncodedSigningKey<MlDsa44> =
        signing_key_bytes.try_into().map_err(|_| {
            ProtokenError::SigningFailed(format!(
                "invalid ML-DSA-44 signing key: expected {} bytes, got {}",
                MLDSA44_SIGNING_KEY_LEN,
                signing_key_bytes.len()
            ))
        })?;
    let signing_key = ml_dsa::SigningKey::<MlDsa44>::decode(encoded);

    let payload = Payload {
        metadata: Metadata {
            version: Version::V0,
            algorithm: Algorithm::MlDsa44,
            key_identifier: key_id,
        },
        claims,
    };

    let payload_bytes = serialize_payload(&payload);
    let sig = signing_key
        .try_sign(&payload_bytes)
        .map_err(|e| ProtokenError::SigningFailed(format!("ML-DSA-44 signing failed: {e}")))?;

    let token = SignedToken {
        payload_bytes,
        signature: sig.encode().to_vec(),
        proof: Vec::new(),
    };
    Ok(serialize_signed_token(&token))
}

/// Compute the KeyIdentifier::KeyHash for an ML-DSA-44 public key.
pub fn mldsa44_key_hash(public_key_bytes: &[u8]) -> Result<KeyIdentifier, ProtokenError> {
    if public_key_bytes.len() != MLDSA44_PUBLIC_KEY_LEN {
        return Err(ProtokenError::SigningFailed(format!(
            "invalid ML-DSA-44 public key: expected {} bytes, got {}",
            MLDSA44_PUBLIC_KEY_LEN,
            public_key_bytes.len()
        )));
    }
    let hash = compute_key_hash(public_key_bytes);
    Ok(KeyIdentifier::KeyHash(hash))
}

/// Generate a new Ed25519 key pair, returning (seed, public_key) as raw bytes.
pub fn generate_ed25519_key() -> Result<(Vec<u8>, Vec<u8>), ProtokenError> {
    let mut rng = rand::rngs::OsRng;
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
    let seed = signing_key.to_bytes().to_vec();
    let pk = signing_key.verifying_key().to_bytes().to_vec();
    Ok((seed, pk))
}

/// Generate a new ML-DSA-44 key pair, returning (signing_key_bytes, public_key_bytes).
pub fn generate_mldsa44_key() -> Result<(Vec<u8>, Vec<u8>), ProtokenError> {
    let mut rng = rand::rngs::OsRng;
    let kp = MlDsa44::key_gen(&mut rng);
    let sk_bytes = kp.signing_key().encode().to_vec();
    let pk_bytes = kp.verifying_key().encode().to_vec();
    Ok((sk_bytes, pk_bytes))
}

/// Generate a new HMAC key (32 bytes of cryptographically random data).
pub fn generate_hmac_key() -> Vec<u8> {
    let mut key = vec![0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
    key
}

/// Compute the full 32-byte SHA-256 hash of key material.
/// Used by Groth16Sha256 for full collision resistance (~2^128 at the birthday bound).
#[must_use]
pub fn compute_full_key_hash(key_material: &[u8]) -> [u8; FULL_KEY_HASH_LEN] {
    let hash = Sha256::digest(key_material);
    let mut out = [0u8; FULL_KEY_HASH_LEN];
    out.copy_from_slice(&hash);
    out
}

/// Sign a token with Groth16-SHA256 (symmetric key SNARK proof).
///
/// `pk` is the Groth16 proving key from `snark::setup()`.
/// `key` is the 32-byte symmetric key.
/// `claims` are the token claims.
///
/// Returns the serialized SignedToken wire bytes including the SNARK proof.
pub fn sign_groth16(
    pk: &SnarkProvingKey,
    key: &[u8; 32],
    claims: Claims,
) -> Result<Vec<u8>, ProtokenError> {
    claims.validate()?;
    let key_hash = compute_full_key_hash(key);
    let payload = Payload {
        metadata: Metadata {
            version: Version::V0,
            algorithm: Algorithm::Groth16Sha256,
            key_identifier: KeyIdentifier::FullKeyHash(key_hash),
        },
        claims,
    };

    let payload_bytes = serialize_payload(&payload);
    let (_key_hash, hmac_output, proof_bytes) = crate::snark::prove(pk, key, &payload_bytes)?;

    let token = SignedToken {
        payload_bytes,
        signature: hmac_output.to_vec(),
        proof: proof_bytes,
    };
    Ok(serialize_signed_token(&token))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::serialize::{deserialize_payload, deserialize_signed_token};

    const TEST_HMAC_KEY: &[u8; 32] = &[0xAB; 32];

    #[test]
    fn test_sign_hmac_produces_valid_token() {
        let key: &[u8] = TEST_HMAC_KEY;
        let claims = Claims {
            expires_at: 1700000000,
            ..Default::default()
        };

        let token_bytes = sign_hmac(key, claims).unwrap();
        let token = deserialize_signed_token(&token_bytes).unwrap();
        let payload = deserialize_payload(&token.payload_bytes).unwrap();

        assert_eq!(payload.metadata.version, Version::V0);
        assert_eq!(payload.metadata.algorithm, Algorithm::HmacSha256);
        assert_eq!(payload.claims.expires_at, 1700000000);

        let expected_hash = compute_key_hash(key);
        assert_eq!(
            payload.metadata.key_identifier,
            KeyIdentifier::KeyHash(expected_hash)
        );
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
    fn test_sign_ed25519_produces_valid_token() {
        let (seed, pk) = generate_ed25519_key().unwrap();
        let key_id = KeyIdentifier::KeyHash(compute_key_hash(&pk));
        let claims = Claims {
            expires_at: 1800000000,
            ..Default::default()
        };

        let token_bytes = sign_ed25519(&seed, claims, key_id).unwrap();
        let token = deserialize_signed_token(&token_bytes).unwrap();
        let payload = deserialize_payload(&token.payload_bytes).unwrap();

        assert_eq!(payload.metadata.algorithm, Algorithm::Ed25519);
        assert_eq!(payload.claims.expires_at, 1800000000);
    }

    #[test]
    fn test_ed25519_signing_deterministic() {
        let (seed, pk) = generate_ed25519_key().unwrap();
        let key_id = KeyIdentifier::KeyHash(compute_key_hash(&pk));
        let claims = Claims {
            expires_at: 1800000000,
            not_before: 1799990000,
            issued_at: 1799990000,
            subject: "test".into(),
            ..Default::default()
        };

        let t1 = sign_ed25519(&seed, claims.clone(), key_id.clone()).unwrap();
        let t2 = sign_ed25519(&seed, claims, key_id).unwrap();
        assert_eq!(t1, t2);
    }

    #[test]
    fn test_sign_hmac_rejects_short_key() {
        let short_key = b"too-short";
        let claims = Claims {
            expires_at: 1700000000,
            ..Default::default()
        };
        assert!(sign_hmac(short_key, claims).is_err());
    }

    #[test]
    fn test_sign_rejects_zero_expires_at() {
        let key: &[u8] = TEST_HMAC_KEY;
        let claims = Claims {
            expires_at: 0,
            ..Default::default()
        };
        assert!(sign_hmac(key, claims).is_err());
    }

    #[test]
    fn test_sign_rejects_not_before_after_expires_at() {
        let key: &[u8] = TEST_HMAC_KEY;
        let claims = Claims {
            expires_at: 1000,
            not_before: 2000,
            ..Default::default()
        };
        assert!(sign_hmac(key, claims).is_err());
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

        let token_bytes = sign_hmac(key, claims.clone()).unwrap();
        let token = deserialize_signed_token(&token_bytes).unwrap();
        let payload = deserialize_payload(&token.payload_bytes).unwrap();

        assert_eq!(payload.metadata.version, Version::V0);
        assert_eq!(payload.metadata.algorithm, Algorithm::HmacSha256);
        assert_eq!(payload.claims, claims);
    }

    #[test]
    fn test_sign_ed25519_with_claims() {
        let (seed, pk) = generate_ed25519_key().unwrap();
        let key_id = KeyIdentifier::KeyHash(compute_key_hash(&pk));
        let claims = Claims {
            expires_at: 1800000000,
            subject: "user:alice".into(),
            audience: "api.example.com".into(),
            ..Default::default()
        };

        let token_bytes = sign_ed25519(&seed, claims.clone(), key_id).unwrap();
        let token = deserialize_signed_token(&token_bytes).unwrap();
        let payload = deserialize_payload(&token.payload_bytes).unwrap();

        assert_eq!(payload.metadata.version, Version::V0);
        assert_eq!(payload.metadata.algorithm, Algorithm::Ed25519);
        assert_eq!(payload.claims, claims);
    }

    #[test]
    fn test_sign_mldsa44_produces_valid_token() {
        let (sk, pk) = generate_mldsa44_key().unwrap();
        let key_id = mldsa44_key_hash(&pk).unwrap();
        let claims = Claims {
            expires_at: 1900000000,
            ..Default::default()
        };

        let token_bytes = sign_mldsa44(&sk, claims, key_id).unwrap();
        let token = deserialize_signed_token(&token_bytes).unwrap();
        let payload = deserialize_payload(&token.payload_bytes).unwrap();

        assert_eq!(payload.metadata.algorithm, Algorithm::MlDsa44);
        assert_eq!(payload.claims.expires_at, 1900000000);
    }

    #[test]
    fn test_sign_mldsa44_with_claims() {
        let (sk, pk) = generate_mldsa44_key().unwrap();
        let key_id = mldsa44_key_hash(&pk).unwrap();
        let claims = Claims {
            expires_at: 1900000000,
            subject: "pq-user".into(),
            audience: "pq-api.example.com".into(),
            scopes: vec!["admin".into(), "read".into()],
            ..Default::default()
        };

        let token_bytes = sign_mldsa44(&sk, claims.clone(), key_id).unwrap();
        let token = deserialize_signed_token(&token_bytes).unwrap();
        let payload = deserialize_payload(&token.payload_bytes).unwrap();

        assert_eq!(payload.metadata.version, Version::V0);
        assert_eq!(payload.metadata.algorithm, Algorithm::MlDsa44);
        assert_eq!(payload.claims, claims);
    }

    #[test]
    fn test_mldsa44_key_hash_deterministic() {
        let (_sk, pk) = generate_mldsa44_key().unwrap();
        let h1 = mldsa44_key_hash(&pk).unwrap();
        let h2 = mldsa44_key_hash(&pk).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_mldsa44_key_sizes() {
        let (sk, pk) = generate_mldsa44_key().unwrap();
        assert_eq!(sk.len(), MLDSA44_SIGNING_KEY_LEN);
        assert_eq!(pk.len(), MLDSA44_PUBLIC_KEY_LEN);
    }
}
