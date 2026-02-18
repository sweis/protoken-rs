//! Token signing: HMAC-SHA256, Ed25519, and ML-DSA-44.

use ed25519_dalek::pkcs8::DecodePrivateKey;
use hmac::{Hmac, Mac};
use ml_dsa::signature::Signer as _;
use ml_dsa::{KeyGen, MlDsa44};
use sha2::{Digest, Sha256};

use crate::error::ProtokenError;
use crate::serialize::{serialize_payload, serialize_signed_token};
use crate::types::*;

/// Compute the 8-byte key hash: SHA-256(key_material)[0..8].
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
    };
    Ok(serialize_signed_token(&token))
}

/// Sign a token with Ed25519.
/// Returns the serialized SignedToken wire bytes.
///
/// `pkcs8_private_key` is the PKCS#8 DER-encoded Ed25519 private key.
pub fn sign_ed25519(
    pkcs8_private_key: &[u8],
    claims: Claims,
    key_id: KeyIdentifier,
) -> Result<Vec<u8>, ProtokenError> {
    claims.validate()?;
    let signing_key = ed25519_dalek::SigningKey::from_pkcs8_der(pkcs8_private_key)
        .map_err(|e| ProtokenError::SigningFailed(format!("invalid Ed25519 key: {e}")))?;

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
    };
    Ok(serialize_signed_token(&token))
}

/// Compute the KeyIdentifier::KeyHash for an Ed25519 key pair's public key.
pub fn ed25519_key_hash(pkcs8_private_key: &[u8]) -> Result<KeyIdentifier, ProtokenError> {
    let signing_key = ed25519_dalek::SigningKey::from_pkcs8_der(pkcs8_private_key)
        .map_err(|e| ProtokenError::SigningFailed(format!("invalid Ed25519 key: {e}")))?;

    let public_key_bytes = signing_key.verifying_key().to_bytes();
    let hash = compute_key_hash(&public_key_bytes);
    Ok(KeyIdentifier::KeyHash(hash))
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

/// Split a combined ML-DSA-44 key file (SK || PK) into signing key and public key bytes.
///
/// ML-DSA-44 key files are stored as `signing_key_bytes || public_key_bytes`
/// (2,560 + 1,312 = 3,872 bytes total).
pub fn split_mldsa44_key(combined: &[u8]) -> Result<(&[u8], &[u8]), ProtokenError> {
    let expected = MLDSA44_SIGNING_KEY_LEN + MLDSA44_PUBLIC_KEY_LEN;
    if combined.len() != expected {
        return Err(ProtokenError::SigningFailed(format!(
            "invalid ML-DSA-44 combined key: expected {} bytes (SK {} + PK {}), got {}",
            expected,
            MLDSA44_SIGNING_KEY_LEN,
            MLDSA44_PUBLIC_KEY_LEN,
            combined.len()
        )));
    }
    #[allow(clippy::indexing_slicing)] // length checked above
    Ok(combined.split_at(MLDSA44_SIGNING_KEY_LEN))
}

/// Generate a new Ed25519 key pair, returning the PKCS#8 DER bytes.
pub fn generate_ed25519_key() -> Result<Vec<u8>, ProtokenError> {
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    let mut rng = rand::rngs::OsRng;
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
    let pkcs8 = signing_key
        .to_pkcs8_der()
        .map_err(|e| ProtokenError::SigningFailed(format!("PKCS#8 encoding failed: {e}")))?;
    Ok(pkcs8.as_bytes().to_vec())
}

/// Generate a new ML-DSA-44 key pair, returning (signing_key_bytes, public_key_bytes).
pub fn generate_mldsa44_key() -> Result<(Vec<u8>, Vec<u8>), ProtokenError> {
    let mut rng = rand::rngs::OsRng;
    let kp = MlDsa44::key_gen(&mut rng);
    let sk_bytes = kp.signing_key().encode().to_vec();
    let pk_bytes = kp.verifying_key().encode().to_vec();
    Ok((sk_bytes, pk_bytes))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::serialize::{deserialize_payload, deserialize_signed_token};

    #[test]
    fn test_sign_hmac_produces_valid_token() {
        let key = b"test-secret-key-for-hmac";
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
        let pkcs8 = generate_ed25519_key().unwrap();
        let key_id = ed25519_key_hash(&pkcs8).unwrap();
        let claims = Claims {
            expires_at: 1800000000,
            ..Default::default()
        };

        let token_bytes = sign_ed25519(&pkcs8, claims, key_id).unwrap();
        let token = deserialize_signed_token(&token_bytes).unwrap();
        let payload = deserialize_payload(&token.payload_bytes).unwrap();

        assert_eq!(payload.metadata.algorithm, Algorithm::Ed25519);
        assert_eq!(payload.claims.expires_at, 1800000000);
    }

    #[test]
    fn test_ed25519_signing_deterministic() {
        let pkcs8 = generate_ed25519_key().unwrap();
        let key_id = ed25519_key_hash(&pkcs8).unwrap();
        let claims = Claims {
            expires_at: 1800000000,
            not_before: 1799990000,
            issued_at: 1799990000,
            subject: "test".into(),
            ..Default::default()
        };

        let t1 = sign_ed25519(&pkcs8, claims.clone(), key_id.clone()).unwrap();
        let t2 = sign_ed25519(&pkcs8, claims, key_id).unwrap();
        assert_eq!(t1, t2);
    }

    #[test]
    fn test_sign_hmac_with_claims() {
        let key = b"test-secret-key-for-hmac";
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
        let pkcs8 = generate_ed25519_key().unwrap();
        let key_id = ed25519_key_hash(&pkcs8).unwrap();
        let claims = Claims {
            expires_at: 1800000000,
            subject: "user:alice".into(),
            audience: "api.example.com".into(),
            ..Default::default()
        };

        let token_bytes = sign_ed25519(&pkcs8, claims.clone(), key_id).unwrap();
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

    #[test]
    fn test_split_mldsa44_key() {
        let (sk, pk) = generate_mldsa44_key().unwrap();
        let mut combined = sk.clone();
        combined.extend_from_slice(&pk);
        let (split_sk, split_pk) = split_mldsa44_key(&combined).unwrap();
        assert_eq!(split_sk, sk.as_slice());
        assert_eq!(split_pk, pk.as_slice());
    }
}
