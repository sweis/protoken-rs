//! Token signing: HMAC-SHA256 and Ed25519.

use ring::hmac;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

use crate::error::ProtokenError;
use crate::serialize::{serialize_payload, serialize_signed_token};
use crate::types::*;

/// Compute the 8-byte key hash: SHA-256(key_material)[0..8].
#[must_use]
#[allow(clippy::indexing_slicing)] // SHA-256 always produces 32 bytes >= KEY_HASH_LEN
pub fn compute_key_hash(key_material: &[u8]) -> [u8; KEY_HASH_LEN] {
    use ring::digest;
    let hash = digest::digest(&digest::SHA256, key_material);
    let mut truncated = [0u8; KEY_HASH_LEN];
    truncated.copy_from_slice(&hash.as_ref()[..KEY_HASH_LEN]);
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
    let signing_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&signing_key, &payload_bytes);

    let token = SignedToken {
        payload_bytes,
        signature: tag.as_ref().to_vec(),
    };
    Ok(serialize_signed_token(&token))
}

/// Sign a token with Ed25519.
/// Returns the serialized SignedToken wire bytes.
pub fn sign_ed25519(
    pkcs8_private_key: &[u8],
    claims: Claims,
    key_id: KeyIdentifier,
) -> Result<Vec<u8>, ProtokenError> {
    claims.validate()?;
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_private_key)
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
    let sig = key_pair.sign(&payload_bytes);

    let token = SignedToken {
        payload_bytes,
        signature: sig.as_ref().to_vec(),
    };
    Ok(serialize_signed_token(&token))
}

/// Compute the KeyIdentifier::KeyHash for an Ed25519 key pair's public key.
pub fn ed25519_key_hash(pkcs8_private_key: &[u8]) -> Result<KeyIdentifier, ProtokenError> {
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_private_key)
        .map_err(|e| ProtokenError::SigningFailed(format!("invalid Ed25519 key: {e}")))?;

    let public_key_bytes = key_pair.public_key().as_ref();
    let hash = compute_key_hash(public_key_bytes);
    Ok(KeyIdentifier::KeyHash(hash))
}

/// Generate a new Ed25519 key pair, returning the PKCS#8 document.
pub fn generate_ed25519_key() -> Result<Vec<u8>, ProtokenError> {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| ProtokenError::SigningFailed(format!("key generation failed: {e}")))?;
    Ok(pkcs8.as_ref().to_vec())
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
}
