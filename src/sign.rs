//! Token signing: HMAC-SHA256 and Ed25519.

use ring::hmac;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

use crate::error::ProtokenError;
use crate::serialize::serialize_payload;
use crate::types::*;

/// Compute the 8-byte key hash: SHA-256(key_material)[0..8].
pub fn compute_key_hash(key_material: &[u8]) -> [u8; KEY_HASH_LEN] {
    use ring::digest;
    let hash = digest::digest(&digest::SHA256, key_material);
    let mut truncated = [0u8; KEY_HASH_LEN];
    truncated.copy_from_slice(&hash.as_ref()[..KEY_HASH_LEN]);
    truncated
}

/// Sign a payload with HMAC-SHA256.
///
/// `key` is the raw symmetric key bytes.
/// `expires_at` is the Unix timestamp for token expiration.
///
/// Returns the serialized SignedToken wire bytes.
pub fn sign_hmac(key: &[u8], expires_at: u64) -> Vec<u8> {
    let key_hash = compute_key_hash(key);
    let payload = Payload {
        metadata: Metadata {
            version: Version::V0,
            algorithm: Algorithm::HmacSha256,
            key_identifier: KeyIdentifier::KeyHash(key_hash),
        },
        claims: Claims { expires_at },
    };

    let payload_bytes = serialize_payload(&payload);
    let signing_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&signing_key, &payload_bytes);

    let mut token_bytes = payload_bytes;
    token_bytes.extend_from_slice(tag.as_ref());
    token_bytes
}

/// Sign a payload with Ed25519.
///
/// `pkcs8_private_key` is the PKCS#8-encoded Ed25519 private key.
/// `expires_at` is the Unix timestamp for token expiration.
/// `key_id` determines how the key is identified in the token.
///
/// Returns the serialized SignedToken wire bytes.
pub fn sign_ed25519(
    pkcs8_private_key: &[u8],
    expires_at: u64,
    key_id: KeyIdentifier,
) -> Result<Vec<u8>, ProtokenError> {
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_private_key)
        .map_err(|e| ProtokenError::SigningFailed(format!("invalid Ed25519 key: {e}")))?;

    let payload = Payload {
        metadata: Metadata {
            version: Version::V0,
            algorithm: Algorithm::Ed25519,
            key_identifier: key_id,
        },
        claims: Claims { expires_at },
    };

    let payload_bytes = serialize_payload(&payload);
    let sig = key_pair.sign(&payload_bytes);

    let sig_bytes = sig.as_ref();
    debug_assert_eq!(sig_bytes.len(), ED25519_SIG_LEN);

    let mut token_bytes = payload_bytes;
    token_bytes.extend_from_slice(sig_bytes);
    Ok(token_bytes)
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
mod tests {
    use super::*;
    use crate::serialize::{deserialize_payload, deserialize_signed_token};

    #[test]
    fn test_sign_hmac_produces_valid_token() {
        let key = b"test-secret-key-for-hmac";
        let expires_at = 1700000000u64;

        let token_bytes = sign_hmac(key, expires_at);
        assert_eq!(token_bytes.len(), 19 + 32); // payload + HMAC

        let token = deserialize_signed_token(&token_bytes).unwrap();
        let payload = deserialize_payload(&token.payload_bytes).unwrap();

        assert_eq!(payload.metadata.version, Version::V0);
        assert_eq!(payload.metadata.algorithm, Algorithm::HmacSha256);
        assert_eq!(payload.claims.expires_at, expires_at);

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
        let expires_at = 1800000000u64;

        let token_bytes = sign_ed25519(&pkcs8, expires_at, key_id).unwrap();
        assert_eq!(token_bytes.len(), 19 + 64); // payload + Ed25519 sig

        let token = deserialize_signed_token(&token_bytes).unwrap();
        let payload = deserialize_payload(&token.payload_bytes).unwrap();

        assert_eq!(payload.metadata.algorithm, Algorithm::Ed25519);
        assert_eq!(payload.claims.expires_at, expires_at);
    }

    #[test]
    fn test_ed25519_signing_deterministic() {
        let pkcs8 = generate_ed25519_key().unwrap();
        let key_id = ed25519_key_hash(&pkcs8).unwrap();
        let expires_at = 1800000000u64;

        let t1 = sign_ed25519(&pkcs8, expires_at, key_id.clone()).unwrap();
        let t2 = sign_ed25519(&pkcs8, expires_at, key_id).unwrap();
        // Ed25519 is deterministic: same key + same message = same signature
        assert_eq!(t1, t2);
    }
}
