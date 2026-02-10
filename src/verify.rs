//! Token verification: HMAC-SHA256 and Ed25519.

use ring::hmac;
use ring::signature;

use crate::error::ProtokenError;
use crate::serialize::{deserialize_payload, deserialize_signed_token};
use crate::sign::compute_key_hash;
use crate::types::*;

/// Result of a successful token verification.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifiedClaims {
    pub claims: Claims,
    pub metadata: Metadata,
}

/// Verify an HMAC-SHA256 signed token.
///
/// `key` is the raw symmetric key bytes.
/// `token_bytes` is the serialized SignedToken wire bytes.
/// `now` is the current Unix timestamp for expiry checking.
///
/// Returns the verified claims on success.
pub fn verify_hmac(
    key: &[u8],
    token_bytes: &[u8],
    now: u64,
) -> Result<VerifiedClaims, ProtokenError> {
    let token = deserialize_signed_token(token_bytes)?;
    let payload = deserialize_payload(&token.payload_bytes)?;

    // Check algorithm matches
    if payload.metadata.algorithm != Algorithm::HmacSha256 {
        return Err(ProtokenError::VerificationFailed(format!(
            "expected HMAC-SHA256, got {:?}",
            payload.metadata.algorithm
        )));
    }

    // Check key hash matches
    let expected_hash = compute_key_hash(key);
    match &payload.metadata.key_identifier {
        KeyIdentifier::KeyHash(hash) => {
            if hash != &expected_hash {
                return Err(ProtokenError::KeyHashMismatch);
            }
        }
        KeyIdentifier::PublicKey(_) => {
            return Err(ProtokenError::VerificationFailed(
                "HMAC token has public key identifier".into(),
            ));
        }
    }

    // Verify HMAC
    let verification_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::verify(&verification_key, &token.payload_bytes, &token.signature)
        .map_err(|_| ProtokenError::VerificationFailed("HMAC verification failed".into()))?;

    // Check expiry
    if now > payload.claims.expires_at {
        return Err(ProtokenError::TokenExpired {
            expired_at: payload.claims.expires_at,
            now,
        });
    }

    Ok(VerifiedClaims {
        claims: payload.claims,
        metadata: payload.metadata,
    })
}

/// Verify an Ed25519 signed token.
///
/// `public_key_bytes` is the Ed25519 public key (32 bytes).
/// `token_bytes` is the serialized SignedToken wire bytes.
/// `now` is the current Unix timestamp for expiry checking.
///
/// Returns the verified claims on success.
pub fn verify_ed25519(
    public_key_bytes: &[u8],
    token_bytes: &[u8],
    now: u64,
) -> Result<VerifiedClaims, ProtokenError> {
    let token = deserialize_signed_token(token_bytes)?;
    let payload = deserialize_payload(&token.payload_bytes)?;

    // Check algorithm matches
    if payload.metadata.algorithm != Algorithm::Ed25519 {
        return Err(ProtokenError::VerificationFailed(format!(
            "expected Ed25519, got {:?}",
            payload.metadata.algorithm
        )));
    }

    // Check key hash matches
    let expected_hash = compute_key_hash(public_key_bytes);
    match &payload.metadata.key_identifier {
        KeyIdentifier::KeyHash(hash) => {
            if hash != &expected_hash {
                return Err(ProtokenError::KeyHashMismatch);
            }
        }
        KeyIdentifier::PublicKey(pk) => {
            if pk.as_slice() != public_key_bytes {
                return Err(ProtokenError::KeyHashMismatch);
            }
        }
    }

    // Verify signature
    let peer_public_key = signature::UnparsedPublicKey::new(
        &signature::ED25519,
        public_key_bytes,
    );
    peer_public_key
        .verify(&token.payload_bytes, &token.signature)
        .map_err(|_| ProtokenError::VerificationFailed("Ed25519 signature verification failed".into()))?;

    // Check expiry
    if now > payload.claims.expires_at {
        return Err(ProtokenError::TokenExpired {
            expired_at: payload.claims.expires_at,
            now,
        });
    }

    Ok(VerifiedClaims {
        claims: payload.claims,
        metadata: payload.metadata,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::{generate_ed25519_key, ed25519_key_hash, sign_ed25519, sign_hmac};
    use ring::signature::{Ed25519KeyPair, KeyPair};

    #[test]
    fn test_verify_hmac_valid() {
        let key = b"test-hmac-key-123";
        let expires_at = u64::MAX; // far future
        let token_bytes = sign_hmac(key, expires_at);

        let result = verify_hmac(key, &token_bytes, 1700000000);
        assert!(result.is_ok());
        let verified = result.unwrap();
        assert_eq!(verified.claims.expires_at, expires_at);
    }

    #[test]
    fn test_verify_hmac_wrong_key() {
        let key = b"correct-key";
        let wrong_key = b"wrong-key";
        let token_bytes = sign_hmac(key, u64::MAX);

        let result = verify_hmac(wrong_key, &token_bytes, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_hmac_expired() {
        let key = b"test-key";
        let expires_at = 1000u64;
        let token_bytes = sign_hmac(key, expires_at);

        let result = verify_hmac(key, &token_bytes, 2000);
        assert!(matches!(result, Err(ProtokenError::TokenExpired { .. })));
    }

    #[test]
    fn test_verify_hmac_corrupted_payload() {
        let key = b"test-key";
        let mut token_bytes = sign_hmac(key, u64::MAX);
        // Corrupt the expires_at field (byte 11 is in the middle of it)
        token_bytes[11] ^= 0xFF;

        let result = verify_hmac(key, &token_bytes, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_hmac_corrupted_signature() {
        let key = b"test-key";
        let mut token_bytes = sign_hmac(key, u64::MAX);
        // Corrupt the signature (last byte)
        let last = token_bytes.len() - 1;
        token_bytes[last] ^= 0xFF;

        let result = verify_hmac(key, &token_bytes, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_ed25519_valid() {
        let pkcs8 = generate_ed25519_key().unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(&pkcs8).unwrap();
        let public_key_bytes = key_pair.public_key().as_ref();

        let key_id = ed25519_key_hash(&pkcs8).unwrap();
        let expires_at = u64::MAX;
        let token_bytes = sign_ed25519(&pkcs8, expires_at, key_id).unwrap();

        let result = verify_ed25519(public_key_bytes, &token_bytes, 1700000000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_ed25519_expired() {
        let pkcs8 = generate_ed25519_key().unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(&pkcs8).unwrap();
        let public_key_bytes = key_pair.public_key().as_ref();

        let key_id = ed25519_key_hash(&pkcs8).unwrap();
        let token_bytes = sign_ed25519(&pkcs8, 1000, key_id).unwrap();

        let result = verify_ed25519(public_key_bytes, &token_bytes, 2000);
        assert!(matches!(result, Err(ProtokenError::TokenExpired { .. })));
    }

    #[test]
    fn test_verify_ed25519_corrupted_signature() {
        let pkcs8 = generate_ed25519_key().unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(&pkcs8).unwrap();
        let public_key_bytes = key_pair.public_key().as_ref();

        let key_id = ed25519_key_hash(&pkcs8).unwrap();
        let mut token_bytes = sign_ed25519(&pkcs8, u64::MAX, key_id).unwrap();
        let last = token_bytes.len() - 1;
        token_bytes[last] ^= 0xFF;

        let result = verify_ed25519(public_key_bytes, &token_bytes, 0);
        assert!(result.is_err());
    }

    /// Test corrupting every individual byte of an HMAC token.
    #[test]
    fn test_hmac_corrupt_every_byte() {
        let key = b"corruption-test-key";
        let token_bytes = sign_hmac(key, u64::MAX);

        for i in 0..token_bytes.len() {
            let mut corrupted = token_bytes.clone();
            corrupted[i] ^= 0x01; // flip one bit

            let result = verify_hmac(key, &corrupted, 0);
            assert!(
                result.is_err(),
                "corrupting byte {i} should cause verification failure"
            );
        }
    }

    /// Test corrupting every individual byte of an Ed25519 token.
    #[test]
    fn test_ed25519_corrupt_every_byte() {
        let pkcs8 = generate_ed25519_key().unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(&pkcs8).unwrap();
        let public_key_bytes = key_pair.public_key().as_ref();

        let key_id = ed25519_key_hash(&pkcs8).unwrap();
        let token_bytes = sign_ed25519(&pkcs8, u64::MAX, key_id).unwrap();

        for i in 0..token_bytes.len() {
            let mut corrupted = token_bytes.clone();
            corrupted[i] ^= 0x01;

            let result = verify_ed25519(public_key_bytes, &corrupted, 0);
            assert!(
                result.is_err(),
                "corrupting byte {i} should cause verification failure"
            );
        }
    }
}
