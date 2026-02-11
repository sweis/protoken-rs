//! Token verification: HMAC-SHA256 and Ed25519.
//! Auto-detects v0 vs v1 format.

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

/// Verify an HMAC-SHA256 signed token (auto-detects v0/v1).
///
/// `key` is the raw symmetric key bytes.
/// `token_bytes` is the serialized SignedToken wire bytes.
/// `now` is the current Unix timestamp for expiry checking.
pub fn verify_hmac(
    key: &[u8],
    token_bytes: &[u8],
    now: u64,
) -> Result<VerifiedClaims, ProtokenError> {
    let token = deserialize_signed_token(token_bytes)?;
    let payload = deserialize_payload(&token.payload_bytes)?;

    if payload.metadata.algorithm != Algorithm::HmacSha256 {
        return Err(ProtokenError::VerificationFailed(format!(
            "expected HMAC-SHA256, got {:?}",
            payload.metadata.algorithm
        )));
    }

    // Check key hash
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

    // Verify HMAC over the raw payload bytes
    let verification_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::verify(&verification_key, &token.payload_bytes, &token.signature)
        .map_err(|_| ProtokenError::VerificationFailed("HMAC verification failed".into()))?;

    check_temporal_claims(&payload.claims, now)?;

    Ok(VerifiedClaims {
        claims: payload.claims,
        metadata: payload.metadata,
    })
}

/// Verify an Ed25519 signed token (auto-detects v0/v1).
///
/// `public_key_bytes` is the Ed25519 public key (32 bytes).
/// `token_bytes` is the serialized SignedToken wire bytes.
/// `now` is the current Unix timestamp for expiry checking.
pub fn verify_ed25519(
    public_key_bytes: &[u8],
    token_bytes: &[u8],
    now: u64,
) -> Result<VerifiedClaims, ProtokenError> {
    let token = deserialize_signed_token(token_bytes)?;
    let payload = deserialize_payload(&token.payload_bytes)?;

    if payload.metadata.algorithm != Algorithm::Ed25519 {
        return Err(ProtokenError::VerificationFailed(format!(
            "expected Ed25519, got {:?}",
            payload.metadata.algorithm
        )));
    }

    // Check key identity
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

    // Verify signature over the raw payload bytes
    let peer_public_key =
        signature::UnparsedPublicKey::new(&signature::ED25519, public_key_bytes);
    peer_public_key
        .verify(&token.payload_bytes, &token.signature)
        .map_err(|_| {
            ProtokenError::VerificationFailed("Ed25519 signature verification failed".into())
        })?;

    check_temporal_claims(&payload.claims, now)?;

    Ok(VerifiedClaims {
        claims: payload.claims,
        metadata: payload.metadata,
    })
}

/// Check expires_at and not_before against current time.
fn check_temporal_claims(claims: &Claims, now: u64) -> Result<(), ProtokenError> {
    if claims.expires_at != 0 && now > claims.expires_at {
        return Err(ProtokenError::TokenExpired {
            expired_at: claims.expires_at,
            now,
        });
    }
    if claims.not_before != 0 && now < claims.not_before {
        return Err(ProtokenError::TokenNotYetValid {
            not_before: claims.not_before,
            now,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::{
        ed25519_key_hash, generate_ed25519_key, sign_ed25519, sign_ed25519_v1, sign_hmac,
        sign_hmac_v1,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};

    // ─── v0 tests ───

    #[test]
    fn test_verify_hmac_valid() {
        let key = b"test-hmac-key-123";
        let expires_at = u64::MAX;
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
        token_bytes[11] ^= 0xFF;

        let result = verify_hmac(key, &token_bytes, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_hmac_corrupted_signature() {
        let key = b"test-key";
        let mut token_bytes = sign_hmac(key, u64::MAX);
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

    #[test]
    fn test_hmac_corrupt_every_byte() {
        let key = b"corruption-test-key";
        let token_bytes = sign_hmac(key, u64::MAX);

        for i in 0..token_bytes.len() {
            let mut corrupted = token_bytes.clone();
            corrupted[i] ^= 0x01;

            let result = verify_hmac(key, &corrupted, 0);
            assert!(
                result.is_err(),
                "corrupting byte {i} should cause verification failure"
            );
        }
    }

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

    // ─── v1 tests ───

    #[test]
    fn test_verify_hmac_v1() {
        let key = b"test-hmac-key-v1";
        let claims = Claims {
            expires_at: u64::MAX,
            not_before: 1000,
            issued_at: 1000,
            subject: b"alice".to_vec(),
            ..Default::default()
        };

        let token_bytes = sign_hmac_v1(key, claims.clone());
        let result = verify_hmac(key, &token_bytes, 2000);
        assert!(result.is_ok());
        let verified = result.unwrap();
        assert_eq!(verified.claims, claims);
        assert_eq!(verified.metadata.version, Version::V1);
    }

    #[test]
    fn test_verify_ed25519_v1() {
        let pkcs8 = generate_ed25519_key().unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(&pkcs8).unwrap();
        let public_key = key_pair.public_key().as_ref();
        let key_id = ed25519_key_hash(&pkcs8).unwrap();

        let claims = Claims {
            expires_at: u64::MAX,
            subject: b"bob".to_vec(),
            audience: b"api".to_vec(),
            ..Default::default()
        };

        let token_bytes = sign_ed25519_v1(&pkcs8, claims.clone(), key_id).unwrap();
        let result = verify_ed25519(public_key, &token_bytes, 1700000000);
        assert!(result.is_ok());
        let verified = result.unwrap();
        assert_eq!(verified.claims, claims);
    }

    #[test]
    fn test_verify_v1_not_before() {
        let key = b"test-nbf-key";
        let claims = Claims {
            expires_at: u64::MAX,
            not_before: 5000,
            ..Default::default()
        };

        let token_bytes = sign_hmac_v1(key, claims);

        // Before not_before → should fail
        let result = verify_hmac(key, &token_bytes, 3000);
        assert!(matches!(
            result,
            Err(ProtokenError::TokenNotYetValid { .. })
        ));

        // At not_before → should succeed
        let result = verify_hmac(key, &token_bytes, 5000);
        assert!(result.is_ok());

        // After not_before → should succeed
        let result = verify_hmac(key, &token_bytes, 6000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_v1_hmac_corrupt_every_byte() {
        let key = b"v1-corruption-test";
        let claims = Claims {
            expires_at: u64::MAX,
            not_before: 1000,
            subject: b"test".to_vec(),
            ..Default::default()
        };

        let token_bytes = sign_hmac_v1(key, claims);

        for i in 0..token_bytes.len() {
            let mut corrupted = token_bytes.clone();
            corrupted[i] ^= 0x01;

            let result = verify_hmac(key, &corrupted, 2000);
            assert!(
                result.is_err(),
                "v1: corrupting byte {i} should cause verification failure"
            );
        }
    }

    #[test]
    fn test_v1_ed25519_corrupt_every_byte() {
        let pkcs8 = generate_ed25519_key().unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(&pkcs8).unwrap();
        let public_key = key_pair.public_key().as_ref();
        let key_id = ed25519_key_hash(&pkcs8).unwrap();

        let claims = Claims {
            expires_at: u64::MAX,
            subject: b"test".to_vec(),
            audience: b"svc".to_vec(),
            ..Default::default()
        };

        let token_bytes = sign_ed25519_v1(&pkcs8, claims, key_id).unwrap();

        for i in 0..token_bytes.len() {
            let mut corrupted = token_bytes.clone();
            corrupted[i] ^= 0x01;

            let result = verify_ed25519(public_key, &corrupted, 1000);
            assert!(
                result.is_err(),
                "v1: corrupting byte {i} should cause verification failure"
            );
        }
    }
}
