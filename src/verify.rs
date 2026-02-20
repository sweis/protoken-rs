//! Token verification: HMAC-SHA256, Ed25519, and ML-DSA-44.

use hmac::{Hmac, Mac};
use ml_dsa::signature::Verifier as _;
use ml_dsa::MlDsa44;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::ProtokenError;
use crate::serialize::{deserialize_payload, deserialize_signed_token};
use crate::sign::compute_key_hash;
use crate::types::*;

/// Constant-time key comparison. Returns KeyHashMismatch if slices differ.
fn verify_key_match(a: &[u8], b: &[u8]) -> Result<(), ProtokenError> {
    if bool::from(a.ct_eq(b)) {
        Ok(())
    } else {
        Err(ProtokenError::KeyHashMismatch)
    }
}

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

    // Check key hash (constant-time comparison)
    let expected_hash = compute_key_hash(key);
    match &payload.metadata.key_identifier {
        KeyIdentifier::KeyHash(hash) => {
            verify_key_match(hash, &expected_hash)?;
        }
        KeyIdentifier::PublicKey(_) => {
            return Err(ProtokenError::VerificationFailed(
                "HMAC token has public key identifier".into(),
            ));
        }
    }

    // Verify HMAC over the raw payload bytes
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|e| ProtokenError::VerificationFailed(format!("invalid HMAC key: {e}")))?;
    mac.update(&token.payload_bytes);
    mac.verify_slice(&token.signature)
        .map_err(|_| ProtokenError::VerificationFailed("HMAC verification failed".into()))?;

    check_temporal_claims(&payload.claims, now)?;

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

    // Check key identity (constant-time comparison)
    let expected_hash = compute_key_hash(public_key_bytes);
    match &payload.metadata.key_identifier {
        KeyIdentifier::KeyHash(hash) => {
            verify_key_match(hash, &expected_hash)?;
        }
        KeyIdentifier::PublicKey(pk) => {
            verify_key_match(pk, public_key_bytes)?;
        }
    }

    // Parse the public key and signature
    let vk_bytes: [u8; ED25519_PUBLIC_KEY_LEN] = public_key_bytes.try_into().map_err(|_| {
        ProtokenError::VerificationFailed(format!(
            "invalid Ed25519 public key: expected {} bytes, got {}",
            ED25519_PUBLIC_KEY_LEN,
            public_key_bytes.len()
        ))
    })?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&vk_bytes).map_err(|e| {
        ProtokenError::VerificationFailed(format!("invalid Ed25519 public key: {e}"))
    })?;

    let sig_bytes: [u8; ED25519_SIG_LEN] = token.signature.as_slice().try_into().map_err(|_| {
        ProtokenError::VerificationFailed(format!(
            "invalid Ed25519 signature: expected {} bytes, got {}",
            ED25519_SIG_LEN,
            token.signature.len()
        ))
    })?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    verifying_key
        .verify(&token.payload_bytes, &signature)
        .map_err(|_| {
            ProtokenError::VerificationFailed("Ed25519 signature verification failed".into())
        })?;

    check_temporal_claims(&payload.claims, now)?;

    Ok(VerifiedClaims {
        claims: payload.claims,
        metadata: payload.metadata,
    })
}

/// Verify an ML-DSA-44 signed token.
///
/// `public_key_bytes` is the ML-DSA-44 public key (1,312 bytes).
/// `token_bytes` is the serialized SignedToken wire bytes.
/// `now` is the current Unix timestamp for expiry checking.
pub fn verify_mldsa44(
    public_key_bytes: &[u8],
    token_bytes: &[u8],
    now: u64,
) -> Result<VerifiedClaims, ProtokenError> {
    let token = deserialize_signed_token(token_bytes)?;
    let payload = deserialize_payload(&token.payload_bytes)?;

    if payload.metadata.algorithm != Algorithm::MlDsa44 {
        return Err(ProtokenError::VerificationFailed(format!(
            "expected ML-DSA-44, got {:?}",
            payload.metadata.algorithm
        )));
    }

    // Check key identity (constant-time comparison)
    let expected_hash = compute_key_hash(public_key_bytes);
    match &payload.metadata.key_identifier {
        KeyIdentifier::KeyHash(hash) => {
            verify_key_match(hash, &expected_hash)?;
        }
        KeyIdentifier::PublicKey(pk) => {
            verify_key_match(pk, public_key_bytes)?;
        }
    }

    // Parse the public key
    let vk_encoded: &ml_dsa::EncodedVerifyingKey<MlDsa44> =
        public_key_bytes.try_into().map_err(|_| {
            ProtokenError::VerificationFailed(format!(
                "invalid ML-DSA-44 public key: expected {} bytes, got {}",
                MLDSA44_PUBLIC_KEY_LEN,
                public_key_bytes.len()
            ))
        })?;
    let verifying_key = ml_dsa::VerifyingKey::<MlDsa44>::decode(vk_encoded);

    // Parse the signature
    let signature =
        ml_dsa::Signature::<MlDsa44>::try_from(token.signature.as_slice()).map_err(|_| {
            ProtokenError::VerificationFailed("invalid ML-DSA-44 signature encoding".into())
        })?;

    verifying_key
        .verify(&token.payload_bytes, &signature)
        .map_err(|_| {
            ProtokenError::VerificationFailed("ML-DSA-44 signature verification failed".into())
        })?;

    check_temporal_claims(&payload.claims, now)?;

    Ok(VerifiedClaims {
        claims: payload.claims,
        metadata: payload.metadata,
    })
}

/// Check expires_at and not_before against current time.
fn check_temporal_claims(claims: &Claims, now: u64) -> Result<(), ProtokenError> {
    if claims.expires_at == 0 {
        return Err(ProtokenError::VerificationFailed(
            "token has no expiry (expires_at = 0)".into(),
        ));
    }
    if now > claims.expires_at {
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
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    use crate::sign::{
        generate_ed25519_key, generate_mldsa44_key, mldsa44_key_hash, sign_ed25519, sign_hmac,
        sign_mldsa44,
    };

    #[test]
    fn test_verify_hmac_valid() {
        let key = b"test-hmac-key-123";
        let claims = Claims {
            expires_at: u64::MAX,
            ..Default::default()
        };
        let token_bytes = sign_hmac(key, claims).unwrap();

        let result = verify_hmac(key, &token_bytes, 1700000000);
        assert!(result.is_ok());
        let verified = result.unwrap();
        assert_eq!(verified.claims.expires_at, u64::MAX);
    }

    #[test]
    fn test_verify_hmac_wrong_key() {
        let key = b"correct-key";
        let wrong_key = b"wrong-key";
        let claims = Claims {
            expires_at: u64::MAX,
            ..Default::default()
        };
        let token_bytes = sign_hmac(key, claims).unwrap();

        let result = verify_hmac(wrong_key, &token_bytes, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_hmac_expired() {
        let key = b"test-key";
        let claims = Claims {
            expires_at: 1000,
            ..Default::default()
        };
        let token_bytes = sign_hmac(key, claims).unwrap();

        let result = verify_hmac(key, &token_bytes, 2000);
        assert!(matches!(result, Err(ProtokenError::TokenExpired { .. })));
    }

    #[test]
    fn test_verify_hmac_corrupted_payload() {
        let key = b"test-key";
        let claims = Claims {
            expires_at: u64::MAX,
            ..Default::default()
        };
        let mut token_bytes = sign_hmac(key, claims).unwrap();
        // Corrupt a byte in the payload area (after the proto3 envelope header)
        token_bytes[5] ^= 0xFF;

        let result = verify_hmac(key, &token_bytes, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_hmac_corrupted_signature() {
        let key = b"test-key";
        let claims = Claims {
            expires_at: u64::MAX,
            ..Default::default()
        };
        let mut token_bytes = sign_hmac(key, claims).unwrap();
        let last = token_bytes.len() - 1;
        token_bytes[last] ^= 0xFF;

        let result = verify_hmac(key, &token_bytes, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_ed25519_valid() {
        let (seed, pk) = generate_ed25519_key().unwrap();
        let key_id = KeyIdentifier::KeyHash(compute_key_hash(&pk));
        let claims = Claims {
            expires_at: u64::MAX,
            ..Default::default()
        };
        let token_bytes = sign_ed25519(&seed, claims, key_id).unwrap();

        let result = verify_ed25519(&pk, &token_bytes, 1700000000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_ed25519_expired() {
        let (seed, pk) = generate_ed25519_key().unwrap();
        let key_id = KeyIdentifier::KeyHash(compute_key_hash(&pk));
        let claims = Claims {
            expires_at: 1000,
            ..Default::default()
        };
        let token_bytes = sign_ed25519(&seed, claims, key_id).unwrap();

        let result = verify_ed25519(&pk, &token_bytes, 2000);
        assert!(matches!(result, Err(ProtokenError::TokenExpired { .. })));
    }

    #[test]
    fn test_verify_ed25519_corrupted_signature() {
        let (seed, pk) = generate_ed25519_key().unwrap();
        let key_id = KeyIdentifier::KeyHash(compute_key_hash(&pk));
        let claims = Claims {
            expires_at: u64::MAX,
            ..Default::default()
        };
        let mut token_bytes = sign_ed25519(&seed, claims, key_id).unwrap();
        let last = token_bytes.len() - 1;
        token_bytes[last] ^= 0xFF;

        let result = verify_ed25519(&pk, &token_bytes, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_hmac_corrupt_every_byte_with_scopes() {
        let key = b"scope-corruption-key";
        let claims = Claims {
            expires_at: u64::MAX,
            scopes: vec!["admin".into(), "read".into(), "write".into()],
            ..Default::default()
        };

        let token_bytes = sign_hmac(key, claims).unwrap();

        for i in 0..token_bytes.len() {
            let mut corrupted = token_bytes.clone();
            corrupted[i] ^= 0x01;

            let result = verify_hmac(key, &corrupted, 2000);
            assert!(
                result.is_err(),
                "corrupting byte {i} should cause verification failure"
            );
        }
    }

    #[test]
    fn test_hmac_corrupt_every_byte() {
        let key = b"corruption-test-key";
        let claims = Claims {
            expires_at: u64::MAX,
            not_before: 1000,
            subject: "test".into(),
            ..Default::default()
        };

        let token_bytes = sign_hmac(key, claims).unwrap();

        for i in 0..token_bytes.len() {
            let mut corrupted = token_bytes.clone();
            corrupted[i] ^= 0x01;

            let result = verify_hmac(key, &corrupted, 2000);
            assert!(
                result.is_err(),
                "corrupting byte {i} should cause verification failure"
            );
        }
    }

    #[test]
    fn test_ed25519_corrupt_every_byte() {
        let (seed, pk) = generate_ed25519_key().unwrap();
        let key_id = KeyIdentifier::KeyHash(compute_key_hash(&pk));
        let claims = Claims {
            expires_at: u64::MAX,
            subject: "test".into(),
            audience: "svc".into(),
            ..Default::default()
        };

        let token_bytes = sign_ed25519(&seed, claims, key_id).unwrap();

        for i in 0..token_bytes.len() {
            let mut corrupted = token_bytes.clone();
            corrupted[i] ^= 0x01;

            let result = verify_ed25519(&pk, &corrupted, 1000);
            assert!(
                result.is_err(),
                "corrupting byte {i} should cause verification failure"
            );
        }
    }

    #[test]
    fn test_verify_not_before() {
        let key = b"test-nbf-key";
        let claims = Claims {
            expires_at: u64::MAX,
            not_before: 5000,
            ..Default::default()
        };

        let token_bytes = sign_hmac(key, claims).unwrap();

        // Before not_before -> should fail
        let result = verify_hmac(key, &token_bytes, 3000);
        assert!(matches!(
            result,
            Err(ProtokenError::TokenNotYetValid { .. })
        ));

        // At not_before -> should succeed
        let result = verify_hmac(key, &token_bytes, 5000);
        assert!(result.is_ok());

        // After not_before -> should succeed
        let result = verify_hmac(key, &token_bytes, 6000);
        assert!(result.is_ok());
    }

    // ML-DSA-44 verification tests

    #[test]
    fn test_verify_mldsa44_valid() {
        let (sk, pk) = generate_mldsa44_key().unwrap();
        let key_id = mldsa44_key_hash(&pk).unwrap();
        let claims = Claims {
            expires_at: u64::MAX,
            ..Default::default()
        };
        let token_bytes = sign_mldsa44(&sk, claims, key_id).unwrap();

        let result = verify_mldsa44(&pk, &token_bytes, 1700000000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_mldsa44_expired() {
        let (sk, pk) = generate_mldsa44_key().unwrap();
        let key_id = mldsa44_key_hash(&pk).unwrap();
        let claims = Claims {
            expires_at: 1000,
            ..Default::default()
        };
        let token_bytes = sign_mldsa44(&sk, claims, key_id).unwrap();

        let result = verify_mldsa44(&pk, &token_bytes, 2000);
        assert!(matches!(result, Err(ProtokenError::TokenExpired { .. })));
    }

    #[test]
    fn test_verify_mldsa44_wrong_key() {
        let (sk1, pk1) = generate_mldsa44_key().unwrap();
        let (_sk2, pk2) = generate_mldsa44_key().unwrap();
        let key_id = mldsa44_key_hash(&pk1).unwrap();
        let claims = Claims {
            expires_at: u64::MAX,
            ..Default::default()
        };
        let token_bytes = sign_mldsa44(&sk1, claims, key_id).unwrap();

        let result = verify_mldsa44(&pk2, &token_bytes, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_mldsa44_corrupted_signature() {
        let (sk, pk) = generate_mldsa44_key().unwrap();
        let key_id = mldsa44_key_hash(&pk).unwrap();
        let claims = Claims {
            expires_at: u64::MAX,
            ..Default::default()
        };
        let mut token_bytes = sign_mldsa44(&sk, claims, key_id).unwrap();
        let last = token_bytes.len() - 1;
        token_bytes[last] ^= 0xFF;

        let result = verify_mldsa44(&pk, &token_bytes, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_mldsa44_with_public_key_id() {
        let (sk, pk) = generate_mldsa44_key().unwrap();
        let key_id = KeyIdentifier::PublicKey(pk.clone());
        let claims = Claims {
            expires_at: u64::MAX,
            ..Default::default()
        };
        let token_bytes = sign_mldsa44(&sk, claims, key_id).unwrap();

        let result = verify_mldsa44(&pk, &token_bytes, 0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_mldsa44_not_before() {
        let (sk, pk) = generate_mldsa44_key().unwrap();
        let key_id = mldsa44_key_hash(&pk).unwrap();
        let claims = Claims {
            expires_at: u64::MAX,
            not_before: 5000,
            ..Default::default()
        };

        let token_bytes = sign_mldsa44(&sk, claims, key_id).unwrap();

        // Before not_before -> should fail
        let result = verify_mldsa44(&pk, &token_bytes, 3000);
        assert!(matches!(
            result,
            Err(ProtokenError::TokenNotYetValid { .. })
        ));

        // At not_before -> should succeed
        let result = verify_mldsa44(&pk, &token_bytes, 5000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_mldsa44_sign_verify_with_full_claims() {
        let (sk, pk) = generate_mldsa44_key().unwrap();
        let key_id = mldsa44_key_hash(&pk).unwrap();
        let claims = Claims {
            expires_at: u64::MAX,
            not_before: 1000,
            issued_at: 1000,
            subject: "pq-user".into(),
            audience: "pq-service".into(),
            scopes: vec!["admin".into(), "read".into(), "write".into()],
        };

        let token_bytes = sign_mldsa44(&sk, claims.clone(), key_id).unwrap();
        let result = verify_mldsa44(&pk, &token_bytes, 2000);
        assert!(result.is_ok());
        let verified = result.unwrap();
        assert_eq!(verified.claims, claims);
        assert_eq!(verified.metadata.algorithm, Algorithm::MlDsa44);
    }
}
