//! Token verification: HMAC-SHA256, Ed25519, ML-DSA-44, Groth16-Poseidon, and Groth16-Hybrid.

use hmac::{Hmac, Mac};
use ml_dsa::signature::Verifier as _;
use ml_dsa::MlDsa44;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::ProtokenError;
use crate::serialize::{deserialize_payload, deserialize_signed_token};
use crate::sign::compute_key_hash;
use crate::snark::SnarkVerifyingKey;
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
        KeyIdentifier::PublicKey(_) | KeyIdentifier::FullKeyHash(_) => {
            return Err(ProtokenError::VerificationFailed(
                "HMAC token must use KeyHash key identifier".into(),
            ));
        }
    }

    // Validate signature length before verification
    if token.signature.len() != HMAC_SHA256_SIG_LEN {
        return Err(ProtokenError::VerificationFailed(format!(
            "invalid HMAC-SHA256 signature: expected {} bytes, got {}",
            HMAC_SHA256_SIG_LEN,
            token.signature.len()
        )));
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
        KeyIdentifier::FullKeyHash(_) => {
            return Err(ProtokenError::VerificationFailed(
                "Ed25519 token cannot use FullKeyHash key identifier".into(),
            ));
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
        KeyIdentifier::FullKeyHash(_) => {
            return Err(ProtokenError::VerificationFailed(
                "ML-DSA-44 token cannot use FullKeyHash key identifier".into(),
            ));
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

/// Verify a Groth16-Poseidon token (symmetric key SNARK proof).
///
/// `vk` is the Groth16 SNARK verifying key from `snark::setup()`.
/// `token_bytes` is the serialized SignedToken wire bytes.
/// `now` is the current Unix timestamp for expiry checking.
pub fn verify_groth16(
    vk: &SnarkVerifyingKey,
    token_bytes: &[u8],
    now: u64,
) -> Result<VerifiedClaims, ProtokenError> {
    let token = deserialize_signed_token(token_bytes)?;
    let payload = deserialize_payload(&token.payload_bytes)?;

    if payload.metadata.algorithm != Algorithm::Groth16Poseidon {
        return Err(ProtokenError::VerificationFailed(format!(
            "expected Groth16Poseidon, got {:?}",
            payload.metadata.algorithm
        )));
    }

    // Extract the full key hash from the key identifier
    let key_hash = match &payload.metadata.key_identifier {
        KeyIdentifier::FullKeyHash(hash) => hash,
        _ => {
            return Err(ProtokenError::VerificationFailed(
                "Groth16 token must use FullKeyHash key identifier".into(),
            ));
        }
    };

    // Validate signature length
    if token.signature.len() != HMAC_SHA256_SIG_LEN {
        return Err(ProtokenError::VerificationFailed(format!(
            "invalid Groth16 signature: expected {} bytes, got {}",
            HMAC_SHA256_SIG_LEN,
            token.signature.len()
        )));
    }
    let signature: [u8; 32] = token.signature.as_slice().try_into().map_err(|_| {
        ProtokenError::VerificationFailed("invalid Groth16 signature length".into())
    })?;

    // Validate proof is present
    if token.proof.is_empty() {
        return Err(ProtokenError::VerificationFailed(
            "Groth16 token is missing proof".into(),
        ));
    }

    // Verify the SNARK proof
    crate::snark::verify(vk, key_hash, &signature, &token.proof, &token.payload_bytes)?;

    check_temporal_claims(&payload.claims, now)?;

    Ok(VerifiedClaims {
        claims: payload.claims,
        metadata: payload.metadata,
    })
}

/// Verify a Groth16-Hybrid token (SHA-256 key hash + Poseidon MAC SNARK proof).
///
/// `vk` is the Groth16 SNARK verifying key from `snark::setup_hybrid()`.
/// `token_bytes` is the serialized SignedToken wire bytes.
/// `now` is the current Unix timestamp for expiry checking.
pub fn verify_groth16_hybrid(
    vk: &SnarkVerifyingKey,
    token_bytes: &[u8],
    now: u64,
) -> Result<VerifiedClaims, ProtokenError> {
    let token = deserialize_signed_token(token_bytes)?;
    let payload = deserialize_payload(&token.payload_bytes)?;

    if payload.metadata.algorithm != Algorithm::Groth16Hybrid {
        return Err(ProtokenError::VerificationFailed(format!(
            "expected Groth16Hybrid, got {:?}",
            payload.metadata.algorithm
        )));
    }

    let key_hash = match &payload.metadata.key_identifier {
        KeyIdentifier::FullKeyHash(hash) => hash,
        _ => {
            return Err(ProtokenError::VerificationFailed(
                "Groth16Hybrid token must use FullKeyHash key identifier".into(),
            ));
        }
    };

    if token.signature.len() != HMAC_SHA256_SIG_LEN {
        return Err(ProtokenError::VerificationFailed(format!(
            "invalid Groth16Hybrid signature: expected {} bytes, got {}",
            HMAC_SHA256_SIG_LEN,
            token.signature.len()
        )));
    }
    let signature: [u8; 32] = token.signature.as_slice().try_into().map_err(|_| {
        ProtokenError::VerificationFailed("invalid Groth16Hybrid signature length".into())
    })?;

    if token.proof.is_empty() {
        return Err(ProtokenError::VerificationFailed(
            "Groth16Hybrid token is missing proof".into(),
        ));
    }

    crate::snark::verify_hybrid(vk, key_hash, &signature, &token.proof, &token.payload_bytes)?;

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

    const TEST_HMAC_KEY: &[u8; 32] = &[0xAB; 32];
    const WRONG_HMAC_KEY: &[u8; 32] = &[0xCD; 32];

    #[test]
    fn test_verify_hmac_valid() {
        let key: &[u8] = TEST_HMAC_KEY;
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
        let key: &[u8] = TEST_HMAC_KEY;
        let wrong_key: &[u8] = WRONG_HMAC_KEY;
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
        let key: &[u8] = TEST_HMAC_KEY;
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
        let key: &[u8] = TEST_HMAC_KEY;
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
        let key: &[u8] = TEST_HMAC_KEY;
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
        let key: &[u8] = TEST_HMAC_KEY;
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
        let key: &[u8] = TEST_HMAC_KEY;
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
        let key: &[u8] = TEST_HMAC_KEY;
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

    // Groth16-Poseidon verification tests

    fn groth16_test_token() -> (crate::snark::SnarkVerifyingKey, Vec<u8>, [u8; 32]) {
        let (pk, vk) = crate::snark::setup().unwrap();
        let key = [0x42u8; 32];
        let claims = Claims {
            expires_at: u64::MAX,
            ..Default::default()
        };
        let token_bytes = crate::sign::sign_groth16(&pk, &key, claims).unwrap();
        (vk, token_bytes, key)
    }

    #[test]
    fn test_verify_groth16_valid() {
        let (vk, token_bytes, _key) = groth16_test_token();
        let result = verify_groth16(&vk, &token_bytes, 1700000000);
        assert!(result.is_ok());
        let verified = result.unwrap();
        assert_eq!(verified.metadata.algorithm, Algorithm::Groth16Poseidon);
    }

    #[test]
    fn test_verify_groth16_expired() {
        let (pk, vk) = crate::snark::setup().unwrap();
        let key = [0x42u8; 32];
        let claims = Claims {
            expires_at: 1000,
            ..Default::default()
        };
        let token_bytes = crate::sign::sign_groth16(&pk, &key, claims).unwrap();
        let result = verify_groth16(&vk, &token_bytes, 2000);
        assert!(matches!(result, Err(ProtokenError::TokenExpired { .. })));
    }

    #[test]
    fn test_verify_groth16_not_before() {
        let (pk, vk) = crate::snark::setup().unwrap();
        let key = [0x42u8; 32];
        let claims = Claims {
            expires_at: u64::MAX,
            not_before: 5000,
            ..Default::default()
        };
        let token_bytes = crate::sign::sign_groth16(&pk, &key, claims).unwrap();

        let result = verify_groth16(&vk, &token_bytes, 3000);
        assert!(matches!(
            result,
            Err(ProtokenError::TokenNotYetValid { .. })
        ));

        let result = verify_groth16(&vk, &token_bytes, 5000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_groth16_corrupted_key_hash() {
        let (vk, mut token_bytes, _key) = groth16_test_token();
        // The key hash is inside the payload submessage. Find and corrupt it.
        // The token structure: field 1 (payload LV), field 2 (sig LV), field 3 (proof LV).
        // Corrupt a byte deep in the payload area where the key_hash lives.
        // key_hash is 32 bytes after algorithm+key_id_type fields in the payload.
        // We corrupt byte at offset ~10 which is inside the payload.
        token_bytes[10] ^= 0x01;
        let result = verify_groth16(&vk, &token_bytes, 1700000000);
        assert!(
            result.is_err(),
            "corrupted key hash should fail verification"
        );
    }

    #[test]
    fn test_verify_groth16_corrupted_signature() {
        let (vk, token_bytes, _key) = groth16_test_token();
        let token = crate::serialize::deserialize_signed_token(&token_bytes).unwrap();
        // Corrupt the signature
        let mut bad_sig = token.signature.clone();
        bad_sig[0] ^= 0xFF;
        let bad_token = crate::types::SignedToken {
            payload_bytes: token.payload_bytes,
            signature: bad_sig,
            proof: token.proof,
        };
        let bad_bytes = crate::serialize::serialize_signed_token(&bad_token);
        let result = verify_groth16(&vk, &bad_bytes, 1700000000);
        assert!(
            matches!(&result, Err(ProtokenError::VerificationFailed(msg)) if msg.contains("proof verification failed")),
            "corrupted signature should fail with proof verification error, got: {result:?}"
        );
    }

    #[test]
    fn test_verify_groth16_corrupted_proof() {
        let (vk, token_bytes, _key) = groth16_test_token();
        let token = crate::serialize::deserialize_signed_token(&token_bytes).unwrap();
        // Corrupt the proof
        let mut bad_proof = token.proof.clone();
        bad_proof[0] ^= 0x01;
        let bad_token = crate::types::SignedToken {
            payload_bytes: token.payload_bytes,
            signature: token.signature,
            proof: bad_proof,
        };
        let bad_bytes = crate::serialize::serialize_signed_token(&bad_token);
        let result = verify_groth16(&vk, &bad_bytes, 1700000000);
        assert!(result.is_err(), "corrupted proof should fail verification");
    }

    #[test]
    fn test_verify_groth16_truncated_proof() {
        let (vk, token_bytes, _key) = groth16_test_token();
        let token = crate::serialize::deserialize_signed_token(&token_bytes).unwrap();
        // Truncate the proof
        let bad_token = crate::types::SignedToken {
            payload_bytes: token.payload_bytes,
            signature: token.signature,
            proof: token.proof[..64].to_vec(),
        };
        let bad_bytes = crate::serialize::serialize_signed_token(&bad_token);
        let result = verify_groth16(&vk, &bad_bytes, 1700000000);
        assert!(
            matches!(&result, Err(ProtokenError::VerificationFailed(msg)) if msg.contains("invalid Groth16 proof")),
            "truncated proof should fail with invalid proof error, got: {result:?}"
        );
    }

    #[test]
    fn test_verify_groth16_empty_proof() {
        let (vk, token_bytes, _key) = groth16_test_token();
        let token = crate::serialize::deserialize_signed_token(&token_bytes).unwrap();
        // Empty proof
        let bad_token = crate::types::SignedToken {
            payload_bytes: token.payload_bytes,
            signature: token.signature,
            proof: vec![],
        };
        let bad_bytes = crate::serialize::serialize_signed_token(&bad_token);
        let result = verify_groth16(&vk, &bad_bytes, 1700000000);
        assert!(
            matches!(&result, Err(ProtokenError::VerificationFailed(msg)) if msg.contains("missing proof")),
            "empty proof should fail with missing proof error, got: {result:?}"
        );
    }

    #[test]
    fn test_verify_groth16_wrong_vk() {
        let (_vk1, token_bytes, _key) = groth16_test_token();
        // Generate a different VK (from a different trusted setup)
        let (_pk2, vk2) = crate::snark::setup().unwrap();
        let result = verify_groth16(&vk2, &token_bytes, 1700000000);
        assert!(
            matches!(&result, Err(ProtokenError::VerificationFailed(msg)) if msg.contains("proof verification failed")),
            "wrong verifying key should fail, got: {result:?}"
        );
    }

    #[test]
    fn test_verify_groth16_with_full_claims() {
        let (pk, vk) = crate::snark::setup().unwrap();
        let key = [0x42u8; 32];
        let claims = Claims {
            expires_at: u64::MAX,
            not_before: 1000,
            issued_at: 1000,
            subject: "snark-user".into(),
            audience: "snark-service".into(),
            scopes: vec!["admin".into(), "read".into(), "write".into()],
        };
        let token_bytes = crate::sign::sign_groth16(&pk, &key, claims.clone()).unwrap();
        let result = verify_groth16(&vk, &token_bytes, 2000);
        assert!(result.is_ok());
        let verified = result.unwrap();
        assert_eq!(verified.claims, claims);
        assert_eq!(verified.metadata.algorithm, Algorithm::Groth16Poseidon);
    }

    // ---- Groth16Hybrid verify tests ----
    //
    // SHA-256 circuit needs a large stack in debug mode.

    fn run_with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(f)
            .unwrap()
            .join()
            .unwrap();
    }

    fn groth16_hybrid_test_token() -> (crate::snark::SnarkVerifyingKey, Vec<u8>) {
        let (pk, vk) = crate::snark::setup_hybrid().unwrap();
        let key = [0x42u8; 32];
        let claims = Claims {
            expires_at: 1800000000,
            ..Default::default()
        };
        let token_bytes = crate::sign::sign_groth16_hybrid(&pk, &key, claims).unwrap();
        (vk, token_bytes)
    }

    #[test]
    fn test_verify_groth16_hybrid_valid() {
        run_with_large_stack(|| {
            let (vk, token_bytes) = groth16_hybrid_test_token();
            let result = verify_groth16_hybrid(&vk, &token_bytes, 1700000000);
            assert!(result.is_ok(), "hybrid verify failed: {result:?}");
            let verified = result.unwrap();
            assert_eq!(verified.metadata.algorithm, Algorithm::Groth16Hybrid);
        });
    }

    #[test]
    fn test_verify_groth16_hybrid_expired() {
        run_with_large_stack(|| {
            let (pk, vk) = crate::snark::setup_hybrid().unwrap();
            let key = [0x42u8; 32];
            let claims = Claims {
                expires_at: 1000,
                ..Default::default()
            };
            let token_bytes = crate::sign::sign_groth16_hybrid(&pk, &key, claims).unwrap();
            let result = verify_groth16_hybrid(&vk, &token_bytes, 2000);
            assert!(matches!(result, Err(ProtokenError::TokenExpired { .. })));
        });
    }

    #[test]
    fn test_verify_groth16_hybrid_corrupted_proof() {
        run_with_large_stack(|| {
            let (vk, token_bytes) = groth16_hybrid_test_token();
            let token = crate::serialize::deserialize_signed_token(&token_bytes).unwrap();
            let mut bad_proof = token.proof.clone();
            bad_proof[0] ^= 0x01;
            let bad_token = crate::types::SignedToken {
                payload_bytes: token.payload_bytes,
                signature: token.signature,
                proof: bad_proof,
            };
            let bad_bytes = crate::serialize::serialize_signed_token(&bad_token);
            let result = verify_groth16_hybrid(&vk, &bad_bytes, 1700000000);
            assert!(result.is_err(), "corrupted proof should fail verification");
        });
    }

    #[test]
    fn test_verify_groth16_hybrid_with_full_claims() {
        run_with_large_stack(|| {
            let (pk, vk) = crate::snark::setup_hybrid().unwrap();
            let key = [0x42u8; 32];
            let claims = Claims {
                expires_at: u64::MAX,
                not_before: 1000,
                issued_at: 1000,
                subject: "hybrid-user".into(),
                audience: "hybrid-service".into(),
                scopes: vec!["admin".into(), "read".into()],
            };
            let token_bytes = crate::sign::sign_groth16_hybrid(&pk, &key, claims.clone()).unwrap();
            let result = verify_groth16_hybrid(&vk, &token_bytes, 2000);
            assert!(result.is_ok());
            let verified = result.unwrap();
            assert_eq!(verified.claims, claims);
            assert_eq!(verified.metadata.algorithm, Algorithm::Groth16Hybrid);
        });
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
