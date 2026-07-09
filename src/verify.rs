//! Token verification: HMAC-SHA256, Ed25519, and ML-DSA-44.
//!
//! Verification order for every algorithm:
//! 1. Parse the envelope (structure and size checks only).
//! 2. Check the envelope algorithm matches the caller's key type.
//! 3. Check the key identifier matches the caller's key (constant time).
//! 4. Verify the signature over the envelope's signing input.
//! 5. Only then parse the payload as Claims and check temporal validity.

use ed25519_dalek::Verifier as _;
use hmac::{Hmac, Mac};
use ml_dsa::signature::Verifier as _;
use ml_dsa::MlDsa44;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::ProtokenError;
use crate::serialize::{deserialize_claims, deserialize_signed_token_at};
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

/// Check the token's key identifier against the caller's key material
/// (constant time): a KeyHash must match the hash of the key material, an
/// embedded PublicKey must match it byte for byte.
fn check_key_identity(id: &KeyIdentifier, key_material: &[u8]) -> Result<(), ProtokenError> {
    match id {
        KeyIdentifier::KeyHash(hash) => verify_key_match(hash, &compute_key_hash(key_material)),
        KeyIdentifier::PublicKey(pk) => verify_key_match(pk, key_material),
    }
}

/// Result of a successful token verification.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifiedToken {
    pub algorithm: Algorithm,
    pub key_identifier: KeyIdentifier,
    pub claims: Claims,
}

/// Parse the envelope, check the expected algorithm, and return the signed
/// bytes: the received token bytes up to the signature field. The decoder
/// enforces canonical encoding, so these are exactly the bytes the signer
/// produced with `serialize_signing_input`.
fn parse_envelope(
    token_bytes: &[u8],
    expected_algorithm: Algorithm,
) -> Result<(SignedToken, &[u8]), ProtokenError> {
    let (token, signed_len) = deserialize_signed_token_at(token_bytes)?;
    if token.algorithm != expected_algorithm {
        return Err(ProtokenError::VerificationFailed(format!(
            "expected {:?}, got {:?}",
            expected_algorithm, token.algorithm
        )));
    }
    let signing_input = token_bytes.get(..signed_len).ok_or_else(|| {
        ProtokenError::MalformedEncoding("signature field offset out of range".into())
    })?;
    Ok((token, signing_input))
}

/// Parse the verified payload and check temporal claims.
fn finish_verification(token: SignedToken, now: u64) -> Result<VerifiedToken, ProtokenError> {
    let claims = deserialize_claims(&token.payload)?;
    check_temporal_claims(&claims, now)?;
    Ok(VerifiedToken {
        algorithm: token.algorithm,
        key_identifier: token.key_identifier,
        claims,
    })
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
) -> Result<VerifiedToken, ProtokenError> {
    if key.len() < HMAC_MIN_KEY_LEN {
        return Err(ProtokenError::VerificationFailed(format!(
            "HMAC key too short: {} bytes (minimum {})",
            key.len(),
            HMAC_MIN_KEY_LEN
        )));
    }
    let (token, signing_input) = parse_envelope(token_bytes, Algorithm::HmacSha256)?;

    // The parser guarantees HMAC tokens use a KeyHash identifier.
    check_key_identity(&token.key_identifier, key)?;

    // mac.verify_slice rejects wrong-length tags, so no separate length check.
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|e| ProtokenError::VerificationFailed(format!("invalid HMAC key: {e}")))?;
    mac.update(signing_input);
    mac.verify_slice(&token.signature)
        .map_err(|_| ProtokenError::VerificationFailed("HMAC verification failed".into()))?;

    finish_verification(token, now)
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
) -> Result<VerifiedToken, ProtokenError> {
    let (token, signing_input) = parse_envelope(token_bytes, Algorithm::Ed25519)?;
    check_key_identity(&token.key_identifier, public_key_bytes)?;

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
        .verify(signing_input, &signature)
        .map_err(|_| {
            ProtokenError::VerificationFailed("Ed25519 signature verification failed".into())
        })?;

    finish_verification(token, now)
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
) -> Result<VerifiedToken, ProtokenError> {
    let (token, signing_input) = parse_envelope(token_bytes, Algorithm::MlDsa44)?;
    check_key_identity(&token.key_identifier, public_key_bytes)?;

    let vk_encoded: &ml_dsa::EncodedVerifyingKey<MlDsa44> =
        public_key_bytes.try_into().map_err(|_| {
            ProtokenError::VerificationFailed(format!(
                "invalid ML-DSA-44 public key: expected {} bytes, got {}",
                MLDSA44_PUBLIC_KEY_LEN,
                public_key_bytes.len()
            ))
        })?;
    let verifying_key = ml_dsa::VerifyingKey::<MlDsa44>::decode(vk_encoded);

    let signature =
        ml_dsa::Signature::<MlDsa44>::try_from(token.signature.as_slice()).map_err(|_| {
            ProtokenError::VerificationFailed("invalid ML-DSA-44 signature encoding".into())
        })?;

    verifying_key
        .verify(signing_input, &signature)
        .map_err(|_| {
            ProtokenError::VerificationFailed("ML-DSA-44 signature verification failed".into())
        })?;

    finish_verification(token, now)
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

    use crate::serialize::{
        deserialize_signed_token, serialize_claims, serialize_signed_token, serialize_signing_input,
    };
    use crate::sign::{
        generate_ed25519_key, generate_mldsa44_key, sign_ed25519, sign_hmac, sign_mldsa44,
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
        let token_bytes = sign_hmac(key, &claims).unwrap();

        let verified = verify_hmac(key, &token_bytes, 1700000000).unwrap();
        assert_eq!(verified.claims.expires_at, u64::MAX);
        assert_eq!(verified.algorithm, Algorithm::HmacSha256);
    }

    #[test]
    fn test_verify_hmac_wrong_key() {
        let key: &[u8] = TEST_HMAC_KEY;
        let wrong_key: &[u8] = WRONG_HMAC_KEY;
        let claims = Claims {
            expires_at: u64::MAX,
            ..Default::default()
        };
        let token_bytes = sign_hmac(key, &claims).unwrap();

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
        let token_bytes = sign_hmac(key, &claims).unwrap();

        let result = verify_hmac(key, &token_bytes, 2000);
        assert!(matches!(result, Err(ProtokenError::TokenExpired { .. })));
    }

    #[test]
    fn test_verify_hmac_at_expiry_boundary() {
        // now == expires_at is still valid; now == expires_at + 1 is not.
        let key: &[u8] = TEST_HMAC_KEY;
        let claims = Claims {
            expires_at: 5000,
            ..Default::default()
        };
        let token_bytes = sign_hmac(key, &claims).unwrap();

        assert!(verify_hmac(key, &token_bytes, 5000).is_ok());
        assert!(matches!(
            verify_hmac(key, &token_bytes, 5001),
            Err(ProtokenError::TokenExpired { .. })
        ));
    }

    #[test]
    fn test_verify_hmac_corrupted_payload() {
        let key: &[u8] = TEST_HMAC_KEY;
        let claims = Claims {
            expires_at: u64::MAX,
            ..Default::default()
        };
        let mut token_bytes = sign_hmac(key, &claims).unwrap();
        // Corrupt a byte inside the payload field
        let last = token_bytes.len() - 40;
        token_bytes[last] ^= 0xFF;

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
        let mut token_bytes = sign_hmac(key, &claims).unwrap();
        let last = token_bytes.len() - 1;
        token_bytes[last] ^= 0xFF;

        let result = verify_hmac(key, &token_bytes, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_ed25519_valid() {
        let (seed, pk) = generate_ed25519_key();
        let key_id = KeyIdentifier::KeyHash(compute_key_hash(&pk));
        let claims = Claims {
            expires_at: u64::MAX,
            ..Default::default()
        };
        let token_bytes = sign_ed25519(&seed, &claims, key_id).unwrap();

        let result = verify_ed25519(&pk, &token_bytes, 1700000000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_ed25519_with_embedded_public_key() {
        let (seed, pk) = generate_ed25519_key();
        let key_id = KeyIdentifier::PublicKey(pk.clone());
        let claims = Claims {
            expires_at: u64::MAX,
            ..Default::default()
        };
        let token_bytes = sign_ed25519(&seed, &claims, key_id).unwrap();

        let result = verify_ed25519(&pk, &token_bytes, 1700000000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_ed25519_expired() {
        let (seed, pk) = generate_ed25519_key();
        let key_id = KeyIdentifier::KeyHash(compute_key_hash(&pk));
        let claims = Claims {
            expires_at: 1000,
            ..Default::default()
        };
        let token_bytes = sign_ed25519(&seed, &claims, key_id).unwrap();

        let result = verify_ed25519(&pk, &token_bytes, 2000);
        assert!(matches!(result, Err(ProtokenError::TokenExpired { .. })));
    }

    #[test]
    fn test_verify_ed25519_wrong_key() {
        let (seed, pk) = generate_ed25519_key();
        let (_seed2, pk2) = generate_ed25519_key();
        let key_id = KeyIdentifier::KeyHash(compute_key_hash(&pk));
        let claims = Claims {
            expires_at: u64::MAX,
            ..Default::default()
        };
        let token_bytes = sign_ed25519(&seed, &claims, key_id).unwrap();

        let result = verify_ed25519(&pk2, &token_bytes, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_ed25519_corrupted_signature() {
        let (seed, pk) = generate_ed25519_key();
        let key_id = KeyIdentifier::KeyHash(compute_key_hash(&pk));
        let claims = Claims {
            expires_at: u64::MAX,
            ..Default::default()
        };
        let mut token_bytes = sign_ed25519(&seed, &claims, key_id).unwrap();
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

        let token_bytes = sign_hmac(key, &claims).unwrap();

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

        let token_bytes = sign_hmac(key, &claims).unwrap();

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
        let (seed, pk) = generate_ed25519_key();
        let key_id = KeyIdentifier::KeyHash(compute_key_hash(&pk));
        let claims = Claims {
            expires_at: u64::MAX,
            subject: "test".into(),
            audience: "svc".into(),
            ..Default::default()
        };

        let token_bytes = sign_ed25519(&seed, &claims, key_id).unwrap();

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

        let token_bytes = sign_hmac(key, &claims).unwrap();

        // Before not_before -> should fail
        let result = verify_hmac(key, &token_bytes, 3000);
        assert!(matches!(
            result,
            Err(ProtokenError::TokenNotYetValid { .. })
        ));

        // At not_before -> should succeed
        assert!(verify_hmac(key, &token_bytes, 5000).is_ok());

        // After not_before -> should succeed
        assert!(verify_hmac(key, &token_bytes, 6000).is_ok());
    }

    #[test]
    fn test_verify_rejects_wrong_algorithm_token() {
        // A valid HMAC token must not verify as Ed25519 or ML-DSA-44 —
        // the algorithm is bound into the envelope.
        let key: &[u8] = TEST_HMAC_KEY;
        let claims = Claims {
            expires_at: u64::MAX,
            ..Default::default()
        };
        let token_bytes = sign_hmac(key, &claims).unwrap();

        let (_seed, pk) = generate_ed25519_key();
        let result = verify_ed25519(&pk, &token_bytes, 1000);
        assert!(
            matches!(&result, Err(ProtokenError::VerificationFailed(m)) if m.contains("expected")),
            "HMAC token must not pass Ed25519 verification, got {result:?}"
        );
    }

    #[test]
    fn test_verify_rejects_algorithm_swap() {
        // Take a valid HMAC token and rewrite its algorithm field to Ed25519.
        // The signature covers the algorithm, so verification must fail even
        // if everything else is intact.
        let key: &[u8] = TEST_HMAC_KEY;
        let claims = Claims {
            expires_at: u64::MAX,
            ..Default::default()
        };
        let token_bytes = sign_hmac(key, &claims).unwrap();
        let token = deserialize_signed_token(&token_bytes).unwrap();

        let swapped = SignedToken {
            algorithm: Algorithm::Ed25519,
            ..token
        };
        let swapped_bytes = serialize_signed_token(&swapped);

        // As an Ed25519 token, the 32-byte HMAC tag is not a valid signature length.
        let (_seed, pk) = generate_ed25519_key();
        assert!(verify_ed25519(&pk, &swapped_bytes, 1000).is_err());
        // And it no longer parses as an HMAC token.
        assert!(verify_hmac(key, &swapped_bytes, 1000).is_err());
    }

    // ML-DSA-44 verification tests

    #[test]
    fn test_verify_mldsa44_valid() {
        let (sk, pk) = generate_mldsa44_key();
        let key_id = KeyIdentifier::KeyHash(compute_key_hash(&pk));
        let claims = Claims {
            expires_at: u64::MAX,
            ..Default::default()
        };
        let token_bytes = sign_mldsa44(&sk, &claims, key_id).unwrap();

        let result = verify_mldsa44(&pk, &token_bytes, 1700000000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_mldsa44_expired() {
        let (sk, pk) = generate_mldsa44_key();
        let key_id = KeyIdentifier::KeyHash(compute_key_hash(&pk));
        let claims = Claims {
            expires_at: 1000,
            ..Default::default()
        };
        let token_bytes = sign_mldsa44(&sk, &claims, key_id).unwrap();

        let result = verify_mldsa44(&pk, &token_bytes, 2000);
        assert!(matches!(result, Err(ProtokenError::TokenExpired { .. })));
    }

    #[test]
    fn test_verify_mldsa44_wrong_key() {
        let (sk1, pk1) = generate_mldsa44_key();
        let (_sk2, pk2) = generate_mldsa44_key();
        let key_id = KeyIdentifier::KeyHash(compute_key_hash(&pk1));
        let claims = Claims {
            expires_at: u64::MAX,
            ..Default::default()
        };
        let token_bytes = sign_mldsa44(&sk1, &claims, key_id).unwrap();

        let result = verify_mldsa44(&pk2, &token_bytes, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_mldsa44_corrupted_signature() {
        let (sk, pk) = generate_mldsa44_key();
        let key_id = KeyIdentifier::KeyHash(compute_key_hash(&pk));
        let claims = Claims {
            expires_at: u64::MAX,
            ..Default::default()
        };
        let mut token_bytes = sign_mldsa44(&sk, &claims, key_id).unwrap();
        let last = token_bytes.len() - 1;
        token_bytes[last] ^= 0xFF;

        let result = verify_mldsa44(&pk, &token_bytes, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_mldsa44_with_public_key_id() {
        let (sk, pk) = generate_mldsa44_key();
        let key_id = KeyIdentifier::PublicKey(pk.clone());
        let claims = Claims {
            expires_at: u64::MAX,
            ..Default::default()
        };
        let token_bytes = sign_mldsa44(&sk, &claims, key_id).unwrap();

        let result = verify_mldsa44(&pk, &token_bytes, 0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_mldsa44_not_before() {
        let (sk, pk) = generate_mldsa44_key();
        let key_id = KeyIdentifier::KeyHash(compute_key_hash(&pk));
        let claims = Claims {
            expires_at: u64::MAX,
            not_before: 5000,
            ..Default::default()
        };

        let token_bytes = sign_mldsa44(&sk, &claims, key_id).unwrap();

        // Before not_before -> should fail
        let result = verify_mldsa44(&pk, &token_bytes, 3000);
        assert!(matches!(
            result,
            Err(ProtokenError::TokenNotYetValid { .. })
        ));

        // At not_before -> should succeed
        assert!(verify_mldsa44(&pk, &token_bytes, 5000).is_ok());
    }

    #[test]
    fn test_mldsa44_sign_verify_with_full_claims() {
        let (sk, pk) = generate_mldsa44_key();
        let key_id = KeyIdentifier::KeyHash(compute_key_hash(&pk));
        let claims = Claims {
            expires_at: u64::MAX,
            not_before: 1000,
            issued_at: 1000,
            subject: "pq-user".into(),
            audience: "pq-service".into(),
            scopes: vec!["admin".into(), "read".into(), "write".into()],
        };

        let token_bytes = sign_mldsa44(&sk, &claims, key_id).unwrap();
        let verified = verify_mldsa44(&pk, &token_bytes, 2000).unwrap();
        assert_eq!(verified.claims, claims);
        assert_eq!(verified.algorithm, Algorithm::MlDsa44);
    }

    /// Build a token with sign_key's signature but verify_key's key_hash.
    /// This isolates `verify_key_match` — the signature is valid but the
    /// key identity check should fail first with `KeyHashMismatch`.
    fn build_hmac_token_with_key_hash_of(sign_key: &[u8], hash_key: &[u8]) -> Vec<u8> {
        let claims = Claims {
            expires_at: u64::MAX,
            ..Default::default()
        };
        let key_id = KeyIdentifier::KeyHash(compute_key_hash(hash_key));
        let payload = serialize_claims(&claims);
        let signing_input =
            serialize_signing_input(Version::V0, Algorithm::HmacSha256, &key_id, &payload);
        let mut mac = Hmac::<Sha256>::new_from_slice(sign_key).unwrap();
        mac.update(&signing_input);
        let tag = mac.finalize().into_bytes();
        serialize_signed_token(&SignedToken {
            version: Version::V0,
            algorithm: Algorithm::HmacSha256,
            key_identifier: key_id,
            payload,
            signature: tag.to_vec(),
        })
    }

    #[test]
    fn test_verify_key_match_rejects_mismatch() {
        // verify_key_match should produce KeyHashMismatch specifically — not
        // just any error — when the key hash doesn't match. This proves the
        // key identity check is an independent defense layer, not shadowed by
        // signature verification.
        let key_a: &[u8] = TEST_HMAC_KEY;
        let key_b: &[u8] = WRONG_HMAC_KEY;

        // Token signed with key_a but claims key_b's hash. Verify with key_a.
        let token = build_hmac_token_with_key_hash_of(key_a, key_b);
        let result = verify_hmac(key_a, &token, 1000);
        assert!(
            matches!(result, Err(ProtokenError::KeyHashMismatch)),
            "expected KeyHashMismatch, got {result:?}"
        );
    }

    #[test]
    fn test_verify_key_match_accepts_match() {
        // Positive case: key_hash matches, signature valid → Ok.
        let key: &[u8] = TEST_HMAC_KEY;
        let token = build_hmac_token_with_key_hash_of(key, key);
        assert!(verify_hmac(key, &token, 1000).is_ok());
    }

    #[test]
    fn test_verify_ed25519_key_hash_mismatch() {
        // Sign with key A using key B's key hash; verify with key A.
        // Signature is valid for A, but key identity check must fail.
        let (seed_a, pk_a) = generate_ed25519_key();
        let (_seed_b, pk_b) = generate_ed25519_key();
        let claims = Claims {
            expires_at: u64::MAX,
            ..Default::default()
        };
        let token_bytes = sign_ed25519(
            &seed_a,
            &claims,
            KeyIdentifier::KeyHash(compute_key_hash(&pk_b)),
        )
        .unwrap();
        let result = verify_ed25519(&pk_a, &token_bytes, 1000);
        assert!(
            matches!(result, Err(ProtokenError::KeyHashMismatch)),
            "expected KeyHashMismatch, got {result:?}"
        );
    }

    #[test]
    fn test_verify_rejects_malleated_version_prefix() {
        // Regression test: prepending an explicit version=0 field (bytes
        // 0x08 0x00) once produced a byte-distinct token that still verified,
        // because verification re-canonicalized the signing input. Both the
        // decoder (rejects explicit defaults) and verification over the
        // received wire prefix must reject it.
        let key: &[u8] = TEST_HMAC_KEY;
        let claims = Claims {
            expires_at: u64::MAX,
            ..Default::default()
        };
        let token_bytes = sign_hmac(key, &claims).unwrap();

        let mut malleated = vec![0x08, 0x00];
        malleated.extend_from_slice(&token_bytes);
        assert!(
            verify_hmac(key, &malleated, 1000).is_err(),
            "byte-distinct token with explicit version=0 must not verify"
        );
    }

    #[test]
    fn test_verify_rejects_zero_expiry_claims() {
        // A token whose payload has expires_at=0 (plus another claim so the
        // payload is non-empty) must fail temporal validation.
        let key: &[u8] = TEST_HMAC_KEY;
        let claims = Claims {
            issued_at: 1000,
            ..Default::default()
        };
        let key_id = KeyIdentifier::KeyHash(compute_key_hash(key));
        let payload = serialize_claims(&claims);
        let signing_input =
            serialize_signing_input(Version::V0, Algorithm::HmacSha256, &key_id, &payload);
        let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
        mac.update(&signing_input);
        let tag = mac.finalize().into_bytes();
        let token_bytes = serialize_signed_token(&SignedToken {
            version: Version::V0,
            algorithm: Algorithm::HmacSha256,
            key_identifier: key_id,
            payload,
            signature: tag.to_vec(),
        });

        let result = verify_hmac(key, &token_bytes, 1000);
        assert!(
            matches!(&result, Err(ProtokenError::VerificationFailed(m)) if m.contains("no expiry")),
            "expected no-expiry error, got {result:?}"
        );
    }
}
