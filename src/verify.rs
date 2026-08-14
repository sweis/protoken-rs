//! Token verification: HMAC-SHA256, Ed25519, and ML-DSA-44.
//!
//! Verification order for every algorithm:
//! 1. Parse the envelope (structure and size checks only).
//! 2. Check the envelope algorithm matches the caller's key type.
//! 3. Check the key identifier matches the caller's key (constant time) and
//!    the signature has the algorithm's exact length.
//! 4. Verify the signature over the envelope's signing input.
//! 5. Only then parse the payload as Claims, apply `Claims::validate()`, and
//!    check temporal validity.
//!
//! The functions here take raw key material. `keys::SigningKey::verify` and
//! `keys::VerifyingKey::verify` dispatch on the algorithm.

use ed25519_dalek::Verifier as _;
use hmac::Mac as _;
use ml_dsa::MlDsa44;
use subtle::ConstantTimeEq as _;

use crate::error::ProtokenError;
use crate::serialize::{deserialize_claims, deserialize_signed_token_at};
use crate::sign::{check_hmac_key_len, compute_key_hash, hmac_sha256};
use crate::types::*;

/// Result of a successful token verification.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifiedToken {
    pub algorithm: Algorithm,
    pub key_identifier: KeyIdentifier,
    pub claims: Claims,
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
    check_hmac_key_len(key)?;
    // The parser guarantees HMAC tokens use a KeyHash identifier.
    let (token, signing_input) = parse_envelope(token_bytes, Algorithm::HmacSha256, key)?;

    hmac_sha256(key, signing_input)?
        .verify_slice(&token.signature)
        .map_err(|_| verification_failed("HMAC verification failed"))?;

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
    let (token, signing_input) = parse_envelope(token_bytes, Algorithm::Ed25519, public_key_bytes)?;
    let verifying_key = ed25519_verifying_key(public_key_bytes)?;

    let signature = ed25519_dalek::Signature::from_slice(&token.signature)
        .map_err(|_| verification_failed("invalid Ed25519 signature encoding"))?;
    // verify_strict also rejects small-order public keys and R components, so
    // a signature cannot verify under any key other than the one that made it.
    verifying_key
        .verify_strict(signing_input, &signature)
        .map_err(|_| verification_failed("Ed25519 signature verification failed"))?;

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
    let (token, signing_input) = parse_envelope(token_bytes, Algorithm::MlDsa44, public_key_bytes)?;
    // Decoding the public key expands it, so it comes after the cheap envelope checks.
    let verifying_key = mldsa44_verifying_key(public_key_bytes)?;

    let signature = ml_dsa::Signature::<MlDsa44>::try_from(token.signature.as_slice())
        .map_err(|_| verification_failed("invalid ML-DSA-44 signature encoding"))?;
    verifying_key
        .verify(signing_input, &signature)
        .map_err(|_| verification_failed("ML-DSA-44 signature verification failed"))?;

    finish_verification(token, now)
}

/// Parse and validate an Ed25519 public key. Also used to reject invalid
/// curve points when a key file is loaded.
pub(crate) fn ed25519_verifying_key(
    public_key_bytes: &[u8],
) -> Result<ed25519_dalek::VerifyingKey, ProtokenError> {
    let bytes: &[u8; ED25519_PUBLIC_KEY_LEN] =
        public_key_bytes
            .try_into()
            .map_err(|_| ProtokenError::InvalidKeyLength {
                expected: ED25519_PUBLIC_KEY_LEN,
                actual: public_key_bytes.len(),
            })?;
    ed25519_dalek::VerifyingKey::from_bytes(bytes)
        .map_err(|e| ProtokenError::InvalidKey(format!("invalid Ed25519 public key: {e}")))
}

fn mldsa44_verifying_key(
    public_key_bytes: &[u8],
) -> Result<ml_dsa::VerifyingKey<MlDsa44>, ProtokenError> {
    let encoded: &ml_dsa::EncodedVerifyingKey<MlDsa44> =
        public_key_bytes
            .try_into()
            .map_err(|_| ProtokenError::InvalidKeyLength {
                expected: MLDSA44_PUBLIC_KEY_LEN,
                actual: public_key_bytes.len(),
            })?;
    Ok(ml_dsa::VerifyingKey::<MlDsa44>::decode(encoded))
}

fn verification_failed(msg: &str) -> ProtokenError {
    ProtokenError::VerificationFailed(msg.to_string())
}

/// Parse the envelope, check the expected algorithm and key identity, and
/// return the signed bytes: the received token bytes up to the signature
/// field. The decoder enforces canonical encoding, so these are exactly the
/// bytes the signer produced with `serialize_signing_input`.
///
/// `key_material` is the verifier's own key (HMAC secret or public key). It is
/// compared against the token's key identifier before any signature work.
fn parse_envelope<'a>(
    token_bytes: &'a [u8],
    expected_algorithm: Algorithm,
    key_material: &[u8],
) -> Result<(SignedToken, &'a [u8]), ProtokenError> {
    let (token, signed_len) = deserialize_signed_token_at(token_bytes)?;
    if token.algorithm != expected_algorithm {
        return Err(ProtokenError::VerificationFailed(format!(
            "expected {expected_algorithm}, got {}",
            token.algorithm
        )));
    }
    check_key_identity(&token.key_identifier, key_material)?;
    let expected_sig_len = expected_algorithm.signature_len();
    if token.signature.len() != expected_sig_len {
        return Err(ProtokenError::VerificationFailed(format!(
            "invalid {expected_algorithm} signature length: expected {expected_sig_len} bytes, got {}",
            token.signature.len()
        )));
    }
    let signing_input = token_bytes.get(..signed_len).ok_or_else(|| {
        ProtokenError::MalformedEncoding("signature field offset out of range".into())
    })?;
    Ok((token, signing_input))
}

/// Check the token's key identifier against the caller's key material in
/// constant time: a KeyHash must match the hash of the key material, an
/// embedded PublicKey must match it byte for byte.
fn check_key_identity(id: &KeyIdentifier, key_material: &[u8]) -> Result<(), ProtokenError> {
    let matches = match id {
        KeyIdentifier::KeyHash(hash) => hash.ct_eq(&compute_key_hash(key_material)),
        KeyIdentifier::PublicKey(pk) => pk.ct_eq(key_material),
    };
    if bool::from(matches) {
        Ok(())
    } else {
        Err(ProtokenError::KeyHashMismatch)
    }
}

/// Parse the payload (only after the signature verified), apply the Claims
/// rules the signer was held to, and check the time window.
fn finish_verification(token: SignedToken, now: u64) -> Result<VerifiedToken, ProtokenError> {
    let claims = deserialize_claims(&token.payload)?;
    claims.validate()?;
    check_temporal_claims(&claims, now)?;
    Ok(VerifiedToken {
        algorithm: token.algorithm,
        key_identifier: token.key_identifier,
        claims,
    })
}

/// Check expires_at and not_before against the current time. `validate()`
/// has already run, so expires_at is non-zero; an unset not_before is 0 and
/// therefore never in the future.
fn check_temporal_claims(claims: &Claims, now: u64) -> Result<(), ProtokenError> {
    if now > claims.expires_at {
        return Err(ProtokenError::TokenExpired {
            expired_at: claims.expires_at,
            now,
        });
    }
    if now < claims.not_before {
        return Err(ProtokenError::TokenNotYetValid {
            not_before: claims.not_before,
            now,
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
pub(crate) mod tests {
    use super::*;

    use crate::serialize::{
        append_signature, deserialize_signed_token, serialize_claims, serialize_signed_token,
        serialize_signing_input,
    };
    use crate::sign::tests::key_pair;
    use crate::sign::{sign_ed25519, sign_hmac, sign_mldsa44};

    const TEST_HMAC_KEY: &[u8; 32] = &[0xAB; 32];
    const WRONG_HMAC_KEY: &[u8; 32] = &[0xCD; 32];

    /// Compressed encoding of y = 2, which is not a point on the curve.
    pub(crate) const NOT_ON_CURVE: [u8; 32] = {
        let mut bytes = [0u8; 32];
        bytes[0] = 2;
        bytes
    };

    fn claims_expiring(expires_at: u64) -> Claims {
        Claims {
            expires_at,
            ..Default::default()
        }
    }

    fn never_expires() -> Claims {
        claims_expiring(u64::MAX)
    }

    fn key_hash_id(key_material: &[u8]) -> KeyIdentifier {
        KeyIdentifier::KeyHash(compute_key_hash(key_material))
    }

    /// Ed25519 token signed with a fresh key; returns (public key, token bytes).
    fn ed25519_token(claims: &Claims) -> (Vec<u8>, Vec<u8>) {
        let (seed, pk) = key_pair(Algorithm::Ed25519);
        let token = sign_ed25519(&seed, claims, &key_hash_id(&pk)).unwrap();
        (pk, token)
    }

    /// ML-DSA-44 token signed with a fresh key; returns (public key, token bytes).
    fn mldsa44_token(claims: &Claims) -> (Vec<u8>, Vec<u8>) {
        let (seed, pk) = key_pair(Algorithm::MlDsa44);
        let token = sign_mldsa44(&seed, claims, &key_hash_id(&pk)).unwrap();
        (pk, token)
    }

    /// Build an HMAC token with an arbitrary key identifier and payload,
    /// bypassing the checks in `sign_hmac`.
    fn raw_hmac_token(sign_key: &[u8], key_id: KeyIdentifier, payload: Vec<u8>) -> Vec<u8> {
        let signing_input =
            serialize_signing_input(Version::V0, Algorithm::HmacSha256, &key_id, &payload);
        let tag = hmac_sha256(sign_key, &signing_input)
            .unwrap()
            .finalize()
            .into_bytes();
        append_signature(signing_input, &tag)
    }

    // --- HMAC ---

    #[test]
    fn test_verify_hmac_valid() {
        let token = sign_hmac(TEST_HMAC_KEY, &never_expires()).unwrap();
        let verified = verify_hmac(TEST_HMAC_KEY, &token, 1700000000).unwrap();
        assert_eq!(verified.claims, never_expires());
        assert_eq!(verified.algorithm, Algorithm::HmacSha256);
        assert_eq!(verified.key_identifier, key_hash_id(TEST_HMAC_KEY));
    }

    #[test]
    fn test_verify_hmac_wrong_key() {
        let token = sign_hmac(TEST_HMAC_KEY, &never_expires()).unwrap();
        assert!(matches!(
            verify_hmac(WRONG_HMAC_KEY, &token, 0),
            Err(ProtokenError::KeyHashMismatch)
        ));
    }

    #[test]
    fn test_verify_hmac_rejects_short_key() {
        let token = sign_hmac(TEST_HMAC_KEY, &never_expires()).unwrap();
        assert!(matches!(
            verify_hmac(&TEST_HMAC_KEY[..16], &token, 0),
            Err(ProtokenError::InvalidKey(_))
        ));
    }

    #[test]
    fn test_verify_hmac_expiry_boundary() {
        // now == expires_at is still valid; one second later is not.
        let token = sign_hmac(TEST_HMAC_KEY, &claims_expiring(5000)).unwrap();
        assert!(verify_hmac(TEST_HMAC_KEY, &token, 5000).is_ok());
        assert!(matches!(
            verify_hmac(TEST_HMAC_KEY, &token, 5001),
            Err(ProtokenError::TokenExpired {
                expired_at: 5000,
                now: 5001
            })
        ));
    }

    #[test]
    fn test_verify_not_before_boundary() {
        let claims = Claims {
            expires_at: u64::MAX,
            not_before: 5000,
            ..Default::default()
        };
        let token = sign_hmac(TEST_HMAC_KEY, &claims).unwrap();
        assert!(matches!(
            verify_hmac(TEST_HMAC_KEY, &token, 4999),
            Err(ProtokenError::TokenNotYetValid {
                not_before: 5000,
                now: 4999
            })
        ));
        assert!(verify_hmac(TEST_HMAC_KEY, &token, 5000).is_ok());
        assert!(verify_hmac(TEST_HMAC_KEY, &token, 6000).is_ok());
    }

    #[test]
    fn test_verify_hmac_corrupt_every_byte() {
        let claims = Claims {
            expires_at: u64::MAX,
            not_before: 1000,
            subject: "test".into(),
            scopes: vec!["admin".into(), "read".into(), "write".into()],
            ..Default::default()
        };
        let token = sign_hmac(TEST_HMAC_KEY, &claims).unwrap();
        for i in 0..token.len() {
            let mut corrupted = token.clone();
            corrupted[i] ^= 0x01;
            assert!(
                verify_hmac(TEST_HMAC_KEY, &corrupted, 2000).is_err(),
                "corrupting byte {i} must fail verification"
            );
        }
    }

    #[test]
    fn test_verify_hmac_rejects_truncated_and_extended_tokens() {
        let token = sign_hmac(TEST_HMAC_KEY, &never_expires()).unwrap();
        for len in 0..token.len() {
            assert!(verify_hmac(TEST_HMAC_KEY, &token[..len], 0).is_err());
        }
        let mut extended = token.clone();
        extended.push(0x00);
        assert!(verify_hmac(TEST_HMAC_KEY, &extended, 0).is_err());
    }

    #[test]
    fn test_verify_rejects_key_id_of_other_key() {
        // Signature is valid for TEST_HMAC_KEY, but the identifier names
        // another key. The identity check must fail before the MAC is checked.
        let payload = serialize_claims(&never_expires());
        let token = raw_hmac_token(TEST_HMAC_KEY, key_hash_id(WRONG_HMAC_KEY), payload);
        assert!(matches!(
            verify_hmac(TEST_HMAC_KEY, &token, 1000),
            Err(ProtokenError::KeyHashMismatch)
        ));
    }

    #[test]
    fn test_verify_rejects_wrong_signature_length() {
        // A well-formed envelope whose signature is not exactly 32 bytes.
        let payload = serialize_claims(&never_expires());
        let signing_input = serialize_signing_input(
            Version::V0,
            Algorithm::HmacSha256,
            &key_hash_id(TEST_HMAC_KEY),
            &payload,
        );
        for len in [1, HMAC_SHA256_SIG_LEN - 1, HMAC_SHA256_SIG_LEN + 1] {
            let token = append_signature(signing_input.clone(), &vec![0u8; len]);
            let err = verify_hmac(TEST_HMAC_KEY, &token, 1000).unwrap_err();
            assert!(
                matches!(&err, ProtokenError::VerificationFailed(m) if m.contains("signature length")),
                "len {len}: got {err:?}"
            );
        }
    }

    #[test]
    fn test_verify_rejects_semantically_invalid_payloads() {
        // Correctly signed and canonically encoded, but violating the Claims
        // rules that sign_* enforces. These decode (for `inspect`) but must
        // not verify at any time.
        let without_expiry = Claims {
            issued_at: 1000,
            ..Default::default()
        };
        let inverted_window = Claims {
            expires_at: 1000,
            not_before: 2000,
            ..Default::default()
        };
        for claims in [without_expiry, inverted_window] {
            let payload = serialize_claims(&claims);
            let token = raw_hmac_token(TEST_HMAC_KEY, key_hash_id(TEST_HMAC_KEY), payload);
            for now in [0, 1000, 1500, 2000, u64::MAX] {
                assert!(
                    matches!(
                        verify_hmac(TEST_HMAC_KEY, &token, now),
                        Err(ProtokenError::MalformedEncoding(_))
                    ),
                    "{claims:?} at {now}"
                );
            }
        }
    }

    #[test]
    fn test_verify_rejects_unsigned_payload_tampering() {
        // Swap in a different payload without re-signing.
        let token =
            deserialize_signed_token(&sign_hmac(TEST_HMAC_KEY, &claims_expiring(1000)).unwrap())
                .unwrap();
        let tampered = serialize_signed_token(&SignedToken {
            payload: serialize_claims(&never_expires()),
            ..token
        });
        assert!(matches!(
            verify_hmac(TEST_HMAC_KEY, &tampered, 5000),
            Err(ProtokenError::VerificationFailed(_))
        ));
    }

    // --- Ed25519 ---

    #[test]
    fn test_verify_ed25519_valid() {
        let claims = Claims {
            expires_at: u64::MAX,
            subject: "user:alice".into(),
            scopes: vec!["read".into()],
            ..Default::default()
        };
        let (pk, token) = ed25519_token(&claims);
        let verified = verify_ed25519(&pk, &token, 1700000000).unwrap();
        assert_eq!(verified.claims, claims);
        assert_eq!(verified.algorithm, Algorithm::Ed25519);
    }

    #[test]
    fn test_verify_ed25519_with_embedded_public_key() {
        let (seed, pk) = key_pair(Algorithm::Ed25519);
        let token = sign_ed25519(
            &seed,
            &never_expires(),
            &KeyIdentifier::PublicKey(pk.clone()),
        )
        .unwrap();
        let verified = verify_ed25519(&pk, &token, 1700000000).unwrap();
        assert_eq!(verified.key_identifier, KeyIdentifier::PublicKey(pk));
    }

    #[test]
    fn test_verify_ed25519_expired() {
        let (pk, token) = ed25519_token(&claims_expiring(1000));
        assert!(matches!(
            verify_ed25519(&pk, &token, 2000),
            Err(ProtokenError::TokenExpired { .. })
        ));
    }

    #[test]
    fn test_verify_ed25519_wrong_key() {
        let (_pk, token) = ed25519_token(&never_expires());
        let (_seed, other_pk) = key_pair(Algorithm::Ed25519);
        assert!(matches!(
            verify_ed25519(&other_pk, &token, 0),
            Err(ProtokenError::KeyHashMismatch)
        ));
    }

    #[test]
    fn test_verify_ed25519_key_hash_mismatch_with_valid_signature() {
        // Signed by A but labeled with B's hash; verifying with A must fail
        // on the identity check even though the signature would verify.
        let (seed_a, pk_a) = key_pair(Algorithm::Ed25519);
        let (_seed_b, pk_b) = key_pair(Algorithm::Ed25519);
        let token = sign_ed25519(&seed_a, &never_expires(), &key_hash_id(&pk_b)).unwrap();
        assert!(matches!(
            verify_ed25519(&pk_a, &token, 1000),
            Err(ProtokenError::KeyHashMismatch)
        ));
    }

    #[test]
    fn test_verify_ed25519_corrupt_every_byte() {
        let claims = Claims {
            expires_at: u64::MAX,
            subject: "test".into(),
            audience: "svc".into(),
            ..Default::default()
        };
        let (pk, token) = ed25519_token(&claims);
        for i in 0..token.len() {
            let mut corrupted = token.clone();
            corrupted[i] ^= 0x01;
            assert!(
                verify_ed25519(&pk, &corrupted, 1000).is_err(),
                "corrupting byte {i} must fail verification"
            );
        }
    }

    #[test]
    fn test_verify_ed25519_rejects_bad_public_key() {
        let (_pk, token) = ed25519_token(&never_expires());
        // Wrong length fails the identity check first.
        assert!(matches!(
            verify_ed25519(&[0u8; 31], &token, 0),
            Err(ProtokenError::KeyHashMismatch)
        ));
    }

    #[test]
    fn test_ed25519_verifying_key_rejects_non_canonical_point() {
        // y = 2 has no corresponding x on the curve, so it does not decompress.
        assert!(matches!(
            ed25519_verifying_key(&NOT_ON_CURVE),
            Err(ProtokenError::InvalidKey(_))
        ));
        assert!(matches!(
            ed25519_verifying_key(&[0; 31]),
            Err(ProtokenError::InvalidKeyLength {
                expected: 32,
                actual: 31
            })
        ));
        let (_seed, pk) = key_pair(Algorithm::Ed25519);
        assert!(ed25519_verifying_key(&pk).is_ok());
    }

    #[test]
    fn test_verify_ed25519_rejects_small_order_public_key() {
        // The identity point has small order. verify_strict rejects it even
        // if a token is built that names it, which plain verify would accept
        // for a signature with a small-order R and s = 0.
        let identity = {
            let mut p = [0u8; 32];
            p[0] = 1;
            p
        };
        let key_id = KeyIdentifier::PublicKey(identity.to_vec());
        let payload = serialize_claims(&never_expires());
        let signing_input =
            serialize_signing_input(Version::V0, Algorithm::Ed25519, &key_id, &payload);
        // R = identity, s = 0: [1, 0..0] || [0; 32]
        let mut forged_sig = [0u8; ED25519_SIG_LEN];
        forged_sig[0] = 1;
        let token = append_signature(signing_input, &forged_sig);
        assert!(matches!(
            verify_ed25519(&identity, &token, 0),
            Err(ProtokenError::VerificationFailed(_))
        ));
    }

    // --- Algorithm binding ---

    #[test]
    fn test_verify_rejects_token_of_other_algorithm() {
        let hmac_token = sign_hmac(TEST_HMAC_KEY, &never_expires()).unwrap();
        let (_seed, pk) = key_pair(Algorithm::Ed25519);
        let err = verify_ed25519(&pk, &hmac_token, 1000).unwrap_err();
        assert!(
            matches!(&err, ProtokenError::VerificationFailed(m) if m.contains("expected ed25519")),
            "got {err:?}"
        );

        let (ed_pk, ed_token) = ed25519_token(&never_expires());
        assert!(verify_hmac(TEST_HMAC_KEY, &ed_token, 1000).is_err());
        assert!(verify_mldsa44(&ed_pk, &ed_token, 1000).is_err());
    }

    #[test]
    fn test_verify_rejects_algorithm_field_rewrite() {
        // Rewrite a valid HMAC token's algorithm field. The algorithm is part
        // of the signed bytes, so neither verifier may accept it.
        let token =
            deserialize_signed_token(&sign_hmac(TEST_HMAC_KEY, &never_expires()).unwrap()).unwrap();
        let swapped = serialize_signed_token(&SignedToken {
            algorithm: Algorithm::Ed25519,
            ..token
        });
        let (_seed, pk) = key_pair(Algorithm::Ed25519);
        assert!(verify_ed25519(&pk, &swapped, 1000).is_err());
        assert!(verify_hmac(TEST_HMAC_KEY, &swapped, 1000).is_err());
    }

    #[test]
    fn test_verify_rejects_malleated_version_prefix() {
        // An explicit version=0 field (0x08 0x00) is non-canonical. The
        // decoder rejects it, and verification signs over the received bytes,
        // so a byte-distinct token must never verify.
        let token = sign_hmac(TEST_HMAC_KEY, &never_expires()).unwrap();
        let mut malleated = vec![0x08, 0x00];
        malleated.extend_from_slice(&token);
        assert!(verify_hmac(TEST_HMAC_KEY, &malleated, 1000).is_err());
    }

    // --- ML-DSA-44 ---

    #[test]
    fn test_verify_mldsa44_valid_with_full_claims() {
        let claims = Claims {
            expires_at: u64::MAX,
            not_before: 1000,
            issued_at: 1000,
            subject: "pq-user".into(),
            audience: "pq-service".into(),
            scopes: vec!["admin".into(), "read".into(), "write".into()],
        };
        let (pk, token) = mldsa44_token(&claims);
        let verified = verify_mldsa44(&pk, &token, 2000).unwrap();
        assert_eq!(verified.claims, claims);
        assert_eq!(verified.algorithm, Algorithm::MlDsa44);
    }

    #[test]
    fn test_verify_mldsa44_with_embedded_public_key() {
        let (seed, pk) = key_pair(Algorithm::MlDsa44);
        let token = sign_mldsa44(
            &seed,
            &never_expires(),
            &KeyIdentifier::PublicKey(pk.clone()),
        )
        .unwrap();
        assert!(verify_mldsa44(&pk, &token, 0).is_ok());
    }

    #[test]
    fn test_verify_mldsa44_temporal_claims() {
        let (pk, token) = mldsa44_token(&claims_expiring(1000));
        assert!(verify_mldsa44(&pk, &token, 1000).is_ok());
        assert!(matches!(
            verify_mldsa44(&pk, &token, 2000),
            Err(ProtokenError::TokenExpired { .. })
        ));

        let claims = Claims {
            expires_at: u64::MAX,
            not_before: 5000,
            ..Default::default()
        };
        let (pk, token) = mldsa44_token(&claims);
        assert!(matches!(
            verify_mldsa44(&pk, &token, 3000),
            Err(ProtokenError::TokenNotYetValid { .. })
        ));
        assert!(verify_mldsa44(&pk, &token, 5000).is_ok());
    }

    #[test]
    fn test_verify_mldsa44_wrong_key() {
        let (_pk, token) = mldsa44_token(&never_expires());
        let (_seed, other_pk) = key_pair(Algorithm::MlDsa44);
        assert!(matches!(
            verify_mldsa44(&other_pk, &token, 0),
            Err(ProtokenError::KeyHashMismatch)
        ));
    }

    #[test]
    fn test_verify_mldsa44_corrupted_signature_and_payload() {
        let (pk, token) = mldsa44_token(&never_expires());

        let mut bad_sig = token.clone();
        *bad_sig.last_mut().unwrap() ^= 0xFF;
        assert!(matches!(
            verify_mldsa44(&pk, &bad_sig, 0),
            Err(ProtokenError::VerificationFailed(_))
        ));

        // The payload starts after the 4-byte algorithm/key_id_type prefix
        // and the 10-byte key_id field; flip a byte of the expires_at varint.
        let mut bad_payload = token.clone();
        bad_payload[16] ^= 0x01;
        assert!(verify_mldsa44(&pk, &bad_payload, 0).is_err());
    }

    // --- Internal helpers ---

    #[test]
    fn test_check_key_identity() {
        let key = b"0123456789abcdef0123456789abcdef";
        assert!(check_key_identity(&key_hash_id(key), key).is_ok());
        assert!(check_key_identity(&key_hash_id(b"other"), key).is_err());
        assert!(check_key_identity(&KeyIdentifier::PublicKey(key.to_vec()), key).is_ok());
        assert!(check_key_identity(&KeyIdentifier::PublicKey(key.to_vec()), &key[..31]).is_err());
    }

    #[test]
    fn test_check_temporal_claims() {
        let claims = Claims {
            expires_at: 100,
            not_before: 50,
            ..Default::default()
        };
        assert!(check_temporal_claims(&claims, 49).is_err());
        assert!(check_temporal_claims(&claims, 50).is_ok());
        assert!(check_temporal_claims(&claims, 100).is_ok());
        assert!(check_temporal_claims(&claims, 101).is_err());

        // Unset not_before never blocks.
        assert!(check_temporal_claims(&claims_expiring(100), 0).is_ok());
    }
}
