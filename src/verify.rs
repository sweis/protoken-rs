//! Token verification. The entry points are `keys::VerifyingKey::verify` and
//! `keys::SigningKey::verify`.
//!
//! Verification order:
//! 1. Parse the envelope (structure and size checks only).
//! 2. Check the envelope algorithm matches the caller's key.
//! 3. Check the key identifier matches the caller's key (constant time) and
//!    the signature has the algorithm's exact length.
//! 4. Verify the signature over the envelope's signing input.
//! 5. Only then parse the payload as Claims, apply `Claims::validate()`, and
//!    check temporal validity.

use subtle::ConstantTimeEq as _;

use crate::crypto::scheme;
use crate::error::ProtokenError;
use crate::serialize::{deserialize_claims, deserialize_signed_token_at};
use crate::sign::compute_key_hash;
use crate::types::*;

/// Result of a successful token verification. The caller must still check
/// that `claims.audience` and `claims.scopes` fit the request.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifiedToken {
    pub algorithm: Algorithm,
    pub key_identifier: KeyIdentifier,
    pub claims: Claims,
}

/// `key_material` is the HMAC secret or the public key. This stays private to
/// the crate so that the algorithm always comes from a key, never from a token.
pub(crate) fn verify_token(
    algorithm: Algorithm,
    key_material: &[u8],
    token_bytes: &[u8],
    now: u64,
) -> Result<VerifiedToken, ProtokenError> {
    let (token, signing_input) = parse_envelope(token_bytes, algorithm, key_material)?;
    if !scheme(algorithm).verify(key_material, signing_input, &token.signature) {
        return Err(ProtokenError::VerificationFailed(format!(
            "{algorithm} signature verification failed"
        )));
    }
    finish_verification(token, now)
}

/// Parse the envelope, check the expected algorithm and key identity, and
/// return the signed bytes: the received token bytes up to the signature
/// field. The decoder enforces canonical encoding, so these are exactly the
/// bytes the signer produced with `serialize_signing_input`.
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
    let signing_input = token_bytes
        .get(..signed_len)
        .ok_or_else(|| ProtokenError::malformed("signature field offset out of range"))?;
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
mod tests {
    use super::*;

    use crate::keys::tests::{fixed_key, ASYMMETRIC};
    use crate::keys::SigningKey;
    use crate::serialize::{
        append_signature, deserialize_signed_token, serialize_claims, serialize_signed_token,
        serialize_signing_input,
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

    /// A correctly signed token with an arbitrary key identifier and payload.
    fn raw_token(key: &SigningKey, key_id: &KeyIdentifier, payload: &[u8]) -> Vec<u8> {
        let input = serialize_signing_input(Version::V0, key.algorithm(), key_id, payload);
        let signature = scheme(key.algorithm())
            .sign(key.secret_key(), &input)
            .unwrap();
        append_signature(input, &signature)
    }

    fn is_verification_failure<T>(result: Result<T, ProtokenError>, needle: &str) -> bool {
        matches!(result, Err(ProtokenError::VerificationFailed(m)) if m.contains(needle))
    }

    #[test]
    fn test_time_window_is_inclusive() {
        let claims = Claims {
            expires_at: 6000,
            not_before: 5000,
            ..Default::default()
        };
        for algorithm in Algorithm::ALL {
            let key = fixed_key(algorithm);
            let token = key.sign(&claims).unwrap();
            assert!(matches!(
                key.verify(&token, 4999),
                Err(ProtokenError::TokenNotYetValid {
                    not_before: 5000,
                    now: 4999
                })
            ));
            assert!(key.verify(&token, 5000).is_ok());
            assert!(key.verify(&token, 6000).is_ok());
            assert!(matches!(
                key.verify(&token, 6001),
                Err(ProtokenError::TokenExpired {
                    expired_at: 6000,
                    now: 6001
                })
            ));
        }
    }

    #[test]
    fn test_rejects_corrupted_truncated_and_extended_tokens() {
        let claims = Claims {
            expires_at: u64::MAX,
            not_before: 1000,
            subject: "test".into(),
            scopes: vec!["admin".into(), "read".into(), "write".into()],
            ..Default::default()
        };
        for algorithm in Algorithm::ALL {
            let key = fixed_key(algorithm);
            let token = key.sign(&claims).unwrap();
            // Every byte of the envelope and both ends of the signature, and a
            // sample of the bytes in between.
            let positions =
                (0..token.len()).filter(|i| *i < 128 || i + 128 > token.len() || i % 97 == 0);
            for i in positions {
                let mut corrupted = token.clone();
                corrupted[i] ^= 0x01;
                assert!(key.verify(&corrupted, 2000).is_err(), "{algorithm}: {i}");
                assert!(key.verify(&token[..i], 2000).is_err(), "{algorithm}: {i}");
            }
            let extended = [&token[..], &[0x00]].concat();
            assert!(key.verify(&extended, 2000).is_err(), "{algorithm}");
        }
    }

    #[test]
    fn test_rejects_valid_signature_with_another_keys_identifier() {
        let payload = serialize_claims(&never_expires());
        for algorithm in Algorithm::ALL {
            let key = fixed_key(algorithm);
            let token = raw_token(&key, &key_hash_id(b"another key"), &payload);
            assert!(matches!(
                key.verify(&token, 0),
                Err(ProtokenError::KeyHashMismatch)
            ));
        }
    }

    #[test]
    fn test_rejects_another_keys_signature_under_the_right_identifier() {
        let payload = serialize_claims(&never_expires());
        for algorithm in Algorithm::ALL {
            let key = fixed_key(algorithm);
            let key_id = key.key_identifier(KeyIdType::KeyHash).unwrap();
            let forger = SigningKey::generate(algorithm).unwrap();
            let token = raw_token(&forger, &key_id, &payload);
            assert!(is_verification_failure(
                key.verify(&token, 0),
                "signature verification failed"
            ));
        }
    }

    #[test]
    fn test_rejects_wrong_signature_length() {
        let payload = serialize_claims(&never_expires());
        for algorithm in Algorithm::ALL {
            let key = fixed_key(algorithm);
            let key_id = key.key_identifier(KeyIdType::KeyHash).unwrap();
            let input = serialize_signing_input(Version::V0, algorithm, &key_id, &payload);
            let full = algorithm.signature_len();
            for len in [1, full - 1, (full + 1).min(MAX_SIGNATURE_BYTES)] {
                let token = append_signature(input.clone(), &vec![0; len]);
                let needle = if len == full { "failed" } else { "length" };
                assert!(
                    is_verification_failure(key.verify(&token, 0), needle),
                    "{algorithm}: {len}"
                );
            }
        }
    }

    #[test]
    fn test_rejects_signed_but_invalid_claims() {
        // These decode (for `inspect`) but must not verify at any time.
        let without_expiry = Claims {
            issued_at: 1000,
            ..Default::default()
        };
        let inverted_window = Claims {
            expires_at: 1000,
            not_before: 2000,
            ..Default::default()
        };
        let key = fixed_key(Algorithm::HmacSha384);
        for claims in [without_expiry, inverted_window] {
            let payload = serialize_claims(&claims);
            let token = raw_token(&key, &key_hash_id(key.secret_key()), &payload);
            for now in [0, 1000, 1500, 2000, u64::MAX] {
                assert!(
                    matches!(
                        key.verify(&token, now),
                        Err(ProtokenError::MalformedEncoding(_))
                    ),
                    "{claims:?} at {now}"
                );
            }
        }
    }

    #[test]
    fn test_bad_signature_is_reported_before_the_payload_is_parsed() {
        let key = fixed_key(Algorithm::HmacSha384);
        let token = deserialize_signed_token(&key.sign(&never_expires()).unwrap()).unwrap();
        let tampered = serialize_signed_token(&SignedToken {
            payload: vec![0xFF],
            ..token
        });
        assert!(is_verification_failure(key.verify(&tampered, 0), "failed"));
    }

    #[test]
    fn test_rejects_tokens_of_every_other_algorithm() {
        let keys = Algorithm::ALL.map(fixed_key);
        for signer in &keys {
            let token = signer.sign(&never_expires()).unwrap();
            for verifier in keys.iter().filter(|key| *key != signer) {
                let expected = format!("expected {}", verifier.algorithm());
                assert!(is_verification_failure(
                    verifier.verify(&token, 0),
                    &expected
                ));
            }
        }
    }

    #[test]
    fn test_public_key_used_as_hmac_secret_is_rejected() {
        // The classic JWT attack: MAC a token with the verifier's public key.
        let payload = serialize_claims(&never_expires());
        for algorithm in ASYMMETRIC {
            let verifying_key = fixed_key(algorithm).verifying_key().unwrap();
            let key_id = KeyIdentifier::KeyHash(verifying_key.key_hash());
            let input =
                serialize_signing_input(Version::V0, Algorithm::HmacSha384, &key_id, &payload);
            let tag = scheme(Algorithm::HmacSha384)
                .sign(verifying_key.public_key(), &input)
                .unwrap();
            let token = append_signature(input, &tag);
            assert!(is_verification_failure(
                verifying_key.verify(&token, 0),
                "expected"
            ));
        }
    }

    #[test]
    fn test_rejects_explicit_version_prefix() {
        let key = fixed_key(Algorithm::HmacSha384);
        let token = key.sign(&never_expires()).unwrap();
        let malleated = [&[0x08, 0x00], &token[..]].concat();
        assert!(matches!(
            key.verify(&malleated, 0),
            Err(ProtokenError::InvalidVersion(0))
        ));
    }

    #[test]
    fn test_check_key_identity() {
        let key = b"0123456789abcdef0123456789abcdef";
        assert!(check_key_identity(&key_hash_id(key), key).is_ok());
        assert!(check_key_identity(&key_hash_id(b"other"), key).is_err());
        assert!(check_key_identity(&KeyIdentifier::PublicKey(key.to_vec()), key).is_ok());
        assert!(check_key_identity(&KeyIdentifier::PublicKey(key.to_vec()), &key[..31]).is_err());
        assert!(check_key_identity(&KeyIdentifier::PublicKey(vec![0; 32]), key).is_err());
    }
}
