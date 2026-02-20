//! Token signing: HMAC-SHA256, Ed25519, and ML-DSA-44/65/87.

use hmac::{Hmac, Mac};
use ml_dsa::signature::Signer as _;
use ml_dsa::KeyGen;
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
    if key.len() < HMAC_MIN_KEY_LEN {
        return Err(ProtokenError::SigningFailed(format!(
            "HMAC key too short: {} bytes (minimum {})",
            key.len(),
            HMAC_MIN_KEY_LEN
        )));
    }
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
/// `seed` is the raw 32-byte Ed25519 private key seed.
pub fn sign_ed25519(
    seed: &[u8],
    claims: Claims,
    key_id: KeyIdentifier,
) -> Result<Vec<u8>, ProtokenError> {
    claims.validate()?;
    let seed_array: [u8; ED25519_SEED_LEN] = seed.try_into().map_err(|_| {
        ProtokenError::SigningFailed(format!(
            "invalid Ed25519 seed: expected {} bytes, got {}",
            ED25519_SEED_LEN,
            seed.len()
        ))
    })?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed_array);

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

/// Macro to generate ML-DSA sign, key generation, and key hash functions for a parameter set.
macro_rules! impl_mldsa {
    (
        param_set: $ParamSet:ty,
        algorithm: $algo:expr,
        sk_len: $sk_len:expr,
        pk_len: $pk_len:expr,
        name: $name:literal,
        sign_fn: $sign_fn:ident,
        generate_fn: $generate_fn:ident,
        key_hash_fn: $key_hash_fn:ident
    ) => {
        #[doc = concat!("Sign a token with ", $name, ". Returns the serialized SignedToken wire bytes.")]
        pub fn $sign_fn(
            signing_key_bytes: &[u8],
            claims: Claims,
            key_id: KeyIdentifier,
        ) -> Result<Vec<u8>, ProtokenError> {
            claims.validate()?;

            let encoded: &ml_dsa::EncodedSigningKey<$ParamSet> =
                signing_key_bytes.try_into().map_err(|_| {
                    ProtokenError::SigningFailed(format!(
                        "invalid {} signing key: expected {} bytes, got {}",
                        $name,
                        $sk_len,
                        signing_key_bytes.len()
                    ))
                })?;
            let signing_key = ml_dsa::SigningKey::<$ParamSet>::decode(encoded);

            let payload = Payload {
                metadata: Metadata {
                    version: Version::V0,
                    algorithm: $algo,
                    key_identifier: key_id,
                },
                claims,
            };

            let payload_bytes = serialize_payload(&payload);
            let sig = signing_key.try_sign(&payload_bytes).map_err(|e| {
                ProtokenError::SigningFailed(format!("{} signing failed: {e}", $name))
            })?;

            let token = SignedToken {
                payload_bytes,
                signature: sig.encode().to_vec(),
            };
            Ok(serialize_signed_token(&token))
        }

        #[doc = concat!("Generate a new ", $name, " key pair, returning (signing_key_bytes, public_key_bytes).")]
        pub fn $generate_fn() -> Result<(Vec<u8>, Vec<u8>), ProtokenError> {
            let mut rng = rand::rngs::OsRng;
            let kp = <$ParamSet>::key_gen(&mut rng);
            let sk_bytes = kp.signing_key().encode().to_vec();
            let pk_bytes = kp.verifying_key().encode().to_vec();
            Ok((sk_bytes, pk_bytes))
        }

        #[doc = concat!("Compute the KeyIdentifier::KeyHash for an ", $name, " public key.")]
        pub fn $key_hash_fn(public_key_bytes: &[u8]) -> Result<KeyIdentifier, ProtokenError> {
            if public_key_bytes.len() != $pk_len {
                return Err(ProtokenError::SigningFailed(format!(
                    "invalid {} public key: expected {} bytes, got {}",
                    $name,
                    $pk_len,
                    public_key_bytes.len()
                )));
            }
            let hash = compute_key_hash(public_key_bytes);
            Ok(KeyIdentifier::KeyHash(hash))
        }
    };
}

impl_mldsa! {
    param_set: ml_dsa::MlDsa44,
    algorithm: Algorithm::MlDsa44,
    sk_len: MLDSA44_SIGNING_KEY_LEN,
    pk_len: MLDSA44_PUBLIC_KEY_LEN,
    name: "ML-DSA-44",
    sign_fn: sign_mldsa44,
    generate_fn: generate_mldsa44_key,
    key_hash_fn: mldsa44_key_hash
}

impl_mldsa! {
    param_set: ml_dsa::MlDsa65,
    algorithm: Algorithm::MlDsa65,
    sk_len: MLDSA65_SIGNING_KEY_LEN,
    pk_len: MLDSA65_PUBLIC_KEY_LEN,
    name: "ML-DSA-65",
    sign_fn: sign_mldsa65,
    generate_fn: generate_mldsa65_key,
    key_hash_fn: mldsa65_key_hash
}

impl_mldsa! {
    param_set: ml_dsa::MlDsa87,
    algorithm: Algorithm::MlDsa87,
    sk_len: MLDSA87_SIGNING_KEY_LEN,
    pk_len: MLDSA87_PUBLIC_KEY_LEN,
    name: "ML-DSA-87",
    sign_fn: sign_mldsa87,
    generate_fn: generate_mldsa87_key,
    key_hash_fn: mldsa87_key_hash
}

/// Generate a new Ed25519 key pair, returning (seed, public_key) as raw bytes.
pub fn generate_ed25519_key() -> Result<(Vec<u8>, Vec<u8>), ProtokenError> {
    let mut rng = rand::rngs::OsRng;
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
    let seed = signing_key.to_bytes().to_vec();
    let pk = signing_key.verifying_key().to_bytes().to_vec();
    Ok((seed, pk))
}

/// Generate a new HMAC key (32 bytes of cryptographically random data).
pub fn generate_hmac_key() -> Vec<u8> {
    let mut key = vec![0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
    key
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::serialize::{deserialize_payload, deserialize_signed_token};

    const TEST_HMAC_KEY: &[u8; 32] = &[0xAB; 32];

    #[test]
    fn test_sign_hmac_produces_valid_token() {
        let key: &[u8] = TEST_HMAC_KEY;
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
        let (seed, pk) = generate_ed25519_key().unwrap();
        let key_id = KeyIdentifier::KeyHash(compute_key_hash(&pk));
        let claims = Claims {
            expires_at: 1800000000,
            ..Default::default()
        };

        let token_bytes = sign_ed25519(&seed, claims, key_id).unwrap();
        let token = deserialize_signed_token(&token_bytes).unwrap();
        let payload = deserialize_payload(&token.payload_bytes).unwrap();

        assert_eq!(payload.metadata.algorithm, Algorithm::Ed25519);
        assert_eq!(payload.claims.expires_at, 1800000000);
    }

    #[test]
    fn test_ed25519_signing_deterministic() {
        let (seed, pk) = generate_ed25519_key().unwrap();
        let key_id = KeyIdentifier::KeyHash(compute_key_hash(&pk));
        let claims = Claims {
            expires_at: 1800000000,
            not_before: 1799990000,
            issued_at: 1799990000,
            subject: "test".into(),
            ..Default::default()
        };

        let t1 = sign_ed25519(&seed, claims.clone(), key_id.clone()).unwrap();
        let t2 = sign_ed25519(&seed, claims, key_id).unwrap();
        assert_eq!(t1, t2);
    }

    #[test]
    fn test_sign_hmac_rejects_short_key() {
        let short_key = b"too-short";
        let claims = Claims {
            expires_at: 1700000000,
            ..Default::default()
        };
        assert!(sign_hmac(short_key, claims).is_err());
    }

    #[test]
    fn test_sign_rejects_zero_expires_at() {
        let key: &[u8] = TEST_HMAC_KEY;
        let claims = Claims {
            expires_at: 0,
            ..Default::default()
        };
        assert!(sign_hmac(key, claims).is_err());
    }

    #[test]
    fn test_sign_rejects_not_before_after_expires_at() {
        let key: &[u8] = TEST_HMAC_KEY;
        let claims = Claims {
            expires_at: 1000,
            not_before: 2000,
            ..Default::default()
        };
        assert!(sign_hmac(key, claims).is_err());
    }

    #[test]
    fn test_sign_hmac_with_claims() {
        let key: &[u8] = TEST_HMAC_KEY;
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
        let (seed, pk) = generate_ed25519_key().unwrap();
        let key_id = KeyIdentifier::KeyHash(compute_key_hash(&pk));
        let claims = Claims {
            expires_at: 1800000000,
            subject: "user:alice".into(),
            audience: "api.example.com".into(),
            ..Default::default()
        };

        let token_bytes = sign_ed25519(&seed, claims.clone(), key_id).unwrap();
        let token = deserialize_signed_token(&token_bytes).unwrap();
        let payload = deserialize_payload(&token.payload_bytes).unwrap();

        assert_eq!(payload.metadata.version, Version::V0);
        assert_eq!(payload.metadata.algorithm, Algorithm::Ed25519);
        assert_eq!(payload.claims, claims);
    }

    // Macro for ML-DSA sign tests
    macro_rules! mldsa_sign_tests {
        ($mod_name:ident, $generate_fn:ident, $sign_fn:ident, $key_hash_fn:ident, $algo:expr, $sk_len:expr, $pk_len:expr) => {
            mod $mod_name {
                use super::*;

                #[test]
                fn test_sign_produces_valid_token() {
                    let (sk, pk) = $generate_fn().unwrap();
                    let key_id = $key_hash_fn(&pk).unwrap();
                    let claims = Claims {
                        expires_at: 1900000000,
                        ..Default::default()
                    };

                    let token_bytes = $sign_fn(&sk, claims, key_id).unwrap();
                    let token = deserialize_signed_token(&token_bytes).unwrap();
                    let payload = deserialize_payload(&token.payload_bytes).unwrap();

                    assert_eq!(payload.metadata.algorithm, $algo);
                    assert_eq!(payload.claims.expires_at, 1900000000);
                }

                #[test]
                fn test_sign_with_claims() {
                    let (sk, pk) = $generate_fn().unwrap();
                    let key_id = $key_hash_fn(&pk).unwrap();
                    let claims = Claims {
                        expires_at: 1900000000,
                        subject: "pq-user".into(),
                        audience: "pq-api.example.com".into(),
                        scopes: vec!["admin".into(), "read".into()],
                        ..Default::default()
                    };

                    let token_bytes = $sign_fn(&sk, claims.clone(), key_id).unwrap();
                    let token = deserialize_signed_token(&token_bytes).unwrap();
                    let payload = deserialize_payload(&token.payload_bytes).unwrap();

                    assert_eq!(payload.metadata.version, Version::V0);
                    assert_eq!(payload.metadata.algorithm, $algo);
                    assert_eq!(payload.claims, claims);
                }

                #[test]
                fn test_key_hash_deterministic() {
                    let (_sk, pk) = $generate_fn().unwrap();
                    let h1 = $key_hash_fn(&pk).unwrap();
                    let h2 = $key_hash_fn(&pk).unwrap();
                    assert_eq!(h1, h2);
                }

                #[test]
                fn test_key_sizes() {
                    let (sk, pk) = $generate_fn().unwrap();
                    assert_eq!(sk.len(), $sk_len);
                    assert_eq!(pk.len(), $pk_len);
                }
            }
        };
    }

    mldsa_sign_tests!(
        mldsa44_tests,
        generate_mldsa44_key,
        sign_mldsa44,
        mldsa44_key_hash,
        Algorithm::MlDsa44,
        MLDSA44_SIGNING_KEY_LEN,
        MLDSA44_PUBLIC_KEY_LEN
    );

    mldsa_sign_tests!(
        mldsa65_tests,
        generate_mldsa65_key,
        sign_mldsa65,
        mldsa65_key_hash,
        Algorithm::MlDsa65,
        MLDSA65_SIGNING_KEY_LEN,
        MLDSA65_PUBLIC_KEY_LEN
    );

    mldsa_sign_tests!(
        mldsa87_tests,
        generate_mldsa87_key,
        sign_mldsa87,
        mldsa87_key_hash,
        Algorithm::MlDsa87,
        MLDSA87_SIGNING_KEY_LEN,
        MLDSA87_PUBLIC_KEY_LEN
    );
}
