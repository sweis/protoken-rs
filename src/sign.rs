//! Token signing and key hashing. The entry point is `keys::SigningKey::sign`.

use sha2::digest::consts::U8;
use sha2::{Digest as _, Sha256};

use crate::crypto::{scheme, CONTEXT};
use crate::error::ProtokenError;
use crate::serialize::{
    append_signature, check_claims_size, serialize_claims, serialize_signing_input,
};
use crate::types::*;

/// Compute the 8-byte key hash: SHA-256(key_material)[0..8].
///
/// This is a key *identifier*, not a security binding. The 8-byte truncation
/// gives ~2^32 collision resistance at the birthday bound. Security relies on
/// full signature verification, not on the key hash being unique.
#[must_use]
pub fn compute_key_hash(key_material: &[u8]) -> [u8; KEY_HASH_LEN] {
    let (hash, _rest) = Sha256::digest(key_material).split::<U8>();
    hash.into()
}

pub(crate) fn sign_token(
    algorithm: Algorithm,
    secret_key: &[u8],
    key_id: &KeyIdentifier,
    claims: &Claims,
) -> Result<Vec<u8>, ProtokenError> {
    claims.validate()?;
    let payload = serialize_claims(claims);
    // Valid claims can exceed the payload size that verifiers accept.
    check_claims_size(&payload)?;
    let signing_input = serialize_signing_input(Version::V0, algorithm, key_id, &payload);
    let signature = scheme(algorithm).sign(secret_key, CONTEXT, &signing_input)?;
    Ok(append_signature(signing_input, &signature))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::keys::tests::fixed_key;
    use crate::serialize::{deserialize_claims, deserialize_signed_token};

    fn claims_expiring(expires_at: u64) -> Claims {
        Claims {
            expires_at,
            ..Default::default()
        }
    }

    /// Claims with `count` scopes of the maximum length.
    fn claims_with_long_scopes(count: usize) -> Claims {
        Claims {
            scopes: (0..count)
                .map(|i| format!("{i:0>width$}", width = MAX_CLAIM_BYTES_LEN))
                .collect(),
            ..claims_expiring(u64::MAX)
        }
    }

    #[test]
    fn test_key_hash_known_value() {
        // First 8 bytes of SHA-256("").
        assert_eq!(
            compute_key_hash(b""),
            [0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14]
        );
    }

    #[test]
    fn test_signed_token_fields() {
        let claims = Claims {
            expires_at: 1900000000,
            not_before: 1800000000,
            issued_at: 1800000000,
            subject: "user:alice".into(),
            audience: "api.example.com".into(),
            scopes: vec!["admin".into(), "read".into()],
        };
        for algorithm in Algorithm::ALL {
            let key = fixed_key(algorithm);
            let token = deserialize_signed_token(&key.sign(&claims).unwrap()).unwrap();
            assert_eq!(token.version, Version::V0);
            assert_eq!(token.algorithm, algorithm);
            assert_eq!(
                token.key_identifier,
                key.key_identifier(KeyIdType::KeyHash).unwrap()
            );
            assert_eq!(deserialize_claims(&token.payload).unwrap(), claims);
            assert_eq!(token.signature.len(), algorithm.signature_len());
        }
    }

    #[test]
    fn test_sign_rejects_valid_claims_larger_than_max_payload() {
        let claims = claims_with_long_scopes(MAX_SCOPES);
        assert!(claims.validate().is_ok());
        for algorithm in Algorithm::ALL {
            let err = fixed_key(algorithm).sign(&claims).unwrap_err();
            assert!(
                matches!(&err, ProtokenError::MalformedEncoding(m) if m.contains("claims too large")),
                "{algorithm}: got {err:?}"
            );
        }
    }

    #[test]
    fn test_largest_signable_claims_verify() {
        // 15 scopes of 258 encoded bytes each, plus expires_at and a subject
        // that fills the payload to exactly MAX_PAYLOAD_BYTES.
        let mut claims = claims_with_long_scopes(15);
        let used = serialize_claims(&claims).len();
        claims.subject = "s".repeat(MAX_PAYLOAD_BYTES - used - 3);
        assert_eq!(serialize_claims(&claims).len(), MAX_PAYLOAD_BYTES);

        for algorithm in Algorithm::ALL {
            let key = fixed_key(algorithm);
            let id_type = if algorithm.is_symmetric() {
                KeyIdType::KeyHash
            } else {
                KeyIdType::PublicKey
            };
            let token = key.sign_with_key_id(&claims, id_type).unwrap();
            assert_eq!(key.verify(&token, 0).unwrap().claims, claims);
        }

        claims.subject.push('s');
        assert!(fixed_key(Algorithm::HmacSha384).sign(&claims).is_err());
    }

    #[test]
    fn test_sign_enforces_claim_limits() {
        let text = |len| "x".repeat(len);
        let scopes = |count| (0..count).map(|i| format!("s{i:03}")).collect();
        let base = || claims_expiring(5000);
        let (max, over) = (MAX_CLAIM_BYTES_LEN, MAX_CLAIM_BYTES_LEN + 1);

        #[rustfmt::skip]
        let cases = [
            (false, claims_expiring(0)),
            (true, Claims { not_before: 5000, ..base() }),
            (false, Claims { not_before: 5001, ..base() }),
            (true, Claims { subject: text(max), ..base() }),
            (false, Claims { subject: text(over), ..base() }),
            (true, Claims { audience: text(max), ..base() }),
            (false, Claims { audience: text(over), ..base() }),
            (true, Claims { scopes: vec![text(max)], ..base() }),
            (false, Claims { scopes: vec![text(over)], ..base() }),
            (true, Claims { scopes: scopes(MAX_SCOPES), ..base() }),
            (false, Claims { scopes: scopes(MAX_SCOPES + 1), ..base() }),
            (false, Claims { scopes: vec![text(1), text(1)], ..base() }),
        ];
        let key = fixed_key(Algorithm::HmacSha384);
        for (ok, claims) in cases {
            assert_eq!(key.sign(&claims).is_ok(), ok, "{claims:?}");
        }
    }
}
