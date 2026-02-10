//! Deterministic binary serialization for protoken payloads and signed tokens.
//!
//! Wire format (v0, key_hash):
//!   [ version:1 | algorithm:1 | key_id_type:1 | key_id:8 | expires_at:8 ] = 19 bytes
//!
//! Wire format (v0, public_key):
//!   [ version:1 | algorithm:1 | key_id_type:1 | key_id:N | expires_at:8 ]
//!   where N depends on the algorithm (33 for P-256 compressed).
//!
//! SignedToken wire format:
//!   [ payload_bytes | signature_bytes ]
//!   Signature length is determined by the algorithm byte at offset 1.

use crate::error::ProtokenError;
use crate::types::*;

/// Minimum payload size: version(1) + algorithm(1) + key_id_type(1) + key_hash(8) + expires_at(8)
const MIN_PAYLOAD_LEN: usize = 19;

/// Header size before key identifier value: version(1) + algorithm(1) + key_id_type(1)
const HEADER_LEN: usize = 3;

/// Size of expires_at field in bytes.
const EXPIRES_AT_LEN: usize = 8;

/// Serialize a Payload into deterministic bytes.
pub fn serialize_payload(payload: &Payload) -> Vec<u8> {
    let key_id_len = payload.metadata.key_identifier.value_len();
    let total_len = HEADER_LEN + key_id_len + EXPIRES_AT_LEN;
    let mut buf = Vec::with_capacity(total_len);

    buf.push(payload.metadata.version.to_byte());
    buf.push(payload.metadata.algorithm.to_byte());
    buf.push(payload.metadata.key_identifier.key_id_type().to_byte());

    match &payload.metadata.key_identifier {
        KeyIdentifier::KeyHash(hash) => buf.extend_from_slice(hash),
        KeyIdentifier::PublicKey(pk) => buf.extend_from_slice(pk),
    }

    buf.extend_from_slice(&payload.claims.expires_at.to_be_bytes());

    debug_assert_eq!(buf.len(), total_len);
    buf
}

/// Deserialize a Payload from deterministic bytes.
pub fn deserialize_payload(data: &[u8]) -> Result<Payload, ProtokenError> {
    if data.len() < HEADER_LEN + 1 {
        return Err(ProtokenError::PayloadTooShort {
            expected: HEADER_LEN + 1,
            actual: data.len(),
        });
    }

    let version = Version::from_byte(data[0])
        .ok_or(ProtokenError::InvalidVersion(data[0]))?;
    let algorithm = Algorithm::from_byte(data[1])
        .ok_or(ProtokenError::InvalidAlgorithm(data[1]))?;
    let key_id_type = KeyIdType::from_byte(data[2])
        .ok_or(ProtokenError::InvalidKeyIdType(data[2]))?;

    let key_id_len = match key_id_type {
        KeyIdType::KeyHash => KEY_HASH_LEN,
        KeyIdType::PublicKey => match algorithm {
            Algorithm::Ed25519 => ED25519_PUBLIC_KEY_LEN,
            Algorithm::HmacSha256 => {
                // HMAC doesn't use public key embedding
                return Err(ProtokenError::InvalidKeyIdType(key_id_type.to_byte()));
            }
        },
    };

    let expected_len = HEADER_LEN + key_id_len + EXPIRES_AT_LEN;
    if data.len() < expected_len {
        return Err(ProtokenError::PayloadTooShort {
            expected: expected_len,
            actual: data.len(),
        });
    }
    if data.len() != expected_len {
        return Err(ProtokenError::PayloadTooShort {
            expected: expected_len,
            actual: data.len(),
        });
    }

    let key_id_start = HEADER_LEN;
    let key_id_end = key_id_start + key_id_len;
    let key_identifier = match key_id_type {
        KeyIdType::KeyHash => {
            let mut hash = [0u8; KEY_HASH_LEN];
            hash.copy_from_slice(&data[key_id_start..key_id_end]);
            KeyIdentifier::KeyHash(hash)
        }
        KeyIdType::PublicKey => {
            KeyIdentifier::PublicKey(data[key_id_start..key_id_end].to_vec())
        }
    };

    let expires_at_bytes: [u8; 8] = data[key_id_end..key_id_end + 8]
        .try_into()
        .expect("slice is exactly 8 bytes");
    let expires_at = u64::from_be_bytes(expires_at_bytes);

    Ok(Payload {
        metadata: Metadata {
            version,
            algorithm,
            key_identifier,
        },
        claims: Claims { expires_at },
    })
}

/// Serialize a SignedToken into wire bytes: payload || signature.
pub fn serialize_signed_token(token: &SignedToken) -> Vec<u8> {
    let mut buf = Vec::with_capacity(token.payload_bytes.len() + token.signature.len());
    buf.extend_from_slice(&token.payload_bytes);
    buf.extend_from_slice(&token.signature);
    buf
}

/// Deserialize a SignedToken from wire bytes.
///
/// Reads the algorithm byte at offset 1 to determine signature length,
/// then splits the data into payload and signature.
pub fn deserialize_signed_token(data: &[u8]) -> Result<SignedToken, ProtokenError> {
    if data.len() < 2 {
        return Err(ProtokenError::TokenTooShort {
            expected: 2,
            actual: data.len(),
        });
    }

    let algorithm = Algorithm::from_byte(data[1])
        .ok_or(ProtokenError::InvalidAlgorithm(data[1]))?;

    let sig_len = algorithm.signature_len();

    if data.len() <= sig_len {
        return Err(ProtokenError::TokenTooShort {
            expected: sig_len + MIN_PAYLOAD_LEN,
            actual: data.len(),
        });
    }

    let payload_len = data.len() - sig_len;
    let payload_bytes = data[..payload_len].to_vec();
    let signature = data[payload_len..].to_vec();

    // Validate that the payload is well-formed
    deserialize_payload(&payload_bytes)?;

    Ok(SignedToken {
        payload_bytes,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_payload_hmac() -> Payload {
        Payload {
            metadata: Metadata {
                version: Version::V0,
                algorithm: Algorithm::HmacSha256,
                key_identifier: KeyIdentifier::KeyHash([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
            },
            claims: Claims {
                expires_at: 1700000000,
            },
        }
    }

    fn sample_payload_p256() -> Payload {
        Payload {
            metadata: Metadata {
                version: Version::V0,
                algorithm: Algorithm::Ed25519,
                key_identifier: KeyIdentifier::KeyHash([0xaa; 8]),
            },
            claims: Claims {
                expires_at: 1800000000,
            },
        }
    }

    #[test]
    fn test_payload_roundtrip_hmac() {
        let payload = sample_payload_hmac();
        let bytes = serialize_payload(&payload);
        assert_eq!(bytes.len(), 19);
        let decoded = deserialize_payload(&bytes).unwrap();
        assert_eq!(payload, decoded);
    }

    #[test]
    fn test_payload_roundtrip_p256() {
        let payload = sample_payload_p256();
        let bytes = serialize_payload(&payload);
        assert_eq!(bytes.len(), 19); // key_hash variant
        let decoded = deserialize_payload(&bytes).unwrap();
        assert_eq!(payload, decoded);
    }

    #[test]
    fn test_payload_deterministic() {
        let payload = sample_payload_hmac();
        let bytes1 = serialize_payload(&payload);
        let bytes2 = serialize_payload(&payload);
        assert_eq!(bytes1, bytes2, "serialization must be deterministic");
    }

    #[test]
    fn test_payload_wire_format() {
        let payload = sample_payload_hmac();
        let bytes = serialize_payload(&payload);

        assert_eq!(bytes[0], 0x00); // version V0
        assert_eq!(bytes[1], 0x01); // algorithm HMAC-SHA256
        assert_eq!(bytes[2], 0x01); // key_id_type KeyHash
        assert_eq!(&bytes[3..11], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(&bytes[11..19], &1700000000u64.to_be_bytes());
    }

    #[test]
    fn test_deserialize_payload_too_short() {
        assert!(deserialize_payload(&[]).is_err());
        assert!(deserialize_payload(&[0x00]).is_err());
        assert!(deserialize_payload(&[0x00, 0x01]).is_err());
        assert!(deserialize_payload(&[0x00, 0x01, 0x01]).is_err());
    }

    #[test]
    fn test_deserialize_payload_invalid_version() {
        let mut bytes = serialize_payload(&sample_payload_hmac());
        bytes[0] = 0xFF;
        assert!(matches!(
            deserialize_payload(&bytes),
            Err(ProtokenError::InvalidVersion(0xFF))
        ));
    }

    #[test]
    fn test_deserialize_payload_invalid_algorithm() {
        let mut bytes = serialize_payload(&sample_payload_hmac());
        bytes[1] = 0xFF;
        assert!(matches!(
            deserialize_payload(&bytes),
            Err(ProtokenError::InvalidAlgorithm(0xFF))
        ));
    }

    #[test]
    fn test_signed_token_roundtrip() {
        let payload_bytes = serialize_payload(&sample_payload_hmac());
        let signature = vec![0xAB; 32]; // fake HMAC signature
        let token = SignedToken {
            payload_bytes: payload_bytes.clone(),
            signature: signature.clone(),
        };
        let wire = serialize_signed_token(&token);
        assert_eq!(wire.len(), 19 + 32);

        let decoded = deserialize_signed_token(&wire).unwrap();
        assert_eq!(decoded.payload_bytes, payload_bytes);
        assert_eq!(decoded.signature, signature);
    }

    #[test]
    fn test_signed_token_p256_roundtrip() {
        let payload_bytes = serialize_payload(&sample_payload_p256());
        let signature = vec![0xCD; 64]; // fake P-256 signature
        let token = SignedToken {
            payload_bytes: payload_bytes.clone(),
            signature: signature.clone(),
        };
        let wire = serialize_signed_token(&token);
        assert_eq!(wire.len(), 19 + 64);

        let decoded = deserialize_signed_token(&wire).unwrap();
        assert_eq!(decoded.payload_bytes, payload_bytes);
        assert_eq!(decoded.signature, signature);
    }

    #[test]
    fn test_deserialize_signed_token_too_short() {
        assert!(deserialize_signed_token(&[]).is_err());
        assert!(deserialize_signed_token(&[0x00]).is_err());
    }
}
