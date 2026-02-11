//! Deterministic binary serialization for protoken payloads and signed tokens.
//!
//! Uses canonical proto3 wire encoding: fields in ascending order, minimal
//! varints, default values omitted.
//!
//! Payload proto3 fields:
//!   uint32 version = 1;      tag 0x08
//!   uint32 algorithm = 2;    tag 0x10
//!   uint32 key_id_type = 3;  tag 0x18
//!   bytes  key_id = 4;       tag 0x22
//!   uint64 expires_at = 5;   tag 0x28
//!   uint64 not_before = 6;   tag 0x30
//!   uint64 issued_at = 7;    tag 0x38
//!   bytes  subject = 8;      tag 0x42
//!   bytes  audience = 9;     tag 0x4A
//!
//! SignedToken proto3 fields:
//!   Payload payload = 1;     tag 0x0A (submessage)
//!   bytes   signature = 2;   tag 0x12

use crate::error::ProtokenError;
use crate::proto3;
use crate::types::*;

/// Serialize a Payload into canonical proto3 bytes.
pub fn serialize_payload(payload: &Payload) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32);

    proto3::encode_uint32(1, payload.metadata.version.to_byte() as u32, &mut buf);
    proto3::encode_uint32(2, payload.metadata.algorithm.to_byte() as u32, &mut buf);
    proto3::encode_uint32(
        3,
        payload.metadata.key_identifier.key_id_type().to_byte() as u32,
        &mut buf,
    );

    match &payload.metadata.key_identifier {
        KeyIdentifier::KeyHash(hash) => proto3::encode_bytes(4, hash, &mut buf),
        KeyIdentifier::PublicKey(pk) => proto3::encode_bytes(4, pk, &mut buf),
    }

    proto3::encode_uint64(5, payload.claims.expires_at, &mut buf);
    proto3::encode_uint64(6, payload.claims.not_before, &mut buf);
    proto3::encode_uint64(7, payload.claims.issued_at, &mut buf);
    proto3::encode_bytes(8, &payload.claims.subject, &mut buf);
    proto3::encode_bytes(9, &payload.claims.audience, &mut buf);

    buf
}

/// Deserialize a Payload from canonical proto3 bytes.
pub fn deserialize_payload(data: &[u8]) -> Result<Payload, ProtokenError> {
    if data.is_empty() {
        return Err(ProtokenError::PayloadTooShort {
            expected: 1,
            actual: 0,
        });
    }

    let mut version: u32 = 0;
    let mut algorithm: u32 = 0;
    let mut key_id_type: u32 = 0;
    let mut key_id: Vec<u8> = Vec::new();
    let mut expires_at: u64 = 0;
    let mut not_before: u64 = 0;
    let mut issued_at: u64 = 0;
    let mut subject: Vec<u8> = Vec::new();
    let mut audience: Vec<u8> = Vec::new();

    let mut pos = 0;
    let mut last_field_number = 0u32;

    while pos < data.len() {
        let (field_number, wire_type) = proto3::decode_tag(data, &mut pos)?;

        // Enforce ascending field order (canonical encoding)
        if field_number <= last_field_number {
            return Err(ProtokenError::MalformedEncoding(format!(
                "fields not in ascending order: field {field_number} after {last_field_number}"
            )));
        }
        last_field_number = field_number;

        match (field_number, wire_type) {
            (1, 0) => version = proto3::read_varint_value(data, &mut pos)? as u32,
            (2, 0) => algorithm = proto3::read_varint_value(data, &mut pos)? as u32,
            (3, 0) => key_id_type = proto3::read_varint_value(data, &mut pos)? as u32,
            (4, 2) => key_id = proto3::read_bytes_value(data, &mut pos)?.to_vec(),
            (5, 0) => expires_at = proto3::read_varint_value(data, &mut pos)?,
            (6, 0) => not_before = proto3::read_varint_value(data, &mut pos)?,
            (7, 0) => issued_at = proto3::read_varint_value(data, &mut pos)?,
            (8, 2) => {
                let bytes = proto3::read_bytes_value(data, &mut pos)?;
                if bytes.len() > MAX_CLAIM_BYTES_LEN {
                    return Err(ProtokenError::MalformedEncoding(format!(
                        "subject too long: {} bytes (max {})",
                        bytes.len(),
                        MAX_CLAIM_BYTES_LEN
                    )));
                }
                subject = bytes.to_vec();
            }
            (9, 2) => {
                let bytes = proto3::read_bytes_value(data, &mut pos)?;
                if bytes.len() > MAX_CLAIM_BYTES_LEN {
                    return Err(ProtokenError::MalformedEncoding(format!(
                        "audience too long: {} bytes (max {})",
                        bytes.len(),
                        MAX_CLAIM_BYTES_LEN
                    )));
                }
                audience = bytes.to_vec();
            }
            (_, _) => {
                // Unknown field — skip it (forward compatibility for inspect),
                // but note that re-canonicalization will drop it, so signature
                // verification will naturally fail if unknown fields were signed.
                proto3::skip_field(wire_type, data, &mut pos)?;
            }
        }
    }

    // Validate required fields
    let version = Version::from_byte(version as u8)
        .ok_or(ProtokenError::InvalidVersion(version as u8))?;

    let algorithm = Algorithm::from_byte(algorithm as u8)
        .ok_or(ProtokenError::InvalidAlgorithm(algorithm as u8))?;
    let key_id_type = KeyIdType::from_byte(key_id_type as u8)
        .ok_or(ProtokenError::InvalidKeyIdType(key_id_type as u8))?;

    // Validate key_id length
    let key_identifier = match key_id_type {
        KeyIdType::KeyHash => {
            if key_id.len() != KEY_HASH_LEN {
                return Err(ProtokenError::InvalidKeyLength {
                    expected: KEY_HASH_LEN,
                    actual: key_id.len(),
                });
            }
            let mut hash = [0u8; KEY_HASH_LEN];
            hash.copy_from_slice(&key_id);
            KeyIdentifier::KeyHash(hash)
        }
        KeyIdType::PublicKey => {
            match algorithm {
                Algorithm::Ed25519 => {
                    if key_id.len() != ED25519_PUBLIC_KEY_LEN {
                        return Err(ProtokenError::InvalidKeyLength {
                            expected: ED25519_PUBLIC_KEY_LEN,
                            actual: key_id.len(),
                        });
                    }
                }
                Algorithm::HmacSha256 => {
                    return Err(ProtokenError::InvalidKeyIdType(key_id_type.to_byte()));
                }
            }
            KeyIdentifier::PublicKey(key_id)
        }
    };

    Ok(Payload {
        metadata: Metadata {
            version,
            algorithm,
            key_identifier,
        },
        claims: Claims {
            expires_at,
            not_before,
            issued_at,
            subject,
            audience,
        },
    })
}

/// Serialize a SignedToken as proto3: { Payload payload = 1; bytes signature = 2; }
pub fn serialize_signed_token(token: &SignedToken) -> Vec<u8> {
    let mut buf = Vec::with_capacity(token.payload_bytes.len() + token.signature.len() + 6);
    proto3::encode_bytes(1, &token.payload_bytes, &mut buf);
    proto3::encode_bytes(2, &token.signature, &mut buf);
    buf
}

/// Deserialize a SignedToken from proto3 bytes.
/// Returns the raw payload bytes (for signature verification) and signature.
pub fn deserialize_signed_token(data: &[u8]) -> Result<SignedToken, ProtokenError> {
    if data.is_empty() {
        return Err(ProtokenError::TokenTooShort {
            expected: 1,
            actual: 0,
        });
    }

    let mut payload_bytes: Option<Vec<u8>> = None;
    let mut signature: Option<Vec<u8>> = None;

    let mut pos = 0;
    let mut last_field_number = 0u32;

    while pos < data.len() {
        let (field_number, wire_type) = proto3::decode_tag(data, &mut pos)?;

        if field_number <= last_field_number {
            return Err(ProtokenError::MalformedEncoding(format!(
                "fields not in ascending order: field {field_number} after {last_field_number}"
            )));
        }
        last_field_number = field_number;

        match (field_number, wire_type) {
            (1, 2) => {
                payload_bytes = Some(proto3::read_bytes_value(data, &mut pos)?.to_vec());
            }
            (2, 2) => {
                signature = Some(proto3::read_bytes_value(data, &mut pos)?.to_vec());
            }
            (_, _) => {
                proto3::skip_field(wire_type, data, &mut pos)?;
            }
        }
    }

    let payload_bytes = payload_bytes.ok_or_else(|| {
        ProtokenError::MalformedEncoding("missing payload field in SignedToken".into())
    })?;
    let signature = signature.ok_or_else(|| {
        ProtokenError::MalformedEncoding("missing signature field in SignedToken".into())
    })?;

    // Validate payload is parseable
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
                ..Default::default()
            },
        }
    }

    fn sample_payload_full() -> Payload {
        Payload {
            metadata: Metadata {
                version: Version::V0,
                algorithm: Algorithm::Ed25519,
                key_identifier: KeyIdentifier::KeyHash([0xaa; 8]),
            },
            claims: Claims {
                expires_at: 1700000000,
                not_before: 1699990000,
                issued_at: 1699990000,
                subject: b"user:alice".to_vec(),
                audience: b"api.example.com".to_vec(),
            },
        }
    }

    #[test]
    fn test_payload_roundtrip_hmac() {
        let payload = sample_payload_hmac();
        let bytes = serialize_payload(&payload);
        let decoded = deserialize_payload(&bytes).unwrap();
        assert_eq!(payload, decoded);
    }

    #[test]
    fn test_payload_roundtrip_full() {
        let payload = sample_payload_full();
        let bytes = serialize_payload(&payload);
        let decoded = deserialize_payload(&bytes).unwrap();
        assert_eq!(payload, decoded);
    }

    #[test]
    fn test_payload_deterministic() {
        let payload = sample_payload_full();
        let bytes1 = serialize_payload(&payload);
        let bytes2 = serialize_payload(&payload);
        assert_eq!(bytes1, bytes2, "serialization must be deterministic");
    }

    #[test]
    fn test_payload_wire_format() {
        let payload = sample_payload_hmac();
        let bytes = serialize_payload(&payload);

        // version=0 is default, omitted per proto3
        // algorithm=1: tag 0x10, value 0x01
        assert_eq!(bytes[0], 0x10);
        assert_eq!(bytes[1], 0x01);
        // key_id_type=1: tag 0x18, value 0x01
        assert_eq!(bytes[2], 0x18);
        assert_eq!(bytes[3], 0x01);
        // key_id: tag 0x22, length 0x08, then 8 bytes
        assert_eq!(bytes[4], 0x22);
        assert_eq!(bytes[5], 0x08);
        assert_eq!(&bytes[6..14], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        // expires_at: tag 0x28, varint 1700000000
        assert_eq!(bytes[14], 0x28);
    }

    #[test]
    fn test_payload_default_omission() {
        // When version=0, not_before=0, issued_at=0, subject/audience empty,
        // those fields should not appear in the encoding
        let payload = sample_payload_hmac();
        let bytes = serialize_payload(&payload);

        // Should NOT contain tag for field 1 (0x08) since version=0
        assert_ne!(bytes[0], 0x08, "version=0 should be omitted");
        // Should NOT contain tags for fields 6 (0x30), 7 (0x38), 8 (0x42), 9 (0x4A)
        assert!(!bytes.contains(&0x30), "not_before=0 should be omitted");
        assert!(!bytes.contains(&0x38), "issued_at=0 should be omitted");
        assert!(!bytes.contains(&0x42), "empty subject should be omitted");
        assert!(!bytes.contains(&0x4A), "empty audience should be omitted");
    }

    #[test]
    fn test_payload_with_optional_fields() {
        let payload = sample_payload_full();
        let bytes = serialize_payload(&payload);

        // Should contain tags for fields 6, 7, 8, 9
        assert!(bytes.contains(&0x30), "not_before should be present");
        assert!(bytes.contains(&0x38), "issued_at should be present");
        assert!(bytes.contains(&0x42), "subject should be present");
        assert!(bytes.contains(&0x4A), "audience should be present");
    }

    #[test]
    fn test_payload_ed25519_pubkey() {
        let payload = Payload {
            metadata: Metadata {
                version: Version::V0,
                algorithm: Algorithm::Ed25519,
                key_identifier: KeyIdentifier::PublicKey(vec![0xbb; 32]),
            },
            claims: Claims {
                expires_at: 1800000000,
                ..Default::default()
            },
        };
        let bytes = serialize_payload(&payload);
        let decoded = deserialize_payload(&bytes).unwrap();
        assert_eq!(payload, decoded);
    }

    #[test]
    fn test_deserialize_payload_too_short() {
        assert!(deserialize_payload(&[]).is_err());
    }

    #[test]
    fn test_deserialize_payload_invalid_algorithm() {
        // Manually encode algorithm=255
        let mut bad = Vec::new();
        proto3::encode_uint32(2, 255, &mut bad);
        proto3::encode_uint32(3, 1, &mut bad);
        proto3::encode_bytes(4, &[0; 8], &mut bad);
        proto3::encode_uint64(5, 1700000000, &mut bad);
        assert!(matches!(
            deserialize_payload(&bad),
            Err(ProtokenError::InvalidAlgorithm(255))
        ));
    }

    #[test]
    fn test_signed_token_roundtrip() {
        let payload = sample_payload_hmac();
        let payload_bytes = serialize_payload(&payload);
        let signature = vec![0xAB; 32];
        let token = SignedToken {
            payload_bytes: payload_bytes.clone(),
            signature: signature.clone(),
        };
        let wire = serialize_signed_token(&token);

        // Should start with 0x0A (field 1, LEN)
        assert_eq!(wire[0], 0x0A);

        let decoded = deserialize_signed_token(&wire).unwrap();
        assert_eq!(decoded.payload_bytes, payload_bytes);
        assert_eq!(decoded.signature, signature);
    }

    #[test]
    fn test_signed_token_ed25519_roundtrip() {
        let payload = sample_payload_full();
        let payload_bytes = serialize_payload(&payload);
        let signature = vec![0xCD; 64];
        let token = SignedToken {
            payload_bytes: payload_bytes.clone(),
            signature: signature.clone(),
        };
        let wire = serialize_signed_token(&token);
        let decoded = deserialize_signed_token(&wire).unwrap();
        assert_eq!(decoded.payload_bytes, payload_bytes);
        assert_eq!(decoded.signature, signature);
    }

    #[test]
    fn test_deserialize_signed_token_too_short() {
        assert!(deserialize_signed_token(&[]).is_err());
    }

    #[test]
    fn test_rejects_non_ascending_fields() {
        // Manually encode fields out of order: field 2 before field 1
        let mut bad = Vec::new();
        proto3::encode_uint32(2, 1, &mut bad); // algorithm first
        proto3::encode_uint32(1, 1, &mut bad); // version second (wrong!)
        assert!(deserialize_payload(&bad).is_err());
    }
}
