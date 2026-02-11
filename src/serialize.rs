//! Deterministic binary serialization for protoken payloads and signed tokens.
//!
//! ## v0 Wire Format (custom fixed-layout)
//!   [ version:1 | algorithm:1 | key_id_type:1 | key_id:N | expires_at:8 ]
//!   SignedToken: [ payload | signature ] (split by algorithm-determined sig length)
//!
//! ## v1 Wire Format (canonical proto3)
//!   Payload: proto3 message with fields 1-9 in ascending order
//!   SignedToken: proto3 message { Payload payload = 1; bytes signature = 2; }
//!
//! Auto-detection by first byte: 0x00 = v0, 0x08/0x10 = v1 Payload, 0x0A = v1 SignedToken.

use crate::error::ProtokenError;
use crate::proto3;
use crate::types::*;

// ─── v0 constants ───

const MIN_V0_PAYLOAD_LEN: usize = 19;
const V0_HEADER_LEN: usize = 3;
const EXPIRES_AT_LEN: usize = 8;

// ─── v0 serialization (unchanged) ───

/// Serialize a v0 Payload into deterministic bytes.
pub fn serialize_payload_v0(payload: &Payload) -> Vec<u8> {
    let key_id_len = payload.metadata.key_identifier.value_len();
    let total_len = V0_HEADER_LEN + key_id_len + EXPIRES_AT_LEN;
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

/// Deserialize a v0 Payload from deterministic bytes.
pub fn deserialize_payload_v0(data: &[u8]) -> Result<Payload, ProtokenError> {
    if data.len() < V0_HEADER_LEN + 1 {
        return Err(ProtokenError::PayloadTooShort {
            expected: V0_HEADER_LEN + 1,
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
                return Err(ProtokenError::InvalidKeyIdType(key_id_type.to_byte()));
            }
        },
    };

    let expected_len = V0_HEADER_LEN + key_id_len + EXPIRES_AT_LEN;
    if data.len() != expected_len {
        return Err(ProtokenError::PayloadTooShort {
            expected: expected_len,
            actual: data.len(),
        });
    }

    let key_id_start = V0_HEADER_LEN;
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
        claims: Claims {
            expires_at,
            ..Default::default()
        },
    })
}

/// Serialize a v0 SignedToken: payload || signature.
pub fn serialize_signed_token_v0(token: &SignedToken) -> Vec<u8> {
    let mut buf = Vec::with_capacity(token.payload_bytes.len() + token.signature.len());
    buf.extend_from_slice(&token.payload_bytes);
    buf.extend_from_slice(&token.signature);
    buf
}

/// Deserialize a v0 SignedToken from wire bytes.
pub fn deserialize_signed_token_v0(data: &[u8]) -> Result<SignedToken, ProtokenError> {
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
            expected: sig_len + MIN_V0_PAYLOAD_LEN,
            actual: data.len(),
        });
    }

    let payload_len = data.len() - sig_len;
    let payload_bytes = data[..payload_len].to_vec();
    let signature = data[payload_len..].to_vec();

    deserialize_payload_v0(&payload_bytes)?;

    Ok(SignedToken {
        payload_bytes,
        signature,
    })
}

// ─── v1 serialization (canonical proto3) ───
//
// Payload proto3 fields:
//   uint32 version = 1;      tag 0x08
//   uint32 algorithm = 2;    tag 0x10
//   uint32 key_id_type = 3;  tag 0x18
//   bytes  key_id = 4;       tag 0x22
//   uint64 expires_at = 5;   tag 0x28
//   uint64 not_before = 6;   tag 0x30
//   uint64 issued_at = 7;    tag 0x38
//   bytes  subject = 8;      tag 0x42
//   bytes  audience = 9;     tag 0x4A
//
// SignedToken proto3 fields:
//   Payload payload = 1;     tag 0x0A (submessage)
//   bytes   signature = 2;   tag 0x12

/// Serialize a v1 Payload into canonical proto3 bytes.
pub fn serialize_payload_v1(payload: &Payload) -> Vec<u8> {
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

/// Deserialize a v1 Payload from canonical proto3 bytes.
pub fn deserialize_payload_v1(data: &[u8]) -> Result<Payload, ProtokenError> {
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
    if version == Version::V0 {
        return Err(ProtokenError::MalformedEncoding(
            "version 0 must use v0 custom format, not proto3".into(),
        ));
    }

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

/// Serialize a v1 SignedToken as proto3: { Payload payload = 1; bytes signature = 2; }
pub fn serialize_signed_token_v1(token: &SignedToken) -> Vec<u8> {
    let mut buf = Vec::with_capacity(token.payload_bytes.len() + token.signature.len() + 6);
    proto3::encode_bytes(1, &token.payload_bytes, &mut buf);
    proto3::encode_bytes(2, &token.signature, &mut buf);
    buf
}

/// Deserialize a v1 SignedToken from proto3 bytes.
/// Returns the raw payload bytes (for signature verification) and signature.
pub fn deserialize_signed_token_v1(data: &[u8]) -> Result<SignedToken, ProtokenError> {
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
    deserialize_payload_v1(&payload_bytes)?;

    Ok(SignedToken {
        payload_bytes,
        signature,
    })
}

// ─── Auto-detecting wrappers ───

/// Serialize a Payload, choosing format based on version.
pub fn serialize_payload(payload: &Payload) -> Vec<u8> {
    match payload.metadata.version {
        Version::V0 => serialize_payload_v0(payload),
        Version::V1 => serialize_payload_v1(payload),
    }
}

/// Deserialize a Payload, auto-detecting v0 vs v1 by first byte.
pub fn deserialize_payload(data: &[u8]) -> Result<Payload, ProtokenError> {
    if data.is_empty() {
        return Err(ProtokenError::PayloadTooShort {
            expected: 1,
            actual: 0,
        });
    }
    match data[0] {
        0x00 => deserialize_payload_v0(data),
        // 0x08 = field 1 (version) varint, 0x10 = field 2 (algorithm) varint
        0x08 | 0x10 => deserialize_payload_v1(data),
        b => Err(ProtokenError::MalformedEncoding(format!(
            "unrecognized payload format: first byte 0x{b:02X}"
        ))),
    }
}

/// Serialize a SignedToken, choosing format based on payload version.
pub fn serialize_signed_token(token: &SignedToken) -> Vec<u8> {
    // Detect version from payload bytes
    if !token.payload_bytes.is_empty() && token.payload_bytes[0] != 0x00 {
        serialize_signed_token_v1(token)
    } else {
        serialize_signed_token_v0(token)
    }
}

/// Deserialize a SignedToken, auto-detecting v0 vs v1 by first byte.
pub fn deserialize_signed_token(data: &[u8]) -> Result<SignedToken, ProtokenError> {
    if data.is_empty() {
        return Err(ProtokenError::TokenTooShort {
            expected: 1,
            actual: 0,
        });
    }
    match data[0] {
        0x00 => deserialize_signed_token_v0(data),
        // 0x0A = field 1 (payload submessage) LEN
        0x0A => deserialize_signed_token_v1(data),
        b => Err(ProtokenError::MalformedEncoding(format!(
            "unrecognized token format: first byte 0x{b:02X}"
        ))),
    }
}

// ─── Tests ───

#[cfg(test)]
mod tests {
    use super::*;

    // ─── v0 tests (unchanged) ───

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

    fn sample_payload_ed25519() -> Payload {
        Payload {
            metadata: Metadata {
                version: Version::V0,
                algorithm: Algorithm::Ed25519,
                key_identifier: KeyIdentifier::KeyHash([0xaa; 8]),
            },
            claims: Claims {
                expires_at: 1800000000,
                ..Default::default()
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
    fn test_payload_roundtrip_ed25519() {
        let payload = sample_payload_ed25519();
        let bytes = serialize_payload(&payload);
        assert_eq!(bytes.len(), 19);
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
        assert!(deserialize_payload_v0(&[0x00]).is_err());
        assert!(deserialize_payload_v0(&[0x00, 0x01]).is_err());
        assert!(deserialize_payload_v0(&[0x00, 0x01, 0x01]).is_err());
    }

    #[test]
    fn test_deserialize_payload_invalid_version() {
        let mut bytes = serialize_payload_v0(&sample_payload_hmac());
        bytes[0] = 0xFF;
        assert!(matches!(
            deserialize_payload_v0(&bytes),
            Err(ProtokenError::InvalidVersion(0xFF))
        ));
    }

    #[test]
    fn test_deserialize_payload_invalid_algorithm() {
        let mut bytes = serialize_payload_v0(&sample_payload_hmac());
        bytes[1] = 0xFF;
        assert!(matches!(
            deserialize_payload_v0(&bytes),
            Err(ProtokenError::InvalidAlgorithm(0xFF))
        ));
    }

    #[test]
    fn test_signed_token_roundtrip() {
        let payload_bytes = serialize_payload_v0(&sample_payload_hmac());
        let signature = vec![0xAB; 32];
        let token = SignedToken {
            payload_bytes: payload_bytes.clone(),
            signature: signature.clone(),
        };
        let wire = serialize_signed_token_v0(&token);
        assert_eq!(wire.len(), 19 + 32);

        let decoded = deserialize_signed_token_v0(&wire).unwrap();
        assert_eq!(decoded.payload_bytes, payload_bytes);
        assert_eq!(decoded.signature, signature);
    }

    #[test]
    fn test_signed_token_ed25519_roundtrip() {
        let payload_bytes = serialize_payload_v0(&sample_payload_ed25519());
        let signature = vec![0xCD; 64];
        let token = SignedToken {
            payload_bytes: payload_bytes.clone(),
            signature: signature.clone(),
        };
        let wire = serialize_signed_token_v0(&token);
        assert_eq!(wire.len(), 19 + 64);

        let decoded = deserialize_signed_token_v0(&wire).unwrap();
        assert_eq!(decoded.payload_bytes, payload_bytes);
        assert_eq!(decoded.signature, signature);
    }

    #[test]
    fn test_deserialize_signed_token_too_short() {
        assert!(deserialize_signed_token(&[]).is_err());
        assert!(deserialize_signed_token_v0(&[0x00]).is_err());
    }

    // ─── v1 tests ───

    fn sample_payload_v1_hmac() -> Payload {
        Payload {
            metadata: Metadata {
                version: Version::V1,
                algorithm: Algorithm::HmacSha256,
                key_identifier: KeyIdentifier::KeyHash([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
            },
            claims: Claims {
                expires_at: 1700000000,
                ..Default::default()
            },
        }
    }

    fn sample_payload_v1_full() -> Payload {
        Payload {
            metadata: Metadata {
                version: Version::V1,
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
    fn test_v1_payload_roundtrip_hmac() {
        let payload = sample_payload_v1_hmac();
        let bytes = serialize_payload_v1(&payload);
        let decoded = deserialize_payload_v1(&bytes).unwrap();
        assert_eq!(payload, decoded);
    }

    #[test]
    fn test_v1_payload_roundtrip_full() {
        let payload = sample_payload_v1_full();
        let bytes = serialize_payload_v1(&payload);
        let decoded = deserialize_payload_v1(&bytes).unwrap();
        assert_eq!(payload, decoded);
    }

    #[test]
    fn test_v1_payload_deterministic() {
        let payload = sample_payload_v1_full();
        let bytes1 = serialize_payload_v1(&payload);
        let bytes2 = serialize_payload_v1(&payload);
        assert_eq!(bytes1, bytes2, "v1 serialization must be deterministic");
    }

    #[test]
    fn test_v1_payload_wire_format() {
        let payload = sample_payload_v1_hmac();
        let bytes = serialize_payload_v1(&payload);

        // version=1: tag 0x08, value 0x01
        assert_eq!(bytes[0], 0x08);
        assert_eq!(bytes[1], 0x01);
        // algorithm=1: tag 0x10, value 0x01
        assert_eq!(bytes[2], 0x10);
        assert_eq!(bytes[3], 0x01);
        // key_id_type=1: tag 0x18, value 0x01
        assert_eq!(bytes[4], 0x18);
        assert_eq!(bytes[5], 0x01);
        // key_id: tag 0x22, length 0x08, then 8 bytes
        assert_eq!(bytes[6], 0x22);
        assert_eq!(bytes[7], 0x08);
        assert_eq!(&bytes[8..16], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        // expires_at: tag 0x28, varint 1700000000
        assert_eq!(bytes[16], 0x28);
    }

    #[test]
    fn test_v1_payload_default_omission() {
        // When not_before=0, issued_at=0, subject/audience empty,
        // those fields should not appear in the encoding
        let payload = sample_payload_v1_hmac();
        let bytes = serialize_payload_v1(&payload);

        // Should NOT contain tags for fields 6 (0x30), 7 (0x38), 8 (0x42), 9 (0x4A)
        assert!(!bytes.contains(&0x30), "not_before=0 should be omitted");
        assert!(!bytes.contains(&0x38), "issued_at=0 should be omitted");
        assert!(!bytes.contains(&0x42), "empty subject should be omitted");
        assert!(!bytes.contains(&0x4A), "empty audience should be omitted");
    }

    #[test]
    fn test_v1_payload_with_optional_fields() {
        let payload = sample_payload_v1_full();
        let bytes = serialize_payload_v1(&payload);

        // Should contain tags for fields 6, 7, 8, 9
        assert!(bytes.contains(&0x30), "not_before should be present");
        assert!(bytes.contains(&0x38), "issued_at should be present");
        assert!(bytes.contains(&0x42), "subject should be present");
        assert!(bytes.contains(&0x4A), "audience should be present");
    }

    #[test]
    fn test_v1_payload_ed25519_pubkey() {
        let payload = Payload {
            metadata: Metadata {
                version: Version::V1,
                algorithm: Algorithm::Ed25519,
                key_identifier: KeyIdentifier::PublicKey(vec![0xbb; 32]),
            },
            claims: Claims {
                expires_at: 1800000000,
                ..Default::default()
            },
        };
        let bytes = serialize_payload_v1(&payload);
        let decoded = deserialize_payload_v1(&bytes).unwrap();
        assert_eq!(payload, decoded);
    }

    #[test]
    fn test_v1_signed_token_roundtrip() {
        let payload = sample_payload_v1_hmac();
        let payload_bytes = serialize_payload_v1(&payload);
        let signature = vec![0xAB; 32];
        let token = SignedToken {
            payload_bytes: payload_bytes.clone(),
            signature: signature.clone(),
        };
        let wire = serialize_signed_token_v1(&token);

        // Should start with 0x0A (field 1, LEN)
        assert_eq!(wire[0], 0x0A);

        let decoded = deserialize_signed_token_v1(&wire).unwrap();
        assert_eq!(decoded.payload_bytes, payload_bytes);
        assert_eq!(decoded.signature, signature);
    }

    #[test]
    fn test_v1_signed_token_ed25519_roundtrip() {
        let payload = sample_payload_v1_full();
        let payload_bytes = serialize_payload_v1(&payload);
        let signature = vec![0xCD; 64];
        let token = SignedToken {
            payload_bytes: payload_bytes.clone(),
            signature: signature.clone(),
        };
        let wire = serialize_signed_token_v1(&token);
        let decoded = deserialize_signed_token_v1(&wire).unwrap();
        assert_eq!(decoded.payload_bytes, payload_bytes);
        assert_eq!(decoded.signature, signature);
    }

    // ─── Auto-detection tests ───

    #[test]
    fn test_auto_detect_payload_v0() {
        let payload = sample_payload_hmac();
        let bytes = serialize_payload(&payload);
        assert_eq!(bytes[0], 0x00);
        let decoded = deserialize_payload(&bytes).unwrap();
        assert_eq!(decoded.metadata.version, Version::V0);
    }

    #[test]
    fn test_auto_detect_payload_v1() {
        let payload = sample_payload_v1_hmac();
        let bytes = serialize_payload(&payload);
        assert_eq!(bytes[0], 0x08);
        let decoded = deserialize_payload(&bytes).unwrap();
        assert_eq!(decoded.metadata.version, Version::V1);
    }

    #[test]
    fn test_auto_detect_signed_token_v0() {
        let payload_bytes = serialize_payload_v0(&sample_payload_hmac());
        let token = SignedToken {
            payload_bytes,
            signature: vec![0xAB; 32],
        };
        let wire = serialize_signed_token(&token);
        assert_eq!(wire[0], 0x00); // v0 format
        let decoded = deserialize_signed_token(&wire).unwrap();
        assert_eq!(decoded.signature.len(), 32);
    }

    #[test]
    fn test_auto_detect_signed_token_v1() {
        let payload_bytes = serialize_payload_v1(&sample_payload_v1_hmac());
        let token = SignedToken {
            payload_bytes,
            signature: vec![0xAB; 32],
        };
        let wire = serialize_signed_token(&token);
        assert_eq!(wire[0], 0x0A); // v1 proto3 format
        let decoded = deserialize_signed_token(&wire).unwrap();
        assert_eq!(decoded.signature.len(), 32);
    }

    #[test]
    fn test_v1_rejects_non_ascending_fields() {
        // Manually encode fields out of order: field 2 before field 1
        let mut bad = Vec::new();
        proto3::encode_uint32(2, 1, &mut bad); // algorithm first
        proto3::encode_uint32(1, 1, &mut bad); // version second (wrong!)
        assert!(deserialize_payload_v1(&bad).is_err());
    }

    #[test]
    fn test_v1_rejects_version_zero() {
        // Proto3 format with explicit version=0 should fail
        // (version=0 is omitted per proto3, so this is a manually crafted test)
        let mut bad = Vec::new();
        // Skip version (field 1, which would encode version=0 as absent)
        proto3::encode_uint32(2, 1, &mut bad); // algorithm=HMAC
        proto3::encode_uint32(3, 1, &mut bad); // key_id_type=key_hash
        proto3::encode_bytes(4, &[0; 8], &mut bad); // key_id
        proto3::encode_uint64(5, 1700000000, &mut bad); // expires_at

        // version defaults to 0, which should be rejected
        assert!(deserialize_payload_v1(&bad).is_err());
    }
}
