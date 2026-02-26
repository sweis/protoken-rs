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
//!   repeated string scope = 10; tag 0x52 (one per entry, sorted)
//!
//! SignedToken proto3 fields:
//!   Payload payload = 1;     tag 0x0A (submessage)
//!   bytes   signature = 2;   tag 0x12
//!   bytes   proof = 3;       tag 0x1A (Groth16 proof, empty for other algorithms)

use crate::error::ProtokenError;
use crate::proto3;
use crate::types::*;

/// Serialize a Payload into canonical proto3 bytes.
#[must_use]
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
        KeyIdentifier::FullKeyHash(hash) => proto3::encode_bytes(4, hash, &mut buf),
    }

    proto3::encode_uint64(5, payload.claims.expires_at, &mut buf);
    proto3::encode_uint64(6, payload.claims.not_before, &mut buf);
    proto3::encode_uint64(7, payload.claims.issued_at, &mut buf);
    proto3::encode_bytes(8, payload.claims.subject.as_bytes(), &mut buf);
    proto3::encode_bytes(9, payload.claims.audience.as_bytes(), &mut buf);

    // Repeated field 10: scopes, sorted for canonical encoding
    let mut sorted_scopes: Vec<&str> = payload.claims.scopes.iter().map(|s| s.as_str()).collect();
    sorted_scopes.sort();
    for scope in sorted_scopes {
        proto3::encode_bytes(10, scope.as_bytes(), &mut buf);
    }

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
    if data.len() > MAX_PAYLOAD_BYTES {
        return Err(ProtokenError::MalformedEncoding(format!(
            "payload too large: {} bytes (max {})",
            data.len(),
            MAX_PAYLOAD_BYTES
        )));
    }

    let mut version: u32 = 0;
    let mut algorithm: u32 = 0;
    let mut key_id_type: u32 = 0;
    let mut key_id: Vec<u8> = Vec::new();
    let mut expires_at: u64 = 0;
    let mut not_before: u64 = 0;
    let mut issued_at: u64 = 0;
    let mut subject: String = String::new();
    let mut audience: String = String::new();
    let mut scopes: Vec<String> = Vec::new();

    let mut pos = 0;
    let mut last_field_number = 0u32;

    while pos < data.len() {
        let (field_number, wire_type) = proto3::decode_tag(data, &mut pos)?;

        // Enforce ascending field order (canonical encoding).
        // Field 10 (scope) is repeated, so consecutive 10s are allowed.
        if field_number < last_field_number
            || (field_number == last_field_number && field_number != 10)
        {
            return Err(ProtokenError::MalformedEncoding(format!(
                "fields not in ascending order: field {field_number} after {last_field_number}"
            )));
        }
        last_field_number = field_number;

        match (field_number, wire_type) {
            (1, 0) => version = proto3::read_u32(data, &mut pos)?,
            (2, 0) => algorithm = proto3::read_u32(data, &mut pos)?,
            (3, 0) => key_id_type = proto3::read_u32(data, &mut pos)?,
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
                subject = std::str::from_utf8(bytes)
                    .map_err(|_| {
                        ProtokenError::MalformedEncoding("subject is not valid UTF-8".into())
                    })?
                    .to_string();
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
                audience = std::str::from_utf8(bytes)
                    .map_err(|_| {
                        ProtokenError::MalformedEncoding("audience is not valid UTF-8".into())
                    })?
                    .to_string();
            }
            (10, 2) => {
                let bytes = proto3::read_bytes_value(data, &mut pos)?;
                if bytes.len() > MAX_CLAIM_BYTES_LEN {
                    return Err(ProtokenError::MalformedEncoding(format!(
                        "scope entry too long: {} bytes (max {})",
                        bytes.len(),
                        MAX_CLAIM_BYTES_LEN
                    )));
                }
                if scopes.len() >= MAX_SCOPES {
                    return Err(ProtokenError::MalformedEncoding(format!(
                        "too many scopes: max {}",
                        MAX_SCOPES
                    )));
                }
                let s = std::str::from_utf8(bytes).map_err(|_| {
                    ProtokenError::MalformedEncoding("scope is not valid UTF-8".into())
                })?;
                // Enforce sorted order (canonical encoding)
                if let Some(prev) = scopes.last() {
                    if s <= prev.as_str() {
                        return Err(ProtokenError::MalformedEncoding(format!(
                            "scopes not in sorted order: {:?} after {:?}",
                            s, prev
                        )));
                    }
                }
                scopes.push(s.to_string());
            }
            (_, _) => {
                return Err(ProtokenError::MalformedEncoding(format!(
                    "unexpected field {field_number} (wire type {wire_type}) in Payload"
                )));
            }
        }
    }

    // Validate required fields
    let version = proto3::to_u8(version, "version")?;
    let version = Version::from_byte(version).ok_or(ProtokenError::InvalidVersion(version))?;

    let algorithm = proto3::to_u8(algorithm, "algorithm")?;
    let algorithm =
        Algorithm::from_byte(algorithm).ok_or(ProtokenError::InvalidAlgorithm(algorithm))?;
    let key_id_type = proto3::to_u8(key_id_type, "key_id_type")?;
    let key_id_type =
        KeyIdType::from_byte(key_id_type).ok_or(ProtokenError::InvalidKeyIdType(key_id_type))?;

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
            let expected_len = match algorithm {
                Algorithm::Ed25519 => ED25519_PUBLIC_KEY_LEN,
                Algorithm::MlDsa44 => MLDSA44_PUBLIC_KEY_LEN,
                Algorithm::HmacSha256 | Algorithm::Groth16Poseidon => {
                    return Err(ProtokenError::InvalidKeyIdType(key_id_type.to_byte()));
                }
            };
            if key_id.len() != expected_len {
                return Err(ProtokenError::InvalidKeyLength {
                    expected: expected_len,
                    actual: key_id.len(),
                });
            }
            KeyIdentifier::PublicKey(key_id)
        }
        KeyIdType::FullKeyHash => {
            if key_id.len() != FULL_KEY_HASH_LEN {
                return Err(ProtokenError::InvalidKeyLength {
                    expected: FULL_KEY_HASH_LEN,
                    actual: key_id.len(),
                });
            }
            let mut hash = [0u8; FULL_KEY_HASH_LEN];
            hash.copy_from_slice(&key_id);
            KeyIdentifier::FullKeyHash(hash)
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
            scopes,
        },
    })
}

/// Serialize a SignedToken as proto3:
/// { Payload payload = 1; bytes signature = 2; bytes proof = 3; }
#[must_use]
pub fn serialize_signed_token(token: &SignedToken) -> Vec<u8> {
    let mut buf = Vec::with_capacity(token.payload_bytes.len() + token.signature.len() + 10);
    proto3::encode_bytes(1, &token.payload_bytes, &mut buf);
    proto3::encode_bytes(2, &token.signature, &mut buf);
    proto3::encode_bytes(3, &token.proof, &mut buf);
    buf
}

/// Deserialize a SignedToken from proto3 bytes.
/// Returns the raw payload bytes (for signature verification) and signature.
/// Callers should use `deserialize_payload()` on `payload_bytes` to validate and parse the payload.
/// Maximum total size for a serialized SignedToken (payload + signature + proof + framing).
const MAX_SIGNED_TOKEN_BYTES: usize =
    MAX_PAYLOAD_BYTES + MAX_SIGNATURE_BYTES + MAX_PROOF_BYTES + 32;

pub fn deserialize_signed_token(data: &[u8]) -> Result<SignedToken, ProtokenError> {
    if data.is_empty() {
        return Err(ProtokenError::TokenTooShort {
            expected: 1,
            actual: 0,
        });
    }
    if data.len() > MAX_SIGNED_TOKEN_BYTES {
        return Err(ProtokenError::MalformedEncoding(format!(
            "signed token too large: {} bytes (max {})",
            data.len(),
            MAX_SIGNED_TOKEN_BYTES
        )));
    }

    let mut payload_bytes: Option<Vec<u8>> = None;
    let mut signature: Option<Vec<u8>> = None;
    let mut proof: Vec<u8> = Vec::new();

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
                let bytes = proto3::read_bytes_value(data, &mut pos)?;
                if bytes.len() > MAX_PAYLOAD_BYTES {
                    return Err(ProtokenError::MalformedEncoding(format!(
                        "payload too large: {} bytes (max {})",
                        bytes.len(),
                        MAX_PAYLOAD_BYTES
                    )));
                }
                payload_bytes = Some(bytes.to_vec());
            }
            (2, 2) => {
                let bytes = proto3::read_bytes_value(data, &mut pos)?;
                if bytes.len() > MAX_SIGNATURE_BYTES {
                    return Err(ProtokenError::MalformedEncoding(format!(
                        "signature too large: {} bytes (max {})",
                        bytes.len(),
                        MAX_SIGNATURE_BYTES
                    )));
                }
                signature = Some(bytes.to_vec());
            }
            (3, 2) => {
                let bytes = proto3::read_bytes_value(data, &mut pos)?;
                if bytes.len() > MAX_PROOF_BYTES {
                    return Err(ProtokenError::MalformedEncoding(format!(
                        "proof too large: {} bytes (max {})",
                        bytes.len(),
                        MAX_PROOF_BYTES
                    )));
                }
                proof = bytes.to_vec();
            }
            (_, _) => {
                return Err(ProtokenError::MalformedEncoding(format!(
                    "unexpected field {field_number} (wire type {wire_type}) in SignedToken"
                )));
            }
        }
    }

    let payload_bytes = payload_bytes.ok_or_else(|| {
        ProtokenError::MalformedEncoding("missing payload field in SignedToken".into())
    })?;
    let signature = signature.ok_or_else(|| {
        ProtokenError::MalformedEncoding("missing signature field in SignedToken".into())
    })?;

    Ok(SignedToken {
        payload_bytes,
        signature,
        proof,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn sample_payload_hmac() -> Payload {
        Payload {
            metadata: Metadata {
                version: Version::V0,
                algorithm: Algorithm::HmacSha256,
                key_identifier: KeyIdentifier::KeyHash([
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                ]),
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
                subject: "user:alice".into(),
                audience: "api.example.com".into(),
                scopes: vec!["admin".into(), "read".into(), "write".into()],
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
        assert_eq!(
            &bytes[6..14],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
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
            proof: Vec::new(),
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
            proof: Vec::new(),
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

    #[test]
    fn test_payload_with_scopes() {
        let payload = Payload {
            metadata: Metadata {
                version: Version::V0,
                algorithm: Algorithm::HmacSha256,
                key_identifier: KeyIdentifier::KeyHash([0x01; 8]),
            },
            claims: Claims {
                expires_at: 1700000000,
                scopes: vec!["read".into(), "write".into()],
                ..Default::default()
            },
        };
        let bytes = serialize_payload(&payload);
        let decoded = deserialize_payload(&bytes).unwrap();
        assert_eq!(payload, decoded);
        assert_eq!(decoded.claims.scopes, vec!["read", "write"]);
    }

    #[test]
    fn test_scopes_sorted_on_encode() {
        let payload = Payload {
            metadata: Metadata {
                version: Version::V0,
                algorithm: Algorithm::HmacSha256,
                key_identifier: KeyIdentifier::KeyHash([0x01; 8]),
            },
            claims: Claims {
                expires_at: 1700000000,
                // Intentionally unsorted input
                scopes: vec!["write".into(), "admin".into(), "read".into()],
                ..Default::default()
            },
        };
        let bytes = serialize_payload(&payload);
        let decoded = deserialize_payload(&bytes).unwrap();
        // Should come back sorted
        assert_eq!(decoded.claims.scopes, vec!["admin", "read", "write"]);
    }

    #[test]
    fn test_empty_scopes_omitted() {
        let payload = sample_payload_hmac();
        let bytes = serialize_payload(&payload);
        // Tag for field 10 wire type 2 is 0x52
        assert!(!bytes.contains(&0x52), "empty scopes should be omitted");
    }

    #[test]
    fn test_rejects_unsorted_scopes() {
        // Manually encode scopes out of order
        let mut bad = Vec::new();
        proto3::encode_uint32(2, 1, &mut bad);
        proto3::encode_uint32(3, 1, &mut bad);
        proto3::encode_bytes(4, &[0; 8], &mut bad);
        proto3::encode_uint64(5, 1700000000, &mut bad);
        proto3::encode_bytes(10, b"write", &mut bad);
        proto3::encode_bytes(10, b"read", &mut bad); // out of order
        assert!(deserialize_payload(&bad).is_err());
    }

    #[test]
    fn test_rejects_duplicate_scopes() {
        let mut bad = Vec::new();
        proto3::encode_uint32(2, 1, &mut bad);
        proto3::encode_uint32(3, 1, &mut bad);
        proto3::encode_bytes(4, &[0; 8], &mut bad);
        proto3::encode_uint64(5, 1700000000, &mut bad);
        proto3::encode_bytes(10, b"read", &mut bad);
        proto3::encode_bytes(10, b"read", &mut bad); // duplicate
        assert!(deserialize_payload(&bad).is_err());
    }

    #[test]
    fn test_rejects_invalid_utf8_scope() {
        let mut bad = Vec::new();
        proto3::encode_uint32(2, 1, &mut bad);
        proto3::encode_uint32(3, 1, &mut bad);
        proto3::encode_bytes(4, &[0; 8], &mut bad);
        proto3::encode_uint64(5, 1700000000, &mut bad);
        proto3::encode_bytes(10, &[0xFF, 0xFE], &mut bad); // invalid UTF-8
        assert!(deserialize_payload(&bad).is_err());
    }

    #[test]
    fn test_rejects_invalid_utf8_subject() {
        let mut bad = Vec::new();
        proto3::encode_uint32(2, 1, &mut bad);
        proto3::encode_uint32(3, 1, &mut bad);
        proto3::encode_bytes(4, &[0; 8], &mut bad);
        proto3::encode_uint64(5, 1700000000, &mut bad);
        proto3::encode_bytes(8, &[0xFF, 0xFE], &mut bad); // invalid UTF-8
        assert!(deserialize_payload(&bad).is_err());
    }

    #[test]
    fn test_rejects_invalid_utf8_audience() {
        let mut bad = Vec::new();
        proto3::encode_uint32(2, 1, &mut bad);
        proto3::encode_uint32(3, 1, &mut bad);
        proto3::encode_bytes(4, &[0; 8], &mut bad);
        proto3::encode_uint64(5, 1700000000, &mut bad);
        proto3::encode_bytes(9, &[0xFF, 0xFE], &mut bad); // invalid UTF-8
        assert!(deserialize_payload(&bad).is_err());
    }

    #[test]
    fn test_rejects_scope_too_long() {
        let mut bad = Vec::new();
        proto3::encode_uint32(2, 1, &mut bad);
        proto3::encode_uint32(3, 1, &mut bad);
        proto3::encode_bytes(4, &[0; 8], &mut bad);
        proto3::encode_uint64(5, 1700000000, &mut bad);
        let long_scope = vec![b'a'; MAX_CLAIM_BYTES_LEN + 1];
        proto3::encode_bytes(10, &long_scope, &mut bad);
        assert!(deserialize_payload(&bad).is_err());
    }

    #[test]
    fn test_rejects_too_many_scopes() {
        let mut bad = Vec::new();
        proto3::encode_uint32(2, 1, &mut bad);
        proto3::encode_uint32(3, 1, &mut bad);
        proto3::encode_bytes(4, &[0; 8], &mut bad);
        proto3::encode_uint64(5, 1700000000, &mut bad);
        for i in 0..=MAX_SCOPES {
            proto3::encode_bytes(10, format!("scope{i:03}").as_bytes(), &mut bad);
        }
        assert!(deserialize_payload(&bad).is_err());
    }

    #[test]
    fn test_rejects_scope_wrong_wire_type() {
        // Field 10 with wire type 0 (varint) instead of 2 (LEN).
        // Strict canonical parsing rejects unexpected (field, wire_type) pairs.
        let mut bad = Vec::new();
        proto3::encode_uint32(2, 1, &mut bad);
        proto3::encode_uint32(3, 1, &mut bad);
        proto3::encode_bytes(4, &[0; 8], &mut bad);
        proto3::encode_uint64(5, 1700000000, &mut bad);
        proto3::encode_uint64(10, 42, &mut bad); // varint instead of LEN
        assert!(
            deserialize_payload(&bad).is_err(),
            "wrong wire type for field 10 should be rejected"
        );
    }

    #[test]
    fn test_rejects_subject_too_long() {
        let mut bad = Vec::new();
        proto3::encode_uint32(2, 1, &mut bad);
        proto3::encode_uint32(3, 1, &mut bad);
        proto3::encode_bytes(4, &[0; 8], &mut bad);
        proto3::encode_uint64(5, 1700000000, &mut bad);
        proto3::encode_bytes(8, &vec![b'x'; MAX_CLAIM_BYTES_LEN + 1], &mut bad);
        assert!(deserialize_payload(&bad).is_err());
    }

    #[test]
    fn test_rejects_audience_too_long() {
        let mut bad = Vec::new();
        proto3::encode_uint32(2, 1, &mut bad);
        proto3::encode_uint32(3, 1, &mut bad);
        proto3::encode_bytes(4, &[0; 8], &mut bad);
        proto3::encode_uint64(5, 1700000000, &mut bad);
        proto3::encode_bytes(9, &vec![b'x'; MAX_CLAIM_BYTES_LEN + 1], &mut bad);
        assert!(deserialize_payload(&bad).is_err());
    }

    #[test]
    fn test_rejects_truncated_payload() {
        let payload = sample_payload_hmac();
        let bytes = serialize_payload(&payload);
        // Truncate at various points
        for len in 1..bytes.len() {
            let truncated = &bytes[..len];
            // Should either parse partially or error, never panic
            let _ = deserialize_payload(truncated);
        }
    }

    #[test]
    fn test_rejects_truncated_signed_token() {
        let payload = sample_payload_hmac();
        let payload_bytes = serialize_payload(&payload);
        let token = SignedToken {
            payload_bytes,
            signature: vec![0xAB; 32],
            proof: Vec::new(),
        };
        let wire = serialize_signed_token(&token);
        for len in 1..wire.len() {
            let truncated = &wire[..len];
            let _ = deserialize_signed_token(truncated);
        }
    }

    #[test]
    fn test_rejects_invalid_key_id_length() {
        // key_id_type=1 (key_hash) but key_id is 7 bytes instead of 8
        let mut bad = Vec::new();
        proto3::encode_uint32(2, 1, &mut bad);
        proto3::encode_uint32(3, 1, &mut bad);
        proto3::encode_bytes(4, &[0; 7], &mut bad); // wrong length
        proto3::encode_uint64(5, 1700000000, &mut bad);
        assert!(matches!(
            deserialize_payload(&bad),
            Err(ProtokenError::InvalidKeyLength {
                expected: 8,
                actual: 7
            })
        ));
    }

    #[test]
    fn test_rejects_invalid_version() {
        let mut bad = Vec::new();
        proto3::encode_uint32(1, 99, &mut bad); // invalid version
        proto3::encode_uint32(2, 1, &mut bad);
        proto3::encode_uint32(3, 1, &mut bad);
        proto3::encode_bytes(4, &[0; 8], &mut bad);
        proto3::encode_uint64(5, 1700000000, &mut bad);
        assert!(matches!(
            deserialize_payload(&bad),
            Err(ProtokenError::InvalidVersion(99))
        ));
    }

    #[test]
    fn test_rejects_hmac_with_public_key_id() {
        // HMAC (algorithm=1) should not use public_key key_id_type
        let mut bad = Vec::new();
        proto3::encode_uint32(2, 1, &mut bad); // HMAC
        proto3::encode_uint32(3, 2, &mut bad); // public_key
        proto3::encode_bytes(4, &[0; 32], &mut bad);
        proto3::encode_uint64(5, 1700000000, &mut bad);
        assert!(deserialize_payload(&bad).is_err());
    }

    #[test]
    fn test_rejects_signed_token_missing_payload() {
        // Only signature field, no payload
        let mut bad = Vec::new();
        proto3::encode_bytes(2, &[0; 32], &mut bad);
        assert!(deserialize_signed_token(&bad).is_err());
    }

    #[test]
    fn test_rejects_signed_token_missing_signature() {
        let payload = sample_payload_hmac();
        let payload_bytes = serialize_payload(&payload);
        // Only payload field, no signature
        let mut bad = Vec::new();
        proto3::encode_bytes(1, &payload_bytes, &mut bad);
        assert!(deserialize_signed_token(&bad).is_err());
    }

    #[test]
    fn test_scopes_with_signed_token_roundtrip() {
        let payload = Payload {
            metadata: Metadata {
                version: Version::V0,
                algorithm: Algorithm::HmacSha256,
                key_identifier: KeyIdentifier::KeyHash([0x01; 8]),
            },
            claims: Claims {
                expires_at: 1700000000,
                scopes: vec!["admin".into(), "read".into(), "write".into()],
                ..Default::default()
            },
        };
        let payload_bytes = serialize_payload(&payload);
        let token = SignedToken {
            payload_bytes: payload_bytes.clone(),
            signature: vec![0xAB; 32],
            proof: Vec::new(),
        };
        let wire = serialize_signed_token(&token);
        let decoded = deserialize_signed_token(&wire).unwrap();
        let decoded_payload = deserialize_payload(&decoded.payload_bytes).unwrap();
        assert_eq!(
            decoded_payload.claims.scopes,
            vec!["admin", "read", "write"]
        );
    }
}
