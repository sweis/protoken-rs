//! Deterministic binary serialization for token claims and signed envelopes.
//!
//! Uses canonical proto3 wire encoding: fields in ascending order, minimal
//! varints, default values omitted.
//!
//! SignedToken (envelope) proto3 fields:
//!   uint32 version = 1;      tag 0x08 (reserved, always 0, omitted)
//!   uint32 algorithm = 2;    tag 0x10
//!   uint32 key_id_type = 3;  tag 0x18
//!   bytes  key_id = 4;       tag 0x22
//!   bytes  payload = 5;      tag 0x2A (canonical proto3 bytes of the inner message)
//!   bytes  signature = 6;    tag 0x32 (over envelope fields 1-5)
//!
//! Claims (payload) proto3 fields:
//!   uint64 expires_at = 1;   tag 0x08
//!   uint64 not_before = 2;   tag 0x10
//!   uint64 issued_at = 3;    tag 0x18
//!   string subject = 4;      tag 0x22
//!   string audience = 5;     tag 0x2A
//!   repeated string scope = 6; tag 0x32 (one per entry, sorted)
//!
//! The signature is computed over the canonical encoding of envelope fields
//! 1-5. Because decoding enforces canonical form (ascending field order,
//! minimal varints, no unknown or duplicate fields), the signing input equals
//! the received token bytes minus the trailing signature field. This binds the
//! algorithm and key identifier into the signature.

use crate::error::ProtokenError;
use crate::proto3;
use crate::types::*;

/// Serialize Claims into canonical proto3 bytes.
#[must_use]
pub fn serialize_claims(claims: &Claims) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32);

    proto3::encode_uint64(1, claims.expires_at, &mut buf);
    proto3::encode_uint64(2, claims.not_before, &mut buf);
    proto3::encode_uint64(3, claims.issued_at, &mut buf);
    proto3::encode_bytes(4, claims.subject.as_bytes(), &mut buf);
    proto3::encode_bytes(5, claims.audience.as_bytes(), &mut buf);

    // Repeated field 6: scopes, sorted for canonical encoding
    let mut sorted_scopes: Vec<&str> = claims.scopes.iter().map(|s| s.as_str()).collect();
    sorted_scopes.sort();
    for scope in sorted_scopes {
        proto3::encode_bytes(6, scope.as_bytes(), &mut buf);
    }

    buf
}

/// Read a varint field value, rejecting an explicit zero (canonical encoding
/// omits default values, so a zero on the wire is non-canonical).
fn read_nonzero_varint(data: &[u8], pos: &mut usize, field_name: &str) -> Result<u64, ProtokenError> {
    let value = proto3::read_varint_value(data, pos)?;
    if value == 0 {
        return Err(ProtokenError::MalformedEncoding(format!(
            "{field_name} is zero (canonical encoding omits default values)"
        )));
    }
    Ok(value)
}

/// Read a length-delimited field value, rejecting empty values (canonical
/// encoding omits empty fields) and enforcing a maximum length.
pub(crate) fn read_bounded_bytes<'a>(
    data: &'a [u8],
    pos: &mut usize,
    max_len: usize,
    field_name: &str,
) -> Result<&'a [u8], ProtokenError> {
    let bytes = proto3::read_bytes_value(data, pos)?;
    if bytes.is_empty() {
        return Err(ProtokenError::MalformedEncoding(format!(
            "{field_name} is empty (canonical encoding omits empty fields)"
        )));
    }
    if bytes.len() > max_len {
        return Err(ProtokenError::MalformedEncoding(format!(
            "{field_name} too long: {} bytes (max {max_len})",
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// Decode a length-limited UTF-8 string field.
fn read_claim_string<'a>(
    data: &'a [u8],
    pos: &mut usize,
    field_name: &str,
) -> Result<&'a str, ProtokenError> {
    let bytes = read_bounded_bytes(data, pos, MAX_CLAIM_BYTES_LEN, field_name)?;
    std::str::from_utf8(bytes)
        .map_err(|_| ProtokenError::MalformedEncoding(format!("{field_name} is not valid UTF-8")))
}

/// Deserialize Claims from canonical proto3 bytes.
pub fn deserialize_claims(data: &[u8]) -> Result<Claims, ProtokenError> {
    if data.is_empty() {
        return Err(ProtokenError::MalformedEncoding("empty claims".into()));
    }
    if data.len() > MAX_PAYLOAD_BYTES {
        return Err(ProtokenError::MalformedEncoding(format!(
            "claims too large: {} bytes (max {})",
            data.len(),
            MAX_PAYLOAD_BYTES
        )));
    }

    let mut claims = Claims::default();

    let mut pos = 0;
    let mut last_field_number = 0u32;

    while pos < data.len() {
        let (field_number, wire_type) = proto3::decode_tag(data, &mut pos)?;

        // Enforce ascending field order (canonical encoding).
        // Field 6 (scope) is repeated, so consecutive 6s are allowed.
        if field_number < last_field_number
            || (field_number == last_field_number && field_number != 6)
        {
            return Err(ProtokenError::MalformedEncoding(format!(
                "fields not in ascending order: field {field_number} after {last_field_number}"
            )));
        }
        last_field_number = field_number;

        match (field_number, wire_type) {
            (1, 0) => claims.expires_at = read_nonzero_varint(data, &mut pos, "expires_at")?,
            (2, 0) => claims.not_before = read_nonzero_varint(data, &mut pos, "not_before")?,
            (3, 0) => claims.issued_at = read_nonzero_varint(data, &mut pos, "issued_at")?,
            (4, 2) => claims.subject = read_claim_string(data, &mut pos, "subject")?.to_string(),
            (5, 2) => claims.audience = read_claim_string(data, &mut pos, "audience")?.to_string(),
            (6, 2) => {
                let s = read_claim_string(data, &mut pos, "scope")?;
                if claims.scopes.len() >= MAX_SCOPES {
                    return Err(ProtokenError::MalformedEncoding(format!(
                        "too many scopes: max {MAX_SCOPES}"
                    )));
                }
                // Enforce sorted order without duplicates (canonical encoding)
                if let Some(prev) = claims.scopes.last() {
                    if s <= prev.as_str() {
                        return Err(ProtokenError::MalformedEncoding(format!(
                            "scopes not in sorted order: {s:?} after {prev:?}"
                        )));
                    }
                }
                claims.scopes.push(s.to_string());
            }
            (_, _) => {
                return Err(ProtokenError::MalformedEncoding(format!(
                    "unexpected field {field_number} (wire type {wire_type}) in Claims"
                )));
            }
        }
    }

    Ok(claims)
}

/// Maximum total size for a serialized SignedToken: payload + signature +
/// embedded ML-DSA-44 public key + framing (6 single-byte tags, 3 length
/// varints of at most 2 bytes each, and 3 varint values — well under 32).
const MAX_SIGNED_TOKEN_BYTES: usize =
    MAX_PAYLOAD_BYTES + MAX_SIGNATURE_BYTES + MLDSA44_PUBLIC_KEY_LEN + 32;

/// Serialize the envelope fields covered by the signature (fields 1-5).
/// Both signing and verification compute the signature over these bytes.
#[must_use]
pub fn serialize_signing_input(
    version: Version,
    algorithm: Algorithm,
    key_identifier: &KeyIdentifier,
    payload: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(payload.len() + key_identifier.as_bytes().len() + 16);
    proto3::encode_uint32(1, version.to_byte() as u32, &mut buf);
    proto3::encode_uint32(2, algorithm.to_byte() as u32, &mut buf);
    proto3::encode_uint32(3, key_identifier.key_id_type().to_byte() as u32, &mut buf);
    proto3::encode_bytes(4, key_identifier.as_bytes(), &mut buf);
    proto3::encode_bytes(5, payload, &mut buf);
    buf
}

/// Append the signature as envelope field 6 to a signing-input buffer,
/// producing the final token wire bytes.
#[must_use]
pub fn append_signature(mut signing_input: Vec<u8>, signature: &[u8]) -> Vec<u8> {
    proto3::encode_bytes(6, signature, &mut signing_input);
    signing_input
}

/// Serialize a SignedToken into canonical proto3 bytes.
#[must_use]
pub fn serialize_signed_token(token: &SignedToken) -> Vec<u8> {
    let signing_input = serialize_signing_input(
        token.version,
        token.algorithm,
        &token.key_identifier,
        &token.payload,
    );
    append_signature(signing_input, &token.signature)
}

/// Deserialize a SignedToken from canonical proto3 bytes.
///
/// Validates structure only (field order, sizes, key_id length). Callers must
/// verify the signature before trusting any field, then parse `payload` with
/// `deserialize_claims()`.
pub fn deserialize_signed_token(data: &[u8]) -> Result<SignedToken, ProtokenError> {
    let (token, _signed_len) = deserialize_signed_token_at(data)?;
    Ok(token)
}

/// Deserialize a SignedToken and also return the length of the signed prefix:
/// the received bytes up to (not including) the signature field. Because the
/// decoder enforces canonical encoding, these bytes are the signing input.
pub(crate) fn deserialize_signed_token_at(
    data: &[u8],
) -> Result<(SignedToken, usize), ProtokenError> {
    if data.is_empty() {
        return Err(ProtokenError::MalformedEncoding("empty token".into()));
    }
    if data.len() > MAX_SIGNED_TOKEN_BYTES {
        return Err(ProtokenError::MalformedEncoding(format!(
            "signed token too large: {} bytes (max {})",
            data.len(),
            MAX_SIGNED_TOKEN_BYTES
        )));
    }

    let mut algorithm: u32 = 0;
    let mut key_id_type: u32 = 0;
    let mut key_id: Vec<u8> = Vec::new();
    let mut payload: Option<Vec<u8>> = None;
    let mut signature: Option<Vec<u8>> = None;
    let mut signed_len: usize = 0;

    let mut pos = 0;
    let mut last_field_number = 0u32;

    while pos < data.len() {
        let field_start = pos;
        let (field_number, wire_type) = proto3::decode_tag(data, &mut pos)?;

        if field_number <= last_field_number {
            return Err(ProtokenError::MalformedEncoding(format!(
                "fields not in ascending order: field {field_number} after {last_field_number}"
            )));
        }
        last_field_number = field_number;

        match (field_number, wire_type) {
            // Version can only legally be 0, and canonical encoding omits
            // zero values, so an explicit version field is always invalid.
            (1, 0) => {
                let v = proto3::read_u32(data, &mut pos)?;
                let v = proto3::to_u8(v, "version")?;
                return Err(ProtokenError::InvalidVersion(v));
            }
            (2, 0) => {
                let v = read_nonzero_varint(data, &mut pos, "algorithm")?;
                algorithm = u32::try_from(v).map_err(|_| {
                    ProtokenError::MalformedEncoding("algorithm exceeds u32 range".into())
                })?;
            }
            (3, 0) => {
                let v = read_nonzero_varint(data, &mut pos, "key_id_type")?;
                key_id_type = u32::try_from(v).map_err(|_| {
                    ProtokenError::MalformedEncoding("key_id_type exceeds u32 range".into())
                })?;
            }
            (4, 2) => {
                key_id = read_bounded_bytes(data, &mut pos, MLDSA44_PUBLIC_KEY_LEN, "key_id")?
                    .to_vec();
            }
            (5, 2) => {
                payload =
                    Some(read_bounded_bytes(data, &mut pos, MAX_PAYLOAD_BYTES, "payload")?.to_vec());
            }
            (6, 2) => {
                signature =
                    Some(read_bounded_bytes(data, &mut pos, MAX_SIGNATURE_BYTES, "signature")?
                        .to_vec());
                // Everything before the signature field is the signed input.
                signed_len = field_start;
            }
            (_, _) => {
                return Err(ProtokenError::MalformedEncoding(format!(
                    "unexpected field {field_number} (wire type {wire_type}) in SignedToken"
                )));
            }
        }
    }

    let version = Version::V0;

    let algorithm = proto3::to_u8(algorithm, "algorithm")?;
    let algorithm =
        Algorithm::from_byte(algorithm).ok_or(ProtokenError::InvalidAlgorithm(algorithm))?;

    let key_id_type = proto3::to_u8(key_id_type, "key_id_type")?;
    let key_id_type =
        KeyIdType::from_byte(key_id_type).ok_or(ProtokenError::InvalidKeyIdType(key_id_type))?;

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
            // Symmetric algorithms have no public key to embed.
            let expected_len = algorithm
                .public_key_len()
                .ok_or(ProtokenError::InvalidKeyIdType(key_id_type.to_byte()))?;
            if key_id.len() != expected_len {
                return Err(ProtokenError::InvalidKeyLength {
                    expected: expected_len,
                    actual: key_id.len(),
                });
            }
            KeyIdentifier::PublicKey(key_id)
        }
    };

    let payload = payload.ok_or_else(|| {
        ProtokenError::MalformedEncoding("missing payload field in SignedToken".into())
    })?;
    let signature = signature.ok_or_else(|| {
        ProtokenError::MalformedEncoding("missing signature field in SignedToken".into())
    })?;

    Ok((
        SignedToken {
            version,
            algorithm,
            key_identifier,
            payload,
            signature,
        },
        signed_len,
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn sample_claims_minimal() -> Claims {
        Claims {
            expires_at: 1700000000,
            ..Default::default()
        }
    }

    fn sample_claims_full() -> Claims {
        Claims {
            expires_at: 1700000000,
            not_before: 1699990000,
            issued_at: 1699990000,
            subject: "user:alice".into(),
            audience: "api.example.com".into(),
            scopes: vec!["admin".into(), "read".into(), "write".into()],
        }
    }

    fn sample_token_hmac() -> SignedToken {
        SignedToken {
            version: Version::V0,
            algorithm: Algorithm::HmacSha256,
            key_identifier: KeyIdentifier::KeyHash([
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            ]),
            payload: serialize_claims(&sample_claims_minimal()),
            signature: vec![0xAB; 32],
        }
    }

    #[test]
    fn test_claims_roundtrip_minimal() {
        let claims = sample_claims_minimal();
        let bytes = serialize_claims(&claims);
        let decoded = deserialize_claims(&bytes).unwrap();
        assert_eq!(claims, decoded);
    }

    #[test]
    fn test_claims_roundtrip_full() {
        let claims = sample_claims_full();
        let bytes = serialize_claims(&claims);
        let decoded = deserialize_claims(&bytes).unwrap();
        assert_eq!(claims, decoded);
    }

    #[test]
    fn test_claims_deterministic() {
        let claims = sample_claims_full();
        let bytes1 = serialize_claims(&claims);
        let bytes2 = serialize_claims(&claims);
        assert_eq!(bytes1, bytes2, "serialization must be deterministic");
    }

    #[test]
    fn test_claims_wire_format() {
        let claims = sample_claims_minimal();
        let bytes = serialize_claims(&claims);

        // expires_at=1700000000: tag 0x08, then 5-byte varint
        assert_eq!(bytes[0], 0x08);
        assert_eq!(bytes.len(), 6);
    }

    #[test]
    fn test_claims_default_omission() {
        // Zero/empty optional fields must not appear in the encoding.
        let claims = sample_claims_minimal();
        let bytes = serialize_claims(&claims);

        assert!(!bytes.contains(&0x10), "not_before=0 should be omitted");
        assert!(!bytes.contains(&0x18), "issued_at=0 should be omitted");
        assert!(!bytes.contains(&0x22), "empty subject should be omitted");
        assert!(!bytes.contains(&0x2A), "empty audience should be omitted");
        assert!(!bytes.contains(&0x32), "empty scopes should be omitted");
    }

    #[test]
    fn test_claims_with_optional_fields() {
        let claims = sample_claims_full();
        let bytes = serialize_claims(&claims);

        assert!(bytes.contains(&0x10), "not_before should be present");
        assert!(bytes.contains(&0x18), "issued_at should be present");
        assert!(bytes.contains(&0x22), "subject should be present");
        assert!(bytes.contains(&0x2A), "audience should be present");
        assert!(bytes.contains(&0x32), "scopes should be present");
    }

    #[test]
    fn test_deserialize_claims_empty() {
        assert!(deserialize_claims(&[]).is_err());
    }

    #[test]
    fn test_scopes_sorted_on_encode() {
        let claims = Claims {
            expires_at: 1700000000,
            // Intentionally unsorted input
            scopes: vec!["write".into(), "admin".into(), "read".into()],
            ..Default::default()
        };
        let bytes = serialize_claims(&claims);
        let decoded = deserialize_claims(&bytes).unwrap();
        assert_eq!(decoded.scopes, vec!["admin", "read", "write"]);
    }

    #[test]
    fn test_rejects_unsorted_scopes() {
        let mut bad = Vec::new();
        proto3::encode_uint64(1, 1700000000, &mut bad);
        proto3::encode_bytes(6, b"write", &mut bad);
        proto3::encode_bytes(6, b"read", &mut bad); // out of order
        assert!(deserialize_claims(&bad).is_err());
    }

    #[test]
    fn test_rejects_duplicate_scopes() {
        let mut bad = Vec::new();
        proto3::encode_uint64(1, 1700000000, &mut bad);
        proto3::encode_bytes(6, b"read", &mut bad);
        proto3::encode_bytes(6, b"read", &mut bad); // duplicate
        assert!(deserialize_claims(&bad).is_err());
    }

    #[test]
    fn test_rejects_invalid_utf8_claim_strings() {
        for field in [4u32, 5, 6] {
            let mut bad = Vec::new();
            proto3::encode_uint64(1, 1700000000, &mut bad);
            proto3::encode_bytes(field, &[0xFF, 0xFE], &mut bad); // invalid UTF-8
            assert!(
                deserialize_claims(&bad).is_err(),
                "field {field} should reject invalid UTF-8"
            );
        }
    }

    #[test]
    fn test_rejects_overlong_claim_strings() {
        for field in [4u32, 5, 6] {
            let mut bad = Vec::new();
            proto3::encode_uint64(1, 1700000000, &mut bad);
            proto3::encode_bytes(field, &vec![b'x'; MAX_CLAIM_BYTES_LEN + 1], &mut bad);
            assert!(
                deserialize_claims(&bad).is_err(),
                "field {field} should reject overlong value"
            );
        }
    }

    #[test]
    fn test_accepts_max_length_claim_strings() {
        for field in [4u32, 5, 6] {
            let mut data = Vec::new();
            proto3::encode_uint64(1, 1700000000, &mut data);
            proto3::encode_bytes(field, &vec![b'x'; MAX_CLAIM_BYTES_LEN], &mut data);
            assert!(
                deserialize_claims(&data).is_ok(),
                "field {field} should accept max-length value"
            );
        }
    }

    #[test]
    fn test_rejects_too_many_scopes() {
        let mut bad = Vec::new();
        proto3::encode_uint64(1, 1700000000, &mut bad);
        for i in 0..=MAX_SCOPES {
            proto3::encode_bytes(6, format!("scope{i:03}").as_bytes(), &mut bad);
        }
        assert!(deserialize_claims(&bad).is_err());
    }

    #[test]
    fn test_accepts_max_scopes() {
        let mut data = Vec::new();
        proto3::encode_uint64(1, 1700000000, &mut data);
        for i in 0..MAX_SCOPES {
            proto3::encode_bytes(6, format!("scope{i:03}").as_bytes(), &mut data);
        }
        let decoded = deserialize_claims(&data).unwrap();
        assert_eq!(decoded.scopes.len(), MAX_SCOPES);
    }

    #[test]
    fn test_rejects_scope_wrong_wire_type() {
        // Field 6 with wire type 0 (varint) instead of 2 (LEN).
        let mut bad = Vec::new();
        proto3::encode_uint64(1, 1700000000, &mut bad);
        proto3::encode_uint64(6, 42, &mut bad);
        assert!(deserialize_claims(&bad).is_err());
    }

    #[test]
    fn test_rejects_unknown_claims_field() {
        let mut bad = Vec::new();
        proto3::encode_uint64(1, 1700000000, &mut bad);
        proto3::encode_uint64(7, 42, &mut bad); // unknown field
        assert!(deserialize_claims(&bad).is_err());
    }

    #[test]
    fn test_rejects_non_ascending_claims_fields() {
        let mut bad = Vec::new();
        proto3::encode_uint64(2, 100, &mut bad); // not_before first
        proto3::encode_uint64(1, 1700000000, &mut bad); // expires_at second (wrong!)
        assert!(deserialize_claims(&bad).is_err());
    }

    #[test]
    fn test_rejects_duplicate_claims_field() {
        let mut bad = Vec::new();
        proto3::encode_uint64(1, 1000, &mut bad);
        proto3::encode_uint64(1, 2000, &mut bad); // duplicate expires_at
        let err = deserialize_claims(&bad).unwrap_err();
        assert!(
            matches!(&err, ProtokenError::MalformedEncoding(m) if m.contains("ascending")),
            "expected ascending-order error, got {err:?}"
        );
    }

    #[test]
    fn test_rejects_oversized_claims() {
        let oversized = vec![0u8; MAX_PAYLOAD_BYTES + 1];
        let err = deserialize_claims(&oversized).unwrap_err();
        assert!(
            matches!(&err, ProtokenError::MalformedEncoding(m) if m.contains("claims too large")),
            "expected 'claims too large', got {err:?}"
        );
    }

    #[test]
    fn test_accepts_exactly_max_claims_bytes() {
        // Exactly MAX_PAYLOAD_BYTES passes the size check (then fails parsing
        // as junk, which is fine).
        let exactly_max = vec![0u8; MAX_PAYLOAD_BYTES];
        let err = deserialize_claims(&exactly_max).unwrap_err();
        assert!(
            !matches!(&err, ProtokenError::MalformedEncoding(m) if m.contains("claims too large")),
            "MAX_PAYLOAD_BYTES should pass size check, got {err:?}"
        );
    }

    // --- SignedToken envelope tests ---

    #[test]
    fn test_signed_token_roundtrip() {
        let token = sample_token_hmac();
        let wire = serialize_signed_token(&token);
        let decoded = deserialize_signed_token(&wire).unwrap();
        assert_eq!(token, decoded);
    }

    #[test]
    fn test_signed_token_ed25519_pubkey_roundtrip() {
        let token = SignedToken {
            version: Version::V0,
            algorithm: Algorithm::Ed25519,
            key_identifier: KeyIdentifier::PublicKey(vec![0xBB; 32]),
            payload: serialize_claims(&sample_claims_full()),
            signature: vec![0xCD; 64],
        };
        let wire = serialize_signed_token(&token);
        let decoded = deserialize_signed_token(&wire).unwrap();
        assert_eq!(token, decoded);
    }

    #[test]
    fn test_signed_token_mldsa44_pubkey_roundtrip() {
        let token = SignedToken {
            version: Version::V0,
            algorithm: Algorithm::MlDsa44,
            key_identifier: KeyIdentifier::PublicKey(vec![0xEE; MLDSA44_PUBLIC_KEY_LEN]),
            payload: serialize_claims(&sample_claims_minimal()),
            signature: vec![0xDD; MLDSA44_SIG_LEN],
        };
        let wire = serialize_signed_token(&token);
        let decoded = deserialize_signed_token(&wire).unwrap();
        assert_eq!(token, decoded);
    }

    #[test]
    fn test_signed_token_wire_format() {
        let token = sample_token_hmac();
        let wire = serialize_signed_token(&token);

        // version=0 omitted; algorithm=1: tag 0x10, value 0x01
        assert_eq!(wire[0], 0x10);
        assert_eq!(wire[1], 0x01);
        // key_id_type=1: tag 0x18, value 0x01
        assert_eq!(wire[2], 0x18);
        assert_eq!(wire[3], 0x01);
        // key_id: tag 0x22, length 8
        assert_eq!(wire[4], 0x22);
        assert_eq!(wire[5], 0x08);
        assert_eq!(&wire[6..14], &[1, 2, 3, 4, 5, 6, 7, 8]);
        // payload: tag 0x2A
        assert_eq!(wire[14], 0x2A);
    }

    #[test]
    fn test_signing_input_is_wire_prefix() {
        // The signing input must be exactly the serialized token minus the
        // trailing signature field.
        let token = sample_token_hmac();
        let wire = serialize_signed_token(&token);
        let input = serialize_signing_input(
            token.version,
            token.algorithm,
            &token.key_identifier,
            &token.payload,
        );
        assert_eq!(&wire[..input.len()], input.as_slice());
        // Remainder is the signature field: tag 0x32, length 32, 32 bytes.
        assert_eq!(wire[input.len()], 0x32);
        assert_eq!(wire.len(), input.len() + 2 + 32);
    }

    #[test]
    fn test_deserialize_signed_token_empty() {
        assert!(deserialize_signed_token(&[]).is_err());
    }

    #[test]
    fn test_rejects_missing_payload() {
        let mut bad = Vec::new();
        proto3::encode_uint32(2, 1, &mut bad);
        proto3::encode_uint32(3, 1, &mut bad);
        proto3::encode_bytes(4, &[0; 8], &mut bad);
        proto3::encode_bytes(6, &[0; 32], &mut bad);
        let err = deserialize_signed_token(&bad).unwrap_err();
        assert!(
            matches!(&err, ProtokenError::MalformedEncoding(m) if m.contains("missing payload")),
            "expected missing payload error, got {err:?}"
        );
    }

    #[test]
    fn test_rejects_missing_signature() {
        let mut bad = Vec::new();
        proto3::encode_uint32(2, 1, &mut bad);
        proto3::encode_uint32(3, 1, &mut bad);
        proto3::encode_bytes(4, &[0; 8], &mut bad);
        proto3::encode_bytes(5, &serialize_claims(&sample_claims_minimal()), &mut bad);
        let err = deserialize_signed_token(&bad).unwrap_err();
        assert!(
            matches!(&err, ProtokenError::MalformedEncoding(m) if m.contains("missing signature")),
            "expected missing signature error, got {err:?}"
        );
    }

    #[test]
    fn test_rejects_missing_key_id() {
        // key_id_type present but key_id absent (0 bytes != KEY_HASH_LEN).
        let mut bad = Vec::new();
        proto3::encode_uint32(2, 1, &mut bad);
        proto3::encode_uint32(3, 1, &mut bad);
        proto3::encode_bytes(5, &serialize_claims(&sample_claims_minimal()), &mut bad);
        proto3::encode_bytes(6, &[0; 32], &mut bad);
        assert!(matches!(
            deserialize_signed_token(&bad),
            Err(ProtokenError::InvalidKeyLength {
                expected: 8,
                actual: 0
            })
        ));
    }

    #[test]
    fn test_rejects_invalid_algorithm() {
        let mut bad = Vec::new();
        proto3::encode_uint32(2, 255, &mut bad);
        proto3::encode_uint32(3, 1, &mut bad);
        proto3::encode_bytes(4, &[0; 8], &mut bad);
        proto3::encode_bytes(5, &[0x08, 0x01], &mut bad);
        proto3::encode_bytes(6, &[0; 32], &mut bad);
        assert!(matches!(
            deserialize_signed_token(&bad),
            Err(ProtokenError::InvalidAlgorithm(255))
        ));
    }

    #[test]
    fn test_rejects_invalid_version() {
        let mut bad = Vec::new();
        proto3::encode_uint32(1, 99, &mut bad);
        proto3::encode_uint32(2, 1, &mut bad);
        proto3::encode_uint32(3, 1, &mut bad);
        proto3::encode_bytes(4, &[0; 8], &mut bad);
        proto3::encode_bytes(5, &[0x08, 0x01], &mut bad);
        proto3::encode_bytes(6, &[0; 32], &mut bad);
        assert!(matches!(
            deserialize_signed_token(&bad),
            Err(ProtokenError::InvalidVersion(99))
        ));
    }

    #[test]
    fn test_rejects_invalid_key_id_type() {
        let mut bad = Vec::new();
        proto3::encode_uint32(2, 1, &mut bad);
        proto3::encode_uint32(3, 9, &mut bad); // invalid key_id_type
        proto3::encode_bytes(4, &[0; 8], &mut bad);
        proto3::encode_bytes(5, &[0x08, 0x01], &mut bad);
        proto3::encode_bytes(6, &[0; 32], &mut bad);
        assert!(matches!(
            deserialize_signed_token(&bad),
            Err(ProtokenError::InvalidKeyIdType(9))
        ));
    }

    #[test]
    fn test_rejects_hmac_with_public_key_id() {
        // HMAC (algorithm=1) has no public key to embed.
        let mut bad = Vec::new();
        proto3::encode_uint32(2, 1, &mut bad); // HMAC
        proto3::encode_uint32(3, 2, &mut bad); // public_key
        proto3::encode_bytes(4, &[0; 32], &mut bad);
        proto3::encode_bytes(5, &[0x08, 0x01], &mut bad);
        proto3::encode_bytes(6, &[0; 32], &mut bad);
        assert!(matches!(
            deserialize_signed_token(&bad),
            Err(ProtokenError::InvalidKeyIdType(2))
        ));
    }

    #[test]
    fn test_rejects_wrong_length_key_hash() {
        let mut bad = Vec::new();
        proto3::encode_uint32(2, 1, &mut bad);
        proto3::encode_uint32(3, 1, &mut bad);
        proto3::encode_bytes(4, &[0; 7], &mut bad); // 7 bytes instead of 8
        proto3::encode_bytes(5, &[0x08, 0x01], &mut bad);
        proto3::encode_bytes(6, &[0; 32], &mut bad);
        assert!(matches!(
            deserialize_signed_token(&bad),
            Err(ProtokenError::InvalidKeyLength {
                expected: 8,
                actual: 7
            })
        ));
    }

    #[test]
    fn test_rejects_wrong_length_ed25519_public_key_id() {
        let mut bad = Vec::new();
        proto3::encode_uint32(2, 2, &mut bad); // Ed25519
        proto3::encode_uint32(3, 2, &mut bad); // public_key
        proto3::encode_bytes(4, &[0; 31], &mut bad); // 31 bytes instead of 32
        proto3::encode_bytes(5, &[0x08, 0x01], &mut bad);
        proto3::encode_bytes(6, &[0; 64], &mut bad);
        assert!(matches!(
            deserialize_signed_token(&bad),
            Err(ProtokenError::InvalidKeyLength {
                expected: 32,
                actual: 31
            })
        ));
    }

    #[test]
    fn test_rejects_explicit_version_zero() {
        // Canonical encoding omits version=0; an explicit `08 00` prefix must
        // be rejected. Otherwise two distinct byte strings would verify under
        // one signature (token malleability).
        let valid = serialize_signed_token(&sample_token_hmac());
        let mut malleated = vec![0x08, 0x00];
        malleated.extend_from_slice(&valid);
        assert!(matches!(
            deserialize_signed_token(&malleated),
            Err(ProtokenError::InvalidVersion(0))
        ));
    }

    #[test]
    fn test_rejects_explicit_zero_envelope_varints() {
        // algorithm=0 and key_id_type=0 encoded explicitly are non-canonical.
        for field in [2u32, 3] {
            let mut bad = Vec::new();
            bad.push((field << 3) as u8); // varint wire type
            bad.push(0x00);
            let err = deserialize_signed_token(&bad).unwrap_err();
            assert!(
                matches!(&err, ProtokenError::MalformedEncoding(m) if m.contains("zero")),
                "field {field}: expected zero-value rejection, got {err:?}"
            );
        }
    }

    #[test]
    fn test_rejects_explicit_zero_claims_varints() {
        // expires_at/not_before/issued_at = 0 encoded explicitly are non-canonical.
        for field in [1u32, 2, 3] {
            let mut bad = Vec::new();
            if field > 1 {
                proto3::encode_uint64(1, 1700000000, &mut bad);
            }
            bad.push((field << 3) as u8); // varint wire type
            bad.push(0x00);
            let err = deserialize_claims(&bad).unwrap_err();
            assert!(
                matches!(&err, ProtokenError::MalformedEncoding(m) if m.contains("zero")),
                "claims field {field}: expected zero-value rejection, got {err:?}"
            );
        }
    }

    #[test]
    fn test_rejects_empty_claim_strings() {
        // Empty subject/audience/scope encoded explicitly are non-canonical.
        for field in [4u32, 5, 6] {
            let mut bad = Vec::new();
            proto3::encode_uint64(1, 1700000000, &mut bad);
            bad.push(((field << 3) | 2) as u8); // LEN wire type
            bad.push(0x00); // length 0
            let err = deserialize_claims(&bad).unwrap_err();
            assert!(
                matches!(&err, ProtokenError::MalformedEncoding(m) if m.contains("empty")),
                "claims field {field}: expected empty-value rejection, got {err:?}"
            );
        }
    }

    #[test]
    fn test_rejects_empty_payload_and_signature_fields() {
        // Zero-length payload/signature fields are non-canonical (omitted when
        // empty), and must not satisfy the required-field checks.
        let mut bad = Vec::new();
        proto3::encode_uint32(2, 1, &mut bad);
        proto3::encode_uint32(3, 1, &mut bad);
        proto3::encode_bytes(4, &[0; 8], &mut bad);
        bad.push(0x2A); // payload tag
        bad.push(0x00); // length 0
        proto3::encode_bytes(6, &[0; 32], &mut bad);
        let err = deserialize_signed_token(&bad).unwrap_err();
        assert!(
            matches!(&err, ProtokenError::MalformedEncoding(m) if m.contains("empty")),
            "empty payload: got {err:?}"
        );

        let mut bad = Vec::new();
        proto3::encode_uint32(2, 1, &mut bad);
        proto3::encode_uint32(3, 1, &mut bad);
        proto3::encode_bytes(4, &[0; 8], &mut bad);
        proto3::encode_bytes(5, &[0x08, 0x01], &mut bad);
        bad.push(0x32); // signature tag
        bad.push(0x00); // length 0
        let err = deserialize_signed_token(&bad).unwrap_err();
        assert!(
            matches!(&err, ProtokenError::MalformedEncoding(m) if m.contains("empty")),
            "empty signature: got {err:?}"
        );
    }

    #[test]
    fn test_rejects_non_ascending_token_fields() {
        let mut bad = Vec::new();
        proto3::encode_uint32(3, 1, &mut bad); // key_id_type first
        proto3::encode_uint32(2, 1, &mut bad); // algorithm second (wrong!)
        assert!(deserialize_signed_token(&bad).is_err());
    }

    #[test]
    fn test_rejects_duplicate_token_field() {
        let mut bad = Vec::new();
        proto3::encode_uint32(2, 1, &mut bad);
        proto3::encode_uint32(2, 1, &mut bad); // duplicate algorithm
        assert!(deserialize_signed_token(&bad).is_err());
    }

    #[test]
    fn test_rejects_unknown_token_field() {
        let mut bad = serialize_signed_token(&sample_token_hmac());
        proto3::encode_bytes(7, &[0xFF; 4], &mut bad); // trailing unknown field
        assert!(deserialize_signed_token(&bad).is_err());
    }

    #[test]
    fn test_rejects_truncated_claims() {
        let bytes = serialize_claims(&sample_claims_full());
        for len in 1..bytes.len() {
            // Should either parse partially or error, never panic
            let _ = deserialize_claims(&bytes[..len]);
        }
    }

    #[test]
    fn test_rejects_truncated_signed_token() {
        let wire = serialize_signed_token(&sample_token_hmac());
        for len in 1..wire.len() {
            let _ = deserialize_signed_token(&wire[..len]);
        }
    }

    #[test]
    fn test_rejects_oversized_signed_token() {
        let oversized = vec![0u8; MAX_SIGNED_TOKEN_BYTES + 1];
        let err = deserialize_signed_token(&oversized).unwrap_err();
        assert!(
            matches!(&err, ProtokenError::MalformedEncoding(m) if m.contains("signed token too large")),
            "expected 'signed token too large', got {err:?}"
        );
    }

    #[test]
    fn test_accepts_exactly_max_signed_token_bytes() {
        let exactly_max = vec![0u8; MAX_SIGNED_TOKEN_BYTES];
        let err = deserialize_signed_token(&exactly_max).unwrap_err();
        assert!(
            !matches!(&err, ProtokenError::MalformedEncoding(m) if m.contains("signed token too large")),
            "MAX_SIGNED_TOKEN_BYTES should pass size check, got {err:?}"
        );
    }

    #[test]
    fn test_max_signed_token_bytes_sanity() {
        // Pins the MAX_SIGNED_TOKEN_BYTES value so arithmetic mutations are
        // caught. Must exceed the largest legitimate token (ML-DSA-44 with
        // embedded public key and a max-size payload).
        // 4096 + 2560 + 1312 + 32 = 8000.
        assert_eq!(MAX_SIGNED_TOKEN_BYTES, 8000);
    }

    #[test]
    fn test_rejects_oversized_payload_inside_token() {
        let mut bad = Vec::new();
        proto3::encode_uint32(2, 1, &mut bad);
        proto3::encode_uint32(3, 1, &mut bad);
        proto3::encode_bytes(4, &[0; 8], &mut bad);
        proto3::encode_bytes(5, &vec![0; MAX_PAYLOAD_BYTES + 1], &mut bad);
        proto3::encode_bytes(6, &[0; 32], &mut bad);
        assert!(deserialize_signed_token(&bad).is_err());
    }

    #[test]
    fn test_accepts_max_size_payload_inside_token() {
        let mut data = Vec::new();
        proto3::encode_uint32(2, 1, &mut data);
        proto3::encode_uint32(3, 1, &mut data);
        proto3::encode_bytes(4, &[0; 8], &mut data);
        proto3::encode_bytes(5, &vec![0x08; MAX_PAYLOAD_BYTES], &mut data);
        proto3::encode_bytes(6, &[0; 32], &mut data);
        let decoded = deserialize_signed_token(&data).unwrap();
        assert_eq!(decoded.payload.len(), MAX_PAYLOAD_BYTES);
    }

    #[test]
    fn test_rejects_oversized_signature_inside_token() {
        let mut bad = Vec::new();
        proto3::encode_uint32(2, 1, &mut bad);
        proto3::encode_uint32(3, 1, &mut bad);
        proto3::encode_bytes(4, &[0; 8], &mut bad);
        proto3::encode_bytes(5, &[0x08, 0x01], &mut bad);
        proto3::encode_bytes(6, &vec![0; MAX_SIGNATURE_BYTES + 1], &mut bad);
        assert!(deserialize_signed_token(&bad).is_err());
    }

    #[test]
    fn test_accepts_max_size_signature() {
        let mut data = Vec::new();
        proto3::encode_uint32(2, 1, &mut data);
        proto3::encode_uint32(3, 1, &mut data);
        proto3::encode_bytes(4, &[0; 8], &mut data);
        proto3::encode_bytes(5, &[0x08, 0x01], &mut data);
        proto3::encode_bytes(6, &vec![0; MAX_SIGNATURE_BYTES], &mut data);
        let decoded = deserialize_signed_token(&data).unwrap();
        assert_eq!(decoded.signature.len(), MAX_SIGNATURE_BYTES);
    }

    #[test]
    fn test_rejects_oversized_key_id() {
        let mut bad = Vec::new();
        proto3::encode_uint32(2, 3, &mut bad); // ML-DSA-44
        proto3::encode_uint32(3, 2, &mut bad); // public_key
        proto3::encode_bytes(4, &vec![0; MLDSA44_PUBLIC_KEY_LEN + 1], &mut bad);
        proto3::encode_bytes(5, &[0x08, 0x01], &mut bad);
        proto3::encode_bytes(6, &[0; 32], &mut bad);
        let err = deserialize_signed_token(&bad).unwrap_err();
        assert!(
            matches!(&err, ProtokenError::MalformedEncoding(m) if m.contains("key_id too long")),
            "expected 'key_id too long', got {err:?}"
        );
    }
}
