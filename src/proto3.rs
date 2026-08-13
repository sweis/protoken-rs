//! Minimal proto3 wire format encoder/decoder.
//!
//! The encoders produce, and the decoding helpers enforce, canonical form:
//! - Fields in ascending field-number order (a repeated field is consecutive)
//! - Minimal varint encoding
//! - Default values (0, empty bytes) omitted, so explicit defaults are rejected
//! - No unknown fields
//!
//! The message-specific decoders in `serialize` and `keys` are built from
//! these helpers. All field numbers are <= 15, so tags are single bytes.

use crate::error::ProtokenError;

/// Wire type for varint fields (uint32, uint64).
pub const WIRE_VARINT: u32 = 0;
/// Wire type for length-delimited fields (bytes, string, submessages).
pub const WIRE_LEN: u32 = 2;

// --- Encoding ---

/// Encode a varint (unsigned, minimal encoding).
pub fn encode_varint(mut value: u64, buf: &mut Vec<u8>) {
    loop {
        if value <= 0x7F {
            buf.push(value as u8);
            return;
        }
        buf.push((value as u8 & 0x7F) | 0x80);
        value >>= 7;
    }
}

/// Encode a field tag: (field_number << 3) | wire_type.
fn encode_tag(field_number: u32, wire_type: u32, buf: &mut Vec<u8>) {
    encode_varint(((field_number as u64) << 3) | wire_type as u64, buf);
}

/// Encode a uint32 field. Omits if value is 0 (proto3 default).
pub fn encode_uint32(field: u32, value: u32, buf: &mut Vec<u8>) {
    if value == 0 {
        return;
    }
    encode_tag(field, WIRE_VARINT, buf);
    encode_varint(value as u64, buf);
}

/// Encode a uint64 field. Omits if value is 0 (proto3 default).
pub fn encode_uint64(field: u32, value: u64, buf: &mut Vec<u8>) {
    if value == 0 {
        return;
    }
    encode_tag(field, WIRE_VARINT, buf);
    encode_varint(value, buf);
}

/// Encode a bytes/submessage field. Omits if value is empty (proto3 default).
pub fn encode_bytes(field: u32, value: &[u8], buf: &mut Vec<u8>) {
    if value.is_empty() {
        return;
    }
    encode_tag(field, WIRE_LEN, buf);
    encode_varint(value.len() as u64, buf);
    buf.extend_from_slice(value);
}

// --- Decoding ---

/// Decode a varint, advancing pos. Returns error on truncation or overlong encoding.
#[allow(clippy::indexing_slicing)] // bounds checked before access
pub fn decode_varint(data: &[u8], pos: &mut usize) -> Result<u64, ProtokenError> {
    let start = *pos;
    let mut value: u64 = 0;
    let mut shift: u32 = 0;

    loop {
        if *pos >= data.len() {
            return Err(ProtokenError::MalformedEncoding(
                "unexpected end of input in varint".into(),
            ));
        }
        let byte = data[*pos];
        *pos += 1;

        // On the 10th byte (shift=63), only bit 0 is valid for u64.
        // Reject values that would overflow.
        if shift == 63 && byte > 1 {
            return Err(ProtokenError::MalformedEncoding(
                "varint exceeds 64 bits".into(),
            ));
        }

        value |= ((byte & 0x7F) as u64) << shift;

        if byte & 0x80 == 0 {
            // Reject non-minimal encoding: leading zero byte (except for value 0 itself)
            if byte == 0 && *pos - start > 1 {
                return Err(ProtokenError::MalformedEncoding(
                    "non-minimal varint encoding".into(),
                ));
            }
            return Ok(value);
        }

        shift += 7;
        if shift > 63 {
            return Err(ProtokenError::MalformedEncoding(
                "varint exceeds 10 bytes".into(),
            ));
        }
    }
}

/// Decode a field tag, returning (field_number, wire_type).
pub fn decode_tag(data: &[u8], pos: &mut usize) -> Result<(u32, u32), ProtokenError> {
    let tag = decode_varint(data, pos)?;
    let wire_type = (tag & 0x07) as u32;
    let field_number_u64 = tag >> 3;

    if field_number_u64 == 0 {
        return Err(ProtokenError::MalformedEncoding(
            "field number 0 is invalid".into(),
        ));
    }

    let field_number = u32::try_from(field_number_u64).map_err(|_| {
        ProtokenError::MalformedEncoding(format!(
            "field number {field_number_u64} exceeds u32::MAX"
        ))
    })?;

    Ok((field_number, wire_type))
}

/// Read a varint field value that must fit in a u8, such as an enum-like
/// uint32 field (caller already consumed the tag).
pub fn read_u8_value(data: &[u8], pos: &mut usize, field_name: &str) -> Result<u8, ProtokenError> {
    let v = decode_varint(data, pos)?;
    u8::try_from(v).map_err(|_| {
        ProtokenError::MalformedEncoding(format!("{field_name} value {v} exceeds u8 range"))
    })
}

/// Read a length-delimited field value (caller already consumed the tag).
/// Returns the byte slice.
#[allow(clippy::indexing_slicing)] // bounds checked before access
pub fn read_bytes_value<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8], ProtokenError> {
    let len_u64 = decode_varint(data, pos)?;
    let len = usize::try_from(len_u64).map_err(|_| {
        ProtokenError::MalformedEncoding(format!(
            "length-delimited field length {len_u64} exceeds platform address space"
        ))
    })?;
    let end = pos.checked_add(len).ok_or_else(|| {
        ProtokenError::MalformedEncoding("length-delimited field length overflow".into())
    })?;
    if end > data.len() {
        return Err(ProtokenError::MalformedEncoding(format!(
            "length-delimited field extends past end: need {} bytes at offset {}, have {}",
            len,
            *pos,
            data.len()
        )));
    }
    let start = *pos;
    *pos += len;
    Ok(&data[start..*pos])
}

// --- Canonical-form helpers shared by the message decoders ---

fn zero_value_error(field_name: &str) -> ProtokenError {
    ProtokenError::MalformedEncoding(format!(
        "{field_name} is zero (canonical encoding omits default values)"
    ))
}

/// Read a varint field value, rejecting an explicit zero (canonical encoding
/// omits default values, so a zero on the wire is non-canonical).
pub fn read_nonzero_varint(
    data: &[u8],
    pos: &mut usize,
    field_name: &str,
) -> Result<u64, ProtokenError> {
    match decode_varint(data, pos)? {
        0 => Err(zero_value_error(field_name)),
        value => Ok(value),
    }
}

/// Read an enum-like uint32 field into a u8, rejecting an explicit zero.
pub fn read_nonzero_u8(
    data: &[u8],
    pos: &mut usize,
    field_name: &str,
) -> Result<u8, ProtokenError> {
    match read_u8_value(data, pos, field_name)? {
        0 => Err(zero_value_error(field_name)),
        value => Ok(value),
    }
}

/// Error for a message that ends before a required field.
pub fn missing_field(field_name: &str, message_name: &str) -> ProtokenError {
    ProtokenError::MalformedEncoding(format!("missing {field_name} field in {message_name}"))
}

/// Error for a field that canonical encoding does not permit at this point:
/// unknown number, wrong wire type, or a duplicate of a non-repeated field.
pub fn unexpected_field(field_number: u32, wire_type: u32, message_name: &str) -> ProtokenError {
    ProtokenError::MalformedEncoding(format!(
        "unexpected field {field_number} (wire type {wire_type}) in {message_name}"
    ))
}

/// Read the next field tag and enforce ascending field order. `repeated` is
/// the one field number that may appear more than once in a row.
pub fn next_field(
    data: &[u8],
    pos: &mut usize,
    last_field_number: &mut u32,
    repeated: Option<u32>,
) -> Result<(u32, u32), ProtokenError> {
    let (field_number, wire_type) = decode_tag(data, pos)?;
    let is_repeat = field_number == *last_field_number;
    if field_number < *last_field_number || (is_repeat && repeated != Some(field_number)) {
        return Err(ProtokenError::MalformedEncoding(format!(
            "fields not in ascending order: field {field_number} after {last_field_number}"
        )));
    }
    *last_field_number = field_number;
    Ok((field_number, wire_type))
}

/// Read a length-delimited field value, rejecting empty values (canonical
/// encoding omits empty fields) and enforcing a maximum length.
pub fn read_bounded_bytes<'a>(
    data: &'a [u8],
    pos: &mut usize,
    max_len: usize,
    field_name: &str,
) -> Result<&'a [u8], ProtokenError> {
    let bytes = read_bytes_value(data, pos)?;
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_roundtrip() {
        for value in [0u64, 1, 127, 128, 16383, 16384, 1700000000, u64::MAX] {
            let mut buf = Vec::new();
            encode_varint(value, &mut buf);
            let mut pos = 0;
            let decoded = decode_varint(&buf, &mut pos).unwrap();
            assert_eq!(decoded, value, "varint roundtrip failed for {value}");
            assert_eq!(pos, buf.len(), "varint did not consume all bytes");
        }
    }

    #[test]
    fn test_varint_encoding_size() {
        let cases: &[(u64, usize)] = &[
            (0, 1),
            (1, 1),
            (127, 1),
            (128, 2),
            (16383, 2),
            (16384, 3),
            (1700000000, 5),
            (u64::MAX, 10),
        ];
        for &(value, expected_len) in cases {
            let mut buf = Vec::new();
            encode_varint(value, &mut buf);
            assert_eq!(buf.len(), expected_len, "varint size mismatch for {value}");
        }
    }

    #[test]
    fn test_varint_minimality() {
        // Non-minimal encoding: value 1 encoded as [0x81, 0x00] (2 bytes instead of 1)
        let non_minimal = &[0x81, 0x00];
        let mut pos = 0;
        let result = decode_varint(non_minimal, &mut pos);
        assert!(result.is_err(), "should reject non-minimal varint");
    }

    #[test]
    fn test_uint32_field_encoding() {
        // algorithm = 1, field 2 → tag 0x10, value 0x01
        let mut buf = Vec::new();
        encode_uint32(2, 1, &mut buf);
        assert_eq!(buf, &[0x10, 0x01]);
    }

    #[test]
    fn test_uint32_field_default_omitted() {
        let mut buf = Vec::new();
        encode_uint32(1, 0, &mut buf);
        assert!(buf.is_empty(), "default value should be omitted");
    }

    #[test]
    fn test_bytes_field_encoding() {
        // key_id field 4, 8 bytes → tag 0x22, length 0x08, then bytes
        let mut buf = Vec::new();
        encode_bytes(
            4,
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            &mut buf,
        );
        assert_eq!(buf[0], 0x22); // tag
        assert_eq!(buf[1], 0x08); // length
        assert_eq!(&buf[2..], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    #[test]
    fn test_bytes_field_empty_omitted() {
        let mut buf = Vec::new();
        encode_bytes(4, &[], &mut buf);
        assert!(buf.is_empty(), "empty bytes should be omitted");
    }

    #[test]
    fn test_read_bytes_overflow_length() {
        // Fuzzer crash: length-delimited field with length near u64::MAX causes
        // addition overflow in pos + len. The varint 0xff..ff 0x01 = u64::MAX.
        let data: &[u8] = &[
            0x0a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x0a, 0x01, 0x28,
        ];
        let result = crate::serialize::deserialize_signed_token(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_tag_rejects_large_field_number() {
        // Field number 0x1_0000_0002 (exceeds u32::MAX) with wire type 0.
        // Without the fix, this would truncate to field 2 (algorithm).
        let tag_value: u64 = 0x1_0000_0002u64 << 3;
        let mut buf = Vec::new();
        encode_varint(tag_value, &mut buf);
        let mut pos = 0;
        let result = decode_tag(&buf, &mut pos);
        assert!(result.is_err(), "should reject field number > u32::MAX");
    }

    #[test]
    fn test_varint_overflow_10th_byte() {
        // A 10-byte varint where the final byte is 2 encodes a value
        // ≥ 2^64, which must be rejected. Exercises proto3.rs:100 `byte > 1`.
        let overflow: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02];
        let mut pos = 0;
        assert!(
            decode_varint(overflow, &mut pos).is_err(),
            "varint with 10th byte=2 should overflow u64"
        );

        // Boundary: 10th byte = 1 is u64::MAX, must succeed.
        let max: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];
        let mut pos = 0;
        assert_eq!(decode_varint(max, &mut pos).unwrap(), u64::MAX);
    }

    #[test]
    fn test_varint_zero_at_nonzero_offset() {
        // Valid single-byte 0x00 at pos > 0. Exercises proto3.rs:110 `*pos - start`.
        // In practice proto3 omits zero-valued fields, but the decoder must still
        // accept a zero varint at any offset correctly.
        let buf: &[u8] = &[0xFF, 0xFF, 0x00]; // padding + varint 0 at pos=2
        let mut pos = 2;
        let v = decode_varint(buf, &mut pos).unwrap();
        assert_eq!(v, 0);
        assert_eq!(pos, 3);
    }

    #[test]
    fn test_varint_non_minimal_at_nonzero_offset() {
        // Non-minimal encoding [0x81, 0x00] at pos > 0 must still be rejected.
        let buf: &[u8] = &[0xFF, 0x81, 0x00]; // padding + non-minimal at pos=1
        let mut pos = 1;
        assert!(decode_varint(buf, &mut pos).is_err());
    }

    #[test]
    fn test_read_u8_value_bounds() {
        for (value, ok) in [(0u64, true), (255, true), (256, false), (u64::MAX, false)] {
            let mut buf = Vec::new();
            encode_varint(value, &mut buf);
            let mut pos = 0;
            let result = read_u8_value(&buf, &mut pos, "test");
            assert_eq!(result.is_ok(), ok, "value {value}: {result:?}");
            if ok {
                assert_eq!(result.unwrap() as u64, value);
                assert_eq!(pos, buf.len());
            }
        }
        let err = read_u8_value(&[0x80, 0x02], &mut 0, "algorithm").unwrap_err();
        assert!(
            matches!(&err, ProtokenError::MalformedEncoding(m) if m == "algorithm value 256 exceeds u8 range"),
            "got {err:?}"
        );
    }

    /// Decode all tags in `tags` with `next_field`, returning the field numbers.
    fn field_numbers(tags: &[u8], repeated: Option<u32>) -> Result<Vec<u32>, ProtokenError> {
        let mut pos = 0;
        let mut last = 0;
        let mut seen = Vec::new();
        // Every input tag is a single byte, so exactly one call per byte.
        for expected_pos in 1..=tags.len() {
            let (field, _wire_type) = next_field(tags, &mut pos, &mut last, repeated)?;
            assert_eq!(pos, expected_pos, "next_field must consume the tag");
            seen.push(field);
        }
        Ok(seen)
    }

    #[test]
    fn test_next_field_order_rules() {
        // Tags for fields 1, 2, 6 (varint wire type): 0x08, 0x10, 0x30.
        assert_eq!(field_numbers(&[0x08, 0x10, 0x30], None).unwrap(), [1, 2, 6]);
        // Descending is rejected regardless of the repeated field.
        assert!(field_numbers(&[0x10, 0x08], None).is_err());
        assert!(field_numbers(&[0x30, 0x08], Some(6)).is_err());
        // A repeat is only allowed for the designated repeated field.
        assert!(field_numbers(&[0x08, 0x08], None).is_err());
        assert!(field_numbers(&[0x08, 0x08], Some(6)).is_err());
        assert_eq!(
            field_numbers(&[0x30, 0x30, 0x30], Some(6)).unwrap(),
            [6, 6, 6]
        );
        // Once a later field appears, the repeated field may not come back.
        assert!(field_numbers(&[0x30, 0x38, 0x30], Some(6)).is_err());
    }

    #[test]
    fn test_nonzero_readers_reject_explicit_zero() {
        assert!(matches!(
            read_nonzero_varint(&[0x00], &mut 0, "f"),
            Err(ProtokenError::MalformedEncoding(m)) if m.starts_with("f is zero")
        ));
        assert_eq!(read_nonzero_varint(&[0x01], &mut 0, "f").unwrap(), 1);
        assert!(matches!(
            read_nonzero_u8(&[0x00], &mut 0, "f"),
            Err(ProtokenError::MalformedEncoding(m)) if m.starts_with("f is zero")
        ));
        assert_eq!(read_nonzero_u8(&[0x07], &mut 0, "f").unwrap(), 7);
        assert!(read_nonzero_u8(&[0x80, 0x02], &mut 0, "f").is_err());
    }

    #[test]
    fn test_read_bounded_bytes_limits() {
        // Length prefix followed by payload.
        assert_eq!(
            read_bounded_bytes(&[0x02, b'h', b'i'], &mut 0, 2, "f").unwrap(),
            b"hi"
        );
        assert!(matches!(
            read_bounded_bytes(&[0x00], &mut 0, 2, "f"),
            Err(ProtokenError::MalformedEncoding(m)) if m.contains("empty")
        ));
        assert!(matches!(
            read_bounded_bytes(&[0x03, b'a', b'b', b'c'], &mut 0, 2, "f"),
            Err(ProtokenError::MalformedEncoding(m)) if m.contains("too long")
        ));
        // Truncated payload is caught by read_bytes_value.
        assert!(read_bounded_bytes(&[0x05, b'a'], &mut 0, 8, "f").is_err());
    }

    #[test]
    fn test_field_tag_values() {
        // Verify our field tag bytes match the proto3 spec
        let cases: &[(u32, u32, u8)] = &[
            (1, WIRE_VARINT, 0x08), // SignedToken.version / Claims.expires_at
            (2, WIRE_VARINT, 0x10), // SignedToken.algorithm / Claims.not_before
            (3, WIRE_VARINT, 0x18), // SignedToken.key_id_type / Claims.issued_at
            (4, WIRE_LEN, 0x22),    // SignedToken.key_id / Claims.subject
            (5, WIRE_LEN, 0x2A),    // SignedToken.payload / Claims.audience
            (6, WIRE_LEN, 0x32),    // SignedToken.signature / Claims.scope
        ];
        for &(field, wire_type, expected_byte) in cases {
            let mut buf = Vec::new();
            encode_tag(field, wire_type, &mut buf);
            assert_eq!(buf.len(), 1, "field {field} tag should be single byte");
            assert_eq!(
                buf[0], expected_byte,
                "field {field} wire_type {wire_type}: expected 0x{expected_byte:02X}, got 0x{:02X}",
                buf[0]
            );
        }
    }
}
