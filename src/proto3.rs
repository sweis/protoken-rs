//! Minimal proto3 wire format encoder/decoder.
//!
//! Produces canonical encoding per our rules:
//! - Fields in ascending field-number order
//! - Minimal varint encoding (no zero-padding)
//! - Default values (0, empty bytes) omitted
//! - No unknown fields
//!
//! All field numbers are <= 15, so tags are single bytes.

use crate::error::ProtokenError;

// --- Shared helpers ---

/// Convert a u32 to u8, rejecting values > 255 to prevent truncation.
pub fn to_u8(v: u32, field_name: &str) -> Result<u8, ProtokenError> {
    u8::try_from(v).map_err(|_| {
        ProtokenError::MalformedEncoding(format!("{field_name} value {v} exceeds u8 range"))
    })
}

/// Read a varint that must fit in a u32. Rejects values > u32::MAX.
pub fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32, ProtokenError> {
    let v = read_varint_value(data, pos)?;
    u32::try_from(v)
        .map_err(|_| ProtokenError::MalformedEncoding(format!("varint value {v} exceeds u32::MAX")))
}

// Wire types
const WIRE_VARINT: u32 = 0;
const WIRE_LEN: u32 = 2;

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

/// Read a varint field value (caller already consumed the tag).
pub fn read_varint_value(data: &[u8], pos: &mut usize) -> Result<u64, ProtokenError> {
    decode_varint(data, pos)
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
    fn test_field_tag_values() {
        // Verify our field tag bytes match the proto3 spec
        let cases: &[(u32, u32, u8)] = &[
            (1, WIRE_VARINT, 0x08), // version
            (2, WIRE_VARINT, 0x10), // algorithm
            (3, WIRE_VARINT, 0x18), // key_id_type
            (4, WIRE_LEN, 0x22),    // key_id
            (5, WIRE_VARINT, 0x28), // expires_at
            (6, WIRE_VARINT, 0x30), // not_before
            (7, WIRE_VARINT, 0x38), // issued_at
            (8, WIRE_LEN, 0x42),    // subject
            (9, WIRE_LEN, 0x4A),    // audience
            (1, WIRE_LEN, 0x0A),    // SignedToken.payload
            (2, WIRE_LEN, 0x12),    // SignedToken.signature
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
