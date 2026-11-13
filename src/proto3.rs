//! Minimal proto3 wire format encoder/decoder.
//!
//! The encoders produce, and [`Reader`] enforces, canonical form:
//! - Fields in ascending field-number order (a repeated field is consecutive)
//! - Minimal varint encoding
//! - Default values (0, empty bytes) omitted, so explicit defaults are rejected
//! - No unknown fields

use crate::error::ProtokenError;

/// Wire type for varint fields (uint32, uint64).
pub const WIRE_VARINT: u32 = 0;
/// Wire type for length-delimited fields (bytes, string, submessages).
pub const WIRE_LEN: u32 = 2;

// --- Encoding ---

/// Encode a varint (unsigned, minimal encoding).
pub fn encode_varint(mut value: u64, buf: &mut Vec<u8>) {
    while value > 0x7F {
        buf.push((value as u8 & 0x7F) | 0x80);
        value >>= 7;
    }
    buf.push(value as u8);
}

fn encode_tag(field_number: u32, wire_type: u32, buf: &mut Vec<u8>) {
    encode_varint((u64::from(field_number) << 3) | u64::from(wire_type), buf);
}

/// Encode a uint32 field. Omitted if the value is 0.
pub fn encode_uint32(field: u32, value: u32, buf: &mut Vec<u8>) {
    encode_uint64(field, value.into(), buf);
}

/// Encode a uint64 field. Omitted if the value is 0.
pub fn encode_uint64(field: u32, value: u64, buf: &mut Vec<u8>) {
    if value == 0 {
        return;
    }
    encode_tag(field, WIRE_VARINT, buf);
    encode_varint(value, buf);
}

/// Encode a bytes, string, or submessage field. Omitted if the value is empty.
pub fn encode_bytes(field: u32, value: &[u8], buf: &mut Vec<u8>) {
    if value.is_empty() {
        return;
    }
    encode_tag(field, WIRE_LEN, buf);
    encode_varint(value.len() as u64, buf);
    buf.extend_from_slice(value);
}

// --- Decoding ---

/// A cursor over one message. Call [`Reader::next_field`], then the `read_*`
/// method for that field's type.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    last_field_number: u32,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader {
            data,
            pos: 0,
            last_field_number: 0,
        }
    }

    /// Number of bytes consumed so far.
    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn is_at_end(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Read the next tag as `(field_number, wire_type)` and enforce ascending
    /// order. `repeated` is the one field number that may appear twice in a row.
    pub fn next_field(&mut self, repeated: Option<u32>) -> Result<(u32, u32), ProtokenError> {
        let (field_number, wire_type) = self.read_tag()?;
        let last = self.last_field_number;
        if field_number < last || (field_number == last && repeated != Some(field_number)) {
            return Err(ProtokenError::malformed(format!(
                "fields not in ascending order: field {field_number} after {last}"
            )));
        }
        self.last_field_number = field_number;
        Ok((field_number, wire_type))
    }

    fn read_tag(&mut self) -> Result<(u32, u32), ProtokenError> {
        let tag = self.read_varint()?;
        let wire_type = (tag & 0x07) as u32;
        match u32::try_from(tag >> 3) {
            Ok(field_number) if field_number != 0 => Ok((field_number, wire_type)),
            _ => Err(ProtokenError::malformed(format!(
                "invalid field number {}",
                tag >> 3
            ))),
        }
    }

    /// Read a varint, rejecting truncated, overlong, and overflowing encodings.
    pub fn read_varint(&mut self) -> Result<u64, ProtokenError> {
        let mut value = 0;
        for shift in (0..64).step_by(7) {
            let byte = *self
                .data
                .get(self.pos)
                .ok_or_else(|| ProtokenError::malformed("unexpected end of input in varint"))?;
            self.pos += 1;

            // Only bit 0 of the 10th byte fits in a u64.
            if shift == 63 && byte > 1 {
                break;
            }
            value |= u64::from(byte & 0x7F) << shift;

            if byte & 0x80 == 0 {
                if byte == 0 && shift > 0 {
                    return Err(ProtokenError::malformed("non-minimal varint encoding"));
                }
                return Ok(value);
            }
        }
        Err(ProtokenError::malformed("varint exceeds 64 bits"))
    }

    /// Read a varint that must fit in a u8, such as an enum-like uint32 field.
    pub fn read_u8(&mut self, field_name: &str) -> Result<u8, ProtokenError> {
        let value = self.read_varint()?;
        u8::try_from(value).map_err(|_| {
            ProtokenError::malformed(format!("{field_name} value {value} exceeds u8 range"))
        })
    }

    pub fn read_nonzero_varint(&mut self, field_name: &str) -> Result<u64, ProtokenError> {
        match self.read_varint()? {
            0 => Err(zero_value(field_name)),
            value => Ok(value),
        }
    }

    pub fn read_nonzero_u8(&mut self, field_name: &str) -> Result<u8, ProtokenError> {
        match self.read_u8(field_name)? {
            0 => Err(zero_value(field_name)),
            value => Ok(value),
        }
    }

    /// Read a length-delimited value of 1 to `max_len` bytes.
    pub fn read_bytes(
        &mut self,
        max_len: usize,
        field_name: &str,
    ) -> Result<&'a [u8], ProtokenError> {
        let len = self.read_varint()?;
        let bytes = usize::try_from(len)
            .ok()
            .and_then(|len| self.data.get(self.pos..self.pos.checked_add(len)?))
            .ok_or_else(|| {
                ProtokenError::malformed(format!(
                    "{field_name} length {len} extends past the end of the input"
                ))
            })?;
        self.pos += bytes.len();

        if bytes.is_empty() {
            return Err(ProtokenError::malformed(format!(
                "{field_name} is empty (canonical encoding omits empty fields)"
            )));
        }
        if bytes.len() > max_len {
            return Err(ProtokenError::malformed(format!(
                "{field_name} too long: {} bytes (max {max_len})",
                bytes.len()
            )));
        }
        Ok(bytes)
    }
}

fn zero_value(field_name: &str) -> ProtokenError {
    ProtokenError::malformed(format!(
        "{field_name} is zero (canonical encoding omits default values)"
    ))
}

/// Error for a message that ends before a required field.
pub(crate) fn missing_field(field_name: &str, message_name: &str) -> ProtokenError {
    ProtokenError::malformed(format!("missing {field_name} field in {message_name}"))
}

/// Error for an unknown field number or a wrong wire type.
pub(crate) fn unexpected_field(
    field_number: u32,
    wire_type: u32,
    message_name: &str,
) -> ProtokenError {
    ProtokenError::malformed(format!(
        "unexpected field {field_number} (wire type {wire_type}) in {message_name}"
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn varint(value: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        encode_varint(value, &mut buf);
        buf
    }

    fn is_malformed<T>(result: Result<T, ProtokenError>, needle: &str) -> bool {
        matches!(result, Err(ProtokenError::MalformedEncoding(m)) if m.contains(needle))
    }

    #[test]
    fn test_varint_roundtrip_and_size() {
        let cases = [
            (0, 1),
            (1, 1),
            (127, 1),
            (128, 2),
            (16383, 2),
            (16384, 3),
            (1700000000, 5),
            (u64::MAX, 10),
        ];
        for (value, expected_len) in cases {
            let buf = varint(value);
            assert_eq!(buf.len(), expected_len, "{value}");
            let mut reader = Reader::new(&buf);
            assert!(!reader.is_at_end());
            assert_eq!(reader.read_varint().unwrap(), value);
            assert_eq!(reader.position(), expected_len);
            assert!(reader.is_at_end());
        }
    }

    #[test]
    fn test_varint_rejects_bad_encodings() {
        let read = |data: &[u8]| Reader::new(data).read_varint();
        assert!(is_malformed(read(&[]), "end of input"));
        assert!(is_malformed(read(&[0x80]), "end of input"));
        assert!(is_malformed(read(&[0x81, 0x00]), "non-minimal"));

        let mut ten_bytes = [0xFF; 10];
        for (last, ok) in [(0x01, true), (0x02, false), (0x81, false)] {
            ten_bytes[9] = last;
            assert_eq!(read(&ten_bytes).is_ok(), ok, "10th byte {last:#x}");
        }
    }

    #[test]
    fn test_varint_minimality_is_relative_to_its_first_byte() {
        let mut reader = Reader::new(&[0x01, 0x00, 0x81, 0x00]);
        assert_eq!(reader.read_varint().unwrap(), 1);
        assert_eq!(reader.read_varint().unwrap(), 0);
        assert!(is_malformed(reader.read_varint(), "non-minimal"));
    }

    #[test]
    fn test_field_encoding() {
        let mut buf = Vec::new();
        encode_uint32(2, 1, &mut buf);
        encode_uint64(3, 300, &mut buf);
        encode_bytes(4, b"hi", &mut buf);
        assert_eq!(buf, [0x10, 0x01, 0x18, 0xAC, 0x02, 0x22, 0x02, b'h', b'i']);
    }

    #[test]
    fn test_default_values_are_omitted() {
        let mut buf = Vec::new();
        encode_uint32(1, 0, &mut buf);
        encode_uint64(2, 0, &mut buf);
        encode_bytes(3, &[], &mut buf);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_next_field_rejects_invalid_field_numbers() {
        // 0x1_0000_0002 would truncate to field 2.
        for field_number in [0, 0x1_0000_0002] {
            let tag = varint(field_number << 3);
            assert!(is_malformed(
                Reader::new(&tag).next_field(Some(0)),
                "invalid field number"
            ));
        }
        let tag = varint((u64::from(u32::MAX) << 3) | 5);
        assert_eq!(Reader::new(&tag).next_field(None).unwrap(), (u32::MAX, 5));
    }

    fn field_numbers(tags: &[u8], repeated: Option<u32>) -> Result<Vec<u32>, ProtokenError> {
        let mut reader = Reader::new(tags);
        tags.iter()
            .map(|_| Ok(reader.next_field(repeated)?.0))
            .collect()
    }

    #[test]
    fn test_next_field_order_rules() {
        // Tags for fields 1, 2, 6, 7 (varint wire type): 0x08, 0x10, 0x30, 0x38.
        assert_eq!(field_numbers(&[0x08, 0x10, 0x30], None).unwrap(), [1, 2, 6]);
        assert!(field_numbers(&[0x10, 0x08], None).is_err());
        assert!(field_numbers(&[0x30, 0x08], Some(6)).is_err());
        assert!(field_numbers(&[0x08, 0x08], None).is_err());
        assert!(field_numbers(&[0x08, 0x08], Some(6)).is_err());
        assert_eq!(
            field_numbers(&[0x30, 0x30, 0x30], Some(6)).unwrap(),
            [6, 6, 6]
        );
        assert!(field_numbers(&[0x30, 0x38, 0x30], Some(6)).is_err());
    }

    #[test]
    fn test_read_u8_bounds() {
        assert_eq!(Reader::new(&varint(0)).read_u8("f").unwrap(), 0);
        assert_eq!(Reader::new(&varint(255)).read_u8("f").unwrap(), 255);
        for value in [256, u64::MAX] {
            assert!(is_malformed(
                Reader::new(&varint(value)).read_u8("f"),
                "exceeds u8 range"
            ));
        }
    }

    #[test]
    fn test_nonzero_readers_reject_explicit_zero() {
        assert!(is_malformed(
            Reader::new(&[0x00]).read_nonzero_varint("f"),
            "f is zero"
        ));
        assert!(is_malformed(
            Reader::new(&[0x00]).read_nonzero_u8("f"),
            "f is zero"
        ));
        assert_eq!(Reader::new(&[0x07]).read_nonzero_varint("f").unwrap(), 7);
        assert_eq!(Reader::new(&[0x07]).read_nonzero_u8("f").unwrap(), 7);
        assert!(Reader::new(&[0x80, 0x02]).read_nonzero_u8("f").is_err());
    }

    #[test]
    fn test_read_bytes_limits() {
        let mut reader = Reader::new(b"\x02hi!");
        assert_eq!(reader.read_bytes(2, "f").unwrap(), b"hi");
        assert_eq!(reader.position(), 3);

        let read = |data: &[u8]| Reader::new(data).read_bytes(2, "f").map(<[u8]>::to_vec);
        assert!(is_malformed(read(b"\x00"), "empty"));
        assert!(is_malformed(read(b"\x03abc"), "too long"));
        assert!(is_malformed(read(b"\x02a"), "past the end"));
        // A length near u64::MAX must not overflow the end offset.
        assert!(is_malformed(read(&varint(u64::MAX)), "past the end"));
    }
}
