#![no_main]
use libfuzzer_sys::fuzz_target;
use protoken::serialize::{deserialize_payload, serialize_payload};

fuzz_target!(|data: &[u8]| {
    // If data parses as a valid payload, re-serializing must produce identical bytes.
    if let Ok(payload) = deserialize_payload(data) {
        let reserialized = serialize_payload(&payload);
        assert_eq!(
            data, &reserialized[..],
            "roundtrip mismatch: deserialize then serialize produced different bytes"
        );
    }
});
