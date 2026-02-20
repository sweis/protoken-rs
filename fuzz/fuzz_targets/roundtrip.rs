#![no_main]
use libfuzzer_sys::fuzz_target;
use protoken::keys::{
    deserialize_signing_key, deserialize_verifying_key, serialize_signing_key,
    serialize_verifying_key,
};
use protoken::serialize::{
    deserialize_payload, deserialize_signed_token, serialize_payload, serialize_signed_token,
};

fuzz_target!(|data: &[u8]| {
    // If data parses as a valid payload, re-serializing must produce identical bytes.
    if let Ok(payload) = deserialize_payload(data) {
        let reserialized = serialize_payload(&payload);
        assert_eq!(
            data, &reserialized[..],
            "payload roundtrip mismatch: deserialize then serialize produced different bytes"
        );
    }

    // Same for SignedToken.
    if let Ok(token) = deserialize_signed_token(data) {
        let reserialized = serialize_signed_token(&token);
        assert_eq!(
            data, &reserialized[..],
            "signed token roundtrip mismatch: deserialize then serialize produced different bytes"
        );
    }

    // Same for SigningKey.
    if let Ok(key) = deserialize_signing_key(data) {
        let reserialized = serialize_signing_key(&key);
        assert_eq!(
            data, &reserialized[..],
            "signing key roundtrip mismatch: deserialize then serialize produced different bytes"
        );
    }

    // Same for VerifyingKey.
    if let Ok(key) = deserialize_verifying_key(data) {
        let reserialized = serialize_verifying_key(&key);
        assert_eq!(
            data, &reserialized[..],
            "verifying key roundtrip mismatch: deserialize then serialize produced different bytes"
        );
    }
});
