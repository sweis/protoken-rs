#![no_main]
use libfuzzer_sys::fuzz_target;
use protoken::serialize::{
    deserialize_claims, deserialize_signed_token, serialize_claims, serialize_signed_token,
};
use protoken::{SigningKey, VerifyingKey};

// Canonical encoding means anything that decodes must re-encode to exactly
// the same bytes. Any accepted-but-different input is a malleability bug.
fuzz_target!(|data: &[u8]| {
    if let Ok(claims) = deserialize_claims(data) {
        assert_eq!(data, serialize_claims(&claims), "claims roundtrip mismatch");
    }
    if let Ok(token) = deserialize_signed_token(data) {
        assert_eq!(
            data,
            serialize_signed_token(&token),
            "signed token roundtrip mismatch"
        );
    }
    if let Ok(key) = SigningKey::from_bytes(data) {
        assert_eq!(data, &key.to_bytes()[..], "signing key roundtrip mismatch");
    }
    if let Ok(key) = VerifyingKey::from_bytes(data) {
        assert_eq!(data, key.to_bytes(), "verifying key roundtrip mismatch");
    }
});
