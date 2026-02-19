#![no_main]
use libfuzzer_sys::fuzz_target;
use protoken::keys::{deserialize_signing_key, deserialize_verifying_key, extract_verifying_key};

fuzz_target!(|data: &[u8]| {
    // Fuzz SigningKey deserialization
    if let Ok(sk) = deserialize_signing_key(data) {
        // If it parses, extracting a verifying key should not panic
        let _ = extract_verifying_key(&sk);
    }

    // Fuzz VerifyingKey deserialization
    let _ = deserialize_verifying_key(data);
});
