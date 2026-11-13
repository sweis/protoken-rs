#![no_main]
use libfuzzer_sys::fuzz_target;
use protoken::{KeyIdType, SigningKey, VerifyingKey};

// A key that decodes must re-encode to the same bytes, decode as only one key
// type, and survive the operations a caller would perform on it.
fuzz_target!(|data: &[u8]| {
    let signing_key = SigningKey::from_bytes(data);
    let verifying_key = VerifyingKey::from_bytes(data);
    assert!(signing_key.is_err() || verifying_key.is_err());

    if let Ok(key) = signing_key {
        assert_eq!(data, &key.to_bytes()[..], "signing key roundtrip mismatch");
        let symmetric = key.algorithm().is_symmetric();
        assert_eq!(key.verifying_key().is_err(), symmetric);
        assert_eq!(key.key_identifier(KeyIdType::PublicKey).is_err(), symmetric);
        assert!(key.key_identifier(KeyIdType::KeyHash).is_ok());
    }
    if let Ok(key) = verifying_key {
        assert_eq!(data, key.to_bytes(), "verifying key roundtrip mismatch");
        assert!(key.verify(data, 0).is_err());
    }
});
