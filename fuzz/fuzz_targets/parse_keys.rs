#![no_main]
use libfuzzer_sys::fuzz_target;
use protoken::{SigningKey, VerifyingKey};

// Key decoding must never panic. Anything that decodes must also survive the
// operations a caller would perform on it.
fuzz_target!(|data: &[u8]| {
    if let Ok(sk) = SigningKey::from_bytes(data) {
        let _ = sk.verifying_key();
        let _ = sk.key_identifier(protoken::KeyIdType::KeyHash);
        let _ = sk.key_identifier(protoken::KeyIdType::PublicKey);
        let _ = format!("{sk:?}");
    }
    if let Ok(vk) = VerifyingKey::from_bytes(data) {
        let _ = vk.key_hash();
        let _ = vk.verify(data, 0);
    }
});
