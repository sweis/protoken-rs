#![no_main]
use libfuzzer_sys::fuzz_target;
use protoken::serialize::{append_signature, serialize_signing_input};
use protoken::types::Version;
use protoken::{Algorithm, KeyIdentifier, VerifyingKey};

// Feeds an arbitrary public key and signature to each primitive. The input is
// an algorithm byte, then bytes that are repeated to fill both values.
fuzz_target!(|data: &[u8]| {
    let Some((&byte, rest)) = data.split_first() else {
        return;
    };
    let Ok(algorithm) = Algorithm::try_from(byte) else {
        return;
    };
    let Some(public_key_len) = algorithm.public_key_len() else {
        return;
    };
    let mut bytes = rest.iter().copied().cycle();
    let public_key: Vec<u8> = bytes.by_ref().take(public_key_len).collect();
    let signature: Vec<u8> = bytes.take(algorithm.signature_len()).collect();

    let Ok(key) = VerifyingKey::new(algorithm, public_key) else {
        return;
    };
    let key_id = KeyIdentifier::KeyHash(key.key_hash());
    let input = serialize_signing_input(Version::V0, algorithm, &key_id, &[0x08, 0x01]);
    let _ = key.verify(&append_signature(input, &signature), 0);
});
