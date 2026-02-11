#![no_main]
use libfuzzer_sys::fuzz_target;
use protoken::serialize::deserialize_signed_token;

fuzz_target!(|data: &[u8]| {
    // Must never panic, regardless of input.
    let _ = deserialize_signed_token(data);
});
