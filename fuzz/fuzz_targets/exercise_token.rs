#![no_main]
use libfuzzer_sys::fuzz_target;
use protoken::serialize::{deserialize_claims, deserialize_signed_token};

// Everything a caller might do with a token that parsed must be panic-free.
fuzz_target!(|data: &[u8]| {
    let Ok(token) = deserialize_signed_token(data) else {
        return;
    };
    let _ = token.version.to_byte();
    let _ = token.algorithm.to_string();
    let _ = token.key_identifier.key_id_type().to_byte();
    let _ = token.key_identifier.as_bytes().len();
    let _ = serde_json::to_string(&token.key_identifier);
    let _ = token.signature.len();

    let Ok(claims) = deserialize_claims(&token.payload) else {
        return;
    };
    let _ = claims.validate();
    let json = serde_json::to_string(&claims).expect("claims serialize to JSON");
    let parsed: protoken::Claims = serde_json::from_str(&json).expect("claims JSON parses");
    assert_eq!(parsed, claims, "claims JSON roundtrip");
});
