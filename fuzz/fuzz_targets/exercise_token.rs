#![no_main]
use libfuzzer_sys::fuzz_target;
use protoken::serialize::{deserialize_claims, deserialize_signed_token};

// Exercises all fields of a successfully parsed signed token.
// If any accessor panics on valid parsed input, this will catch it.
fuzz_target!(|data: &[u8]| {
    if let Ok(token) = deserialize_signed_token(data) {
        // Access every envelope field to check for panics
        let _ = token.version.to_byte();
        let _ = token.algorithm.to_byte();
        let _ = token.key_identifier.key_id_type().to_byte();
        let _ = token.key_identifier.as_bytes().len();
        let _ = token.signature.len();

        // Exercise the payload as Claims
        if let Ok(claims) = deserialize_claims(&token.payload) {
            let _ = claims.expires_at;
            let _ = claims.not_before;
            let _ = claims.issued_at;
            let _ = claims.subject.len();
            let _ = claims.audience.len();
            for scope in &claims.scopes {
                let _ = scope.len();
            }
            // Claims validation should not panic
            let _ = claims.validate();
            // JSON serialization should not panic
            let _ = serde_json::to_string(&claims);
        }
    }
});
