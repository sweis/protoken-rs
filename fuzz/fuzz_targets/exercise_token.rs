#![no_main]
use libfuzzer_sys::fuzz_target;
use protoken::serialize::{deserialize_payload, deserialize_signed_token};

/// Exercises all fields of a successfully parsed signed token.
/// If any accessor panics on valid parsed input, this will catch it.
fuzz_target!(|data: &[u8]| {
    if let Ok(token) = deserialize_signed_token(data) {
        // Exercise the payload
        if let Ok(payload) = deserialize_payload(&token.payload_bytes) {
            // Access every field to check for panics
            let _ = payload.metadata.version.to_byte();
            let _ = payload.metadata.algorithm.to_byte();
            let _ = payload.metadata.algorithm.signature_len();
            let _ = payload.metadata.key_identifier.key_id_type().to_byte();
            let _ = payload.claims.expires_at;
            let _ = payload.claims.not_before;
            let _ = payload.claims.issued_at;
            let _ = payload.claims.subject.len();
            let _ = payload.claims.audience.len();
            for scope in &payload.claims.scopes {
                let _ = scope.len();
            }
            // Verify claims validation doesn't panic
            let _ = payload.claims.validate();
            // JSON serialization should not panic
            let _ = serde_json::to_string(&payload);
        }

        // Check signature length
        let _ = token.signature.len();
    }
});
