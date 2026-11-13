#![no_main]
use std::sync::LazyLock;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use libfuzzer_sys::fuzz_target;
use protoken::serialize::deserialize_claims;
use protoken::{ProtokenError, SigningKey};

/// The reference keys and their tokens. The corpus is seeded with these
/// tokens, so mutations pass the key identity check and reach the primitives.
static REFERENCE: LazyLock<Vec<(SigningKey, Vec<u8>)>> = LazyLock::new(|| {
    let json = include_str!("../../testdata/reference_vectors.json");
    let file: serde_json::Value = serde_json::from_str(json).unwrap();
    let vectors = file["vectors"].as_array().unwrap();
    vectors
        .iter()
        .map(|v| {
            let decode = |field: &str| URL_SAFE_NO_PAD.decode(v[field].as_str().unwrap()).unwrap();
            let key = SigningKey::from_bytes(&decode("signing_key_base64")).unwrap();
            (key, decode("token_base64"))
        })
        .collect()
});

fuzz_target!(|data: &[u8]| {
    // The fuzzer cannot sign, so it may only ever present the reference token.
    for (key, token) in REFERENCE.iter() {
        if key.verify(data, 1_900_000_000).is_ok() {
            assert_eq!(data, token, "{}: forged token", key.algorithm());
        }
    }

    // If the input decodes as Claims, signing must succeed exactly when
    // validate() does, and the result must verify inside its window only.
    let Ok(claims) = deserialize_claims(data) else {
        return;
    };
    // SLH-DSA signing is too slow to fuzz.
    let fast = |key: &&SigningKey| !key.algorithm().name().starts_with("slh-dsa");
    for key in REFERENCE.iter().map(|(key, _)| key).filter(fast) {
        let Ok(token) = key.sign(&claims) else {
            assert!(claims.validate().is_err(), "sign refused valid claims");
            return;
        };
        let verified = key
            .verify(&token, claims.expires_at)
            .unwrap_or_else(|e| panic!("{}: fresh token failed to verify: {e}", key.algorithm()));
        assert_eq!(verified.claims, claims);

        if claims.expires_at < u64::MAX {
            assert!(matches!(
                key.verify(&token, claims.expires_at + 1),
                Err(ProtokenError::TokenExpired { .. })
            ));
        }
        if claims.not_before > 0 {
            assert!(matches!(
                key.verify(&token, claims.not_before - 1),
                Err(ProtokenError::TokenNotYetValid { .. })
            ));
        }
    }
});
