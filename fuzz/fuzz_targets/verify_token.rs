#![no_main]
use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use protoken::serialize::deserialize_claims;
use protoken::{Algorithm, ProtokenError, SigningKey, Zeroizing};

static KEYS: LazyLock<Vec<SigningKey>> = LazyLock::new(|| {
    Algorithm::ALL
        .into_iter()
        .map(|algorithm| {
            SigningKey::from_secret_key(algorithm, Zeroizing::new(vec![0x42; 32]))
                .expect("fixed secret is valid for every algorithm")
        })
        .collect()
});

fuzz_target!(|data: &[u8]| {
    // Verifying arbitrary bytes must never panic.
    for key in KEYS.iter() {
        let _ = key.verify(data, 1_700_000_000);
        if let Ok(vk) = key.verifying_key() {
            let _ = vk.verify(data, 1_700_000_000);
        }
    }

    // If the input decodes as Claims, every algorithm must either sign it and
    // verify the result (with expiry enforced exactly) or refuse it precisely
    // when validate() does.
    let Ok(claims) = deserialize_claims(data) else {
        return;
    };
    for key in KEYS.iter() {
        let token = match key.sign(&claims) {
            Ok(token) => token,
            Err(_) => {
                assert!(claims.validate().is_err(), "sign refused valid claims");
                return;
            }
        };
        let verified = key
            .verify(&token, claims.expires_at)
            .unwrap_or_else(|e| panic!("{}: fresh token failed to verify: {e}", key.algorithm));
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
