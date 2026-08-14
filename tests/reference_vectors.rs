#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Regression tests against testdata/reference_vectors.json: long-lived keys
//! and tokens (expiring 2036) for every algorithm. All three algorithms sign
//! deterministically, so re-signing the stored claims with the stored key
//! must reproduce the stored token byte for byte. Regenerate with
//! `cargo run --example gen_reference_vectors`.

use base64::Engine as _;
use serde::Deserialize;

use protoken::serialize::{deserialize_claims, deserialize_signed_token};
use protoken::{Algorithm, Claims, KeyIdType, KeyIdentifier, SigningKey, VerifyingKey};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// A time inside every reference token's validity window.
const VALID_TIME: u64 = 1_900_000_000;

#[derive(Deserialize)]
struct VectorFile {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    algorithm: Algorithm,
    signing_key_base64: String,
    verifying_key_base64: Option<String>,
    key_hash_base64: String,
    token_base64: String,
    claims: Claims,
}

impl Vector {
    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&decode(&self.signing_key_base64))
            .unwrap_or_else(|e| panic!("{}: bad signing key: {e}", self.name))
    }

    fn verifying_key(&self) -> Option<VerifyingKey> {
        let b64 = self.verifying_key_base64.as_ref()?;
        Some(
            VerifyingKey::from_bytes(&decode(b64))
                .unwrap_or_else(|e| panic!("{}: bad verifying key: {e}", self.name)),
        )
    }

    fn token(&self) -> Vec<u8> {
        decode(&self.token_base64)
    }
}

fn load_vectors() -> Vec<Vector> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/reference_vectors.json"
    );
    let data = std::fs::read_to_string(path).expect("failed to read reference vectors");
    serde_json::from_str::<VectorFile>(&data)
        .expect("failed to parse reference vectors")
        .vectors
}

fn decode(b64: &str) -> Vec<u8> {
    B64.decode(b64).expect("vector contains invalid base64")
}

#[test]
fn test_reference_covers_every_algorithm() {
    let mut algorithms: Vec<Algorithm> = load_vectors().iter().map(|v| v.algorithm).collect();
    algorithms.sort_by_key(|a| a.to_byte());
    assert_eq!(algorithms, Algorithm::ALL);
}

#[test]
fn test_reference_keys_are_consistent() {
    for v in load_vectors() {
        let sk = v.signing_key();
        assert_eq!(sk.algorithm, v.algorithm, "{}", v.name);

        let key_hash = sk.key_identifier(KeyIdType::KeyHash).unwrap();
        assert_eq!(
            B64.encode(key_hash.as_bytes()),
            v.key_hash_base64,
            "{}",
            v.name
        );

        match v.verifying_key() {
            Some(vk) => {
                assert!(!v.algorithm.is_symmetric(), "{}", v.name);
                assert_eq!(vk, sk.verifying_key().unwrap(), "{}", v.name);
                assert_eq!(
                    KeyIdentifier::KeyHash(vk.key_hash()),
                    key_hash,
                    "{}",
                    v.name
                );
            }
            None => assert!(
                v.algorithm.is_symmetric(),
                "{}: missing verifying key",
                v.name
            ),
        }
    }
}

#[test]
fn test_reference_tokens_decode_to_stored_claims() {
    for v in load_vectors() {
        let token =
            deserialize_signed_token(&v.token()).unwrap_or_else(|e| panic!("{}: {e}", v.name));
        assert_eq!(token.algorithm, v.algorithm, "{}", v.name);
        assert_eq!(
            B64.encode(token.key_identifier.as_bytes()),
            v.key_hash_base64,
            "{}",
            v.name
        );
        let claims =
            deserialize_claims(&token.payload).unwrap_or_else(|e| panic!("{}: {e}", v.name));
        assert_eq!(claims, v.claims, "{}", v.name);
        assert_eq!(claims.expires_at, 2087078400, "{}", v.name);
    }
}

#[test]
fn test_reference_tokens_verify() {
    for v in load_vectors() {
        let token = v.token();
        let verifier_result = match v.verifying_key() {
            Some(vk) => vk.verify(&token, VALID_TIME),
            None => v.signing_key().verify(&token, VALID_TIME),
        };
        let verified = verifier_result.unwrap_or_else(|e| panic!("{}: {e}", v.name));
        assert_eq!(verified.claims, v.claims, "{}", v.name);
        assert_eq!(verified.algorithm, v.algorithm, "{}", v.name);

        // The stored tokens are also usable as expiry test cases.
        assert!(
            v.signing_key()
                .verify(&token, v.claims.expires_at + 1)
                .is_err(),
            "{}: must be expired one second after expires_at",
            v.name
        );
    }
}

#[test]
fn test_reference_resign_reproduces_tokens() {
    for v in load_vectors() {
        let token = v.signing_key().sign(&v.claims).unwrap();
        assert_eq!(
            B64.encode(&token),
            v.token_base64,
            "{}: re-signing must reproduce the stored token exactly",
            v.name
        );
    }
}
