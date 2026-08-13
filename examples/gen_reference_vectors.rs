#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Generates long-lived reference keys and tokens for regression testing.
//!
//! All seeds are fixed and all three algorithms sign deterministically, so
//! this program is reproducible: its output must match
//! testdata/reference_vectors.json byte for byte unless the wire format
//! changes. Run with: cargo run --example gen_reference_vectors

use base64::Engine as _;

use protoken::{Algorithm, Claims, KeyIdType, SigningKey, Zeroizing};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Issued 2025-02-19, expires 2036-02-19 00:00:00 UTC.
const ISSUED_AT: u64 = 1739923200;
const EXPIRES_AT: u64 = 2087078400;

const HMAC_KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const ED25519_SEED_HEX: &str = "3cc4bec961d0bf428a58a323812992ea8cd803814871ee8b2477dc3362ac4619";
const MLDSA44_SEED_HEX: &str = "7003d5fd5e928c6468134be85db0babd26d455dc9b413dff84758542c2afcc7b";

fn reference_claims() -> Claims {
    Claims {
        expires_at: EXPIRES_AT,
        not_before: ISSUED_AT,
        issued_at: ISSUED_AT,
        subject: "ref:test-user".into(),
        audience: "ref:test-service".into(),
        scopes: vec!["read".into(), "write".into()],
    }
}

fn signing_key(algorithm: Algorithm, secret_hex: &str) -> SigningKey {
    let secret_key = Zeroizing::new(hex::decode(secret_hex).unwrap());
    SigningKey::from_secret_key(algorithm, secret_key).unwrap()
}

fn vector(name: &str, key: &SigningKey) -> serde_json::Value {
    let claims = reference_claims();
    let token = key.sign(&claims).unwrap();
    let key_hash = key.key_identifier(KeyIdType::KeyHash).unwrap();

    let mut v = serde_json::json!({
        "name": name,
        "algorithm": key.algorithm,
        "signing_key_base64": B64.encode(key.to_bytes()),
        "key_hash_base64": B64.encode(key_hash.as_bytes()),
        "token_base64": B64.encode(&token),
        "claims": claims,
    });
    // HMAC vectors have no verifying key, and the field is omitted rather than null.
    if let (Ok(vk), Some(fields)) = (key.verifying_key(), v.as_object_mut()) {
        fields.insert(
            "verifying_key_base64".into(),
            B64.encode(vk.to_bytes()).into(),
        );
    }
    v
}

fn main() {
    let vectors = vec![
        vector(
            "hmac_reference",
            &signing_key(Algorithm::HmacSha256, HMAC_KEY_HEX),
        ),
        vector(
            "ed25519_reference",
            &signing_key(Algorithm::Ed25519, ED25519_SEED_HEX),
        ),
        vector(
            "mldsa44_reference",
            &signing_key(Algorithm::MlDsa44, MLDSA44_SEED_HEX),
        ),
    ];

    let output = serde_json::json!({
        "description": "Long-lived protoken reference vectors (expire 2036). All algorithms sign deterministically; any change in token_base64 indicates a wire format regression.",
        "generated_by": "gen_reference_vectors",
        "vectors": vectors
    });

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}
