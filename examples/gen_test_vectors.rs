#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Generates wire format test vectors. Fully deterministic; the output must
//! match testdata/vectors.json unless the wire format changes.
//! Run with: cargo run --example gen_test_vectors

use base64::Engine as _;

use protoken::serialize::serialize_claims;
use protoken::sign::compute_key_hash;
use protoken::{Algorithm, Claims, KeyIdType, SigningKey, Zeroizing};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

const HMAC_KEY: &[u8] = b"protoken-test-vector-key-do-not-use-in-production!!";
const ED25519_SEED_HEX: &str = "3cc4bec961d0bf428a58a323812992ea8cd803814871ee8b2477dc3362ac4619";

fn claims_vector(name: &str, claims: &Claims) -> serde_json::Value {
    let bytes = serialize_claims(claims);
    serde_json::json!({
        "name": name,
        "type": "claims",
        "input": claims,
        "expected_base64": B64.encode(&bytes),
        "expected_len": bytes.len()
    })
}

fn signed_vector(
    name: &str,
    key: &SigningKey,
    id_type: KeyIdType,
    expires_at: u64,
) -> serde_json::Value {
    let claims = Claims {
        expires_at,
        ..Default::default()
    };
    let token = key.sign_with_key_id(&claims, id_type).unwrap();
    let key_hash = key.key_identifier(KeyIdType::KeyHash).unwrap();
    serde_json::json!({
        "name": name,
        "type": "signed_token",
        "input": {
            "algorithm": key.algorithm,
            "signing_key_base64": B64.encode(key.to_bytes()),
            "key_hash_base64": B64.encode(key_hash.as_bytes()),
            "key_id_type": id_type,
            "expires_at": expires_at
        },
        "expected_base64": B64.encode(&token),
        "expected_len": token.len(),
    })
}

fn key_hash_vector(name: &str, input: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "type": "key_hash",
        "input_base64": B64.encode(input),
        "expected_base64": B64.encode(compute_key_hash(input))
    })
}

fn main() {
    let hmac_key =
        SigningKey::from_secret_key(Algorithm::HmacSha256, Zeroizing::new(HMAC_KEY.to_vec()))
            .unwrap();
    let ed25519_key = SigningKey::from_secret_key(
        Algorithm::Ed25519,
        Zeroizing::new(hex::decode(ED25519_SEED_HEX).unwrap()),
    )
    .unwrap();

    let vectors = vec![
        claims_vector(
            "claims_minimal",
            &Claims {
                expires_at: 1700000000,
                ..Default::default()
            },
        ),
        claims_vector(
            "claims_full",
            &Claims {
                expires_at: 1700000000,
                not_before: 1699990000,
                issued_at: 1699990000,
                subject: "user:alice".into(),
                audience: "api.example.com".into(),
                ..Default::default()
            },
        ),
        claims_vector(
            "claims_max_expiry",
            &Claims {
                expires_at: u64::MAX,
                ..Default::default()
            },
        ),
        claims_vector(
            "claims_scopes",
            &Claims {
                expires_at: 1700000000,
                scopes: vec!["admin".into(), "read".into(), "write".into()],
                ..Default::default()
            },
        ),
        signed_vector("signed_hmac", &hmac_key, KeyIdType::KeyHash, 1700000000),
        signed_vector(
            "signed_ed25519_keyhash",
            &ed25519_key,
            KeyIdType::KeyHash,
            1800000000,
        ),
        signed_vector(
            "signed_ed25519_pubkey",
            &ed25519_key,
            KeyIdType::PublicKey,
            1800000000,
        ),
        key_hash_vector("key_hash_hmac", HMAC_KEY),
        key_hash_vector("key_hash_ed25519_pubkey", &ed25519_key.public_key),
    ];

    let output = serde_json::json!({
        "description": "Protoken wire format test vectors (canonical proto3). All binary data is URL-safe base64 (no padding). Any change in these values indicates a wire format regression.",
        "generated_by": "gen_test_vectors",
        "vectors": vectors
    });

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}
