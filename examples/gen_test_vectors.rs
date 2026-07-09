#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Generates test vectors for protoken wire format regression testing.
//! Run with: cargo run --example gen_test_vectors

use base64::Engine;
use zeroize::Zeroizing;

use protoken::keys::{serialize_signing_key, SigningKey};
use protoken::serialize::serialize_claims;
use protoken::sign::{compute_key_hash, sign_ed25519, sign_hmac};
use protoken::types::*;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn claims_vector(name: &str, claims: &Claims, input: serde_json::Value) -> serde_json::Value {
    let bytes = serialize_claims(claims);
    serde_json::json!({
        "name": name,
        "type": "claims",
        "input": input,
        "expected_base64": B64.encode(&bytes),
        "expected_len": bytes.len()
    })
}

fn main() {
    let mut vectors: Vec<serde_json::Value> = Vec::new();

    // === Claims serialization vectors ===

    vectors.push(claims_vector(
        "claims_minimal",
        &Claims {
            expires_at: 1700000000,
            ..Default::default()
        },
        serde_json::json!({ "expires_at": 1700000000u64 }),
    ));

    vectors.push(claims_vector(
        "claims_full",
        &Claims {
            expires_at: 1700000000,
            not_before: 1699990000,
            issued_at: 1699990000,
            subject: "user:alice".into(),
            audience: "api.example.com".into(),
            ..Default::default()
        },
        serde_json::json!({
            "expires_at": 1700000000u64,
            "not_before": 1699990000u64,
            "issued_at": 1699990000u64,
            "subject": "user:alice",
            "audience": "api.example.com"
        }),
    ));

    vectors.push(claims_vector(
        "claims_max_expiry",
        &Claims {
            expires_at: u64::MAX,
            ..Default::default()
        },
        serde_json::json!({ "expires_at": 18446744073709551615u64 }),
    ));

    vectors.push(claims_vector(
        "claims_scopes",
        &Claims {
            expires_at: 1700000000,
            scopes: vec!["admin".into(), "read".into(), "write".into()],
            ..Default::default()
        },
        serde_json::json!({
            "expires_at": 1700000000u64,
            "scopes": ["admin", "read", "write"]
        }),
    ));

    // === HMAC signed token vectors ===

    let hmac_key = b"protoken-test-vector-key-do-not-use-in-production!!";
    let hmac_key_hash = compute_key_hash(hmac_key);

    let hmac_sk = SigningKey {
        algorithm: Algorithm::HmacSha256,
        secret_key: Zeroizing::new(hmac_key.to_vec()),
        public_key: Vec::new(),
    };

    let hmac_expires = 1700000000u64;
    let hmac_claims = Claims {
        expires_at: hmac_expires,
        ..Default::default()
    };
    let hmac_token = sign_hmac(hmac_key, &hmac_claims).unwrap();
    vectors.push(serde_json::json!({
        "name": "signed_hmac",
        "type": "signed_token",
        "input": {
            "algorithm": "hmac",
            "signing_key_base64": B64.encode(serialize_signing_key(&hmac_sk)),
            "key_hash_base64": B64.encode(hmac_key_hash),
            "expires_at": hmac_expires
        },
        "expected_base64": B64.encode(&hmac_token),
        "expected_len": hmac_token.len(),
    }));

    // === Ed25519 signed token vectors ===

    let (seed, public_key) = fixed_ed25519_key();
    let ed25519_key_hash_val = compute_key_hash(&public_key);

    let ed25519_sk = SigningKey {
        algorithm: Algorithm::Ed25519,
        secret_key: Zeroizing::new(seed.clone()),
        public_key: public_key.clone(),
    };

    // Ed25519 signed token with key_hash
    let ed25519_expires = 1800000000u64;
    let ed25519_key_id = KeyIdentifier::KeyHash(ed25519_key_hash_val);
    let ed25519_claims = Claims {
        expires_at: ed25519_expires,
        ..Default::default()
    };
    let ed25519_token = sign_ed25519(&seed, &ed25519_claims, ed25519_key_id).unwrap();
    vectors.push(serde_json::json!({
        "name": "signed_ed25519_keyhash",
        "type": "signed_token",
        "input": {
            "algorithm": "ed25519",
            "signing_key_base64": B64.encode(serialize_signing_key(&ed25519_sk)),
            "key_hash_base64": B64.encode(ed25519_key_hash_val),
            "key_id_type": "key_hash",
            "expires_at": ed25519_expires
        },
        "expected_base64": B64.encode(&ed25519_token),
        "expected_len": ed25519_token.len(),
    }));

    // Ed25519 signed token with embedded public key
    let ed25519_key_id_pk = KeyIdentifier::PublicKey(public_key.to_vec());
    let ed25519_claims_pk = Claims {
        expires_at: ed25519_expires,
        ..Default::default()
    };
    let ed25519_token_pk = sign_ed25519(&seed, &ed25519_claims_pk, ed25519_key_id_pk).unwrap();
    vectors.push(serde_json::json!({
        "name": "signed_ed25519_pubkey",
        "type": "signed_token",
        "input": {
            "algorithm": "ed25519",
            "signing_key_base64": B64.encode(serialize_signing_key(&ed25519_sk)),
            "key_id_type": "public_key",
            "expires_at": ed25519_expires
        },
        "expected_base64": B64.encode(&ed25519_token_pk),
        "expected_len": ed25519_token_pk.len(),
    }));

    // === Key hash vectors ===
    vectors.push(serde_json::json!({
        "name": "key_hash_hmac",
        "type": "key_hash",
        "input_base64": B64.encode(hmac_key),
        "expected_base64": B64.encode(hmac_key_hash)
    }));

    vectors.push(serde_json::json!({
        "name": "key_hash_ed25519_pubkey",
        "type": "key_hash",
        "input_base64": B64.encode(&public_key),
        "expected_base64": B64.encode(ed25519_key_hash_val)
    }));

    let output = serde_json::json!({
        "description": "Protoken wire format test vectors (canonical proto3). All binary data is URL-safe base64 (no padding). Any change in these values indicates a wire format regression.",
        "generated_by": "gen_test_vectors",
        "vectors": vectors
    });

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

/// Returns a hardcoded Ed25519 key (seed, public_key) for reproducible test vectors.
fn fixed_ed25519_key() -> (Vec<u8>, Vec<u8>) {
    let seed =
        hex::decode("3cc4bec961d0bf428a58a323812992ea8cd803814871ee8b2477dc3362ac4619").unwrap();
    let public_key =
        hex::decode("b5409fbc174d2372837326a22174a912eb5a2410d344d44139cf953bd7db99e8").unwrap();
    (seed, public_key)
}
