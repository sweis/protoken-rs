#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Generates long-lived reference keys and tokens for regression testing.
//! Tokens expire in 2036. Run with: cargo run --bin gen_reference_vectors

use base64::Engine;

use protoken::keys::{
    extract_verifying_key, serialize_signing_key, serialize_verifying_key, SigningKey,
};
use protoken::sign::{
    compute_key_hash, generate_mldsa44_key, mldsa44_key_hash, sign_ed25519, sign_hmac, sign_mldsa44,
};
use protoken::types::{Algorithm, Claims, KeyIdentifier};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Fixed timestamps: issued 2025-02-19, expires 2036-02-19 (~11 years).
const ISSUED_AT: u64 = 1739923200;
const NOT_BEFORE: u64 = 1739923200;
const EXPIRES_AT: u64 = 2087078400; // 2036-02-19 00:00:00 UTC

fn reference_claims() -> Claims {
    Claims {
        expires_at: EXPIRES_AT,
        not_before: NOT_BEFORE,
        issued_at: ISSUED_AT,
        subject: "ref:test-user".into(),
        audience: "ref:test-service".into(),
        scopes: vec!["read".into(), "write".into()],
    }
}

fn main() {
    let mut vectors: Vec<serde_json::Value> = Vec::new();

    // === HMAC-SHA256 ===
    let hmac_key: Vec<u8> = (0x00..=0x1f).collect();
    let claims = reference_claims();
    let hmac_token = sign_hmac(&hmac_key, claims.clone()).unwrap();
    let hmac_sk = SigningKey {
        algorithm: Algorithm::HmacSha256,
        secret_key: hmac_key.clone(),
        public_key: Vec::new(),
    };
    vectors.push(serde_json::json!({
        "name": "hmac_reference",
        "algorithm": "hmac-sha256",
        "signing_key_base64": B64.encode(serialize_signing_key(&hmac_sk)),
        "key_hash_base64": B64.encode(compute_key_hash(&hmac_key)),
        "token_base64": B64.encode(&hmac_token),
        "claims": {
            "expires_at": EXPIRES_AT,
            "not_before": NOT_BEFORE,
            "issued_at": ISSUED_AT,
            "subject": "ref:test-user",
            "audience": "ref:test-service",
            "scopes": ["read", "write"]
        }
    }));

    // === Ed25519 ===
    let ed25519_seed = vec![
        0x3c, 0xc4, 0xbe, 0xc9, 0x61, 0xd0, 0xbf, 0x42, 0x8a, 0x58, 0xa3, 0x23, 0x81, 0x29, 0x92,
        0xea, 0x8c, 0xd8, 0x03, 0x81, 0x48, 0x71, 0xee, 0x8b, 0x24, 0x77, 0xdc, 0x33, 0x62, 0xac,
        0x46, 0x19,
    ];
    let ed25519_pk = vec![
        0xb5, 0x40, 0x9f, 0xbc, 0x17, 0x4d, 0x23, 0x72, 0x83, 0x73, 0x26, 0xa2, 0x21, 0x74, 0xa9,
        0x12, 0xeb, 0x5a, 0x24, 0x10, 0xd3, 0x44, 0xd4, 0x41, 0x39, 0xcf, 0x95, 0x3b, 0xd7, 0xdb,
        0x99, 0xe8,
    ];
    let ed25519_key_hash = compute_key_hash(&ed25519_pk);
    let claims = reference_claims();
    let ed25519_token = sign_ed25519(
        &ed25519_seed,
        claims.clone(),
        KeyIdentifier::KeyHash(ed25519_key_hash),
    )
    .unwrap();
    let ed25519_sk = SigningKey {
        algorithm: Algorithm::Ed25519,
        secret_key: ed25519_seed,
        public_key: ed25519_pk.clone(),
    };
    let ed25519_vk = extract_verifying_key(&ed25519_sk).unwrap();
    vectors.push(serde_json::json!({
        "name": "ed25519_reference",
        "algorithm": "ed25519",
        "signing_key_base64": B64.encode(serialize_signing_key(&ed25519_sk)),
        "verifying_key_base64": B64.encode(serialize_verifying_key(&ed25519_vk)),
        "key_hash_base64": B64.encode(ed25519_key_hash),
        "token_base64": B64.encode(&ed25519_token),
        "claims": {
            "expires_at": EXPIRES_AT,
            "not_before": NOT_BEFORE,
            "issued_at": ISSUED_AT,
            "subject": "ref:test-user",
            "audience": "ref:test-service",
            "scopes": ["read", "write"]
        }
    }));

    // === ML-DSA-44 ===
    // ML-DSA-44 signing is non-deterministic, so we generate and freeze the token.
    let (mldsa_sk_bytes, mldsa_pk_bytes) = generate_mldsa44_key().unwrap();
    let mldsa_key_hash = mldsa44_key_hash(&mldsa_pk_bytes).unwrap();
    let claims = reference_claims();
    let mldsa_token = sign_mldsa44(&mldsa_sk_bytes, claims, mldsa_key_hash).unwrap();
    let mldsa_sk = SigningKey {
        algorithm: Algorithm::MlDsa44,
        secret_key: mldsa_sk_bytes,
        public_key: mldsa_pk_bytes.clone(),
    };
    let mldsa_vk = extract_verifying_key(&mldsa_sk).unwrap();
    vectors.push(serde_json::json!({
        "name": "mldsa44_reference",
        "algorithm": "ml-dsa-44",
        "signing_key_base64": B64.encode(serialize_signing_key(&mldsa_sk)),
        "verifying_key_base64": B64.encode(serialize_verifying_key(&mldsa_vk)),
        "key_hash_base64": B64.encode(compute_key_hash(&mldsa_pk_bytes)),
        "token_base64": B64.encode(&mldsa_token),
        "claims": {
            "expires_at": EXPIRES_AT,
            "not_before": NOT_BEFORE,
            "issued_at": ISSUED_AT,
            "subject": "ref:test-user",
            "audience": "ref:test-service",
            "scopes": ["read", "write"]
        }
    }));

    let output = serde_json::json!({
        "description": "Long-lived protoken reference vectors (expire 2036). Any change in HMAC/Ed25519 token_base64 indicates a wire format regression. ML-DSA-44 tokens are non-deterministic but must still verify.",
        "generated_by": "gen_reference_vectors",
        "vectors": vectors
    });

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}
