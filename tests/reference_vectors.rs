#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Regression tests against long-lived reference vectors (expire 2036).
//! All three algorithms sign deterministically (ML-DSA-44 uses the FIPS 204
//! deterministic variant with an empty context), so re-signing the stored
//! claims with the stored key must reproduce token_base64 exactly.

use base64::Engine;
use protoken::keys::{deserialize_signing_key, deserialize_verifying_key};
use protoken::serialize::{deserialize_claims, deserialize_signed_token};
use protoken::sign::{compute_key_hash, sign_ed25519, sign_hmac, sign_mldsa44};
use protoken::types::{Claims, KeyIdentifier};
use protoken::verify::{verify_ed25519, verify_hmac, verify_mldsa44};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn load_reference_vectors() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/reference_vectors.json"
    );
    let data = std::fs::read_to_string(path).expect("failed to read reference vectors");
    serde_json::from_str(&data).expect("failed to parse reference vectors")
}

fn find_vector(vectors: &serde_json::Value, name: &str) -> serde_json::Value {
    vectors["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"].as_str().unwrap() == name)
        .unwrap_or_else(|| panic!("reference vector '{name}' not found"))
        .clone()
}

/// A timestamp within the token's validity window (between not_before and expires_at).
const VALID_TIME: u64 = 1900000000;

#[test]
fn test_reference_hmac_exact_match() {
    let vectors = load_reference_vectors();
    let v = find_vector(&vectors, "hmac_reference");

    // Verify token_base64 matches exactly (HMAC is deterministic)
    let token_bytes = B64
        .decode(v["token_base64"].as_str().unwrap())
        .expect("bad base64");

    // Deserialize and check claims
    let token = deserialize_signed_token(&token_bytes).unwrap();
    let claims = deserialize_claims(&token.payload).unwrap();
    assert_eq!(claims.expires_at, 2087078400);
    assert_eq!(claims.subject, "ref:test-user");
    assert_eq!(claims.audience, "ref:test-service");
    assert_eq!(claims.scopes, vec!["read", "write"]);

    // Verify with the stored key
    let sk_bytes = B64
        .decode(v["signing_key_base64"].as_str().unwrap())
        .expect("bad signing key base64");
    let sk = deserialize_signing_key(&sk_bytes).unwrap();
    let verified = verify_hmac(&sk.secret_key, &token_bytes, VALID_TIME).unwrap();
    assert_eq!(verified.claims.subject, "ref:test-user");
}

#[test]
fn test_reference_ed25519_exact_match() {
    let vectors = load_reference_vectors();
    let v = find_vector(&vectors, "ed25519_reference");

    // Ed25519 is deterministic — exact base64 must match
    let token_bytes = B64
        .decode(v["token_base64"].as_str().unwrap())
        .expect("bad base64");

    // Deserialize and check claims
    let token = deserialize_signed_token(&token_bytes).unwrap();
    let claims = deserialize_claims(&token.payload).unwrap();
    assert_eq!(claims.expires_at, 2087078400);
    assert_eq!(claims.subject, "ref:test-user");
    assert_eq!(claims.scopes, vec!["read", "write"]);

    // Verify with the stored verifying key
    let vk_bytes = B64
        .decode(v["verifying_key_base64"].as_str().unwrap())
        .expect("bad verifying key base64");
    let vk = deserialize_verifying_key(&vk_bytes).unwrap();
    let verified = verify_ed25519(&vk.public_key, &token_bytes, VALID_TIME).unwrap();
    assert_eq!(verified.claims.audience, "ref:test-service");
}

#[test]
fn test_reference_mldsa44_verifies() {
    let vectors = load_reference_vectors();
    let v = find_vector(&vectors, "mldsa44_reference");

    // Stored ML-DSA-44 token must verify with the stored key
    let token_bytes = B64
        .decode(v["token_base64"].as_str().unwrap())
        .expect("bad base64");

    // Deserialize and check claims
    let token = deserialize_signed_token(&token_bytes).unwrap();
    let claims = deserialize_claims(&token.payload).unwrap();
    assert_eq!(claims.expires_at, 2087078400);
    assert_eq!(claims.subject, "ref:test-user");

    // Verify with the stored verifying key
    let vk_bytes = B64
        .decode(v["verifying_key_base64"].as_str().unwrap())
        .expect("bad verifying key base64");
    let vk = deserialize_verifying_key(&vk_bytes).unwrap();
    let verified = verify_mldsa44(&vk.public_key, &token_bytes, VALID_TIME).unwrap();
    assert_eq!(verified.claims.scopes, vec!["read", "write"]);
}

#[test]
fn test_reference_all_keys_deserialize() {
    let vectors = load_reference_vectors();
    for v in vectors["vectors"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let sk_bytes = B64
            .decode(v["signing_key_base64"].as_str().unwrap())
            .expect("bad signing key base64");
        let sk = deserialize_signing_key(&sk_bytes)
            .unwrap_or_else(|e| panic!("failed to deserialize signing key for {name}: {e}"));

        if let Some(vk_b64) = v["verifying_key_base64"].as_str() {
            let vk_bytes = B64.decode(vk_b64).expect("bad verifying key base64");
            let _vk = deserialize_verifying_key(&vk_bytes)
                .unwrap_or_else(|e| panic!("failed to deserialize verifying key for {name}: {e}"));
        }

        // Token should deserialize
        let token_bytes = B64
            .decode(v["token_base64"].as_str().unwrap())
            .expect("bad token base64");
        let token = deserialize_signed_token(&token_bytes)
            .unwrap_or_else(|e| panic!("failed to deserialize token for {name}: {e}"));
        let _claims = deserialize_claims(&token.payload)
            .unwrap_or_else(|e| panic!("failed to deserialize claims for {name}: {e}"));

        // Signing key should have non-empty secret_key
        assert!(!sk.secret_key.is_empty(), "{name}: empty secret_key");
    }
}

/// Rebuild the reference claims from the stored vector.
fn claims_from_vector(v: &serde_json::Value) -> Claims {
    let c = &v["claims"];
    Claims {
        expires_at: c["expires_at"].as_u64().unwrap(),
        not_before: c["not_before"].as_u64().unwrap(),
        issued_at: c["issued_at"].as_u64().unwrap(),
        subject: c["subject"].as_str().unwrap().to_string(),
        audience: c["audience"].as_str().unwrap().to_string(),
        scopes: c["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect(),
    }
}

/// Re-sign the stored claims with the stored key; the result must reproduce
/// token_base64 byte for byte. This pins the deterministic sign path, not
/// just decoder compatibility.
#[test]
fn test_reference_resign_reproduces_tokens() {
    let vectors = load_reference_vectors();
    for name in ["hmac_reference", "ed25519_reference", "mldsa44_reference"] {
        let v = find_vector(&vectors, name);
        let claims = claims_from_vector(&v);
        let sk_bytes = B64
            .decode(v["signing_key_base64"].as_str().unwrap())
            .unwrap();
        let sk = deserialize_signing_key(&sk_bytes).unwrap();

        let token_bytes = match name {
            "hmac_reference" => sign_hmac(&sk.secret_key, &claims).unwrap(),
            "ed25519_reference" => sign_ed25519(
                &sk.secret_key,
                &claims,
                KeyIdentifier::KeyHash(compute_key_hash(&sk.public_key)),
            )
            .unwrap(),
            _ => sign_mldsa44(
                &sk.secret_key,
                &claims,
                KeyIdentifier::KeyHash(compute_key_hash(&sk.public_key)),
            )
            .unwrap(),
        };

        assert_eq!(
            B64.encode(&token_bytes),
            v["token_base64"].as_str().unwrap(),
            "{name}: re-signing must reproduce the stored token exactly"
        );
    }
}
