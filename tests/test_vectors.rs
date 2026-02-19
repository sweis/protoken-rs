#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Regression tests that verify serialization against stored test vectors.
//! If any test here fails, it means the wire format has changed.

use base64::Engine;

use protoken::keys::deserialize_signing_key;
use protoken::serialize::{deserialize_payload, deserialize_signed_token, serialize_payload};
use protoken::sign::{compute_key_hash, sign_ed25519, sign_hmac};
use protoken::types::*;
use protoken::verify::{verify_ed25519, verify_hmac};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Load test vectors from testdata/vectors.json.
fn load_vectors() -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/vectors.json");
    let data = std::fs::read_to_string(path).expect("failed to read test vectors file");
    serde_json::from_str(&data).expect("failed to parse test vectors JSON")
}

/// Find a vector by name.
fn find_vector(vectors: &serde_json::Value, name: &str) -> serde_json::Value {
    vectors["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"].as_str().unwrap() == name)
        .unwrap_or_else(|| panic!("test vector '{name}' not found"))
        .clone()
}

// === Payload serialization vectors ===

#[test]
fn test_vector_payload_hmac_keyhash() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "payload_hmac_keyhash");

    let payload = Payload {
        metadata: Metadata {
            version: Version::V0,
            algorithm: Algorithm::HmacSha256,
            key_identifier: KeyIdentifier::KeyHash([
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            ]),
        },
        claims: Claims {
            expires_at: 1700000000,
            ..Default::default()
        },
    };

    let bytes = serialize_payload(&payload);
    assert_eq!(
        B64.encode(&bytes),
        v["expected_base64"].as_str().unwrap(),
        "payload_hmac_keyhash wire format mismatch"
    );
    assert_eq!(bytes.len(), v["expected_len"].as_u64().unwrap() as usize);

    // Verify roundtrip
    let decoded = deserialize_payload(&bytes).unwrap();
    assert_eq!(decoded, payload);
}

#[test]
fn test_vector_payload_ed25519_keyhash() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "payload_ed25519_keyhash");

    let payload = Payload {
        metadata: Metadata {
            version: Version::V0,
            algorithm: Algorithm::Ed25519,
            key_identifier: KeyIdentifier::KeyHash([0xaa; 8]),
        },
        claims: Claims {
            expires_at: 1800000000,
            ..Default::default()
        },
    };

    let bytes = serialize_payload(&payload);
    assert_eq!(
        B64.encode(&bytes),
        v["expected_base64"].as_str().unwrap(),
        "payload_ed25519_keyhash wire format mismatch"
    );
}

#[test]
fn test_vector_payload_ed25519_pubkey() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "payload_ed25519_pubkey");

    let payload = Payload {
        metadata: Metadata {
            version: Version::V0,
            algorithm: Algorithm::Ed25519,
            key_identifier: KeyIdentifier::PublicKey(vec![0xbb; 32]),
        },
        claims: Claims {
            expires_at: 1900000000,
            ..Default::default()
        },
    };

    let bytes = serialize_payload(&payload);
    assert_eq!(
        B64.encode(&bytes),
        v["expected_base64"].as_str().unwrap(),
        "payload_ed25519_pubkey wire format mismatch"
    );
    assert_eq!(bytes.len(), v["expected_len"].as_u64().unwrap() as usize);
}

#[test]
fn test_vector_payload_full_claims() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "payload_hmac_full_claims");

    let payload = Payload {
        metadata: Metadata {
            version: Version::V0,
            algorithm: Algorithm::HmacSha256,
            key_identifier: KeyIdentifier::KeyHash([0x11; 8]),
        },
        claims: Claims {
            expires_at: 1700000000,
            not_before: 1699990000,
            issued_at: 1699990000,
            subject: "user:alice".into(),
            audience: "api.example.com".into(),
            ..Default::default()
        },
    };

    let bytes = serialize_payload(&payload);
    assert_eq!(
        B64.encode(&bytes),
        v["expected_base64"].as_str().unwrap(),
        "payload_hmac_full_claims wire format mismatch"
    );
    assert_eq!(bytes.len(), v["expected_len"].as_u64().unwrap() as usize);

    let decoded = deserialize_payload(&bytes).unwrap();
    assert_eq!(decoded, payload);
}

#[test]
fn test_vector_payload_max() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "payload_hmac_max");

    let payload = Payload {
        metadata: Metadata {
            version: Version::V0,
            algorithm: Algorithm::HmacSha256,
            key_identifier: KeyIdentifier::KeyHash([0xff; 8]),
        },
        claims: Claims {
            expires_at: u64::MAX,
            ..Default::default()
        },
    };

    let bytes = serialize_payload(&payload);
    assert_eq!(
        B64.encode(&bytes),
        v["expected_base64"].as_str().unwrap(),
        "payload_hmac_max wire format mismatch"
    );
}

#[test]
fn test_vector_payload_scopes() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "payload_hmac_scopes");

    let payload = Payload {
        metadata: Metadata {
            version: Version::V0,
            algorithm: Algorithm::HmacSha256,
            key_identifier: KeyIdentifier::KeyHash([0x22; 8]),
        },
        claims: Claims {
            expires_at: 1700000000,
            scopes: vec!["admin".into(), "read".into(), "write".into()],
            ..Default::default()
        },
    };

    let bytes = serialize_payload(&payload);
    assert_eq!(
        B64.encode(&bytes),
        v["expected_base64"].as_str().unwrap(),
        "payload_hmac_scopes wire format mismatch"
    );
    assert_eq!(bytes.len(), v["expected_len"].as_u64().unwrap() as usize);

    let decoded = deserialize_payload(&bytes).unwrap();
    assert_eq!(decoded, payload);
}

// === Signed token vectors ===

#[test]
fn test_vector_signed_hmac() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "signed_hmac");

    // Extract key material from stored proto SigningKey
    let sk_bytes = B64
        .decode(v["input"]["signing_key_base64"].as_str().unwrap())
        .unwrap();
    let sk = deserialize_signing_key(&sk_bytes).unwrap();

    let expires_at = 1700000000u64;
    let claims = Claims {
        expires_at,
        ..Default::default()
    };
    let token_bytes = sign_hmac(&sk.secret_key, claims).unwrap();

    assert_eq!(
        B64.encode(&token_bytes),
        v["expected_base64"].as_str().unwrap(),
        "signed_hmac wire format mismatch"
    );
    assert_eq!(
        token_bytes.len(),
        v["expected_len"].as_u64().unwrap() as usize
    );

    // Verify the token is valid
    let verified = verify_hmac(&sk.secret_key, &token_bytes, expires_at).unwrap();
    assert_eq!(verified.claims.expires_at, expires_at);
}

#[test]
fn test_vector_signed_ed25519_keyhash() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "signed_ed25519_keyhash");

    // Extract key material from stored proto SigningKey
    let sk_bytes = B64
        .decode(v["input"]["signing_key_base64"].as_str().unwrap())
        .unwrap();
    let sk = deserialize_signing_key(&sk_bytes).unwrap();

    let expires_at = 1800000000u64;
    let key_hash = compute_key_hash(&sk.public_key);
    let key_id = KeyIdentifier::KeyHash(key_hash);
    let claims = Claims {
        expires_at,
        ..Default::default()
    };
    let token_bytes = sign_ed25519(&sk.secret_key, claims, key_id).unwrap();

    assert_eq!(
        B64.encode(&token_bytes),
        v["expected_base64"].as_str().unwrap(),
        "signed_ed25519_keyhash wire format mismatch"
    );

    // Verify the token
    let verified = verify_ed25519(&sk.public_key, &token_bytes, expires_at).unwrap();
    assert_eq!(verified.claims.expires_at, expires_at);
}

#[test]
fn test_vector_signed_ed25519_pubkey() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "signed_ed25519_pubkey");

    // Extract key material from stored proto SigningKey
    let sk_bytes = B64
        .decode(v["input"]["signing_key_base64"].as_str().unwrap())
        .unwrap();
    let sk = deserialize_signing_key(&sk_bytes).unwrap();

    let expires_at = 1800000000u64;
    let key_id = KeyIdentifier::PublicKey(sk.public_key.clone());
    let claims = Claims {
        expires_at,
        ..Default::default()
    };
    let token_bytes = sign_ed25519(&sk.secret_key, claims, key_id).unwrap();

    assert_eq!(
        B64.encode(&token_bytes),
        v["expected_base64"].as_str().unwrap(),
        "signed_ed25519_pubkey wire format mismatch"
    );

    // Verify the token
    let verified = verify_ed25519(&sk.public_key, &token_bytes, expires_at).unwrap();
    assert_eq!(verified.claims.expires_at, expires_at);
}

// === Key hash vectors ===

#[test]
fn test_vector_key_hash_hmac() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "key_hash_hmac");

    let input = B64.decode(v["input_base64"].as_str().unwrap()).unwrap();
    let hash = compute_key_hash(&input);

    assert_eq!(
        B64.encode(hash),
        v["expected_base64"].as_str().unwrap(),
        "key_hash_hmac mismatch"
    );
}

#[test]
fn test_vector_key_hash_ed25519() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "key_hash_ed25519_pubkey");

    let input = B64.decode(v["input_base64"].as_str().unwrap()).unwrap();
    let hash = compute_key_hash(&input);

    assert_eq!(
        B64.encode(hash),
        v["expected_base64"].as_str().unwrap(),
        "key_hash_ed25519_pubkey mismatch"
    );
}

// === Cross-language interop: verify from raw base64 ===

#[test]
fn test_vector_deserialize_from_stored_base64() {
    let vectors = load_vectors();

    // Verify every payload vector can be deserialized from stored base64
    for name in &[
        "payload_hmac_keyhash",
        "payload_ed25519_keyhash",
        "payload_ed25519_pubkey",
        "payload_hmac_full_claims",
        "payload_hmac_max",
        "payload_hmac_scopes",
    ] {
        let v = find_vector(&vectors, name);
        let bytes = B64.decode(v["expected_base64"].as_str().unwrap()).unwrap();
        let payload = deserialize_payload(&bytes)
            .unwrap_or_else(|e| panic!("failed to deserialize {name}: {e}"));

        // Re-serialize and verify roundtrip is exact
        let reserialized = serialize_payload(&payload);
        assert_eq!(
            bytes, reserialized,
            "{name}: roundtrip through deserialize->serialize must produce identical bytes"
        );
    }
}

#[test]
fn test_vector_deserialize_signed_from_stored_base64() {
    let vectors = load_vectors();

    for name in &[
        "signed_hmac",
        "signed_ed25519_keyhash",
        "signed_ed25519_pubkey",
    ] {
        let v = find_vector(&vectors, name);
        let bytes = B64.decode(v["expected_base64"].as_str().unwrap()).unwrap();
        let _token = deserialize_signed_token(&bytes)
            .unwrap_or_else(|e| panic!("failed to deserialize {name}: {e}"));
    }
}
