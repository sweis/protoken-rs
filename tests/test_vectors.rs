//! Regression tests that verify serialization against stored test vectors.
//! If any test here fails, it means the wire format has changed.

use protoken::serialize::{deserialize_payload, deserialize_signed_token, serialize_payload};
use protoken::sign::{compute_key_hash, sign_ed25519, sign_hmac};
use protoken::types::*;
use protoken::verify::{verify_ed25519, verify_hmac};

use ring::signature::{Ed25519KeyPair, KeyPair};

/// Load test vectors from testdata/v0_vectors.json.
fn load_vectors() -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/v0_vectors.json");
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
            key_identifier: KeyIdentifier::KeyHash([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
        },
        claims: Claims { expires_at: 1700000000, ..Default::default() },
    };

    let bytes = serialize_payload(&payload);
    assert_eq!(
        hex::encode(&bytes),
        v["expected_hex"].as_str().unwrap(),
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
        claims: Claims { expires_at: 1800000000, ..Default::default() },
    };

    let bytes = serialize_payload(&payload);
    assert_eq!(
        hex::encode(&bytes),
        v["expected_hex"].as_str().unwrap(),
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
        claims: Claims { expires_at: 1900000000, ..Default::default() },
    };

    let bytes = serialize_payload(&payload);
    assert_eq!(
        hex::encode(&bytes),
        v["expected_hex"].as_str().unwrap(),
        "payload_ed25519_pubkey wire format mismatch"
    );
    assert_eq!(bytes.len(), 43);
}

#[test]
fn test_vector_payload_zeros() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "payload_hmac_zeros");

    let payload = Payload {
        metadata: Metadata {
            version: Version::V0,
            algorithm: Algorithm::HmacSha256,
            key_identifier: KeyIdentifier::KeyHash([0x00; 8]),
        },
        claims: Claims { expires_at: 0, ..Default::default() },
    };

    let bytes = serialize_payload(&payload);
    assert_eq!(
        hex::encode(&bytes),
        v["expected_hex"].as_str().unwrap(),
        "payload_hmac_zeros wire format mismatch"
    );
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
        claims: Claims { expires_at: u64::MAX, ..Default::default() },
    };

    let bytes = serialize_payload(&payload);
    assert_eq!(
        hex::encode(&bytes),
        v["expected_hex"].as_str().unwrap(),
        "payload_hmac_max wire format mismatch"
    );
}

// === Signed token vectors ===

#[test]
fn test_vector_signed_hmac() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "signed_hmac");

    let key = b"protoken-test-vector-key-do-not-use-in-production!!";
    let expires_at = 1700000000u64;
    let token_bytes = sign_hmac(key, expires_at);

    assert_eq!(
        hex::encode(&token_bytes),
        v["expected_hex"].as_str().unwrap(),
        "signed_hmac wire format mismatch"
    );
    assert_eq!(token_bytes.len(), v["expected_len"].as_u64().unwrap() as usize);

    // Verify the token is valid
    let verified = verify_hmac(key, &token_bytes, expires_at).unwrap();
    assert_eq!(verified.claims.expires_at, expires_at);

    // Verify deserialization splits correctly
    let token = deserialize_signed_token(&token_bytes).unwrap();
    assert_eq!(token.payload_bytes.len(), v["payload_len"].as_u64().unwrap() as usize);
    assert_eq!(token.signature.len(), v["signature_len"].as_u64().unwrap() as usize);
}

#[test]
fn test_vector_signed_ed25519_keyhash() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "signed_ed25519_keyhash");

    let pkcs8 = hex::decode(v["input"]["private_key_pkcs8_hex"].as_str().unwrap()).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(&pkcs8).unwrap();
    let public_key = key_pair.public_key().as_ref();

    let expires_at = 1800000000u64;
    let key_hash = compute_key_hash(public_key);
    let key_id = KeyIdentifier::KeyHash(key_hash);
    let token_bytes = sign_ed25519(&pkcs8, expires_at, key_id).unwrap();

    assert_eq!(
        hex::encode(&token_bytes),
        v["expected_hex"].as_str().unwrap(),
        "signed_ed25519_keyhash wire format mismatch"
    );

    // Verify the token
    let verified = verify_ed25519(public_key, &token_bytes, expires_at).unwrap();
    assert_eq!(verified.claims.expires_at, expires_at);

    // Verify deserialization splits correctly
    let token = deserialize_signed_token(&token_bytes).unwrap();
    assert_eq!(token.payload_bytes.len(), 19);
    assert_eq!(token.signature.len(), 64);
}

#[test]
fn test_vector_signed_ed25519_pubkey() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "signed_ed25519_pubkey");

    let pkcs8 = hex::decode(v["input"]["private_key_pkcs8_hex"].as_str().unwrap()).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(&pkcs8).unwrap();
    let public_key = key_pair.public_key().as_ref();

    let expires_at = 1800000000u64;
    let key_id = KeyIdentifier::PublicKey(public_key.to_vec());
    let token_bytes = sign_ed25519(&pkcs8, expires_at, key_id).unwrap();

    assert_eq!(
        hex::encode(&token_bytes),
        v["expected_hex"].as_str().unwrap(),
        "signed_ed25519_pubkey wire format mismatch"
    );

    // Verify the token
    let verified = verify_ed25519(public_key, &token_bytes, expires_at).unwrap();
    assert_eq!(verified.claims.expires_at, expires_at);

    let token = deserialize_signed_token(&token_bytes).unwrap();
    assert_eq!(token.payload_bytes.len(), 43);
    assert_eq!(token.signature.len(), 64);
}

// === Key hash vectors ===

#[test]
fn test_vector_key_hash_hmac() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "key_hash_hmac");

    let input = hex::decode(v["input_hex"].as_str().unwrap()).unwrap();
    let hash = compute_key_hash(&input);

    assert_eq!(
        hex::encode(hash),
        v["expected_hex"].as_str().unwrap(),
        "key_hash_hmac mismatch"
    );
}

#[test]
fn test_vector_key_hash_ed25519() {
    let vectors = load_vectors();
    let v = find_vector(&vectors, "key_hash_ed25519_pubkey");

    let input = hex::decode(v["input_hex"].as_str().unwrap()).unwrap();
    let hash = compute_key_hash(&input);

    assert_eq!(
        hex::encode(hash),
        v["expected_hex"].as_str().unwrap(),
        "key_hash_ed25519_pubkey mismatch"
    );
}

// === Cross-language interop: verify from raw hex ===
// These tests parse the expected_hex directly (not produced by our code)
// to verify the deserializer matches the stored vectors.

#[test]
fn test_vector_deserialize_from_stored_hex() {
    let vectors = load_vectors();

    // Verify every payload vector can be deserialized from stored hex
    for name in &[
        "payload_hmac_keyhash",
        "payload_ed25519_keyhash",
        "payload_ed25519_pubkey",
        "payload_hmac_zeros",
        "payload_hmac_max",
    ] {
        let v = find_vector(&vectors, name);
        let bytes = hex::decode(v["expected_hex"].as_str().unwrap()).unwrap();
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
fn test_vector_deserialize_signed_from_stored_hex() {
    let vectors = load_vectors();

    for name in &[
        "signed_hmac",
        "signed_ed25519_keyhash",
        "signed_ed25519_pubkey",
    ] {
        let v = find_vector(&vectors, name);
        let bytes = hex::decode(v["expected_hex"].as_str().unwrap()).unwrap();
        let token = deserialize_signed_token(&bytes)
            .unwrap_or_else(|e| panic!("failed to deserialize {name}: {e}"));

        assert_eq!(
            token.payload_bytes.len(),
            v["payload_len"].as_u64().unwrap() as usize,
            "{name}: payload length mismatch"
        );
        assert_eq!(
            token.signature.len(),
            v["signature_len"].as_u64().unwrap() as usize,
            "{name}: signature length mismatch"
        );
    }
}
