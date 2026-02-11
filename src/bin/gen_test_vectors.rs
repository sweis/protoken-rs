//! Generates test vectors for protoken wire format regression testing.
//! Run with: cargo run --bin gen_test_vectors

use ring::signature::{Ed25519KeyPair, KeyPair};

use protoken::serialize::serialize_payload;
use protoken::sign::{compute_key_hash, sign_ed25519, sign_hmac};
use protoken::types::*;

fn main() {
    let mut vectors: Vec<serde_json::Value> = Vec::new();

    // === Payload serialization vectors ===

    // Vector 1: HMAC + key_hash, minimal
    let p1 = Payload {
        metadata: Metadata {
            version: Version::V0,
            algorithm: Algorithm::HmacSha256,
            key_identifier: KeyIdentifier::KeyHash([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
        },
        claims: Claims { expires_at: 1700000000, ..Default::default() },
    };
    vectors.push(serde_json::json!({
        "name": "payload_hmac_keyhash",
        "type": "payload",
        "input": {
            "version": 0,
            "algorithm": 1,
            "key_id_type": 1,
            "key_id_hex": "0102030405060708",
            "expires_at": 1700000000u64
        },
        "expected_hex": hex::encode(serialize_payload(&p1)),
        "expected_len": serialize_payload(&p1).len()
    }));

    // Vector 2: Ed25519 + key_hash
    let p2 = Payload {
        metadata: Metadata {
            version: Version::V0,
            algorithm: Algorithm::Ed25519,
            key_identifier: KeyIdentifier::KeyHash([0xaa; 8]),
        },
        claims: Claims { expires_at: 1800000000, ..Default::default() },
    };
    vectors.push(serde_json::json!({
        "name": "payload_ed25519_keyhash",
        "type": "payload",
        "input": {
            "version": 0,
            "algorithm": 2,
            "key_id_type": 1,
            "key_id_hex": "aaaaaaaaaaaaaaaa",
            "expires_at": 1800000000u64
        },
        "expected_hex": hex::encode(serialize_payload(&p2)),
        "expected_len": serialize_payload(&p2).len()
    }));

    // Vector 3: Ed25519 + embedded public key (32 bytes of 0xbb)
    let fake_pk = vec![0xbb; 32];
    let p3 = Payload {
        metadata: Metadata {
            version: Version::V0,
            algorithm: Algorithm::Ed25519,
            key_identifier: KeyIdentifier::PublicKey(fake_pk.clone()),
        },
        claims: Claims { expires_at: 1900000000, ..Default::default() },
    };
    vectors.push(serde_json::json!({
        "name": "payload_ed25519_pubkey",
        "type": "payload",
        "input": {
            "version": 0,
            "algorithm": 2,
            "key_id_type": 2,
            "key_id_hex": hex::encode(&fake_pk),
            "expires_at": 1900000000u64
        },
        "expected_hex": hex::encode(serialize_payload(&p3)),
        "expected_len": serialize_payload(&p3).len()
    }));

    // Vector 4: HMAC + key_hash, expires_at = 0 (edge case)
    let p4 = Payload {
        metadata: Metadata {
            version: Version::V0,
            algorithm: Algorithm::HmacSha256,
            key_identifier: KeyIdentifier::KeyHash([0x00; 8]),
        },
        claims: Claims { expires_at: 0, ..Default::default() },
    };
    vectors.push(serde_json::json!({
        "name": "payload_hmac_zeros",
        "type": "payload",
        "input": {
            "version": 0,
            "algorithm": 1,
            "key_id_type": 1,
            "key_id_hex": "0000000000000000",
            "expires_at": 0u64
        },
        "expected_hex": hex::encode(serialize_payload(&p4)),
        "expected_len": serialize_payload(&p4).len()
    }));

    // Vector 5: HMAC + key_hash, expires_at = u64::MAX (edge case)
    let p5 = Payload {
        metadata: Metadata {
            version: Version::V0,
            algorithm: Algorithm::HmacSha256,
            key_identifier: KeyIdentifier::KeyHash([0xff; 8]),
        },
        claims: Claims { expires_at: u64::MAX, ..Default::default() },
    };
    vectors.push(serde_json::json!({
        "name": "payload_hmac_max",
        "type": "payload",
        "input": {
            "version": 0,
            "algorithm": 1,
            "key_id_type": 1,
            "key_id_hex": "ffffffffffffffff",
            "expires_at": 18446744073709551615u64
        },
        "expected_hex": hex::encode(serialize_payload(&p5)),
        "expected_len": serialize_payload(&p5).len()
    }));

    // === HMAC signed token vectors ===

    // Use a well-known key so anyone can reproduce
    let hmac_key = b"protoken-test-vector-key-do-not-use-in-production!!";
    let hmac_key_hash = compute_key_hash(hmac_key);

    // Vector 6: HMAC signed token
    let hmac_expires = 1700000000u64;
    let hmac_token = sign_hmac(hmac_key, hmac_expires);
    vectors.push(serde_json::json!({
        "name": "signed_hmac",
        "type": "signed_token",
        "input": {
            "algorithm": "hmac",
            "key_hex": hex::encode(hmac_key),
            "key_hash_hex": hex::encode(hmac_key_hash),
            "expires_at": hmac_expires
        },
        "expected_hex": hex::encode(&hmac_token),
        "expected_len": hmac_token.len(),
        "payload_len": 19,
        "signature_len": 32
    }));

    // === Ed25519 signed token vectors ===
    // We need a fixed key. Generate one and embed the PKCS#8 bytes.
    // To make this reproducible, we use a hardcoded PKCS#8 key.
    let pkcs8_hex = generate_fixed_ed25519_key();
    let pkcs8_bytes = hex::decode(&pkcs8_hex).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(&pkcs8_bytes).unwrap();
    let public_key = key_pair.public_key().as_ref();
    let ed25519_key_hash = compute_key_hash(public_key);

    // Vector 7: Ed25519 signed token with key_hash
    let ed25519_expires = 1800000000u64;
    let ed25519_key_id = KeyIdentifier::KeyHash(ed25519_key_hash);
    let ed25519_token = sign_ed25519(&pkcs8_bytes, ed25519_expires, ed25519_key_id).unwrap();
    vectors.push(serde_json::json!({
        "name": "signed_ed25519_keyhash",
        "type": "signed_token",
        "input": {
            "algorithm": "ed25519",
            "private_key_pkcs8_hex": pkcs8_hex,
            "public_key_hex": hex::encode(public_key),
            "key_hash_hex": hex::encode(ed25519_key_hash),
            "key_id_type": "key_hash",
            "expires_at": ed25519_expires
        },
        "expected_hex": hex::encode(&ed25519_token),
        "expected_len": ed25519_token.len(),
        "payload_len": 19,
        "signature_len": 64
    }));

    // Vector 8: Ed25519 signed token with embedded public key
    let ed25519_key_id_pk = KeyIdentifier::PublicKey(public_key.to_vec());
    let ed25519_token_pk = sign_ed25519(&pkcs8_bytes, ed25519_expires, ed25519_key_id_pk).unwrap();
    vectors.push(serde_json::json!({
        "name": "signed_ed25519_pubkey",
        "type": "signed_token",
        "input": {
            "algorithm": "ed25519",
            "private_key_pkcs8_hex": pkcs8_hex,
            "public_key_hex": hex::encode(public_key),
            "key_id_type": "public_key",
            "expires_at": ed25519_expires
        },
        "expected_hex": hex::encode(&ed25519_token_pk),
        "expected_len": ed25519_token_pk.len(),
        "payload_len": 43,
        "signature_len": 64
    }));

    // === Key hash vectors ===
    vectors.push(serde_json::json!({
        "name": "key_hash_hmac",
        "type": "key_hash",
        "input_hex": hex::encode(hmac_key),
        "expected_hex": hex::encode(hmac_key_hash)
    }));

    vectors.push(serde_json::json!({
        "name": "key_hash_ed25519_pubkey",
        "type": "key_hash",
        "input_hex": hex::encode(public_key),
        "expected_hex": hex::encode(ed25519_key_hash)
    }));

    let output = serde_json::json!({
        "format_version": "v0",
        "description": "Protoken v0 wire format test vectors. Any change in these values indicates a wire format regression.",
        "generated_by": "gen_test_vectors",
        "vectors": vectors
    });

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

/// Returns a hardcoded Ed25519 PKCS#8 key for reproducible test vectors.
fn generate_fixed_ed25519_key() -> String {
    // Generated once; frozen for test vector stability.
    "3051020101300506032b6570042204203cc4bec961d0bf428a58a323812992ea\
     8cd803814871ee8b2477dc3362ac4619812100b5409fbc174d2372837326a221\
     74a912eb5a2410d344d44139cf953bd7db99e8"
        .to_string()
}
