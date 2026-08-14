#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Regression tests against testdata/vectors.json. A failure here means the
//! wire format has changed. Regenerate with `cargo run --example gen_test_vectors`.

use base64::Engine as _;
use serde::Deserialize;

use protoken::serialize::{
    deserialize_claims, deserialize_signed_token, serialize_claims, serialize_signed_token,
};
use protoken::sign::compute_key_hash;
use protoken::{Claims, KeyIdType, SigningKey};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[derive(Deserialize)]
struct VectorFile {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Vector {
    Claims {
        name: String,
        input: Claims,
        expected_base64: String,
        expected_len: usize,
    },
    SignedToken {
        name: String,
        input: SignedInput,
        expected_base64: String,
        expected_len: usize,
    },
    KeyHash {
        name: String,
        input_base64: String,
        expected_base64: String,
    },
}

#[derive(Deserialize)]
struct SignedInput {
    signing_key_base64: String,
    key_hash_base64: String,
    key_id_type: KeyIdType,
    expires_at: u64,
}

fn load_vectors() -> Vec<Vector> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/vectors.json");
    let data = std::fs::read_to_string(path).expect("failed to read test vectors file");
    serde_json::from_str::<VectorFile>(&data)
        .expect("failed to parse test vectors JSON")
        .vectors
}

fn decode(b64: &str) -> Vec<u8> {
    B64.decode(b64).expect("vector contains invalid base64")
}

#[test]
fn test_vector_file_covers_every_vector_type() {
    let vectors = load_vectors();
    let claims = vectors
        .iter()
        .filter(|v| matches!(v, Vector::Claims { .. }))
        .count();
    let signed = vectors
        .iter()
        .filter(|v| matches!(v, Vector::SignedToken { .. }))
        .count();
    let hashes = vectors
        .iter()
        .filter(|v| matches!(v, Vector::KeyHash { .. }))
        .count();
    assert_eq!((claims, signed, hashes), (4, 3, 2));
}

#[test]
fn test_claims_vectors_serialize_and_roundtrip() {
    for vector in load_vectors() {
        let Vector::Claims {
            name,
            input,
            expected_base64,
            expected_len,
        } = vector
        else {
            continue;
        };
        let bytes = serialize_claims(&input);
        assert_eq!(
            B64.encode(&bytes),
            expected_base64,
            "{name}: wire format mismatch"
        );
        assert_eq!(bytes.len(), expected_len, "{name}: length mismatch");
        assert_eq!(
            deserialize_claims(&bytes).unwrap(),
            input,
            "{name}: roundtrip"
        );

        // Decoding the stored bytes and re-encoding must be byte-identical.
        let stored = decode(&expected_base64);
        let decoded = deserialize_claims(&stored).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            serialize_claims(&decoded),
            stored,
            "{name}: re-encode of stored bytes"
        );
    }
}

#[test]
fn test_signed_token_vectors_resign_and_verify() {
    for vector in load_vectors() {
        let Vector::SignedToken {
            name,
            input,
            expected_base64,
            expected_len,
        } = vector
        else {
            continue;
        };
        let key = SigningKey::from_bytes(&decode(&input.signing_key_base64))
            .unwrap_or_else(|e| panic!("{name}: bad signing key: {e}"));
        let claims = Claims {
            expires_at: input.expires_at,
            ..Default::default()
        };

        // Signing is deterministic for every algorithm, so re-signing must
        // reproduce the stored token exactly.
        let token = key.sign_with_key_id(&claims, input.key_id_type).unwrap();
        assert_eq!(
            B64.encode(&token),
            expected_base64,
            "{name}: wire format mismatch"
        );
        assert_eq!(token.len(), expected_len, "{name}: length mismatch");

        let key_hash = key.key_identifier(KeyIdType::KeyHash).unwrap();
        assert_eq!(
            B64.encode(key_hash.as_bytes()),
            input.key_hash_base64,
            "{name}: key hash"
        );

        let verified = key.verify(&token, input.expires_at).unwrap();
        assert_eq!(verified.claims, claims, "{name}: claims");
        assert_eq!(
            verified.key_identifier.key_id_type(),
            input.key_id_type,
            "{name}: id type"
        );

        // Decoding the stored bytes and re-encoding must be byte-identical.
        let stored = decode(&expected_base64);
        let decoded = deserialize_signed_token(&stored).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            serialize_signed_token(&decoded),
            stored,
            "{name}: re-encode of stored bytes"
        );
    }
}

#[test]
fn test_key_hash_vectors() {
    for vector in load_vectors() {
        let Vector::KeyHash {
            name,
            input_base64,
            expected_base64,
        } = vector
        else {
            continue;
        };
        let hash = compute_key_hash(&decode(&input_base64));
        assert_eq!(
            B64.encode(hash),
            expected_base64,
            "{name}: key hash mismatch"
        );
    }
}
