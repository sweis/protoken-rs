#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Generates long-lived reference keys and tokens for regression testing.
//!
//! All keys are fixed. FN-DSA, the one randomized algorithm, is driven by a
//! fixed random stream here. So this program is reproducible: its output must match
//! testdata/reference_vectors.json byte for byte unless the wire format
//! changes. Run with: cargo run --example gen_reference_vectors

#[path = "common/fn_dsa_fixed.rs"]
mod fn_dsa_fixed;

use base64::Engine as _;

use protoken::serialize::{append_signature, serialize_claims, serialize_signing_input};
use protoken::types::Version;
use protoken::{Algorithm, Claims, KeyIdType, SigningKey, Zeroizing};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Issued 2025-02-19, expires 2036-02-19 00:00:00 UTC.
const ISSUED_AT: u64 = 1739923200;
const EXPIRES_AT: u64 = 2087078400;

/// The SLH-DSA keys are the first NIST ACVP keyGen case of each parameter set.
const KEYS: [(Algorithm, &str); 7] = [
    (
        Algorithm::HmacSha384,
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
         202122232425262728292a2b2c2d2e2f",
    ),
    (
        Algorithm::MlDsa44,
        "7003d5fd5e928c6468134be85db0babd26d455dc9b413dff84758542c2afcc7b",
    ),
    (
        Algorithm::MlDsa65,
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    ),
    (
        Algorithm::MlDsa87,
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
    ),
    (
        Algorithm::SlhDsaSha2_128s,
        "173d04c938c1c36bf289c3c022d04b1463ae23c41aa546da589774ac20b745c4\
         0d794777914c99766827f0f09ca972be0162c10219d422adba1359e6aa65299c",
    ),
    (
        Algorithm::SlhDsaSha2_192s,
        "040266529c1864088925506c20a624a2b6d50cd77c1c6f0d2841150ae8157512\
         ef34a343ffea77ff7d9e814b45a8b41464462665f4202886206a8f632267186c\
         a6a1cad08a2b9a862c6a7bc4ac4aaa84accef60d529f0311274f205e8da642c9",
    ),
    (
        Algorithm::SlhDsaSha2_256s,
        "fcbf36a9807b30697be063a5105e091b412a391dd39e1326eba23cbd4096ca77\
         ef4121c08dd71be913572f1f91e57d0acbcd5cec28539ac275832bbaa6c11081\
         a0b4f5549ebcadb951dc2e512c76b0620d8fb8100b4ee886ef8784780d52a254\
         3e57ab494d47068ffee4b8244aad6f19cdf94a2172bd134a15a6b5f298d5a80e",
    ),
];

const FN_DSA: [Algorithm; 2] = [Algorithm::FnDsa512, Algorithm::FnDsa1024];

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

fn vector(algorithm: Algorithm, secret_key: Vec<u8>) -> serde_json::Value {
    let key = SigningKey::from_secret_key(algorithm, Zeroizing::new(secret_key)).unwrap();
    let claims = reference_claims();
    let key_hash = key.key_identifier(KeyIdType::KeyHash).unwrap();
    let token = if FN_DSA.contains(&algorithm) {
        let payload = serialize_claims(&claims);
        let input = serialize_signing_input(Version::V0, algorithm, &key_hash, &payload);
        let signature = fn_dsa_fixed::sign(key.secret_key(), b"protoken", &input).unwrap();
        append_signature(input, &signature)
    } else {
        key.sign(&claims).unwrap()
    };

    let mut v = serde_json::json!({
        "name": format!("{algorithm}_reference"),
        "algorithm": algorithm,
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
    let stored = KEYS.map(|(algorithm, hex)| vector(algorithm, hex::decode(hex).unwrap()));
    let generated = FN_DSA.map(|a| vector(a, fn_dsa_fixed::secret_key(a, b"reference")));
    let vectors = [&stored[..], &generated[..]].concat();

    let output = serde_json::json!({
        "description": "Long-lived protoken reference vectors (expire 2036). Any change in token_base64 indicates a wire format regression. FN-DSA signing is randomized, so its tokens can be verified but not reproduced through the library.",
        "generated_by": "gen_reference_vectors",
        "vectors": vectors
    });

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}
