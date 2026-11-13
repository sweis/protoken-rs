#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Writes the reference keys, tokens, and payloads as raw files to seed a
//! fuzz corpus. Without seeds the fuzzers cannot reach the "accepted" paths
//! for asymmetric keys, since a signing key is only accepted when its stored
//! public key matches the one derived from the seed.
//!
//! Usage: cargo run --example gen_fuzz_seeds <output-dir>
//! (`make fuzz` runs this for the target's corpus directory.)

use std::fs;
use std::path::Path;

use base64::Engine as _;
use serde::Deserialize;

use protoken::serialize::deserialize_signed_token;
use protoken::VerifyingKey;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[derive(Deserialize)]
struct VectorFile {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    signing_key_base64: String,
    verifying_key_base64: Option<String>,
    token_base64: String,
}

fn main() {
    let out_dir = std::env::args()
        .nth(1)
        .expect("usage: gen_fuzz_seeds <output-dir>");
    let out_dir = Path::new(&out_dir);
    fs::create_dir_all(out_dir).expect("create output directory");

    let json = include_str!("../testdata/reference_vectors.json");
    let file: VectorFile = serde_json::from_str(json).expect("reference vectors parse");

    let mut written = 0;
    for v in &file.vectors {
        let token_bytes = B64.decode(&v.token_base64).unwrap();
        let token = deserialize_signed_token(&token_bytes).expect("reference token parses");
        let mut seeds = vec![
            ("signing_key", B64.decode(&v.signing_key_base64).unwrap()),
            ("token", token_bytes),
            ("claims", token.payload),
        ];
        if let Some(vk) = &v.verifying_key_base64 {
            let vk_bytes = B64.decode(vk).unwrap();
            let vk = VerifyingKey::from_bytes(&vk_bytes).unwrap();
            // The input format of the verify_untrusted_key target.
            let raw = [&[vk.algorithm() as u8], vk.public_key(), &token.signature].concat();
            seeds.push(("key_and_signature", raw));
            seeds.push(("verifying_key", vk_bytes));
        }

        for (kind, bytes) in seeds {
            fs::write(out_dir.join(format!("{}.{kind}", v.name)), bytes).expect("write seed");
            written += 1;
        }
    }
    eprintln!("wrote {written} seed files to {}", out_dir.display());
}
