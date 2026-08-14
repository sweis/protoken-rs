#![allow(clippy::expect_used)]

use criterion::{criterion_group, criterion_main, Criterion};
use protoken::serialize::deserialize_signed_token;
use protoken::{Algorithm, Claims, SigningKey};

const NOW: u64 = 1_000_000;

/// Number of distinct messages each sign/verify benchmark cycles through.
///
/// ML-DSA signing uses rejection sampling, and the number of rejections is
/// fixed for a given (key, message), so timing one message repeatedly reports
/// an arbitrary point of a wide distribution. Rotating through many messages
/// reports the mean instead. The same inputs are used for every algorithm.
const MESSAGES: usize = 64;

fn make_claims() -> Claims {
    Claims {
        expires_at: u64::MAX,
        issued_at: NOW,
        ..Default::default()
    }
}

fn varied_claims() -> Vec<Claims> {
    (0..MESSAGES)
        .map(|i| Claims {
            subject: format!("user:{i}"),
            ..make_claims()
        })
        .collect()
}

/// Benchmark names match the columns in PERFORMANCE.md and scripts/bench-to-csv.sh.
fn bench_name(algorithm: Algorithm) -> &'static str {
    match algorithm {
        Algorithm::HmacSha256 => "hmac",
        Algorithm::Ed25519 => "ed25519",
        Algorithm::MlDsa44 => "mldsa44",
    }
}

fn bench_sign_verify(c: &mut Criterion) {
    let claims = varied_claims();
    for algorithm in Algorithm::ALL {
        let name = bench_name(algorithm);
        let key = SigningKey::generate(algorithm).expect("keygen");
        let tokens: Vec<Vec<u8>> = claims
            .iter()
            .map(|claims| key.sign(claims).expect("sign"))
            .collect();

        c.bench_function(&format!("{name}_sign"), |b| {
            let mut inputs = claims.iter().cycle();
            b.iter(|| key.sign(inputs.next().expect("cycle")).expect("sign"));
        });
        c.bench_function(&format!("{name}_verify"), |b| {
            let mut inputs = tokens.iter().cycle();
            b.iter(|| {
                key.verify(inputs.next().expect("cycle"), NOW)
                    .expect("verify")
            });
        });
    }
}

fn bench_keygen(c: &mut Criterion) {
    for algorithm in Algorithm::ALL {
        let name = bench_name(algorithm);
        c.bench_function(&format!("{name}_keygen"), |b| {
            b.iter(|| SigningKey::generate(algorithm).expect("keygen"));
        });
    }
}

fn bench_parse(c: &mut Criterion) {
    let key = SigningKey::generate(Algorithm::MlDsa44).expect("keygen");
    let token = key.sign(&make_claims()).expect("sign");
    c.bench_function("parse_mldsa44_envelope", |b| {
        b.iter(|| deserialize_signed_token(&token).expect("parse"));
    });
}

criterion_group!(benches, bench_sign_verify, bench_keygen, bench_parse);
criterion_main!(benches);
