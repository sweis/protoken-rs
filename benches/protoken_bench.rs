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
/// reports the mean instead.
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

/// Groups are named after the algorithm; scripts/bench-to-csv.sh depends on that.
fn bench_algorithms(c: &mut Criterion) {
    for algorithm in Algorithm::ALL {
        let mut group = c.benchmark_group(algorithm.name());
        let mut claims = varied_claims();
        // SLH-DSA signing takes about a second and does not vary with the message.
        if algorithm.name().starts_with("slh-dsa") {
            group.sample_size(10);
            claims.truncate(4);
        }
        let key = SigningKey::generate(algorithm).expect("keygen");
        let tokens: Vec<Vec<u8>> = claims
            .iter()
            .map(|claims| key.sign(claims).expect("sign"))
            .collect();

        group.bench_function("keygen", |b| {
            b.iter(|| SigningKey::generate(algorithm).expect("keygen"));
        });
        group.bench_function("sign", |b| {
            let mut inputs = claims.iter().cycle();
            b.iter(|| key.sign(inputs.next().expect("cycle")).expect("sign"));
        });
        group.bench_function("verify", |b| {
            let mut inputs = tokens.iter().cycle();
            b.iter(|| {
                key.verify(inputs.next().expect("cycle"), NOW)
                    .expect("verify")
            });
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

criterion_group!(benches, bench_algorithms, bench_parse);
criterion_main!(benches);
