#![allow(clippy::expect_used)]

use criterion::{criterion_group, criterion_main, Criterion};
use protoken::sign::{
    compute_key_hash, generate_ed25519_key, generate_mldsa44_key, sign_ed25519, sign_hmac,
    sign_mldsa44,
};
use protoken::types::{Claims, KeyIdentifier};
use protoken::verify::{verify_ed25519, verify_hmac, verify_mldsa44};

fn make_claims() -> Claims {
    Claims {
        expires_at: u64::MAX,
        issued_at: 1_000_000,
        ..Default::default()
    }
}

fn bench_hmac(c: &mut Criterion) {
    let key = [0xABu8; 32];
    let claims = make_claims();
    let token = sign_hmac(&key, &claims).expect("sign");

    c.bench_function("hmac_sign", |b| {
        b.iter(|| sign_hmac(&key, &claims).expect("sign"));
    });
    c.bench_function("hmac_verify", |b| {
        b.iter(|| verify_hmac(&key, &token, 1_000_000).expect("verify"));
    });
}

fn bench_ed25519(c: &mut Criterion) {
    let (seed, pk) = generate_ed25519_key();
    let key_id = KeyIdentifier::KeyHash(compute_key_hash(&pk));

    let claims = make_claims();
    let token = sign_ed25519(&seed, &claims, key_id.clone()).expect("sign");

    c.bench_function("ed25519_sign", |b| {
        b.iter(|| sign_ed25519(&seed, &claims, key_id.clone()).expect("sign"));
    });
    c.bench_function("ed25519_verify", |b| {
        b.iter(|| verify_ed25519(&pk, &token, 1_000_000).expect("verify"));
    });
}

fn bench_mldsa44(c: &mut Criterion) {
    let (sk, pk) = generate_mldsa44_key();
    let key_id = KeyIdentifier::KeyHash(compute_key_hash(&pk));
    let claims = make_claims();
    let token = sign_mldsa44(&sk, &claims, key_id.clone()).expect("sign");

    c.bench_function("mldsa44_sign", |b| {
        b.iter(|| sign_mldsa44(&sk, &claims, key_id.clone()).expect("sign"));
    });
    c.bench_function("mldsa44_verify", |b| {
        b.iter(|| verify_mldsa44(&pk, &token, 1_000_000).expect("verify"));
    });
}

criterion_group!(benches, bench_hmac, bench_ed25519, bench_mldsa44);
criterion_main!(benches);
