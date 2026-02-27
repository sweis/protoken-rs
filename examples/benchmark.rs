#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Benchmark all 5 signing algorithms and report token/key sizes.
//!
//! Usage: cargo run --release --example benchmark

use std::time::{Duration, Instant};

use protoken::keys::{serialize_signing_key, serialize_verifying_key, SigningKey, VerifyingKey};
use protoken::sign::{
    compute_key_hash, generate_ed25519_key, generate_hmac_key, generate_mldsa44_key,
    mldsa44_key_hash, sign_ed25519, sign_groth16, sign_groth16_hybrid, sign_hmac, sign_mldsa44,
};
use protoken::snark;
use protoken::types::{Algorithm, Claims, KeyIdentifier};
use protoken::verify::{
    verify_ed25519, verify_groth16, verify_groth16_hybrid, verify_hmac, verify_mldsa44,
};
use protoken::Zeroizing;

fn make_claims() -> Claims {
    Claims {
        expires_at: u64::MAX,
        not_before: 0,
        issued_at: 1_000_000,
        subject: "user:alice".into(),
        audience: "api.example.com".into(),
        scopes: vec!["read".into(), "write".into()],
    }
}

/// Run a benchmark for `duration`, returning (iterations, total_time).
fn bench_fn<F: FnMut()>(duration: Duration, mut f: F) -> (u64, Duration) {
    // Warm up with 1 iteration
    f();

    let start = Instant::now();
    let mut iterations = 0u64;
    while start.elapsed() < duration {
        f();
        iterations += 1;
    }
    (iterations, start.elapsed())
}

fn format_rate(iterations: u64, elapsed: Duration) -> String {
    let secs = elapsed.as_secs_f64();
    let ops_per_sec = iterations as f64 / secs;
    let mean_us = secs * 1_000_000.0 / iterations as f64;

    if ops_per_sec >= 1000.0 {
        format!(
            "{:>10.0} ops/s  (mean: {:>8.1} µs)",
            ops_per_sec, mean_us
        )
    } else if ops_per_sec >= 1.0 {
        format!(
            "{:>10.1} ops/s  (mean: {:>8.1} ms)",
            ops_per_sec,
            mean_us / 1000.0
        )
    } else {
        format!(
            "{:>10.3} ops/s  (mean: {:>8.1} s)",
            ops_per_sec,
            mean_us / 1_000_000.0
        )
    }
}

struct BenchResult {
    algo_name: String,
    sign_iters: u64,
    sign_elapsed: Duration,
    verify_iters: u64,
    verify_elapsed: Duration,
    token_size: usize,
    signing_key_size: usize,
    verifying_key_size: Option<usize>,
}

fn main() {
    let bench_duration = Duration::from_secs(10);
    let groth16_sign_duration = Duration::from_secs(30);
    let groth16_verify_duration = Duration::from_secs(10);
    let claims = make_claims();
    let now = 1_000_000u64;

    let mut results: Vec<BenchResult> = Vec::new();

    // ── HMAC-SHA256 ──
    {
        println!("Benchmarking HMAC-SHA256...");
        let key = generate_hmac_key();
        let token = sign_hmac(&key, claims.clone()).unwrap();

        let sk = SigningKey {
            algorithm: Algorithm::HmacSha256,
            secret_key: Zeroizing::new(key.clone()),
            public_key: Vec::new(),
        };

        let (si, se) = bench_fn(bench_duration, || {
            let _ = sign_hmac(&key, claims.clone()).unwrap();
        });
        let (vi, ve) = bench_fn(bench_duration, || {
            let _ = verify_hmac(&key, &token, now).unwrap();
        });
        results.push(BenchResult {
            algo_name: "HMAC-SHA256".into(),
            sign_iters: si,
            sign_elapsed: se,
            verify_iters: vi,
            verify_elapsed: ve,
            token_size: token.len(),
            signing_key_size: serialize_signing_key(&sk).len(),
            verifying_key_size: None,
        });
    }

    // ── Ed25519 ──
    {
        println!("Benchmarking Ed25519...");
        let (seed, pk) = generate_ed25519_key().unwrap();
        let key_id = KeyIdentifier::KeyHash(compute_key_hash(&pk));
        let token = sign_ed25519(&seed, claims.clone(), key_id.clone()).unwrap();

        let sk = SigningKey {
            algorithm: Algorithm::Ed25519,
            secret_key: Zeroizing::new(seed.clone()),
            public_key: pk.clone(),
        };
        let vk = VerifyingKey {
            algorithm: Algorithm::Ed25519,
            public_key: pk.clone(),
        };

        let (si, se) = bench_fn(bench_duration, || {
            let _ = sign_ed25519(&seed, claims.clone(), key_id.clone()).unwrap();
        });
        let (vi, ve) = bench_fn(bench_duration, || {
            let _ = verify_ed25519(&pk, &token, now).unwrap();
        });
        results.push(BenchResult {
            algo_name: "Ed25519".into(),
            sign_iters: si,
            sign_elapsed: se,
            verify_iters: vi,
            verify_elapsed: ve,
            token_size: token.len(),
            signing_key_size: serialize_signing_key(&sk).len(),
            verifying_key_size: Some(serialize_verifying_key(&vk).len()),
        });
    }

    // ── ML-DSA-44 ──
    {
        println!("Benchmarking ML-DSA-44...");
        let (sk_bytes, pk_bytes) = generate_mldsa44_key().unwrap();
        let key_id = mldsa44_key_hash(&pk_bytes).unwrap();
        let token = sign_mldsa44(&sk_bytes, claims.clone(), key_id.clone()).unwrap();

        let sk = SigningKey {
            algorithm: Algorithm::MlDsa44,
            secret_key: Zeroizing::new(sk_bytes.clone()),
            public_key: pk_bytes.clone(),
        };
        let vk = VerifyingKey {
            algorithm: Algorithm::MlDsa44,
            public_key: pk_bytes.clone(),
        };

        let (si, se) = bench_fn(bench_duration, || {
            let _ = sign_mldsa44(&sk_bytes, claims.clone(), key_id.clone()).unwrap();
        });
        let (vi, ve) = bench_fn(bench_duration, || {
            let _ = verify_mldsa44(&pk_bytes, &token, now).unwrap();
        });
        results.push(BenchResult {
            algo_name: "ML-DSA-44".into(),
            sign_iters: si,
            sign_elapsed: se,
            verify_iters: vi,
            verify_elapsed: ve,
            token_size: token.len(),
            signing_key_size: serialize_signing_key(&sk).len(),
            verifying_key_size: Some(serialize_verifying_key(&vk).len()),
        });
    }

    // ── Groth16-Poseidon ──
    {
        println!("Setting up Groth16-Poseidon (trusted setup)...");
        let setup_start = Instant::now();
        let (pk, vk) = snark::setup().unwrap();
        println!(
            "  Setup complete in {:.1}s",
            setup_start.elapsed().as_secs_f64()
        );

        let key = [0xABu8; 32];
        let token = sign_groth16(&pk, &key, claims.clone()).unwrap();

        let sk_proto = SigningKey {
            algorithm: Algorithm::Groth16Poseidon,
            secret_key: Zeroizing::new(key.to_vec()),
            public_key: Vec::new(),
        };

        println!("Benchmarking Groth16-Poseidon sign ({groth16_sign_duration:?})...");
        let (si, se) = bench_fn(groth16_sign_duration, || {
            let _ = sign_groth16(&pk, &key, claims.clone()).unwrap();
        });

        println!("Benchmarking Groth16-Poseidon verify ({groth16_verify_duration:?})...");
        let (vi, ve) = bench_fn(groth16_verify_duration, || {
            let _ = verify_groth16(&vk, &token, now).unwrap();
        });
        results.push(BenchResult {
            algo_name: "Groth16-Poseidon".into(),
            sign_iters: si,
            sign_elapsed: se,
            verify_iters: vi,
            verify_elapsed: ve,
            token_size: token.len(),
            signing_key_size: serialize_signing_key(&sk_proto).len(),
            verifying_key_size: None,
        });
    }

    // ── Groth16-Hybrid ──
    {
        println!("Setting up Groth16-Hybrid (trusted setup)...");
        let setup_start = Instant::now();
        // Hybrid setup needs a large stack for SHA-256 circuit
        let (pk, vk) = std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| snark::setup_hybrid().unwrap())
            .unwrap()
            .join()
            .unwrap();
        println!(
            "  Setup complete in {:.1}s",
            setup_start.elapsed().as_secs_f64()
        );

        let key = [0xABu8; 32];
        // Sign on a large-stack thread
        let pk_clone = pk.clone();
        let claims_clone = claims.clone();
        let token = std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(move || sign_groth16_hybrid(&pk_clone, &key, claims_clone).unwrap())
            .unwrap()
            .join()
            .unwrap();

        let sk_proto = SigningKey {
            algorithm: Algorithm::Groth16Hybrid,
            secret_key: Zeroizing::new(key.to_vec()),
            public_key: Vec::new(),
        };

        println!("Benchmarking Groth16-Hybrid sign ({groth16_sign_duration:?})...");
        let pk_ref = &pk;
        let (si, se) = {
            let pk_inner = pk_ref.clone();
            std::thread::Builder::new()
                .stack_size(64 * 1024 * 1024)
                .spawn(move || {
                    bench_fn(groth16_sign_duration, || {
                        let _ =
                            sign_groth16_hybrid(&pk_inner, &[0xABu8; 32], claims.clone()).unwrap();
                    })
                })
                .unwrap()
                .join()
                .unwrap()
        };

        println!("Benchmarking Groth16-Hybrid verify ({groth16_verify_duration:?})...");
        let (vi, ve) = bench_fn(groth16_verify_duration, || {
            let _ = verify_groth16_hybrid(&vk, &token, now).unwrap();
        });

        results.push(BenchResult {
            algo_name: "Groth16-Hybrid".into(),
            sign_iters: si,
            sign_elapsed: se,
            verify_iters: vi,
            verify_elapsed: ve,
            token_size: token.len(),
            signing_key_size: serialize_signing_key(&sk_proto).len(),
            verifying_key_size: None,
        });
    }

    // ── Print Results ──
    println!();
    println!("═══════════════════════════════════════════════════════════════════════════════");
    println!("  PROTOKEN BENCHMARK RESULTS");
    println!("═══════════════════════════════════════════════════════════════════════════════");
    println!();

    // Performance table
    println!("┌─────────────────┬──────────────────────────────────┬──────────────────────────────────┐");
    println!(
        "│ {:<15} │ {:<32} │ {:<32} │",
        "Algorithm", "Sign", "Verify"
    );
    println!("├─────────────────┼──────────────────────────────────┼──────────────────────────────────┤");
    for r in &results {
        println!(
            "│ {:<15} │ {:<32} │ {:<32} │",
            r.algo_name,
            format_rate(r.sign_iters, r.sign_elapsed),
            format_rate(r.verify_iters, r.verify_elapsed),
        );
    }
    println!("└─────────────────┴──────────────────────────────────┴──────────────────────────────────┘");

    // Size table
    println!();
    println!("┌─────────────────┬──────────────┬──────────────────┬──────────────────┐");
    println!(
        "│ {:<15} │ {:>12} │ {:>16} │ {:>16} │",
        "Algorithm", "Token (B)", "Signing Key (B)", "Verify Key (B)"
    );
    println!("├─────────────────┼──────────────┼──────────────────┼──────────────────┤");
    for r in &results {
        let vk_str = match r.verifying_key_size {
            Some(sz) => format!("{sz}"),
            None => "N/A (symmetric)".into(),
        };
        println!(
            "│ {:<15} │ {:>12} │ {:>16} │ {:>16} │",
            r.algo_name, r.token_size, r.signing_key_size, vk_str,
        );
    }
    println!("└─────────────────┴──────────────┴──────────────────┴──────────────────┘");
    println!();
    println!(
        "Claims: subject={:?}, audience={:?}, scopes={:?}",
        "user:alice", "api.example.com", ["read", "write"]
    );
    println!("Note: Groth16 signing/verifying system keys (CRS) are excluded from key sizes.");
}
