# Performance

Benchmarks for protoken sign and verify operations across all three algorithms.

## Summary

Measured 2026-08-13 through `SigningKey::sign` / `SigningKey::verify`,
averaged over 64 different messages per benchmark.

| Operation | Time | Ops/sec |
|---|---|---|
| HMAC-SHA256 sign | ~344 ns | ~2,900,000 |
| HMAC-SHA256 verify | ~409 ns | ~2,440,000 |
| Ed25519 sign | ~31.1 µs | ~32,200 |
| Ed25519 verify (strict) | ~50.6 µs | ~19,800 |
| ML-DSA-44 sign | ~467 µs | ~2,140 |
| ML-DSA-44 verify | ~92.4 µs | ~10,800 |
| HMAC-SHA256 keygen | ~360 ns | |
| Ed25519 keygen | ~15.1 µs | |
| ML-DSA-44 keygen | ~150 µs | |
| Parse ML-DSA-44 envelope (no crypto) | ~137 ns | |

Notes:

- ML-DSA-44 signing uses rejection sampling, and the number of rejections is
  fixed for a given key and message. Timing one fixed message reports an
  arbitrary point of a wide distribution; single-message runs on this machine
  ranged from ~450 µs to ~1 ms. The 202 µs recorded earlier was a
  single-message measurement on a different CPU. The benchmark now rotates
  through 64 messages, so the sign numbers are means and are not directly
  comparable with the earlier CSV row.
- The signing API takes the 32-byte seed, so every ML-DSA-44 signature also
  pays the ~150 µs key expansion shown in the keygen row. A caller signing at
  high volume would benefit from an API that keeps the expanded key; the
  format does not need to change for that.
- Ed25519 verification uses `verify_strict`, which adds a small-order check on
  top of standard verification.

## Token Sizes

| Algorithm | KeyHash token | PublicKey token |
|---|---|---|
| HMAC-SHA256 | ~56 B | n/a |
| Ed25519 | ~88 B | ~112 B |
| ML-DSA-44 | ~2,450 B | ~3,760 B |

## Platform

- **CPU**: Intel Xeon Platinum 8488C (Sapphire Rapids) for the summary table above; the 2026-02 CSV row was measured on a Granite Rapids machine
- **OS**: Linux x86_64
- **Rust**: edition 2021, optimized release build
- **Tooling**: [Criterion.rs](https://github.com/bheisler/criterion.rs) 0.8

## Running Benchmarks

```bash
# Full criterion benchmarks (generates HTML reports in target/criterion/)
cargo bench

# Append a CSV row to the table below
./scripts/bench-to-csv.sh

# Preview CSV row without writing
./scripts/bench-to-csv.sh --dry-run
```

## Plotting

The CSV data below can be loaded directly by pandas, gnuplot, or any spreadsheet tool.

**Python example:**
```python
import pandas as pd
import matplotlib.pyplot as plt
import subprocess, io

# Extract CSV from PERFORMANCE.md
csv = subprocess.check_output(
    ["sed", "-n", "/^date,git_rev/,$p", "PERFORMANCE.md"], text=True)
df = pd.read_csv(io.StringIO(csv))

for col in ["hmac_sign_ns", "ed25519_sign_ns", "mldsa44_sign_ns"]:
    plt.plot(df["date"], df[col], label=col, marker="o")
plt.ylabel("nanoseconds")
plt.legend()
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("bench_trend.png")
```

**gnuplot example:**
```gnuplot
set datafile separator ","
set xdata time
set timefmt "%Y-%m-%d"
set ylabel "ns"
set key autotitle columnheader
plot "benchmarks.csv" using 1:5 with linespoints title "hmac_sign", \
     "" using 1:7 with linespoints title "ed25519_sign", \
     "" using 1:9 with linespoints title "mldsa44_sign"
```

To extract just the CSV for external tools:
```bash
tail -n +2 PERFORMANCE.md | sed -n '/^date,/,$p' > benchmarks.csv
```

## Benchmark Data (CSV)

date,git_rev,cpu,os,hmac_sign_ns,hmac_verify_ns,ed25519_sign_ns,ed25519_verify_ns,mldsa44_sign_ns,mldsa44_verify_ns
2026-02-18,5cf3536,unknown,Linux,351.92,432.21,37814.000,42144.000,202330.00,119300.00
