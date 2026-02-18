# Performance

Benchmarks for protoken sign and verify operations across all three algorithms.

## Summary

| Operation | Time | Ops/sec |
|---|---|---|
| HMAC-SHA256 sign | ~352 ns | ~2,840,000 |
| HMAC-SHA256 verify | ~432 ns | ~2,310,000 |
| Ed25519 sign | ~37.8 µs | ~26,400 |
| Ed25519 verify | ~42.1 µs | ~23,700 |
| ML-DSA-44 sign | ~202 µs | ~4,940 |
| ML-DSA-44 verify | ~119 µs | ~8,400 |

## Token Sizes

| Algorithm | KeyHash token | PublicKey token |
|---|---|---|
| HMAC-SHA256 | ~56 B | n/a |
| Ed25519 | ~88 B | ~120 B |
| ML-DSA-44 | ~2,500 B | ~3,800 B |

## Platform

- **CPU**: Intel (Granite Rapids family, model 207), 16 cores
- **OS**: Linux x86_64
- **Rust**: edition 2021, optimized release build
- **Tooling**: [Criterion.rs](https://github.com/bheisler/criterion.rs) 0.5

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
