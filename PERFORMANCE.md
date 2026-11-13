# Performance

Measured 2026-11-13 through `SigningKey::generate`, `sign`, and `verify` (medians, release
build, [Criterion](https://github.com/bheisler/criterion.rs) 0.8) on an Intel Xeon at 2.50 GHz
with AVX2 but without SHA extensions.

| Algorithm | Keygen | Sign | Verify | Minimal token |
|---|---|---|---|---|
| hmac-sha384 | 174 ns | 2.12 µs | 2.17 µs | 72 B |
| ml-dsa-44 | 214 µs | 606 µs | 143 µs | 2,445 B |
| ml-dsa-65 | 349 µs | 1.2 ms | 229 µs | 3,334 B |
| ml-dsa-87 | 538 µs | 1.35 ms | 373 µs | 4,652 B |
| fn-dsa-512 | 3.72 ms | 390 µs | 25.5 µs | 691 B |
| fn-dsa-1024 | 16.2 ms | 804 µs | 49.3 µs | 1,305 B |
| slh-dsa-sha2-128s | 217 ms | 829 ms | 828 µs | 7,881 B |
| slh-dsa-sha2-192s | 316 ms | 1.43 s | 1.19 ms | 16,249 B |
| slh-dsa-sha2-256s | 210 ms | 1.27 s | 1.72 ms | 29,818 B |

Parsing an ML-DSA-44 envelope without any cryptography takes about 200 ns.

Notes:

- ML-DSA signing uses rejection sampling, and the number of rejections is fixed for a given
  key and message. The benchmark rotates through 64 messages to report a typical time.
- Keys are expanded on every call. ML-DSA signing includes the work in the keygen column, and
  FN-DSA signing includes decoding the key. Caching the expanded key inside `SigningKey` would
  need no format change.
- SLH-DSA keygen computes the root twice: once to generate and once to validate. Loading a key
  costs half the keygen time. SHA extensions should speed up the 128s set most.
- FN-DSA keygen time varies widely from key to key.

## Running

```bash
cargo bench                          # HTML reports in target/criterion/
./scripts/bench-to-csv.sh            # also append rows to the table below (needs jq)
./scripts/bench-to-csv.sh --dry-run  # print the rows only
```

Extract the CSV with `sed -n '/^date,git_rev/,$p' PERFORMANCE.md`.

## Benchmark data (CSV)

date,git_rev,cpu,os,algorithm,operation,median_ns
