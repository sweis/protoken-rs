---
name: verify
description: Verify protoken-rs changes by driving the CLI end-to-end (build, keygen, sign, verify, inspect, negative probes).
---

# Verifying protoken-rs

The surface is the `protoken` CLI. Build and drive it; don't stop at unit tests.

## Build and run

```sh
cargo build                 # binary at target/debug/protoken
```

## Core flow (repeat for hmac, ed25519, ml-dsa-44)

```sh
BIN=target/debug/protoken
$BIN generate-key -a <alg> > sign.key
$BIN sign sign.key 4d --subject user:alice --audience api.test --scope read --scope write > token.b64
# HMAC verifies with the signing key; asymmetric with the verifying key:
$BIN get-verifying-key sign.key > verify.key       # ed25519 / ml-dsa-44 only
$BIN verify verify.key $(cat token.b64)            # expect OK + claims
$BIN inspect $(cat token.b64) --json               # no key needed
```

## Probes worth running

- Verify with a different key of the same algorithm → must be rejected.
- Flip a byte in the middle of the token (base64-decode, xor, re-encode) → "signature verification failed".
- Garbage base64 and garbage bytes → clean errors, exit 1.
- `--scope x --scope x` (duplicate) → rejected at sign time.
- `sign key 0s` → rejected ("duration must be at least 1 second").
- `verify -` with no token argument → clean usage error.

## Gotchas

- `$TMPDIR` may be unset in the sandbox shell; use the session scratchpad path explicitly.
- Wire-format changes require regenerating stored vectors:
  `cargo run --example gen_test_vectors > testdata/vectors.json` and
  `cargo run --example gen_reference_vectors > testdata/reference_vectors.json`.
