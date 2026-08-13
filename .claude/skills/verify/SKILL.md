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
- `inspect CICD0f-vBw` (expires_at in year 10000) → prints raw epoch seconds, exit 0, no panic.
- `inspect GAE` (payload with only issued_at) → shown with "Expires (not set...)", exit 0.
- A key file written as *padded* base64 (either alphabet) → accepted by `sign`/`verify`.

## Also check

- `make vectors-check`: both generators are deterministic and must reproduce
  `testdata/*.json` exactly. Only run `make vectors` for an intentional wire-format change.
- Python bindings, if `bindings/python` or the library API changed: create a venv
  (`python3 -m venv --system-site-packages <scratch>/venv`, activate it), then
  `cd bindings/python && maturin develop && pytest`. The pytest suite re-verifies and
  re-signs the reference vectors, so it also proves CLI/Python interop.

## Gotchas

- `$TMPDIR` may be unset in the sandbox shell; use the session scratchpad path explicitly.
- In a worktree session, compound shell commands with redirects may be refused;
  put the CLI flow in a small script under the scratchpad and run that instead.
- `maturin develop` leaves `_protoken.abi3.so` in the source tree; it is gitignored.
