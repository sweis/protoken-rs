# Security Audit — April 2026

Multi-agent adversarial review (6 dimensions, 43 agents, 27 false positives
rejected). One critical issue fixed; eight low-severity hardening findings.

## Fixed

### CRITICAL — Groth16 auth bypass via attacker-controlled key hash
`verify_groth16` / `verify_groth16_hybrid` read `key_hash` from the token
payload and used it as a SNARK public input. Since the proof only attests
"I know K with Hash(K) = key_hash" and the CRS is public, anyone could mint
tokens with arbitrary claims. **Fix:** both functions now take a caller-supplied
`expected_key_hash: &[u8; 32]`, compare it (constant-time) against the embedded
hash, and verify the proof against the trusted value. CLI `verify` now requires
`--key-hash`. Regression tests: `test_verify_groth16_rejects_forged_key_hash`,
`test_verify_groth16_hybrid_rejects_forged_key_hash`, `tests/audit_poc.rs`.

### LOW — Non-Groth16 verifiers ignored `proof` field (malleability)
Appending proto3 field 3 to any HMAC/Ed25519/ML-DSA token produced distinct
bytes that still verified. **Fix:** `reject_unexpected_proof()` called in all
three verifiers.

### LOW — `SigningKey` derived `Debug`, printing secret bytes
`Zeroizing<Vec<u8>>` passes Debug through. **Fix:** manual `Debug` impl that
redacts `secret_key` as `[N bytes redacted]`.

### LOW — `read_keyfile` returned plain `Vec<u8>`
Decoded SigningKey proto bytes were dropped un-wiped. **Fix:** returns
`Zeroizing<Vec<u8>>`.

## Open (low severity, deferred)

### Groth16 `mac` accepts non-canonical Fr encodings (snark.rs:200)
`from_le_bytes_mod_order` lets ~6 distinct 32-byte values verify. Groth16
proofs are already re-randomizable so token-byte uniqueness was never a
property. *Recommend:* reject `mac_bytes ≥ BN254 r`; document that Groth16
token bytes are not identifiers.

### Decoders accept explicit default values (serialize.rs:107)
`[0x28, 0x00]` (varint 0) and `[0x52, 0x00]` (empty LEN) parse but don't
re-serialize identically; `scopes=[""]` is parseable but unencodable. Not a
forgery (signature covers raw bytes). *Recommend:* reject zero varints / empty
LEN in all four decoders.

### Verify API performs no audience check (verify.rs)
None of the `verify_*` functions take `expected_audience`. Cross-service replay
hazard if multiple services trust one issuer. *Recommend:* add
`expected_audience: Option<&str>` parameter or document caller responsibility
explicitly in README.

### `generate-key` writes secrets to stdout (main.rs)
`> key.file` honors umask (typically 0644). *Recommend:* add `--output <path>`
with `mode(0o600).create_new(true)`.

### No Poseidon domain separation between key_hash and MAC (snark.rs:80)
`Poseidon([K]) == Poseidon([K, 0])` since arkworks sponge has no length
padding. Unexploitable (~2^253 work + still need K) but violates SAFE-sponge
guidance. *Recommend:* absorb domain constants `[1, K]` / `[2, K, payload]`.
Breaking change — requires new trusted setup.
