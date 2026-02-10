# P-256 (ECDSA) vs Ed25519 (EdDSA) for Protoken Signed Tokens

Research comparing the two candidate asymmetric signature algorithms for protoken-rs,
as referenced in CLAUDE.md Design Guideline #4.

## 1. Performance

Both algorithms are fast compared to RSA. Benchmarks vary by implementation and hardware,
but they are in the same ballpark for signing and verification.

### OpenSSL Benchmarks (x86-64)

| Operation          | ECDSA P-256   | Ed25519       |
|--------------------|---------------|---------------|
| Sign (ops/sec)     | ~32,800       | ~30,700       |
| Verify (ops/sec)   | ~10,500       | ~11,800       |

Source: [Benchmarking Digital Signatures (Prof Buchanan)](https://billatnapier.medium.com/benchmarking-digital-signatures-ed25519-eddsa-wins-for-signing-rsa-wins-for-verifying-316944a1d43d)

### Rust `ring` Crate Benchmarks (Xeon E3-1225 v5 @ 3.3GHz)

| Operation          | ECDSA P-256 | Ed25519     |
|--------------------|-------------|-------------|
| Sign               | ~18 us      | ~21 us      |
| Verify             | ~56 us      | ~62 us      |

Source: [crypto-bench](https://github.com/briansmith/crypto-bench)

### Rust `ed25519-dalek` (AVX2 backend, same hardware)

| Operation | Time     |
|-----------|----------|
| Sign      | ~16 us   |
| Verify    | ~34 us   |

**Summary:** Performance is roughly equivalent. P-256 has a slight edge in `ring`; Ed25519
has a slight edge in pure-Rust `dalek` with AVX2. Neither is a bottleneck for token
signing/verification workloads. For protoken's use case (sign once, verify once or a few
times), both are more than adequate.

## 2. Token Size

| Property           | Ed25519              | ECDSA P-256                        |
|--------------------|----------------------|------------------------------------|
| Private key        | 32 bytes             | 32 bytes                           |
| Public key         | 32 bytes             | 33 bytes (compressed) / 65 (uncompressed) |
| Signature          | 64 bytes (fixed)     | 64 bytes (raw r||s) / ~71 (DER)    |
| Security level     | ~128-bit             | ~128-bit                           |

**Summary:** Nearly identical. Ed25519 is 1 byte smaller on the public key (32 vs 33
compressed). Signature sizes are the same at 64 bytes when using raw encoding (which we
would, since we control the wire format). For protoken, the difference is negligible.

## 3. NIST / FIPS Compliance

### P-256

- Approved in FIPS 186-4 (2013) and FIPS 186-5 (2023).
- Long track record in FIPS 140-2 and FIPS 140-3 validated modules.
- Included in the original CNSA 1.0 suite (via P-384, but P-256 is FIPS-approved).
- Universally available in all FIPS-validated crypto libraries.

### Ed25519

- **Approved in FIPS 186-5** (effective February 3, 2023). EdDSA was added as a third
  approved signature scheme alongside RSA and ECDSA.
  Source: [FIPS 186-5 Final](https://csrc.nist.gov/pubs/fips/186-5/final)
- Also approved in NIST SP 800-186 (2023) which lists Curve25519 as a recommended curve.
- FIPS 140-3 validated modules with Ed25519 support are now appearing:
  - Bouncy Castle Java FIPS 2.1.0 (Certificate 4943, Jan 2025)
  - AWS-LC FIPS 3.0 (2025)
  Source: [ExceptionFactory FIPS Ed25519](https://exceptionfactory.com/posts/2025/02/07/between-now-and-later-fips-compliance-and-java-support-for-ed25519/)
- Practical availability in FIPS-validated modules is catching up but not yet as
  ubiquitous as P-256.

### CNSA 2.0 / Post-Quantum

- CNSA 2.0 (Sep 2022) deprecates **all** classical elliptic curve algorithms (both P-256
  and Ed25519) in favor of post-quantum algorithms (ML-DSA/Dilithium for signatures).
- Transition timeline: 2025-2030 depending on equipment type.
- **Neither P-256 nor Ed25519 is in CNSA 2.0.** Both are pre-quantum algorithms on a
  deprecation path for national security systems.
  Source: [CNSA 2.0 FAQ (NSA)](https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF)

**Summary:** Ed25519 is now FIPS-approved under FIPS 186-5. P-256 has deeper FIPS module
availability today, but Ed25519 is catching up. Both are being phased out under CNSA 2.0
for national security use. For non-NSS commercial use, both are fully acceptable. The
FIPS gap for Ed25519 is closing rapidly.

## 4. Security Properties

### ECDSA P-256 Weaknesses

- **Nonce sensitivity:** ECDSA requires a unique, secret nonce per signature. Reusing a
  nonce across two signatures reveals the private key. Even a few bits of nonce bias
  enable lattice-based key recovery (LadderLeak demonstrated this with < 1 bit of
  leakage).
  Source: [Trail of Bits: ECDSA Handle with Care](https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care/)
- **Side channels:** Implementations must be constant-time, but this is hard to get right
  on Weierstrass curves. Timing leaks in scalar multiplication have been exploited
  (Minerva attack).
  Source: [Minerva](https://eprint.iacr.org/2020/728.pdf)
- **RFC 6979 mitigates** nonce reuse by deriving nonces deterministically, but this must
  be explicitly implemented and adds complexity.
- **Real-world failures:** Sony PS3 (static nonce), Java "Psychic Signatures" (CVE-2022-21449),
  numerous blockchain wallet compromises.

### Ed25519 Strengths

- **Deterministic by design:** Nonces are derived from SHA-512(private_key || message).
  No randomness needed at signing time. Nonce reuse is structurally impossible.
- **Side-channel resistant by design:** The Edwards curve formulas have complete addition
  laws (no special cases), and the Schnorr-like construction is simpler to implement
  safely. Constant-time scalar multiplication is easier on twisted Edwards curves.
- **Simpler to implement correctly:** Fewer moving parts, fewer ways to get it wrong.
- **No "nothing up my sleeve" concerns:** Curve25519 parameters are derived from simple,
  transparent choices (y^2 = x^3 + 486662x^2 + x over the prime 2^255 - 19). P-256's
  seed parameters have unexplained provenance, leading to some distrust.

### Ed25519 Caveats

- **Verification malleability:** Some Ed25519 implementations accept non-canonical
  signatures (e.g., cofactor vs cofactorless verification). This is a library choice,
  not a protocol flaw. RFC 8032 specifies strict verification.
- **No public key recovery:** Unlike ECDSA, you cannot recover the signer's public key
  from a signature. (Not relevant for protoken since we include key metadata.)

**Summary:** Ed25519 has significantly better security ergonomics. P-256 ECDSA is
cryptographically sound but fragile in implementation -- the nonce handling alone has
caused numerous real-world key compromises. For a security-focused library that may be
implemented by others, Ed25519's misuse resistance is a major advantage.

## 5. Rust Ecosystem Support

### Ed25519

| Crate            | Type       | Downloads (all-time) | Notes |
|------------------|------------|---------------------|-------|
| `ring`           | C/asm      | Very high           | Ed25519 sign + verify. Battle-tested BoringSSL backend. Not pure Rust. |
| `ed25519-dalek`  | Pure Rust  | ~69M                | Mature, widely used. Part of dalek-cryptography. Past advisory (fixed). |
| `aws-lc-rs`      | C/asm      | Growing             | AWS-backed. FIPS 140-3 validated. |

### P-256 (ECDSA)

| Crate            | Type       | Downloads (all-time) | Notes |
|------------------|------------|---------------------|-------|
| `ring`           | C/asm      | Very high           | ECDSA P-256 verify only (no signing until recently). |
| `p256`           | Pure Rust  | ~67M                | RustCrypto. Audited by zkSecurity (April 2025). `no_std` compatible. |
| `aws-lc-rs`      | C/asm      | Growing             | AWS-backed. Full ECDSA support. FIPS validated. |

Sources:
- [ed25519-dalek on crates.io](https://crates.io/crates/ed25519-dalek)
- [p256 on crates.io](https://crates.io/crates/p256)
- [p256 audit by zkSecurity](https://reports.zksecurity.xyz/reports/near-p256/)
- [Awesome Rust Cryptography](https://cryptography.rs/)

**Summary:** Both algorithms have mature Rust crate support. `ring` supports both but is
not pure Rust. The pure-Rust options (`ed25519-dalek` and `p256`) are both well-maintained
with comparable download counts. The `p256` crate received a professional audit in 2025.
`ed25519-dalek` has been around longer and is arguably more battle-tested in the Rust
ecosystem.

## 6. Adoption in Token Formats

| Format      | P-256 (ES256)                          | Ed25519 (EdDSA)                    |
|-------------|----------------------------------------|------------------------------------|
| JWT/JOSE    | Widely supported (ES256), mandatory in many profiles | Supported via "EdDSA" alg. Growing but not universal. |
| CWT/COSE    | Primary curve in RFC 8392 examples     | Supported in RFC 9053, fewer examples |
| x509/TLS    | Ubiquitous                             | Supported in TLS 1.3, growing      |
| SSH         | Supported (ecdsa-sha2-nistp256)        | Widely preferred (ssh-ed25519)     |
| PASETO      | Not used                               | Mandated (Ed25519 only)            |
| Biscuit     | Not used                               | Ed25519 only                       |
| OpenPGP     | Supported                              | Supported                          |

Sources:
- [JWT with EdDSA](https://connect2id.com/products/nimbus-jose-jwt/examples/jwt-with-eddsa)
- [JWT Signing Algorithms (Scott Brady)](https://www.scottbrady.io/jose/jwts-which-signing-algorithm-should-i-use)
- [Things that use Ed25519](https://ianix.com/pub/ed25519-deployment.html)

**Summary:** P-256 has broader legacy adoption in enterprise/government token formats
(JWT ES256, CWT, x509). Ed25519 is the standard choice in modern, security-focused
token designs (PASETO, Biscuit) and is the preferred algorithm in SSH. The trend is
clearly toward Ed25519 for new protocols.

## 7. Comparison Summary

| Criterion               | P-256 (ECDSA)          | Ed25519 (EdDSA)       | Winner        |
|--------------------------|------------------------|-----------------------|---------------|
| Signing speed            | Slightly faster        | Slightly slower       | Tie           |
| Verification speed       | Comparable             | Comparable            | Tie           |
| Public key size          | 33 bytes (compressed)  | 32 bytes              | Ed25519 (marginal) |
| Signature size           | 64 bytes (raw)         | 64 bytes              | Tie           |
| FIPS approved            | Yes (long history)     | Yes (FIPS 186-5, 2023) | P-256 (marginal) |
| FIPS module availability | Widely available       | Catching up           | P-256         |
| CNSA 2.0                 | Deprecated             | Deprecated            | Tie (both out) |
| Nonce safety             | Fragile                | Deterministic         | **Ed25519**   |
| Side-channel resistance  | Implementation-dependent | By design            | **Ed25519**   |
| Implementation simplicity| Complex                | Simple                | **Ed25519**   |
| Rust ecosystem           | Mature                 | Mature                | Tie           |
| Legacy token adoption    | Higher                 | Lower                 | P-256         |
| Modern token adoption    | Lower                  | Higher (PASETO, etc.) | Ed25519       |

## 8. Recommendation

**Use Ed25519.**

Rationale:

1. **Security is the top priority.** Protoken is security-focused software (per CLAUDE.md).
   Ed25519's deterministic nonces and misuse resistance are decisive advantages. P-256's
   nonce fragility has caused real-world key compromises, and protoken cannot control how
   downstream users manage their signing environments.

2. **FIPS compliance is no longer a differentiator.** Ed25519 is approved in FIPS 186-5
   (Feb 2023) and FIPS 140-3 validated modules now exist. The practical gap is small and
   shrinking. Both algorithms are deprecated under CNSA 2.0 anyway.

3. **Performance and size are equivalent.** There is no meaningful difference for a
   token-signing use case. Ed25519 saves 1 byte on the public key, which is negligible.

4. **Alignment with modern token design.** PASETO and Biscuit both chose Ed25519
   exclusively. Protoken is a new protocol and should follow modern best practice rather
   than legacy compatibility.

5. **Simpler Rust implementation.** `ed25519-dalek` (pure Rust, `no_std`) or `ring`
   (C/asm backend) both provide clean, well-tested Ed25519 APIs. The deterministic
   nature of Ed25519 means fewer things can go wrong at the implementation level.

### Recommended Crate

For protoken-rs, **`ed25519-dalek`** is the recommended primary crate because:
- Pure Rust, `no_std` compatible
- Widely used (~69M downloads)
- Implements the `signature` trait crate for clean abstractions
- If FIPS-validated module support becomes necessary later, `aws-lc-rs` can be used as
  an alternative backend

### Wire Format Impact

With Ed25519 chosen, the Algorithm enum becomes:
```
enum Algorithm {
  ALGORITHM_UNSPECIFIED = 0;
  ALGORITHM_HMAC_SHA256 = 1;
  ALGORITHM_ED25519 = 2;
}
```

Key sizes for the deterministic serialization format:
- Public key (for KeyIdentifier): 32 bytes
- Key hash: 8 bytes (truncated hash, per existing design)
- Signature: 64 bytes

## References

- [FIPS 186-5 Final (NIST)](https://csrc.nist.gov/pubs/fips/186-5/final)
- [FIPS 186-5 PDF](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf)
- [CNSA 2.0 FAQ (NSA/DoD)](https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF)
- [ExceptionFactory: FIPS Compliance and Ed25519](https://exceptionfactory.com/posts/2025/02/07/between-now-and-later-fips-compliance-and-java-support-for-ed25519/)
- [Trail of Bits: ECDSA Handle with Care](https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care/)
- [Soatok: Guidance for Choosing an EC Signature Algorithm](https://soatok.blog/2022/05/19/guidance-for-choosing-an-elliptic-curve-signature-algorithm-in-2022/)
- [Benchmarking Digital Signatures (Prof Buchanan)](https://billatnapier.medium.com/benchmarking-digital-signatures-ed25519-eddsa-wins-for-signing-rsa-wins-for-verifying-316944a1d43d)
- [Fastcrypto Benchmarking Paper](https://eprint.iacr.org/2024/442.pdf)
- [ed25519-dalek on crates.io](https://crates.io/crates/ed25519-dalek)
- [p256 on crates.io](https://crates.io/crates/p256)
- [p256 Audit by zkSecurity](https://reports.zksecurity.xyz/reports/near-p256/)
- [Awesome Rust Cryptography](https://cryptography.rs/)
- [Ed25519 Deployment Tracker](https://ianix.com/pub/ed25519-deployment.html)
- [Chainguard FIPS 186-5 Milestones](https://www.chainguard.dev/unchained/forging-ahead-in-federal-compliance-chainguards-fips-140-3-and-186-5-milestones)
- [AWS-LC FIPS 3.0](https://aws.amazon.com/blogs/security/aws-lc-fips-3-0-first-cryptographic-library-to-include-ml-kem-in-fips-140-3-validation/)
