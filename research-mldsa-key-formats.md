# Research: ML-DSA-44 Key Formats (PKCS#8, SPKI, DER/ASN.1)

## 1. Does FIPS 204 define a key serialization format?

**Partially.** FIPS 204 defines the raw byte-level encoding of keys (Section 7.2):

- **Public key (pk)**: `rho || t1_encoded` = 1,312 bytes for ML-DSA-44
- **Secret key (sk)**: `rho || K || tr || s1 || s2 || t0` = 2,560 bytes for ML-DSA-44
- **Seed (xi)**: 32 bytes, from which sk and pk can be deterministically derived

FIPS 204 does **not** define PKCS#8, SPKI, or any ASN.1/DER wrapping. That is delegated to IETF.

Reference: [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)

## 2. OIDs for ML-DSA-44

Standardized OIDs are assigned under the NIST `sigAlgs` arc:

| Algorithm | OID | Security Level |
|-----------|-----|----------------|
| ML-DSA-44 | `2.16.840.1.101.3.4.3.17` | Category 2 (AES-128 equivalent) |
| ML-DSA-65 | `2.16.840.1.101.3.4.3.18` | Category 3 (AES-192 equivalent) |
| ML-DSA-87 | `2.16.840.1.101.3.4.3.19` | Category 5 (AES-256 equivalent) |

Full arc: `joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) sigAlgs(3)`

The AlgorithmIdentifier MUST have **absent parameters** (a SEQUENCE of one component, the OID only).

## 3. RFCs and NIST documents defining DER encoding

### RFC 9881 (October 2025) -- The definitive reference

**"Internet X.509 Public Key Infrastructure -- Algorithm Identifiers for the Module-Lattice-Based Digital Signature Algorithm (ML-DSA)"**

This RFC defines how ML-DSA keys are encoded in:

- **SubjectPublicKeyInfo** (X.509 certificates): The `subjectPublicKey` BIT STRING contains the raw FIPS 204 public key bytes.
- **OneAsymmetricKey / PKCS#8** (private keys): The `privateKey` OCTET STRING contains the 32-byte seed (xi).

Reference: [RFC 9881](https://datatracker.ietf.org/doc/rfc9881/)

#### Private key ASN.1 structure (seed-only, per RFC 9881):
```
SEQUENCE {
  INTEGER { 0 }                          -- version (v1)
  SEQUENCE {
    OBJECT IDENTIFIER { 2.16.840.1.101.3.4.3.17 }  -- id-ml-dsa-44
  }
  OCTET STRING {                         -- privateKey
    <32-byte seed>
  }
}
```

#### Public key ASN.1 structure (SubjectPublicKeyInfo):
```
SEQUENCE {
  SEQUENCE {
    OBJECT IDENTIFIER { 2.16.840.1.101.3.4.3.17 }  -- id-ml-dsa-44
  }
  BIT STRING {                           -- subjectPublicKey
    <1312-byte raw public key>
  }
}
```

### OpenSSL 3.5 ML-DSA-PrivateKey ASN.1 (broader format)

OpenSSL 3.5 defines a richer private key structure supporting multiple representations:

```asn1
ML-DSA-PrivateKey ::= CHOICE {
    seed        [0] IMPLICIT OCTET STRING (SIZE (32)),
    expandedKey     OCTET STRING (SIZE (2560 | 4032 | 4896)),
    both        SEQUENCE {
        seed        OCTET STRING (SIZE (32)),
        expandedKey OCTET STRING (SIZE (2560 | 4032 | 4896))
    }
}
```

Five serialization profiles: seed-only, priv-only, both, bare-seed, bare-priv.

Reference: [OpenSSL 3.5 EVP_PKEY-ML-DSA](https://docs.openssl.org/3.5/man7/EVP_PKEY-ML-DSA/)

### Other related documents:

- **draft-ietf-lamps-cms-ml-dsa**: ML-DSA in CMS (Cryptographic Message Syntax)
- **draft-ietf-lamps-pq-composite-sigs**: Composite ML-DSA + traditional algorithm hybrid certificates

### Interoperability note

There have been interoperability issues between implementations (e.g., Bouncy Castle added an extra OCTET STRING tag wrapper around the private key bytes). RFC 9881 is the authoritative reference; implementations should follow it strictly.

Reference: [bcgit/bc-java#1969](https://github.com/bcgit/bc-java/issues/1969)

## 4. Does the `ml-dsa` Rust crate support PKCS#8 / SPKI?

**Yes.** As of version 0.0.4 (published April 2025), the `ml-dsa` crate has a `pkcs8` feature that is **enabled by default**.

### Feature flags (ml-dsa 0.0.4):
- `pkcs8` (default) -- PKCS#8 and SPKI encoding/decoding
- `rand_core` (default) -- key generation from RNG
- `alloc` (default) -- required for `EncodePrivateKey` and `EncodePublicKey`
- `zeroize` -- secure memory zeroing

### Trait implementations:

**`KeyPair<MlDsa44>`:**
- `EncodePrivateKey` -- `to_pkcs8_der()` encodes the 32-byte seed in PKCS#8 with OID `2.16.840.1.101.3.4.3.17`
- `TryFrom<PrivateKeyInfo>` -- decodes PKCS#8 (expects 32-byte seed as private key bytes)
- `SignatureAlgorithmIdentifier`
- `Signer<Signature<P>>`

**`SigningKey<MlDsa44>`:**
- `TryFrom<PrivateKeyInfo>` / `DecodePrivateKey` -- decodes from PKCS#8 (via KeyPair internally)
- `SignatureAlgorithmIdentifier`
- `Signer`, `RandomizedSigner`

**`VerifyingKey<MlDsa44>`:**
- `EncodePublicKey` -- `to_public_key_der()` encodes raw 1312-byte public key in SubjectPublicKeyInfo
- `TryFrom<SubjectPublicKeyInfoRef>` / `DecodePublicKey` -- decodes from SPKI
- `SignatureAlgorithmIdentifier`
- `Verifier<Signature<P>>`

### Key encoding detail (from source):

The `EncodePrivateKey` implementation on `KeyPair` stores only the **32-byte seed** in the PKCS#8 `privateKey` field:
```rust
fn to_pkcs8_der(&self) -> pkcs8::Result<der::SecretDocument> {
    let pkcs8_key = pkcs8::PrivateKeyInfo::new(P::ALGORITHM_IDENTIFIER, &self.seed);
    Ok(der::SecretDocument::encode_msg(&pkcs8_key)?)
}
```

The `TryFrom<PrivateKeyInfo>` implementation expects the raw 32-byte seed and regenerates the full key pair:
```rust
fn try_from(private_key_info: pkcs8::PrivateKeyInfo<'_>) -> pkcs8::Result<Self> {
    // ...verify OID matches...
    let seed = Array::try_from(private_key_info.private_key)
        .map_err(|_| pkcs8::Error::KeyMalformed)?;
    Ok(P::key_gen_internal(&seed))
}
```

This is the **seed-only format** per RFC 9881 -- compact (32 bytes) and deterministically expandable.

### Current project status:

In `protoken-rs`, the `ml-dsa` dependency is declared as:
```toml
ml-dsa = { version = "0.0", features = ["rand_core"] }
```

Since `pkcs8` is a **default feature** of ml-dsa 0.0.4, it is already enabled. The project currently stores ML-DSA-44 keys as raw SK||PK (3,872 bytes). Switching to PKCS#8 seed format (32 bytes + DER overhead ~50 bytes) would be much more compact and standards-compliant.

**Note:** The latest pre-release is `ml-dsa 0.1.0-rc.7` (Feb 2026), which uses Rust edition 2024 and requires Rust 1.85+. The 0.0.4 version used by this project uses edition 2021.

### Source location:
`/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/ml-dsa-0.0.4/src/lib.rs`

## 5. Comparison: ed25519-dalek PKCS#8

**Yes, `ed25519-dalek` uses standard PKCS#8 with OID `1.3.101.112`** (defined in [RFC 8410](https://www.rfc-editor.org/rfc/rfc8410)).

- OID: `1.3.101.112` = `{iso(1) identified-organization(3) thawte(101) id-Ed25519(112)}`
- The `pkcs8` feature on `ed25519-dalek` enables `DecodePrivateKey` / `EncodePrivateKey`
- Private key: 32-byte seed in PKCS#8 `privateKey` field
- Public key: 32-byte compressed point in SubjectPublicKeyInfo `subjectPublicKey` BIT STRING

Both `ed25519-dalek` and `ml-dsa` follow the same RustCrypto pattern: seed-based PKCS#8 private keys, raw-bytes SPKI public keys, with standard OIDs.

## Summary table

| Property | Ed25519 | ML-DSA-44 |
|----------|---------|-----------|
| OID | `1.3.101.112` | `2.16.840.1.101.3.4.3.17` |
| Standard | RFC 8410 | RFC 9881 |
| PKCS#8 private key content | 32-byte seed | 32-byte seed (xi) |
| SPKI public key content | 32 bytes | 1,312 bytes |
| PKCS#8 total DER size | ~48 bytes | ~82 bytes |
| SPKI total DER size | ~44 bytes | ~1,330 bytes |
| RustCrypto crate | `ed25519-dalek` (pkcs8 feature) | `ml-dsa` (pkcs8 feature, default) |
| Rust traits | `EncodePrivateKey`, `DecodePrivateKey`, `EncodePublicKey`, `DecodePublicKey` | Same |

## Implications for protoken-rs

1. **Key generation** could output PKCS#8 DER / PEM for ML-DSA-44 private keys (32 bytes + DER wrapper) instead of raw SK||PK (3,872 bytes).
2. **Public keys** could be output as SPKI DER / PEM for interoperability with X.509 tooling.
3. The `pkcs8` feature is already available and default-enabled in the ml-dsa 0.0.4 dependency.
4. This would align ML-DSA-44 key handling with the Ed25519 key handling (both using standard PKCS#8/SPKI).
5. Seed-based PKCS#8 is compact and RFC 9881 compliant, but note: loading a key requires regenerating the expanded key from seed, which takes ~200us for ML-DSA-44.

## References

- [NIST FIPS 204 -- ML-DSA Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [RFC 9881 -- ML-DSA Algorithm Identifiers for X.509](https://datatracker.ietf.org/doc/rfc9881/)
- [RFC 8410 -- Ed25519/Ed448 Algorithm Identifiers for X.509](https://www.rfc-editor.org/rfc/rfc8410)
- [OpenSSL 3.5 EVP_PKEY-ML-DSA](https://docs.openssl.org/3.5/man7/EVP_PKEY-ML-DSA/)
- [ml-dsa crate on crates.io](https://crates.io/crates/ml-dsa)
- [RustCrypto/signatures repository (ml-dsa)](https://github.com/RustCrypto/signatures)
- [draft-ietf-lamps-pq-composite-sigs -- Composite ML-DSA](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/)
- [Bouncy Castle interop issue](https://github.com/bcgit/bc-java/issues/1969)
