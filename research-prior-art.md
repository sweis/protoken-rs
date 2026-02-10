# Prior Art Research: Token and Credential Formats

Comparison of JWT, x509 Certificates, Macaroons, Biscuit, and CWT for informing the design of protoken-rs.

## 1. JWT (JSON Web Token) -- RFC 7519

**Specification:** [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519), with algorithms in [RFC 7518 (JWA)](https://tools.ietf.org/html/rfc7518)

### Standard Registered Claims

| Claim | Name           | Type        | Description                                      |
|-------|----------------|-------------|--------------------------------------------------|
| `iss` | Issuer         | StringOrURI | Entity that issued the token                     |
| `sub` | Subject        | StringOrURI | Principal the token describes                    |
| `aud` | Audience       | StringOrURI or array | Intended recipient(s)               |
| `exp` | Expiration     | NumericDate | Token must not be accepted on or after this time |
| `nbf` | Not Before     | NumericDate | Token must not be accepted before this time      |
| `iat` | Issued At      | NumericDate | Time the token was issued                        |
| `jti` | JWT ID         | String      | Unique identifier for replay prevention          |

NumericDate is seconds since Unix epoch (1970-01-01T00:00:00Z). Claims are not mandatory; they are recommended for interoperability.

### Wire Format

- **Encoding:** JSON payload, Base64url-encoded, text-based.
- **Structure (JWS Compact Serialization):** `BASE64URL(Header).BASE64URL(Payload).BASE64URL(Signature)`
- Base64url adds ~33% size overhead over raw binary.
- Also supports JWE (encrypted) format with 5 dot-separated parts.

### Signature Algorithms (JWA)

| Family    | Algorithms                | Type      | Key Type          |
|-----------|---------------------------|-----------|-------------------|
| HMAC      | HS256, HS384, HS512       | MAC       | Shared secret     |
| RSA PKCS1 | RS256, RS384, RS512      | Signature | RSA key pair      |
| RSA-PSS   | PS256, PS384, PS512       | Signature | RSA key pair      |
| ECDSA     | ES256, ES384, ES512       | Signature | P-256/P-384/P-521 |
| EdDSA     | EdDSA (RFC 8037)          | Signature | Ed25519/Ed448     |
| None      | `none`                    | Unsecured | N/A               |

### Key Identification

- JOSE Header `kid` (Key ID): opaque string hint.
- `jwk` header: embedded JSON Web Key.
- `jku` header: URL to a JWK Set.
- `x5c`, `x5t`, `x5u`: x509 certificate chain/thumbprint/URL.

### Token Size

- Typical signed JWT (ES256, minimal claims): ~300-400 bytes.
- Size grows linearly with claim count and string lengths.
- Base64url overhead makes JWTs ~33% larger than an equivalent binary format.

### Security Properties & Revocation

- **Stateless verification** -- no server roundtrip needed.
- **No built-in revocation.** Requires external mechanisms: token blacklists, short-lived tokens + refresh tokens, or introspection endpoints. All reintroduce statefulness.
- The `none` algorithm has been a persistent source of implementation vulnerabilities.
- Algorithm confusion attacks (RSA public key used as HMAC secret) are a known class of bugs.

---

## 2. X.509 Certificates -- RFC 5280

**Specification:** [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) (Internet PKI profile)

### Standard Fields

| Field                     | Description                                          |
|---------------------------|------------------------------------------------------|
| Version                   | Certificate version (v1, v2, v3)                     |
| Serial Number             | Unique identifier assigned by the CA                 |
| Signature Algorithm       | Algorithm the CA used to sign the certificate        |
| Issuer                    | Distinguished Name (DN) of the issuing CA            |
| Validity (Not Before)     | Start of validity period                             |
| Validity (Not After)      | End of validity period                               |
| Subject                   | Distinguished Name of the entity                     |
| Subject Public Key Info   | Public key + algorithm identifier                    |
| Issuer Unique ID (v2+)    | Optional, discouraged in practice                    |
| Subject Unique ID (v2+)   | Optional, discouraged in practice                    |

### Key v3 Extensions

| Extension                   | Purpose                                              |
|-----------------------------|------------------------------------------------------|
| Authority Key Identifier    | Identifies the CA's signing key                      |
| Subject Key Identifier      | Identifies the subject's public key                  |
| Key Usage                   | Digital signature, key agreement, etc.               |
| Extended Key Usage          | Server auth, client auth, code signing, etc.         |
| Basic Constraints           | Is subject a CA? Max path length                     |
| Subject Alternative Name    | DNS names, IPs, emails, URIs                         |
| Name Constraints            | Restricts subtree of allowed names for subordinate CAs |
| CRL Distribution Points     | Where to fetch revocation lists                      |
| Authority Information Access | OCSP responder URL, CA issuer URL                   |
| Certificate Policies        | Policy OIDs governing issuance                       |

### Wire Format

- **Encoding:** ASN.1 DER (binary) or PEM (Base64 of DER with header/footer lines).
- PEM adds ~33% overhead plus ~50 bytes for headers.

### Signature Algorithms

| Family  | Algorithms                                             |
|---------|--------------------------------------------------------|
| RSA     | sha256WithRSA, sha384WithRSA, sha512WithRSA, RSA-PSS  |
| ECDSA   | ecdsa-with-SHA256, ecdsa-with-SHA384, ecdsa-with-SHA512 |
| EdDSA   | Ed25519, Ed448                                         |
| DSA     | dsaWithSHA1 (legacy, deprecated)                       |

### Key Identification

- Authority Key Identifier extension (hash of CA's public key).
- Subject Key Identifier extension (hash of subject's public key).
- Issuer DN + Serial Number pair.
- Subject Alternative Name for entity identification.

### Token Size

- Typical RSA-2048 leaf certificate: ~800-1000 bytes (DER), ~1100-1400 bytes (PEM).
- RSA-4096: ~1500-2000 bytes (DER).
- Certificates with many SANs can reach 10 KB+.
- ECDSA P-256 certificates are smaller due to shorter keys and signatures.

### Security Properties & Revocation

- **Rich revocation ecosystem:**
  - **CRL (Certificate Revocation List):** CA publishes signed list of revoked serial numbers. Clients download and cache. Can be large.
  - **OCSP (Online Certificate Status Protocol, RFC 6960):** Real-time query for individual certificate status. Returns "good", "revoked", or "unknown".
  - **OCSP Stapling:** Server fetches OCSP response and staples it to TLS handshake. Better privacy and performance.
  - **CRLSets/CRLite:** Browser-shipped compressed revocation data (Chrome, Firefox).
- Chain-of-trust model: trust is derived from a root CA through intermediate CAs.
- Path validation is complex and has been a source of many implementation bugs.

---

## 3. Macaroons

**Specification:** [Macaroons: Cookies with Contextual Caveats (Google Research, 2014)](https://research.google/pubs/macaroons-cookies-with-contextual-caveats-for-decentralized-authorization-in-the-cloud/)
**Reference implementation:** [libmacaroons](https://github.com/rescrv/libmacaroons)

### Standard Fields

| Field       | Description                                             |
|-------------|---------------------------------------------------------|
| Location    | Optional hint for where the macaroon should be used     |
| Identifier  | Opaque identifier linking to the root key on the server |
| Caveats     | Ordered list of restrictions (see below)                |
| Signature   | Chained HMAC covering identifier + all caveats          |

There are no standardized claim names. Caveats are freeform strings with application-defined semantics.

### Caveat Types

- **First-party caveats:** Locally verifiable predicates (e.g., `time < 2025-01-01`, `operation = read`, `account = 12345`).
- **Third-party caveats:** Require a discharge macaroon from an external service. The third party's key is encrypted into the caveat. Enables federated authorization.

### Wire Format

- No single standardized encoding. De facto V2 binary format exists.
- V2 binary: TLV-style encoding of location, identifier, caveats, and signature.
- Also serialized as hex strings or Base64 in practice.
- JSON representation also exists.

### Signature Algorithm

- **HMAC-SHA256 only** (chained). Each caveat extends the HMAC chain:
  `sig_n = HMAC(sig_{n-1}, caveat_n)`
- The root signature is: `HMAC(root_key, identifier)`.
- Symmetric only -- no asymmetric signature support.

### Key Identification

- The **Identifier** field maps back to the root key on the issuing server.
- No standardized key ID or key hash mechanism.
- Third-party caveats embed encrypted key material.

### Token Size

- Base size: identifier + 32-byte HMAC signature.
- Grows with each added caveat (caveat string + HMAC chain step).
- Typically compact for simple use cases, but unbounded as caveats accumulate.

### Security Properties & Revocation

- **Attenuation without contacting issuer:** Anyone holding a macaroon can add first-party caveats to restrict it further. Caveats can only narrow scope, never widen it.
- **Third-party caveats** enable delegation requiring proof from external services.
- **No built-in revocation.** The server must maintain state to revoke the root key or identifier.
- **Symmetric only:** Verifiers must hold the root secret, preventing public/offline verification.
- Discharge macaroons are bound to the original macaroon to prevent reuse.

---

## 4. Biscuit

**Specification:** [Biscuit Specification](https://doc.biscuitsec.org/reference/specifications)
**Website:** [biscuitsec.org](https://www.biscuitsec.org/)

### Token Structure (Blocks, not flat claims)

Biscuit does not use flat key-value claims. Instead, it uses a Datalog-derived logic language.

| Component        | Description                                                  |
|------------------|--------------------------------------------------------------|
| Authority Block  | Created by issuer. Contains granted rights as Datalog facts/rules. |
| Attenuation Blocks | Added by holders. Contain checks that restrict scope.     |
| Proof            | Either the next ephemeral private key (for further attenuation) or a final seal signature. |

Each block contains:
- **Facts:** Data assertions (e.g., `right("file1", "read")`).
- **Rules:** Datalog rules that derive new facts.
- **Checks:** Queries that must succeed for authorization (e.g., `check if time($t), $t < 2025-01-01`).

### Wire Format

- **Protobuf** serialization for the outer structure.
- Datalog block content serialized within protobuf bytes fields.
- Transmitted as URL-safe Base64, optionally prefixed with `biscuit:`.

### Signature Algorithms

| Algorithm  | Curve/Type | Notes                                  |
|------------|------------|----------------------------------------|
| Ed25519    | Curve25519 | Default. 32-byte keys, 64-byte sigs.  |
| ECDSA P-256| secp256r1  | Also supported. RFC 6979 deterministic recommended. |

The algorithm is encoded in the public key protobuf message, not in the signed data itself. This avoids JWT-style algorithm confusion attacks.

### Key Identification

- `rootKeyId`: Optional field in the outer Biscuit message. Hint for selecting the correct root public key.
- Each block carries an ephemeral public key for chaining.
- Verification requires only the root public key.

### Token Size

- Minimal single-block token: ~249 bytes.
- Each additional block adds: serialized Datalog + 32-byte public key + 64-byte signature.
- Larger than a minimal JWT but carries richer authorization logic.

### Security Properties & Revocation

- **Public-key verification:** Any party with the root public key can verify.
- **Offline attenuation:** Holders can add restriction blocks without contacting the issuer.
- **Built-in revocation IDs:** Each block has a unique revocation identifier (64 bytes, derived from its signature). Allows revoking a token and all tokens attenuated from it.
- **No algorithm confusion:** Algorithm is bound to the key, not the message.
- **Datalog authorization:** Expressive policy language allows complex, composable authorization rules.
- **Sealed tokens:** Can be sealed to prevent further attenuation.

---

## 5. CWT (CBOR Web Token) -- RFC 8392

**Specification:** [RFC 8392](https://www.rfc-editor.org/rfc/rfc8392.html), with cryptography via [COSE (RFC 9052)](https://www.rfc-editor.org/rfc/rfc9052.html)

### Standard Registered Claims

| Claim | Key | Value Type    | Description                                        |
|-------|-----|---------------|----------------------------------------------------|
| `iss` | 1   | text string   | Issuer                                             |
| `sub` | 2   | text string   | Subject                                            |
| `aud` | 3   | text string   | Audience                                           |
| `exp` | 4   | int/float     | Expiration time (NumericDate)                      |
| `nbf` | 5   | int/float     | Not before (NumericDate)                           |
| `iat` | 6   | int/float     | Issued at (NumericDate)                            |
| `cti` | 7   | byte string   | CWT ID (equivalent to JWT `jti`)                   |

Claims mirror JWT exactly but use integer keys instead of strings for compactness. Additional claims are registered in the [IANA CWT Claims Registry](https://www.iana.org/assignments/cwt).

### Wire Format

- **Encoding:** CBOR (binary), protected by COSE structures.
- CBOR is a binary self-describing format designed for constrained environments.
- Integer map keys (1-7) instead of string keys ("iss", "sub", ...).
- No Base64 encoding needed -- native binary on the wire.

### Signature Algorithms (via COSE)

| Algorithm          | COSE alg ID | Type      | Notes                        |
|--------------------|-------------|-----------|------------------------------|
| ES256 (P-256)      | -7          | Signature | Primary recommended          |
| ES384 (P-384)      | -35         | Signature |                              |
| ES512 (P-521)      | -36         | Signature |                              |
| EdDSA              | -8          | Signature | Ed25519/Ed448                |
| HMAC-256/64        | 4           | MAC       | Truncated HMAC               |
| HMAC-256/256       | 5           | MAC       | Full HMAC-SHA256             |
| AES-CCM-16-64-128  | 10          | AEAD      | For constrained IoT          |

Algorithm identifiers are integers, not strings.

### Key Identification

- `kid` (Key ID): COSE header parameter (label 4), byte string. Matched against `kid` in `COSE_Key` structures.
- `COSE_Key` structures can carry full key material.
- Applications must not assume `kid` values are unique.

### Token Size

- Signed CWT with EC key: ~194 bytes.
- COSE header + ECDSA signature overhead: <90 bytes.
- Roughly 40-50% smaller than equivalent JWT due to binary encoding and integer keys.

### Security Properties & Revocation

- **Same security model as JWT** but with binary encoding efficiency.
- **No built-in revocation** -- same limitations as JWT.
- Designed for constrained IoT environments (low power, low bandwidth).
- COSE provides a cleaner separation of concerns than JOSE.
- Supports COSE_Sign (multiple signatures), COSE_Sign1 (single), COSE_Mac, COSE_Mac0, COSE_Encrypt, COSE_Encrypt0.

---

## Comparison Tables

### Temporal / Identity Claims

| Claim / Field        | JWT     | x509         | Macaroons        | Biscuit            | CWT     |
|----------------------|---------|--------------|------------------|--------------------|---------|
| Expiration           | `exp`   | Not After    | caveat (ad hoc)  | check (Datalog)    | `exp`   |
| Not Before           | `nbf`   | Not Before   | caveat (ad hoc)  | check (Datalog)    | `nbf`   |
| Issued At            | `iat`   | --           | --               | --                 | `iat`   |
| Issuer               | `iss`   | Issuer DN    | Location (hint)  | root key identity  | `iss`   |
| Subject              | `sub`   | Subject DN   | --               | facts (Datalog)    | `sub`   |
| Audience             | `aud`   | --           | caveat (ad hoc)  | check (Datalog)    | `aud`   |
| Unique ID            | `jti`   | Serial Number| Identifier       | revocation ID      | `cti`   |

### Encoding & Size

| Property             | JWT           | x509           | Macaroons       | Biscuit         | CWT            |
|----------------------|---------------|----------------|-----------------|-----------------|----------------|
| Payload encoding     | JSON          | ASN.1 DER      | Binary (V2)     | Protobuf        | CBOR           |
| Wire encoding        | Base64url text| DER or PEM     | Hex/Base64      | Base64url       | Raw binary     |
| Minimal token size   | ~300-400 B    | ~800-1000 B    | ~80-100 B       | ~249 B          | ~194 B         |
| Base64 overhead      | Yes (~33%)    | PEM only       | Varies          | Yes (~33%)      | No             |
| Human readable       | Partially     | No (needs tool)| No              | No              | No             |

### Cryptography

| Property             | JWT              | x509              | Macaroons    | Biscuit           | CWT              |
|----------------------|------------------|--------------------|--------------|-------------------|------------------|
| Symmetric MAC        | HS256/384/512    | --                 | HMAC-SHA256  | --                | HMAC-SHA256+     |
| ECDSA                | ES256/384/512    | P-256/384/521      | --           | P-256             | ES256/384/512    |
| EdDSA                | EdDSA (RFC 8037) | Ed25519, Ed448     | --           | Ed25519 (default) | EdDSA            |
| RSA                  | RS/PS 256/384/512| RSA-PKCS1, RSA-PSS | --           | --                | via COSE         |
| Algorithm in token   | Header (`alg`)   | SignatureAlgorithm | N/A (HMAC only) | In public key  | COSE header      |
| Alg confusion risk   | Yes (known issue)| Low                | N/A          | No (alg in key)   | Low              |

### Key Identification

| Mechanism            | JWT          | x509                | Macaroons      | Biscuit          | CWT            |
|----------------------|--------------|---------------------|----------------|------------------|----------------|
| Key ID (opaque)      | `kid` header | --                  | Identifier     | `rootKeyId`      | `kid` (label 4)|
| Key hash / thumbprint| `x5t` header | Authority Key ID ext| --             | --               | --             |
| Embedded public key  | `jwk` header | Subject Public Key  | --             | per-block pubkey | COSE_Key       |
| Key URL              | `jku`, `x5u` | AIA extension       | --             | --               | --             |
| Issuer+Serial        | --           | Issuer DN + Serial  | --             | --               | --             |

### Revocation & Delegation

| Property                | JWT              | x509           | Macaroons         | Biscuit            | CWT              |
|-------------------------|------------------|----------------|--------------------|--------------------|------------------|
| Built-in revocation     | No               | Yes (CRL, OCSP)| No                 | Yes (revocation ID)| No               |
| Offline attenuation     | No               | No             | Yes (add caveats)  | Yes (add blocks)   | No               |
| Delegation support      | No (app-level)   | Cert chains    | Third-party caveats| Block chaining     | No (app-level)   |
| Scope restriction       | No (app-level)   | Name constraints| First-party caveats| Datalog checks    | No (app-level)   |
| Requires issuer contact | No (verify)      | No (verify)    | No (attenuate)     | No (attenuate)    | No (verify)      |
| Verification key type   | Symmetric or public| Public (CA chain)| Symmetric (root)| Public (root)     | Symmetric or public|

---

## Key Takeaways for protoken-rs

1. **`exp`, `nbf`, `iat` are universal.** Every token format that deals with time includes expiration. Not-before and issued-at are common but not always mandatory. Starting with `expires_at` is sound; `not_before` and `issued_at` are natural next additions.

2. **`iss`, `sub`, `aud` are the core identity triple.** JWT, CWT, and x509 all include some form of these. Macaroons and Biscuit handle identity differently (through caveats/facts). For a minimal token, these can be deferred, but `aud` is particularly useful for preventing token misuse across services.

3. **A unique token ID (`jti`/`cti`/Serial Number) is important** for logging, replay prevention, and revocation. Biscuit's approach of deriving the revocation ID from the signature is elegant -- it requires no extra field.

4. **Binary encoding pays off.** CWT at ~194 bytes vs JWT at ~300-400 bytes for similar claims demonstrates the advantage of binary encoding. Protoken's protobuf approach should yield similar compactness to CWT.

5. **Key identification via hash is common and sufficient.** x509 uses Authority Key Identifier (a hash), JWT uses `kid` (opaque) or `x5t` (thumbprint). Protoken's 8-byte key hash is a reasonable compact approach. It is shorter than typical thumbprints (20-32 bytes) but sufficient for key lookup in a small key set.

6. **Algorithm agility is a double-edged sword.** JWT's broad algorithm support led to algorithm confusion attacks. Protoken's approach of supporting exactly one symmetric and one asymmetric algorithm is a good security decision. Biscuit's approach of binding the algorithm to the key (not the message) is worth noting.

7. **Revocation is the hardest problem.** Only x509 and Biscuit have built-in revocation. For short-lived tokens (the primary protoken use case), short expiration times may be sufficient. A token ID field would enable external revocation lists if needed later.

8. **Attenuation/delegation is powerful but adds complexity.** Macaroons and Biscuit both support offline attenuation. This is out of scope for protoken's minimal design but could be a future consideration.

9. **Ed25519 vs P-256:** Both are widely supported across these formats. Ed25519 offers faster signing/verification and deterministic signatures (no nonce-reuse risk). P-256 has broader FIPS/NIST compliance. Biscuit defaults to Ed25519; COSE/CWT and x509 support both.

## References

- [RFC 7519 - JSON Web Token (JWT)](https://www.rfc-editor.org/rfc/rfc7519)
- [RFC 7518 - JSON Web Algorithms (JWA)](https://tools.ietf.org/html/rfc7518)
- [RFC 8037 - CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JOSE](https://tools.ietf.org/html/rfc8037)
- [RFC 5280 - Internet X.509 PKI Certificate and CRL Profile](https://www.rfc-editor.org/rfc/rfc5280)
- [RFC 6960 - X.509 OCSP](https://datatracker.ietf.org/doc/html/rfc6960)
- [Macaroons: Cookies with Contextual Caveats (Google Research)](https://research.google/pubs/macaroons-cookies-with-contextual-caveats-for-decentralized-authorization-in-the-cloud/)
- [libmacaroons](https://github.com/rescrv/libmacaroons)
- [Biscuit Specification](https://doc.biscuitsec.org/reference/specifications)
- [Biscuit Cryptography](https://doc.biscuitsec.org/reference/cryptography.html)
- [RFC 8392 - CBOR Web Token (CWT)](https://www.rfc-editor.org/rfc/rfc8392.html)
- [RFC 9052 - COSE Structures and Process](https://www.rfc-editor.org/rfc/rfc9052.html)
- [IANA CWT Claims Registry](https://www.iana.org/assignments/cwt)
