# Deterministic Serialization Format

## Problem

Protobuf encoding is implementation-dependent and not guaranteed to produce identical bytes for identical messages. Since we sign over the serialized payload, we need a canonical byte-level format.

## Design: Fixed-Layout Binary Format

All multi-byte integers are big-endian. No length prefixes are needed for v0 since all fields have known sizes.

### Payload Wire Format (v0)

```
Offset  Size  Field
──────  ────  ─────
0       1     version        (0x00 for VERSION_0)
1       1     algorithm      (0x01 = HMAC-SHA256, 0x02 = Ed25519)
2       1     key_id_type    (0x01 = key_hash, 0x02 = public_key)
3       N     key_id_value   (8 bytes for key_hash; algo-dependent for public_key)
3+N     8     expires_at     (uint64 big-endian, Unix timestamp in seconds)
```

For the common case of `key_hash` (8 bytes), the payload is exactly **19 bytes**:

```
[ 0x00 | algo | 0x01 | 8-byte key_hash | 8-byte expires_at ]
```

For `public_key`, the key size is determined by the algorithm:
- Ed25519 public key: 32 bytes → payload = 43 bytes

### SignedToken Wire Format

```
[ payload_bytes | signature_bytes ]
```

The signature length is fully determined by the algorithm byte (offset 1):
- `0x01` HMAC-SHA256: 32 bytes
- `0x02` Ed25519: 64 bytes

**Parsing strategy:** Read byte 1 to determine algorithm → derive signature length → split `total_len - sig_len` to get payload bytes and signature bytes.

### Token Sizes

| Configuration               | Payload | Signature | Total |
|-----------------------------|---------|-----------|-------|
| HMAC-SHA256 + key_hash      | 19 B    | 32 B      | 51 B  |
| Ed25519 + key_hash          | 19 B    | 64 B      | 83 B  |
| Ed25519 + public_key        | 43 B    | 64 B      | 107 B |

For comparison, a minimal JWT with HMAC-SHA256 is ~150+ bytes due to Base64 + JSON overhead.

### Key Hash Computation

`key_hash = SHA-256(key_material)[0..8]`

- For HMAC: hash the raw symmetric key bytes
- For Ed25519: hash the public key (32 bytes)

The 8-byte truncated hash is for key *identification* only (not security). It lets the verifier locate the correct key from a set of candidates.

### Determinism Guarantees

This format is deterministic because:
1. All fields have fixed positions (no reordering)
2. All integers use big-endian (no platform-dependent encoding)
3. No optional fields in v0 (no presence/absence ambiguity)
4. No padding or alignment bytes
5. Key size is fully determined by (algorithm, key_id_type)

### Extensibility

When new claims are added (e.g., `not_before`, `issued_at`, `subject`), the version byte will increment to `0x01` and the payload format will be extended. The parser uses the version byte to select the appropriate deserialization logic. This gives us full control over the wire format for each version without needing protobuf's encoding.

### Relationship to Protobuf

We still define `.proto` files for documentation and potential interop, but the on-the-wire format for signing/verification uses this custom deterministic layout. The proto definitions serve as the canonical schema; this document defines the canonical encoding.
