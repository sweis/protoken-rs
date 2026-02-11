# protoken-rs

Minimal signed tokens as an alternative to JWTs. Binary wire format using canonical proto3 encoding, HMAC-SHA256 or Ed25519 signatures.

## Wire Format — Canonical Proto3

Payloads use proto3 wire encoding with canonical rules: fields in ascending order, minimal varints, default values omitted. The output is valid proto3 that any protobuf library can decode, but is also simple enough to parse without one.

### Proto3 Schema

```proto
message Payload {
  uint32 version = 1;      // reserved, always 0 (omitted on wire)
  uint32 algorithm = 2;    // 1 = HMAC-SHA256, 2 = Ed25519
  uint32 key_id_type = 3;  // 1 = key_hash, 2 = public_key
  bytes  key_id = 4;       // 8 bytes (key_hash) or 32 bytes (public_key)
  uint64 expires_at = 5;   // Unix seconds
  uint64 not_before = 6;   // optional (0 = omitted)
  uint64 issued_at = 7;    // optional (0 = omitted)
  string subject = 8;      // optional (empty = omitted), max 255 bytes
  string audience = 9;     // optional (empty = omitted), max 255 bytes
  repeated string scope = 10; // optional, sorted, max 32 entries
}

message SignedToken {
  Payload payload = 1;     // canonical-encoded Payload submessage
  bytes   signature = 2;   // HMAC-SHA256 (32 bytes) or Ed25519 (64 bytes)
}
```

### Payload Wire Format

Each field is a single-byte tag followed by the value. Tags encode `(field_number << 3) | wire_type`:

```
Tag   Field          Wire Type  Encoding
---   -----          ---------  --------
0x08  version        varint     reserved (omitted when 0)
0x10  algorithm      varint     0x01 = HMAC, 0x02 = Ed25519
0x18  key_id_type    varint     0x01 = key_hash, 0x02 = public_key
0x22  key_id         LEN        varint length + raw bytes
0x28  expires_at     varint     Unix timestamp
0x30  not_before     varint     omitted if 0
0x38  issued_at      varint     omitted if 0
0x42  subject        LEN        UTF-8 string, omitted if empty
0x4A  audience       LEN        UTF-8 string, omitted if empty
0x52  scope          LEN        repeated, sorted, omitted if empty
```

Varint encoding: 7 bits per byte, MSB = continuation flag, little-endian byte order. Values 0-127 fit in 1 byte. Timestamps (~1.7B-4.1B) fit in 5 bytes.

### Canonical Encoding Rules

1. Fields serialized in ascending field-number order (once each, except repeated fields)
2. Varints use minimal encoding (no zero-padding)
3. Fields set to default values (0, empty bytes) are **omitted**
4. No unknown fields
5. `bytes`/`string` fields use wire type 2 with minimal-length varint prefix
6. Repeated fields (`scope`) appear consecutively, sorted lexicographically, no duplicates

### SignedToken Wire Format

```
0A <varint:payload_len> <canonical_payload_bytes> 12 <varint:sig_len> <signature_bytes>
```

The signature is computed over `<canonical_payload_bytes>` — the exact bytes inside field 1.

### Annotated Example: HMAC Token

```
Payload (20 bytes):
  10 01           algorithm = HMAC-SHA256
  18 01           key_id_type = key_hash
  22 08           key_id: 8 bytes follow
    66 b0 78 77 8e ab 1c d4
  28 80 e2 cf aa 06   expires_at = 1700000000

SignedToken envelope:
  0A 14           field 1 (payload): 20 bytes follow
    <20 payload bytes>
  12 20           field 2 (signature): 32 bytes follow
    <32 HMAC-SHA256 bytes>

Total: 56 bytes
```

### Token Sizes

| Configuration | Payload | Sig | Total |
|---|---|---|---|
| HMAC + key_hash (minimal) | ~20 B | 32 B | ~56 B |
| HMAC + key_hash + sub/aud | ~50 B | 32 B | ~86 B |
| Ed25519 + key_hash (minimal) | ~20 B | 64 B | ~88 B |
| Ed25519 + public_key + sub/aud | ~70 B | 64 B | ~138 B |

Sizes vary by 1-2 bytes depending on varint-encoded timestamp values.

## Key Hash

```
key_hash = SHA-256(key_material)[0..8]
```

For HMAC: hash the raw symmetric key. For Ed25519: hash the 32-byte public key. The 8-byte truncation is for key *identification* only.

## Test Vectors

Stored in `testdata/vectors.json`. Regenerate with `cargo run --bin gen_test_vectors`.

## CLI

```sh
# Generate an Ed25519 key pair
protoken generate-key

# Sign a token
protoken sign -a hmac -k keyfile -d 4d --subject "user:alice" --audience "api" --scope read --scope write

# Sign with Ed25519
protoken sign -a ed25519 -k private.pkcs8 -d 1h

# Verify
protoken verify -a hmac -k keyfile -t <token>

# Inspect (no key needed)
protoken inspect -t <token>
```

Token input/output accepts hex or base64url (no padding).
