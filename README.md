# protoken-rs

Minimal signed tokens as an alternative to JWTs. Binary wire format, HMAC-SHA256 or Ed25519 signatures, 51-107 bytes per token.

## Wire Format (v0)

### Payload

Fixed-layout binary. All multi-byte integers are big-endian. No length prefixes — every field size is determined by earlier fields.

```
Offset  Size  Field         Values
------  ----  -----         ------
0       1     version       0x00
1       1     algorithm     0x01 = HMAC-SHA256, 0x02 = Ed25519
2       1     key_id_type   0x01 = key_hash, 0x02 = public_key
3       N     key_id        N depends on (algorithm, key_id_type)
3+N     8     expires_at    uint64 big-endian, Unix seconds
```

Key identifier sizes:

| key_id_type | Size | Description |
|-------------|------|-------------|
| key_hash (0x01) | 8 bytes | SHA-256(key_material)[0..8] |
| public_key (0x02) | 32 bytes | Raw Ed25519 public key |

HMAC-SHA256 tokens always use `key_hash`. Ed25519 tokens may use either.

### Signed Token

```
[ payload_bytes | signature ]
```

No delimiter — the parser reads byte 1 (algorithm) to determine the signature length, then splits from the end.

| Algorithm | Signature size |
|-----------|---------------|
| HMAC-SHA256 | 32 bytes |
| Ed25519 | 64 bytes |

### Token Sizes

| Configuration | Payload | Sig | Total |
|---|---|---|---|
| HMAC-SHA256 + key_hash | 19 B | 32 B | **51 B** |
| Ed25519 + key_hash | 19 B | 64 B | **83 B** |
| Ed25519 + public_key | 43 B | 64 B | **107 B** |

### Key Hash

```
key_hash = SHA-256(key_material)[0..8]
```

For HMAC: hash the raw symmetric key. For Ed25519: hash the 32-byte public key. The 8-byte truncation is for key *identification* only — it lets the verifier select the right key from a set.

### Test Vectors

Stored in `testdata/v0_vectors.json`. Example HMAC token (51 bytes):

```
Key (ASCII): protoken-test-vector-key-do-not-use-in-production!!
expires_at:  1700000000 (2023-11-14T22:13:20Z)

Payload (19 bytes):
  00                              version = 0
  01                              algorithm = HMAC-SHA256
  01                              key_id_type = key_hash
  66 b0 78 77 8e ab 1c d4        key_hash
  00 00 00 00 65 53 f1 00        expires_at = 1700000000

HMAC-SHA256 signature (32 bytes):
  5d 1c 04 15 f5 77 1c 16  da d2 19 76 48 80 5c 98
  40 52 1e d5 5e e1 54 7d  07 80 e0 20 9d 87 22 41

Full token (hex):
  00010166b078778eab1cd4000000006553f100
  5d1c0415f5771c16dad2197648805c9840521ed55ee1547d0780e0209d872241
```

## CLI

```sh
# Generate an Ed25519 key pair
protoken generate-key

# Sign (HMAC)
protoken sign -a hmac -k keyfile -d 4d

# Sign (Ed25519)
protoken sign -a ed25519 -k private.pkcs8 -d 1h

# Verify
protoken verify -a hmac -k keyfile -t <token>

# Inspect (no key needed)
protoken inspect -t <token>
```

Token input/output accepts hex or base64url (no padding).
