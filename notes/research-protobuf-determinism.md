# Research: Protobuf Deterministic Serialization

## 1. Sources of Non-Determinism in Protobuf Encoding

The official protobuf documentation explicitly states: "proto serialization is not (and cannot
be) canonical." ([Proto Serialization Is Not Canonical](https://protobuf.dev/programming-guides/serialization-not-canonical/))

There are **seven** sources of non-determinism in protobuf encoding:

### 1.1 Field Ordering
The spec says: "there is no guaranteed order for how its known or unknown fields will be
written. Serialization order is an implementation detail." In practice, most implementations
serialize in field-number order, but this is not mandated.

### 1.2 Map Ordering
Maps are the **primary** source of non-determinism. They are encoded as repeated key-value
messages, and the iteration order of the backing map data structure (HashMap vs BTreeMap vs
std::map) is implementation-dependent and often non-deterministic.

### 1.3 Unknown Fields
When a parser encounters fields it doesn't recognize, proto2 and proto3 (since 3.5)
preserve them. These unknown fields get re-serialized, but their position in the output is
undefined. This is a cross-version problem: if Service A sends a message with field 10 to
Service B (which doesn't know about field 10), Service B's re-serialization may place field
10 in a different position.

### 1.4 Varint Encoding Length
Varints can be zero-padded: the value `1` can be encoded as `01`, `81 00`, `81 80 00`, etc.
All decode to the same value. Implementations *should* use minimal encoding, but the spec
does not require it.

### 1.5 Default Value Presence
In proto3, fields set to their default value (0 for integers, empty for bytes/strings) may
be omitted or explicitly encoded. Both decode identically. Example: `uint32 version = 1`
with value 0 could be encoded as `08 00` (2 bytes) or omitted entirely (0 bytes).

### 1.6 Packed vs Unpacked Repeated Fields
Repeated scalar fields can be encoded packed (single length-delimited record) or unpacked
(individual records per element). Both are valid.

### 1.7 Duplicate Fields
The same non-repeated field can appear multiple times. The spec says "the last value is used."
This means a serializer could emit field 1 twice with different values and it would be valid.

## 2. Deterministic Serialization Mode

### Official Support by Language

| Language | API | Guarantee |
|----------|-----|-----------|
| C++ | `MessageLite::SerializeWithCachedSizes()` + `SetSerializationDeterministic(true)` | Same binary only |
| Java | `CodedOutputStream.useDeterministicSerialization()` | Same binary only |
| Python | `SerializeToString(deterministic=True)` | Same binary only |
| Go | Default behavior (fields in number order, maps sorted) | De facto deterministic |
| Rust (prost) | No explicit API; de facto field-order encoding | No formal guarantee |
| Rust (rust-protobuf) | No explicit API | No formal guarantee |

**Critical limitation**: Even with deterministic mode enabled, the output is NOT canonical
across languages and NOT stable across library versions. The official docs state:
"Deterministic serialization only guarantees the same byte output for a particular binary."

### Cosmos SDK ADR-027

The most rigorous community specification for deterministic protobuf serialization is
[Cosmos SDK ADR-027](https://docs.cosmos.network/main/build/architecture/adr-027-deterministic-protobuf-serialization).
It defines these rules:

1. Fields serialized **once**, in **ascending field-number order**
2. **No extra fields** or extra data
3. Fields set to **default values must be omitted**
4. Repeated scalar fields use **packed encoding**
5. Varints use **minimal encoding** (no zero-padding)
6. **No maps** (rejected as too complex for v1)

The output is valid protobuf that any parser can decode.

### Canonical Proto3 (regen-network)

The [canonical-proto3](https://github.com/regen-network/canonical-proto3) project defines
similar rules for cryptographic signing contexts. Same core principles as ADR-027.

## 3. What the Protobuf Spec Says About Canonical Encoding

The spec says **nothing** about canonical encoding. It explicitly disclaims it:

> "Unfortunately, protobuf serialization is not (and cannot be) canonical."

The reasons:
- Unknown fields cannot be canonicalized (bytes and sub-messages share wire type 2, so you
  can't know whether to recurse into an unknown field to canonicalize it)
- Serialization order is intentionally undefined to allow optimization
- The spec permits valid encodings that differ byte-for-byte

## 4. Proto3 Wire Format for Fixed-Width Messages

### Wire Types

| ID | Type | Used For |
|----|------|----------|
| 0 | VARINT | uint32, uint64, int32, int64, sint32, sint64, bool, enum |
| 1 | I64 | fixed64, sfixed64, double |
| 2 | LEN | string, bytes, embedded messages, packed repeated |
| 5 | I32 | fixed32, sfixed32, float |

### Field Tag Encoding

Each field is preceded by a tag: `(field_number << 3) | wire_type`

For field numbers 1-15, the tag fits in a **single byte** (since 15 << 3 = 120 < 128).
Field numbers 16-2047 require 2-byte varint tags.

### Tags for Our Message

```
message PayloadV1 {
  uint32 version = 1;      // tag = (1 << 3) | 0 = 0x08
  uint32 algorithm = 2;    // tag = (2 << 3) | 0 = 0x10
  uint32 key_id_type = 3;  // tag = (3 << 3) | 0 = 0x18
  bytes key_id = 4;        // tag = (4 << 3) | 2 = 0x22
  uint64 expires_at = 5;   // tag = (5 << 3) | 0 = 0x28
  uint64 not_before = 6;   // tag = (6 << 3) | 0 = 0x30
  uint64 issued_at = 7;    // tag = (7 << 3) | 0 = 0x38
  bytes subject = 8;       // tag = (8 << 3) | 2 = 0x42
  bytes audience = 9;      // tag = (9 << 3) | 2 = 0x4A
}
```

All tags are single bytes since all field numbers are <= 15.

### Is This Deterministic If We Control the Implementation?

**Yes**, with caveats. For a message with:
- No maps
- No oneof
- No unknown fields
- All scalar types (uint32, uint64, bytes)
- Field numbers 1-15

The encoding is deterministic **in practice** across all mainstream protobuf libraries because:
1. Fields are encoded in field-number order (universal implementation behavior)
2. Minimal varint encoding is used (standard algorithm produces minimal output)
3. `bytes` fields use wire type 2 with a varint length prefix (unambiguous)
4. Proto3 default elision is consistent (0/empty always omitted)

The risk is that this relies on implementation behavior, not spec guarantees. A conforming
protobuf library *could* change field ordering in a future version.

## 5. Varint Encoding Deep Dive

### Algorithm

Varints encode unsigned integers using 7 bits per byte, with the MSB as a continuation flag:
- MSB = 1: more bytes follow
- MSB = 0: this is the last byte
- Bytes are in **little-endian** order (least significant group first)

```
encode(value):
  while value > 0x7F:
    emit byte: (value & 0x7F) | 0x80
    value >>= 7
  emit byte: value & 0x7F
```

### Size Table

| Value Range | Varint Bytes |
|-------------|-------------|
| 0 - 127 (2^7 - 1) | 1 |
| 128 - 16,383 (2^14 - 1) | 2 |
| 16,384 - 2,097,151 (2^21 - 1) | 3 |
| 2,097,152 - 268,435,455 (2^28 - 1) | 4 |
| 268,435,456 - 34,359,738,367 (2^35 - 1) | 5 |
| ... | ... |
| 2^63 - 2^64-1 | 10 |

### Examples for Field Tags (field numbers 1-15)

Tags for field numbers 1-15 with wire type 0 (VARINT):
```
Field 1: (1 << 3) | 0 = 8   = 0x08  (1 byte)
Field 2: (2 << 3) | 0 = 16  = 0x10  (1 byte)
Field 3: (3 << 3) | 0 = 24  = 0x18  (1 byte)
Field 5: (5 << 3) | 0 = 40  = 0x28  (1 byte)
Field 6: (6 << 3) | 0 = 48  = 0x30  (1 byte)
Field 7: (7 << 3) | 0 = 56  = 0x38  (1 byte)
```

Tags with wire type 2 (LEN):
```
Field 4: (4 << 3) | 2 = 34  = 0x22  (1 byte)
Field 8: (8 << 3) | 2 = 66  = 0x42  (1 byte)
Field 9: (9 << 3) | 2 = 74  = 0x4A  (1 byte)
```

### Example: Varint Encoding of 1700000000 (Unix timestamp)

```
1700000000 = 0x6553F100

Step 1: 1700000000 & 0x7F = 0   → byte: 0x80 (continuation)
Step 2: 13281250   & 0x7F = 98  → byte: 0xE2 (0x62 | 0x80)
Step 3: 103759     & 0x7F = 79  → byte: 0xCF (0x4F | 0x80)
Step 4: 810        & 0x7F = 42  → byte: 0xAA (0x2A | 0x80)
Step 5: 6          & 0x7F = 6   → byte: 0x06 (final)

Result: 80 E2 CF AA 06  (5 bytes)
```

Timestamps in the range 2020-2100 (~1.6B to ~4.1B) all fit in 5 varint bytes.

### Example: Varint Encoding of Small Values (1, 2)

```
Value 1: 0x01  (1 byte)
Value 2: 0x02  (1 byte)
```

## 6. Byte-Level Encoding of a Typical PayloadV1

### Example Values

```
version      = 0          (default → OMITTED per proto3 rules)
algorithm    = 1          (HMAC-SHA256)
key_id_type  = 1          (key_hash)
key_id       = [01 02 03 04 05 06 07 08]  (8 bytes)
expires_at   = 1700000000 (Nov 14, 2023 22:13:20 UTC)
not_before   = 1699990000
issued_at    = 1699990000
subject      = ""         (default → OMITTED)
audience     = ""         (default → OMITTED)
```

### Byte-by-Byte Encoding

```
Offset  Hex                            Field
──────  ───                            ─────
0       10                             tag: field 2 (algorithm), wire type 0
1       01                             varint: 1
2       18                             tag: field 3 (key_id_type), wire type 0
3       01                             varint: 1
4       22                             tag: field 4 (key_id), wire type 2
5       08                             length varint: 8
6-13    01 02 03 04 05 06 07 08        key_id bytes
14      28                             tag: field 5 (expires_at), wire type 0
15-19   80 E2 CF AA 06                 varint: 1700000000
20      30                             tag: field 6 (not_before), wire type 0
21-25   F0 93 CF AA 06                 varint: 1699990000
26      38                             tag: field 7 (issued_at), wire type 0
27-31   F0 93 CF AA 06                 varint: 1699990000
```

**Total: 32 bytes** (with all three timestamps and 8-byte key_hash, no optional fields)

### Verification of not_before/issued_at varint (1699990000)

```
1699990000 = 0x6553B9F0

Step 1: 1699990000 & 0x7F = 112 → byte: 0xF0 (0x70 | 0x80)
Step 2: 13281172   & 0x7F = 19  → wait...
```

Verified:
```
1699990000 = 0x6553C9F0 → varint: F0 93 CF AA 06  (5 bytes)
```

### Full Hex Dump

```
10 01 18 01 22 08 01 02 03 04 05 06 07 08 28 80
E2 CF AA 06 30 F0 93 CF AA 06 38 F0 93 CF AA 06
```

### Variant: With subject = "user:alice" (10 bytes)

Additional bytes at the end:
```
32      42                             tag: field 8 (subject), wire type 2
33      0A                             length varint: 10
34-43   75 73 65 72 3A 61 6C 69 63 65 "user:alice" in UTF-8
```

**Total: 44 bytes** (32 + 12 for subject)

### Variant: With 32-byte public key instead of 8-byte key_hash

Field 4 becomes: `22 20 [32 bytes]` (34 bytes instead of 10 bytes)

**Total: 56 bytes** (no optional fields)

### Size Comparison with Current Custom Format

| Configuration | Custom v0 | Proto3 Canonical | Difference |
|---------------|-----------|-----------------|------------|
| HMAC + key_hash + expires_at only | 19 B | 20 B* | +1 B |
| HMAC + key_hash + 3 timestamps | N/A | 32 B | -- |
| Ed25519 + key_hash + 3 timestamps | N/A | 32 B | -- |
| Ed25519 + pubkey + 3 timestamps | N/A | 56 B | -- |
| Any + key_hash + 3 timestamps + subject(10) | N/A | 44 B | -- |

*Proto3 is 1 byte larger because of the length-prefix on key_id bytes field.

**Note on version=0**: Since proto3 omits default values, `version=0` is represented by the
absence of field 1. This is fine: version 0 is the implicit default. Future versions (1, 2, ...)
add 2 bytes: `08 01` or `08 02`.

## 7. Could We Use Proto3 Wire Format as Our Canonical Encoding?

### Proposed Canonical Rules (following ADR-027)

We could define our canonical encoding as:

> **Protoken Canonical Encoding**: Proto3 wire format with these constraints:
> 1. Fields serialized exactly once, in ascending field-number order
> 2. Varints use minimal encoding (no zero-padding)
> 3. Fields set to proto3 default values (0, empty bytes) are omitted
> 4. No unknown fields permitted
> 5. No map fields permitted (none in our schema)
> 6. `bytes` fields use wire type 2 with minimal-length varint prefix

This produces a fully deterministic, documentable byte format. The output is valid proto3
that any protobuf parser can decode.

### Advantages over Current Custom Format

1. **Self-describing to anyone who knows protobuf**: Field tags encode field numbers and wire types
2. **No custom parser needed**: Any proto3 library can decode the payload
3. **Extensible without version bumps**: New fields at the end are backward-compatible
   (old parsers skip unknown fields with known wire types)
4. **Variable-length encoding saves space**: Timestamps use 5-6 bytes instead of fixed 8
5. **Widely understood format**: Easier to audit, implement in other languages, debug
6. **Tools exist**: `protoc --decode_raw` can inspect any payload without a schema

### Disadvantages vs Current Custom Format

1. **~1-2 bytes larger** for the simplest case (length prefix overhead on bytes fields)
2. **Varint encoding is variable-width**: Same field can have different byte lengths depending
   on value (e.g., expires_at in year 2024 = 5 bytes, but in year 10000 = 6 bytes). This
   makes fixed-offset parsing impossible without walking the varints.
3. **Relies on implementation behavior**: While prost/go/C++ all serialize in field-number
   order with minimal varints, this is not spec-guaranteed. We'd document our canonical rules
   and test against them.
4. **Default value elision means version=0 is invisible**: Can't distinguish "version is 0"
   from "version field is absent." (This is acceptable for our versioning scheme.)

### Risks

The primary risk is that a future prost version changes serialization order (extremely
unlikely but possible). Mitigations:
- Pin prost version in Cargo.lock
- Write test vectors that verify exact byte output
- Consider implementing a small canonical encoder ourselves (simple for our message shape)

## 8. Rust Crate Analysis

### prost (tokio-rs/prost)

- **Encoding order**: Fields encoded in struct declaration order (= field number order for
  generated code). This is an implementation detail, not a guarantee.
- **Varint encoding**: Uses minimal encoding (standard algorithm).
- **Default values**: Proto3 default elision is implemented (0/empty omitted).
- **Unknown fields**: **Discarded** during decode (issue #2, open since 2017). This is
  actually beneficial for our use case -- no unknown fields in re-serialized output.
- **Maps**: Uses `HashMap` by default (non-deterministic). Can configure `BTreeMap` for
  deterministic map serialization.
- **Formal determinism guarantee**: **None**. Issue #965 is open requesting this. Maintainer
  is receptive but waiting for a contributor to build a test suite.
- **Downloads**: ~30M/month, the dominant Rust protobuf library.

### stepancheg/rust-protobuf

- **Encoding order**: Field number order (implementation detail).
- **Unknown fields**: Preserved by default (unlike prost). This could be a source of
  non-determinism if roundtripping.
- **Formal determinism guarantee**: None.
- **Status**: Approaching end-of-life. An official Google protobuf Rust implementation is
  in development.
- **Downloads**: ~1M/month. Much less popular than prost.

### Recommendation for Protoken

If we switch to proto3 wire format, **prost is the right choice** because:
1. It's the dominant Rust protobuf library
2. It discards unknown fields (good for our canonical encoding)
3. De facto deterministic for messages without maps
4. Well-maintained by the tokio team

We should:
- Use prost for code generation
- Write exhaustive test vectors that pin the exact byte output
- Document our canonical encoding rules explicitly
- Consider a thin wrapper that validates output matches our canonical rules

## 9. Comparison: Custom Format vs Proto3 Canonical for Protoken

### Token Sizes (Payload + Signature)

For HMAC-SHA256 + key_hash (the common case):

| Format | Payload | + HMAC Sig (32B) | + Ed25519 Sig (64B) |
|--------|---------|-----------------|---------------------|
| Custom v0 (expires_at only) | 19 B | 51 B | 83 B |
| Proto3 canonical (3 timestamps) | 32 B | 64 B | 96 B |
| Proto3 canonical (3 timestamps + subject 10B) | 44 B | 76 B | 108 B |

Proto3 canonical with 3 timestamps is 13 bytes larger than custom v0 with 1 timestamp.
But we're adding 2 more timestamp fields, which accounts for 12 of those 13 bytes
(tag + varint each). The overhead of proto3 framing is minimal.

## 10. Conclusion

**Proto3 wire format CAN be made deterministic** for our specific message type (no maps, no
oneof, no unknown fields, field numbers 1-15). The Cosmos SDK has proven this approach works
at scale for blockchain signing.

The encoding is ~1-2 bytes larger than a hand-rolled fixed format for equivalent fields, but
gains significant benefits in interoperability, tooling, and extensibility.

If we adopt this approach, we should:
1. Define our canonical rules explicitly (based on Cosmos ADR-027)
2. Use prost for serialization with pinned test vectors
3. Verify byte-for-byte output in CI
4. Document that we treat proto3 field-number-order, minimal-varint, default-elision encoding
   as our canonical wire format

## References

- [Proto Serialization Is Not Canonical](https://protobuf.dev/programming-guides/serialization-not-canonical/) - Official protobuf docs
- [Encoding Guide](https://protobuf.dev/programming-guides/encoding/) - Official wire format specification
- [Cosmos SDK ADR-027](https://docs.cosmos.network/main/build/architecture/adr-027-deterministic-protobuf-serialization) - Deterministic serialization for blockchain signing
- [Canonical Proto3](https://github.com/regen-network/canonical-proto3) - Community canonical encoding rules
- [Notes on Protocol Buffers and Deterministic Serialization](https://gist.github.com/kchristidis/39c8b310fd9da43d515c4394c3cd9510) - Community analysis
- [Deterministic Protocol Buffers Serialization (xenoscopic)](https://xenoscopic.com/posts/deterministic-protobuf) - Practical analysis
- [prost Issue #965: Deterministic Serialization](https://github.com/tokio-rs/prost/issues/965) - Feature request
- [prost Issue #2: Unknown Fields](https://github.com/tokio-rs/prost/issues/2) - Unknown field handling
- [Demystifying the Protobuf Wire Format (Kreya)](https://kreya.app/blog/protocolbuffers-wire-format/) - Wire format tutorial
