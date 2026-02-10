# protoken-rs: Protobuf based Tokens in Rust

Protokens are designed to be a simple, fast replacemenmt for JWTs, ad hoc tokens, or in some cases x509 certificates. 

## Design Guidelines
1. The wire format of the tokens will be defined as [Protocol Buffers](https://protobuf.dev/) (protobufs) using proto3.
2. These will be signed tokens that support a single symmetric MAC and a single asymmetric signature option.
3. The symmetric MAC will be HMAC-SHA256.
4. The asymmetric signature will either be P-256 or Ed25519. We will consider performance, token size, and whether Ed25519 signatures would meet NIST or FIPS standards before settling on one.
5. The implementation will be in Rust
6. The goal is to have a minimal token format. We want to start simple and add only fields that are essential to our use cases. We'll start with a set of basic expiry claims:
```
syntax = "proto3";

message Claims {
  uint64 expires_at = 1; // NumericDate per RFC 7519
  // More claims to go here as we evolve a design
}
```
7. There will be a key metadata type to allow verifiers to locate the correct key:
```
syntax = "proto3";

enum Version {
  VERSION_0 = 0;
}

enum Algorithm {
  ALGORITHM_UNSPECIFIED = 0;
  ALGORITHM_HMAC_SHA256 = 1;
  ALGORITHM_P256 = 2; // Or  ALGORITHM_ED25519 = 2;
}

message KeyHash {
  bytes value = 1 [(buf.validate.field).bytes.len = 8];
}

message PublicKey {
  bytes value = 1;
}

message KeyIdentifier {
  oneof kind {
    KeyHash key_hash = 1;
    PublicKey public_key = 2;
  }
}

message Metadata {
  Version version = 1;
  Algorithm algorithm = 2;
  KeyIdentifier key_identifier = 3;
}
```
8. A Payload will be KeyMetdata and claims:
```
message Payload {
  Metadata metadata = 1;
  Claims claims = 2;
}
```
9. We need a deterministic payload serialization / deserialization method that will always produce idential bytes from a payload with identical fields. Protobuf has implementation dependent functions. Whatever we use, we must be able to briefly describe the serialized format. For example, it may be on the wire:
[ one-byte version | one-byte algorithm | key identifier | 8-byte expires_at ] 
10. The token will be an envelope around these claims with
```
message SignedToken {
  bytes serialized_payload = 1;
  bytes signature = 2;  // sign over preceding fields
}
```
11. This SignedToken should also have a universal serialized format, which is just the payload with the signature at the end.

## TODO

1. Create a minimal version of this that we can build from.
2. Start out with just serialization / deserialization
3. Have a command line tool that can take byte string and attempt to deserialize it as either a Payload or a Signed Token. Since the first version is all fixed length fields, this should be easy. Display it to the screen as a JSON which can be piped to jq. 
4. We should have a signing interface that can take the constituent fields, which in the first version will just be expires_at.
5. We should have a command line tool that can take a signing key and a humantime value like "4d" interpreted as a duration to produce a token that is valid from the current time for the duration.
6. We should have a verification interface that takes a signed token and a verification key, verifies that the key matches the key_hash, and returns the deserialized claims as JSON using the same mechanism we already built.
7. Have the command line tool be able to take a verification key and validate a token against the current time.
8. Set up test vectors and unit tests. Use mock clocks to test cases where tokens are expired. Also test corrupting every field of a signed token in isolation and verifying that they will be rejected as expected.

## Research Prior Art

Research prior art: JWT, x509, Macaroons, Biscuits, CWTs. Look at all their standard fields or claims. Create a table comparing what is common across them and what is unique. 

