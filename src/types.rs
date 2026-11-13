use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::ProtokenError;

/// Maximum length for subject, audience, and individual scope fields (bytes).
pub const MAX_CLAIM_BYTES_LEN: usize = 255;
/// Maximum number of scope entries.
pub const MAX_SCOPES: usize = 32;
/// Maximum size of the envelope payload (serialized Claims).
pub const MAX_PAYLOAD_BYTES: usize = 4096;
/// Largest signature of any algorithm (SLH-DSA-SHA2-256s).
pub const MAX_SIGNATURE_BYTES: usize = 29_792;
/// Largest public key of any algorithm (ML-DSA-87).
pub const MAX_PUBLIC_KEY_BYTES: usize = 2592;
/// Largest secret key of any algorithm (FN-DSA-1024).
pub const MAX_SECRET_KEY_BYTES: usize = 2369;

/// The SHA-384 output size.
pub const HMAC_MIN_KEY_LEN: usize = 48;
/// The SHA-384 block size. HMAC hashes longer keys down to 48 bytes, so they
/// add no strength.
pub const HMAC_MAX_KEY_LEN: usize = 128;
pub const KEY_HASH_LEN: usize = 8;

/// Token format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[repr(u8)]
pub enum Version {
    V0 = 0,
}

/// Signing algorithm. Serializes to its canonical name (see [`Algorithm::name`]).
///
/// FN-DSA is experimental: FIPS 206 is unpublished, so its keys and signatures
/// may stop working in a later release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(into = "&str", try_from = "String")]
#[repr(u8)]
pub enum Algorithm {
    HmacSha384 = 1,
    MlDsa44 = 2,
    MlDsa65 = 3,
    MlDsa87 = 4,
    SlhDsaSha2_128s = 5,
    SlhDsaSha2_192s = 6,
    SlhDsaSha2_256s = 7,
    FnDsa512 = 8,
    FnDsa1024 = 9,
}

struct Params {
    name: &'static str,
    secret_key_len: usize,
    public_key_len: Option<usize>,
    signature_len: usize,
}

impl Algorithm {
    pub const ALL: [Algorithm; 9] = [
        Algorithm::HmacSha384,
        Algorithm::MlDsa44,
        Algorithm::MlDsa65,
        Algorithm::MlDsa87,
        Algorithm::SlhDsaSha2_128s,
        Algorithm::SlhDsaSha2_192s,
        Algorithm::SlhDsaSha2_256s,
        Algorithm::FnDsa512,
        Algorithm::FnDsa1024,
    ];

    const fn params(self) -> Params {
        let (name, secret_key_len, public_key_len, signature_len) = match self {
            Algorithm::HmacSha384 => ("hmac-sha384", HMAC_MIN_KEY_LEN, None, 48),
            Algorithm::MlDsa44 => ("ml-dsa-44", 32, Some(1312), 2420),
            Algorithm::MlDsa65 => ("ml-dsa-65", 32, Some(1952), 3309),
            Algorithm::MlDsa87 => ("ml-dsa-87", 32, Some(2592), 4627),
            Algorithm::SlhDsaSha2_128s => ("slh-dsa-sha2-128s", 64, Some(32), 7856),
            Algorithm::SlhDsaSha2_192s => ("slh-dsa-sha2-192s", 96, Some(48), 16_224),
            Algorithm::SlhDsaSha2_256s => ("slh-dsa-sha2-256s", 128, Some(64), 29_792),
            Algorithm::FnDsa512 => ("fn-dsa-512", 1345, Some(897), 666),
            Algorithm::FnDsa1024 => ("fn-dsa-1024", 2369, Some(1793), 1280),
        };
        Params {
            name,
            secret_key_len,
            public_key_len,
            signature_len,
        }
    }

    /// Canonical lowercase name, also accepted by `FromStr`.
    pub const fn name(self) -> &'static str {
        self.params().name
    }

    pub const fn is_symmetric(self) -> bool {
        self.public_key_len().is_none()
    }

    /// Length of a generated secret key. HMAC also accepts longer keys, up to
    /// [`HMAC_MAX_KEY_LEN`].
    pub const fn secret_key_len(self) -> usize {
        self.params().secret_key_len
    }

    /// None for symmetric algorithms.
    pub const fn public_key_len(self) -> Option<usize> {
        self.params().public_key_len
    }

    /// Signature (or MAC tag) length in bytes.
    pub const fn signature_len(self) -> usize {
        self.params().signature_len
    }
}

impl TryFrom<u8> for Algorithm {
    type Error = ProtokenError;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        Algorithm::ALL
            .into_iter()
            .find(|&algorithm| algorithm as u8 == byte)
            .ok_or(ProtokenError::InvalidAlgorithm(byte))
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Algorithm {
    type Err = ProtokenError;

    /// Accepts the canonical names in any case, plus the aliases `hmac` and `mldsa44`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("hmac") {
            return Ok(Algorithm::HmacSha384);
        }
        if s.eq_ignore_ascii_case("mldsa44") {
            return Ok(Algorithm::MlDsa44);
        }
        Algorithm::ALL
            .into_iter()
            .find(|algorithm| s.eq_ignore_ascii_case(algorithm.name()))
            .ok_or_else(|| ProtokenError::UnknownAlgorithmName(s.to_string()))
    }
}

impl From<Algorithm> for &str {
    fn from(algorithm: Algorithm) -> Self {
        algorithm.name()
    }
}

impl TryFrom<String> for Algorithm {
    type Error = ProtokenError;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        name.parse()
    }
}

/// How the key is identified in the token. Serializes as `key_hash` or
/// `public_key`, matching [`KeyIdentifier::type_name`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum KeyIdType {
    KeyHash = 1,
    PublicKey = 2,
}

impl TryFrom<u8> for KeyIdType {
    type Error = ProtokenError;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            1 => Ok(KeyIdType::KeyHash),
            2 => Ok(KeyIdType::PublicKey),
            _ => Err(ProtokenError::InvalidKeyIdType(byte)),
        }
    }
}

/// Key identifier: either a truncated hash or an embedded public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyIdentifier {
    /// 8-byte truncated SHA-256 hash of the key material.
    /// Used for key selection, not as a security binding (~2^32 collision resistance).
    KeyHash([u8; KEY_HASH_LEN]),
    /// Raw public key bytes.
    PublicKey(Vec<u8>),
}

/// Serialize as {"type": "key_hash" | "public_key", "base64": "..."} for readable JSON.
impl Serialize for KeyIdentifier {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use base64::Engine as _;
        use serde::ser::SerializeStruct as _;
        let mut s = serializer.serialize_struct("KeyIdentifier", 2)?;
        s.serialize_field("type", self.type_name())?;
        s.serialize_field(
            "base64",
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.as_bytes()),
        )?;
        s.end()
    }
}

impl KeyIdentifier {
    pub fn key_id_type(&self) -> KeyIdType {
        match self {
            KeyIdentifier::KeyHash(_) => KeyIdType::KeyHash,
            KeyIdentifier::PublicKey(_) => KeyIdType::PublicKey,
        }
    }

    /// Snake-case name of the identifier type, as used in JSON output.
    pub fn type_name(&self) -> &'static str {
        match self {
            KeyIdentifier::KeyHash(_) => "key_hash",
            KeyIdentifier::PublicKey(_) => "public_key",
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            KeyIdentifier::KeyHash(hash) => hash,
            KeyIdentifier::PublicKey(pk) => pk,
        }
    }
}

/// Token claims. Serialized as the envelope's payload bytes.
///
/// Zero and empty fields are "not set"; they are omitted on the wire and in JSON.
/// Unknown JSON fields are rejected so that a misspelled claim is not dropped.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Claims {
    /// Expiration time as Unix timestamp (seconds since epoch). Required.
    pub expires_at: u64,
    /// Earliest valid time.
    #[serde(skip_serializing_if = "is_zero")]
    pub not_before: u64,
    /// Token creation time.
    #[serde(skip_serializing_if = "is_zero")]
    pub issued_at: u64,
    /// Subject identifier, max 255 bytes.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub subject: String,
    /// Audience identifier, max 255 bytes.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub audience: String,
    /// Scopes: at most 32 non-empty distinct entries of at most 255 bytes each.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}

fn check_claim_len(field_name: &str, value: &str) -> Result<(), ProtokenError> {
    if value.len() > MAX_CLAIM_BYTES_LEN {
        return Err(ProtokenError::malformed(format!(
            "{field_name} too long: {} bytes (max {MAX_CLAIM_BYTES_LEN})",
            value.len()
        )));
    }
    Ok(())
}

impl Claims {
    /// Validate that all claim fields are within allowed limits.
    pub fn validate(&self) -> Result<(), ProtokenError> {
        if self.expires_at == 0 {
            return Err(ProtokenError::malformed(
                "expires_at must be set (non-zero)",
            ));
        }
        if self.not_before > self.expires_at {
            return Err(ProtokenError::malformed(format!(
                "not_before ({}) is after expires_at ({})",
                self.not_before, self.expires_at
            )));
        }
        check_claim_len("subject", &self.subject)?;
        check_claim_len("audience", &self.audience)?;
        if self.scopes.len() > MAX_SCOPES {
            return Err(ProtokenError::malformed(format!(
                "too many scopes: {} (max {MAX_SCOPES})",
                self.scopes.len()
            )));
        }
        for scope in &self.scopes {
            // Canonical encoding omits empty fields, so an empty entry would
            // silently vanish on the wire.
            if scope.is_empty() {
                return Err(ProtokenError::malformed("scope entry must not be empty"));
            }
            check_claim_len("scope entry", scope)?;
        }
        let mut seen = BTreeSet::new();
        if let Some(dup) = self.scopes.iter().find(|scope| !seen.insert(*scope)) {
            return Err(ProtokenError::malformed(format!(
                "duplicate scope: {dup:?}"
            )));
        }
        Ok(())
    }
}

/// A signed token envelope: signing metadata, opaque payload bytes, and a
/// signature over the envelope's canonical encoding minus the signature field.
///
/// The payload is the canonical proto3 encoding of a message (`Claims` for
/// tokens); the envelope itself is payload-agnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedToken {
    pub version: Version,
    pub algorithm: Algorithm,
    pub key_identifier: KeyIdentifier,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_wire_values() {
        assert_eq!(Algorithm::ALL.map(|a| a as u8), [1, 2, 3, 4, 5, 6, 7, 8, 9]);
        for algorithm in Algorithm::ALL {
            assert_eq!(Algorithm::try_from(algorithm as u8).unwrap(), algorithm);
        }
        for byte in [0, 10, 255] {
            assert!(matches!(
                Algorithm::try_from(byte),
                Err(ProtokenError::InvalidAlgorithm(b)) if b == byte
            ));
        }
    }

    #[test]
    fn test_algorithm_name_roundtrip() {
        for alg in Algorithm::ALL {
            assert_eq!(alg.name().parse::<Algorithm>().unwrap(), alg);
            assert_eq!(alg.to_string(), alg.name());
            // JSON uses the same names as Display/FromStr.
            let json = serde_json::to_string(&alg).unwrap();
            assert_eq!(json, format!("\"{}\"", alg.name()));
            assert_eq!(serde_json::from_str::<Algorithm>(&json).unwrap(), alg);
        }
    }

    #[test]
    fn test_algorithm_from_str_aliases() {
        assert_eq!("hmac".parse::<Algorithm>().unwrap(), Algorithm::HmacSha384);
        assert_eq!(
            "ML-DSA-65".parse::<Algorithm>().unwrap(),
            Algorithm::MlDsa65
        );
        assert_eq!("mldsa44".parse::<Algorithm>().unwrap(), Algorithm::MlDsa44);
        for unknown in ["hmac-sha256", "ed25519"] {
            let err = unknown.parse::<Algorithm>().unwrap_err();
            assert!(matches!(&err, ProtokenError::UnknownAlgorithmName(s) if s == unknown));
            assert!(err.to_string().contains("slh-dsa-sha2-256s"), "{err}");
        }
    }

    #[test]
    fn test_only_hmac_is_symmetric() {
        for algorithm in Algorithm::ALL {
            assert_eq!(algorithm.is_symmetric(), algorithm == Algorithm::HmacSha384);
        }
    }

    #[test]
    fn test_field_limits_are_the_largest_algorithm_sizes() {
        let max = |size: fn(Algorithm) -> usize| Algorithm::ALL.map(size).into_iter().max();
        assert_eq!(max(Algorithm::signature_len), Some(MAX_SIGNATURE_BYTES));
        assert_eq!(
            max(|a| a.public_key_len().unwrap_or(0)),
            Some(MAX_PUBLIC_KEY_BYTES)
        );
        assert_eq!(
            max(|a| a.secret_key_len().max(HMAC_MAX_KEY_LEN)),
            Some(MAX_SECRET_KEY_BYTES)
        );
    }

    #[test]
    fn test_key_id_type_wire_values() {
        for id_type in [KeyIdType::KeyHash, KeyIdType::PublicKey] {
            assert_eq!(KeyIdType::try_from(id_type as u8).unwrap(), id_type);
        }
        for byte in [0, 3] {
            assert!(matches!(
                KeyIdType::try_from(byte),
                Err(ProtokenError::InvalidKeyIdType(b)) if b == byte
            ));
        }
    }

    #[test]
    fn test_key_id_type_json_matches_identifier_type_name() {
        let hash_id = KeyIdentifier::KeyHash([0; 8]);
        let pk_id = KeyIdentifier::PublicKey(vec![0; 32]);
        for id in [hash_id, pk_id] {
            let json = serde_json::to_string(&id.key_id_type()).unwrap();
            assert_eq!(json, format!("\"{}\"", id.type_name()));
        }
    }

    #[test]
    fn test_key_identifier_key_id_type() {
        assert_eq!(
            KeyIdentifier::KeyHash([0; 8]).key_id_type(),
            KeyIdType::KeyHash
        );
        assert_eq!(
            KeyIdentifier::PublicKey(vec![0; 32]).key_id_type(),
            KeyIdType::PublicKey
        );
    }

    #[test]
    fn test_key_identifier_as_bytes() {
        assert_eq!(KeyIdentifier::KeyHash([0x11; 8]).as_bytes(), &[0x11; 8]);
        assert_eq!(
            KeyIdentifier::PublicKey(vec![0x22; 32]).as_bytes(),
            &[0x22; 32][..]
        );
    }

    #[test]
    fn test_key_identifier_json() {
        let json = serde_json::to_string(&KeyIdentifier::KeyHash([0; 8])).unwrap();
        assert_eq!(json, r#"{"type":"key_hash","base64":"AAAAAAAAAAA"}"#);
        let json = serde_json::to_string(&KeyIdentifier::PublicKey(vec![0xFF; 3])).unwrap();
        assert_eq!(json, r#"{"type":"public_key","base64":"____"}"#);
    }

    #[test]
    fn test_claims_json_skip_zero_fields() {
        let claims = Claims {
            expires_at: 1000,
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_string(&claims).unwrap(),
            r#"{"expires_at":1000}"#
        );
    }

    #[test]
    fn test_claims_json_roundtrip() {
        let claims = Claims {
            expires_at: 1000,
            not_before: 500,
            issued_at: 500,
            subject: "s".into(),
            audience: "a".into(),
            scopes: vec!["read".into(), "write".into()],
        };
        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("not_before"));
        assert!(json.contains("issued_at"));
        assert_eq!(serde_json::from_str::<Claims>(&json).unwrap(), claims);
    }

    #[test]
    fn test_claims_json_missing_fields_default() {
        let claims: Claims = serde_json::from_str(r#"{"expires_at":7}"#).unwrap();
        assert_eq!(
            claims,
            Claims {
                expires_at: 7,
                ..Default::default()
            }
        );
    }

    #[test]
    fn test_claims_json_rejects_unknown_fields() {
        assert!(serde_json::from_str::<Claims>(r#"{"expires_at":7,"aud":"api"}"#).is_err());
    }

    fn with_scopes(scopes: &[&str]) -> Claims {
        Claims {
            expires_at: 1000,
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn test_claims_validate_rejects_duplicate_scopes() {
        for scopes in [
            &["read", "read"][..],
            &["read", "write", "read"],
            &["write", "read", "write"],
        ] {
            let err = with_scopes(scopes).validate().unwrap_err();
            assert!(
                matches!(&err, ProtokenError::MalformedEncoding(m) if m.contains("duplicate scope")),
                "{scopes:?}: got {err:?}"
            );
        }
    }

    #[test]
    fn test_claims_validate_accepts_distinct_scopes() {
        assert!(with_scopes(&["read", "write"]).validate().is_ok());
        assert!(with_scopes(&["write", "admin", "read"]).validate().is_ok());
        assert!(with_scopes(&[]).validate().is_ok());
    }

    #[test]
    fn test_claims_validate_rejects_empty_scope() {
        assert!(with_scopes(&["read", ""]).validate().is_err());
    }

    #[test]
    fn test_claims_validate_temporal() {
        assert!(Claims::default().validate().is_err());
        let bad = Claims {
            expires_at: 10,
            not_before: 11,
            ..Default::default()
        };
        assert!(bad.validate().is_err());
        let boundary = Claims {
            expires_at: 10,
            not_before: 10,
            ..Default::default()
        };
        assert!(boundary.validate().is_ok());
    }
}
