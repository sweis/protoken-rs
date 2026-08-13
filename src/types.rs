use std::fmt;
use std::str::FromStr;

use crate::error::ProtokenError;
use serde::{Deserialize, Serialize};

/// Maximum length for subject, audience, and individual scope fields (bytes).
pub const MAX_CLAIM_BYTES_LEN: usize = 255;
/// Maximum number of scope entries.
pub const MAX_SCOPES: usize = 32;
/// Maximum size of the envelope payload (serialized Claims).
pub const MAX_PAYLOAD_BYTES: usize = 4096;
/// Maximum size of the envelope signature. Must accommodate ML-DSA-44 (2,420 bytes).
pub const MAX_SIGNATURE_BYTES: usize = 2560;

pub const HMAC_MIN_KEY_LEN: usize = 32;
pub const HMAC_SHA256_SIG_LEN: usize = 32;
pub const KEY_HASH_LEN: usize = 8;
pub const ED25519_SEED_LEN: usize = 32;
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
pub const ED25519_SIG_LEN: usize = 64;
pub const MLDSA44_SEED_LEN: usize = 32;
pub const MLDSA44_PUBLIC_KEY_LEN: usize = 1312;
pub const MLDSA44_SIG_LEN: usize = 2420;

/// Token format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[repr(u8)]
pub enum Version {
    V0 = 0,
}

impl Version {
    pub fn from_byte(b: u8) -> Option<Version> {
        match b {
            0 => Some(Version::V0),
            _ => None,
        }
    }

    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

/// Signing algorithm. Serializes to its canonical name (see [`Algorithm::name`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Algorithm {
    #[serde(rename = "hmac-sha256")]
    HmacSha256 = 1,
    #[serde(rename = "ed25519")]
    Ed25519 = 2,
    #[serde(rename = "ml-dsa-44")]
    MlDsa44 = 3,
}

impl Algorithm {
    pub const ALL: [Algorithm; 3] = [
        Algorithm::HmacSha256,
        Algorithm::Ed25519,
        Algorithm::MlDsa44,
    ];

    pub fn from_byte(b: u8) -> Option<Algorithm> {
        match b {
            1 => Some(Algorithm::HmacSha256),
            2 => Some(Algorithm::Ed25519),
            3 => Some(Algorithm::MlDsa44),
            _ => None,
        }
    }

    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// Canonical lowercase name, also accepted by `FromStr`.
    pub fn name(self) -> &'static str {
        match self {
            Algorithm::HmacSha256 => "hmac-sha256",
            Algorithm::Ed25519 => "ed25519",
            Algorithm::MlDsa44 => "ml-dsa-44",
        }
    }

    pub fn is_symmetric(self) -> bool {
        self == Algorithm::HmacSha256
    }

    /// Expected public key length in bytes; None for symmetric algorithms.
    pub fn public_key_len(self) -> Option<usize> {
        match self {
            Algorithm::HmacSha256 => None,
            Algorithm::Ed25519 => Some(ED25519_PUBLIC_KEY_LEN),
            Algorithm::MlDsa44 => Some(MLDSA44_PUBLIC_KEY_LEN),
        }
    }

    /// Signature (or MAC tag) length in bytes.
    pub fn signature_len(self) -> usize {
        match self {
            Algorithm::HmacSha256 => HMAC_SHA256_SIG_LEN,
            Algorithm::Ed25519 => ED25519_SIG_LEN,
            Algorithm::MlDsa44 => MLDSA44_SIG_LEN,
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Algorithm {
    type Err = ProtokenError;

    /// Accepts the canonical names plus the short aliases `hmac` and `mldsa44`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "hmac-sha256" | "hmac" => Ok(Algorithm::HmacSha256),
            "ed25519" => Ok(Algorithm::Ed25519),
            "ml-dsa-44" | "mldsa44" => Ok(Algorithm::MlDsa44),
            _ => Err(ProtokenError::UnknownAlgorithmName(s.to_string())),
        }
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

impl KeyIdType {
    pub fn from_byte(b: u8) -> Option<KeyIdType> {
        match b {
            1 => Some(KeyIdType::KeyHash),
            2 => Some(KeyIdType::PublicKey),
            _ => None,
        }
    }

    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

/// Key identifier: either a truncated hash or an embedded public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyIdentifier {
    /// 8-byte truncated SHA-256 hash of the key material.
    /// Used for key selection, not as a security binding (~2^32 collision resistance).
    KeyHash([u8; KEY_HASH_LEN]),
    /// Raw public key bytes (Ed25519: 32 B, ML-DSA-44: 1312 B).
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
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

fn malformed(msg: String) -> ProtokenError {
    ProtokenError::MalformedEncoding(msg)
}

fn check_claim_len(field_name: &str, value: &str) -> Result<(), ProtokenError> {
    if value.len() > MAX_CLAIM_BYTES_LEN {
        return Err(malformed(format!(
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
            return Err(malformed("expires_at must be set (non-zero)".into()));
        }
        if self.not_before > self.expires_at {
            return Err(malformed(format!(
                "not_before ({}) is after expires_at ({})",
                self.not_before, self.expires_at
            )));
        }
        check_claim_len("subject", &self.subject)?;
        check_claim_len("audience", &self.audience)?;
        if self.scopes.len() > MAX_SCOPES {
            return Err(malformed(format!(
                "too many scopes: {} (max {MAX_SCOPES})",
                self.scopes.len()
            )));
        }
        for scope in &self.scopes {
            // Canonical encoding omits empty fields, so an empty entry would
            // silently vanish on the wire.
            if scope.is_empty() {
                return Err(malformed("scope entry must not be empty".into()));
            }
            check_claim_len("scope entry", scope)?;
        }
        if let Some(dup) = first_duplicate(&self.scopes) {
            return Err(malformed(format!("duplicate scope: {dup:?}")));
        }
        Ok(())
    }
}

/// Find a duplicate entry. Scopes decoded from the wire are already sorted
/// and are checked in place; only caller-built claims pay for a sorted copy.
fn first_duplicate(scopes: &[String]) -> Option<&str> {
    if scopes.is_sorted() {
        return adjacent_duplicate(scopes.iter().map(String::as_str));
    }
    let mut sorted: Vec<&str> = scopes.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    adjacent_duplicate(sorted.into_iter())
}

fn adjacent_duplicate<'a>(sorted: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    let mut previous: Option<&'a str> = None;
    for scope in sorted {
        if previous == Some(scope) {
            return Some(scope);
        }
        previous = Some(scope);
    }
    None
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
    fn test_algorithm_from_byte_all_variants() {
        assert_eq!(Algorithm::from_byte(1), Some(Algorithm::HmacSha256));
        assert_eq!(Algorithm::from_byte(2), Some(Algorithm::Ed25519));
        assert_eq!(Algorithm::from_byte(3), Some(Algorithm::MlDsa44));
        assert_eq!(Algorithm::from_byte(0), None);
        assert_eq!(Algorithm::from_byte(4), None);
    }

    #[test]
    fn test_algorithm_to_byte_roundtrip() {
        for alg in Algorithm::ALL {
            assert_eq!(Algorithm::from_byte(alg.to_byte()), Some(alg));
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
        assert_eq!("hmac".parse::<Algorithm>().unwrap(), Algorithm::HmacSha256);
        assert_eq!(
            "HMAC-SHA256".parse::<Algorithm>().unwrap(),
            Algorithm::HmacSha256
        );
        assert_eq!("mldsa44".parse::<Algorithm>().unwrap(), Algorithm::MlDsa44);
        assert!(matches!(
            "rsa".parse::<Algorithm>(),
            Err(ProtokenError::UnknownAlgorithmName(s)) if s == "rsa"
        ));
    }

    #[test]
    fn test_algorithm_sizes() {
        assert_eq!(Algorithm::HmacSha256.public_key_len(), None);
        assert_eq!(Algorithm::HmacSha256.signature_len(), HMAC_SHA256_SIG_LEN);
        assert!(Algorithm::HmacSha256.is_symmetric());

        assert_eq!(
            Algorithm::Ed25519.public_key_len(),
            Some(ED25519_PUBLIC_KEY_LEN)
        );
        assert_eq!(Algorithm::Ed25519.signature_len(), ED25519_SIG_LEN);
        assert!(!Algorithm::Ed25519.is_symmetric());

        assert_eq!(
            Algorithm::MlDsa44.public_key_len(),
            Some(MLDSA44_PUBLIC_KEY_LEN)
        );
        assert_eq!(Algorithm::MlDsa44.signature_len(), MLDSA44_SIG_LEN);
        assert!(!Algorithm::MlDsa44.is_symmetric());
    }

    #[test]
    fn test_key_id_type_from_byte_all_variants() {
        assert_eq!(KeyIdType::from_byte(1), Some(KeyIdType::KeyHash));
        assert_eq!(KeyIdType::from_byte(2), Some(KeyIdType::PublicKey));
        assert_eq!(KeyIdType::from_byte(0), None);
        assert_eq!(KeyIdType::from_byte(3), None);
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
    fn test_key_id_type_to_byte_roundtrip() {
        for b in 1..=2u8 {
            let kit = KeyIdType::from_byte(b).unwrap();
            assert_eq!(kit.to_byte(), b);
        }
    }

    #[test]
    fn test_version_to_byte() {
        assert_eq!(Version::V0.to_byte(), 0);
        assert_eq!(Version::from_byte(0), Some(Version::V0));
        assert_eq!(Version::from_byte(1), None);
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
