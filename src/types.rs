use crate::error::ProtokenError;
use serde::Serialize;

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

/// Signing algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[repr(u8)]
pub enum Algorithm {
    HmacSha256 = 1,
    Ed25519 = 2,
    MlDsa44 = 3,
    Groth16Poseidon = 4,
    Groth16Hybrid = 5,
}

impl Algorithm {
    pub fn from_byte(b: u8) -> Option<Algorithm> {
        match b {
            1 => Some(Algorithm::HmacSha256),
            2 => Some(Algorithm::Ed25519),
            3 => Some(Algorithm::MlDsa44),
            4 => Some(Algorithm::Groth16Poseidon),
            5 => Some(Algorithm::Groth16Hybrid),
            _ => None,
        }
    }

    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

/// How the key is identified in the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[repr(u8)]
pub enum KeyIdType {
    KeyHash = 1,
    PublicKey = 2,
    /// Full 32-byte hash of the key material.
    /// Groth16Poseidon uses Poseidon; Groth16Hybrid and others use SHA-256.
    FullKeyHash = 3,
}

impl KeyIdType {
    pub fn from_byte(b: u8) -> Option<KeyIdType> {
        match b {
            1 => Some(KeyIdType::KeyHash),
            2 => Some(KeyIdType::PublicKey),
            3 => Some(KeyIdType::FullKeyHash),
            _ => None,
        }
    }

    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

/// Key identifier — either a truncated hash, an embedded public key, or a full hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum KeyIdentifier {
    /// 8-byte truncated SHA-256 hash of the key material.
    /// Used for key selection, not as a security binding (~2^32 collision resistance).
    KeyHash([u8; 8]),
    /// Raw public key bytes (Ed25519: 32 B, ML-DSA-44: 1312 B).
    PublicKey(Vec<u8>),
    /// Full 32-byte hash of the key material.
    /// Groth16Poseidon uses Poseidon(K); Groth16Hybrid uses SHA-256(K). Full collision resistance.
    FullKeyHash([u8; FULL_KEY_HASH_LEN]),
}

impl KeyIdentifier {
    pub fn key_id_type(&self) -> KeyIdType {
        match self {
            KeyIdentifier::KeyHash(_) => KeyIdType::KeyHash,
            KeyIdentifier::PublicKey(_) => KeyIdType::PublicKey,
            KeyIdentifier::FullKeyHash(_) => KeyIdType::FullKeyHash,
        }
    }
}

/// Token metadata: version, algorithm, and key identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Metadata {
    pub version: Version,
    pub algorithm: Algorithm,
    pub key_identifier: KeyIdentifier,
}

/// Token claims.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Claims {
    /// Expiration time as Unix timestamp (seconds since epoch).
    pub expires_at: u64,
    /// Earliest valid time (0 = not set).
    #[serde(skip_serializing_if = "is_zero")]
    pub not_before: u64,
    /// Token creation time (0 = not set).
    #[serde(skip_serializing_if = "is_zero")]
    pub issued_at: u64,
    /// Subject identifier (empty = not set), max 255 bytes.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub subject: String,
    /// Audience identifier (empty = not set), max 255 bytes.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub audience: String,
    /// Scopes (empty list = not set). Each entry is a UTF-8 string.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
}

impl Claims {
    /// Validate that all claim fields are within allowed limits.
    pub fn validate(&self) -> Result<(), ProtokenError> {
        if self.expires_at == 0 {
            return Err(ProtokenError::MalformedEncoding(
                "expires_at must be set (non-zero)".into(),
            ));
        }
        if self.not_before != 0 && self.not_before > self.expires_at {
            return Err(ProtokenError::MalformedEncoding(format!(
                "not_before ({}) is after expires_at ({})",
                self.not_before, self.expires_at
            )));
        }
        if self.subject.len() > MAX_CLAIM_BYTES_LEN {
            return Err(ProtokenError::MalformedEncoding(format!(
                "subject too long: {} bytes (max {})",
                self.subject.len(),
                MAX_CLAIM_BYTES_LEN
            )));
        }
        if self.audience.len() > MAX_CLAIM_BYTES_LEN {
            return Err(ProtokenError::MalformedEncoding(format!(
                "audience too long: {} bytes (max {})",
                self.audience.len(),
                MAX_CLAIM_BYTES_LEN
            )));
        }
        if self.scopes.len() > MAX_SCOPES {
            return Err(ProtokenError::MalformedEncoding(format!(
                "too many scopes: {} (max {})",
                self.scopes.len(),
                MAX_SCOPES
            )));
        }
        for scope in &self.scopes {
            if scope.len() > MAX_CLAIM_BYTES_LEN {
                return Err(ProtokenError::MalformedEncoding(format!(
                    "scope entry too long: {} bytes (max {})",
                    scope.len(),
                    MAX_CLAIM_BYTES_LEN
                )));
            }
        }
        // Check for duplicates via sorted adjacent comparison (avoids HashSet allocation).
        // Scopes are sorted during serialization, but validate() runs before that.
        {
            let mut sorted: Vec<&str> = self.scopes.iter().map(|s| s.as_str()).collect();
            sorted.sort();
            for pair in sorted.windows(2) {
                #[allow(clippy::indexing_slicing)] // windows(2) guarantees exactly 2 elements
                if pair[0] == pair[1] {
                    return Err(ProtokenError::MalformedEncoding(format!(
                        "duplicate scope: {:?}",
                        pair[0]
                    )));
                }
            }
        }
        Ok(())
    }
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}

/// Maximum length for subject, audience, and individual scope fields (bytes).
pub const MAX_CLAIM_BYTES_LEN: usize = 255;

/// Maximum number of scope entries.
pub const MAX_SCOPES: usize = 32;

/// The payload that gets serialized and signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Payload {
    pub metadata: Metadata,
    pub claims: Claims,
}

/// A signed token: serialized payload + signature + optional proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedToken {
    pub payload_bytes: Vec<u8>,
    pub signature: Vec<u8>,
    /// Groth16 SNARK proof (128 bytes for Groth16Poseidon/Groth16Hybrid, empty for other algorithms).
    pub proof: Vec<u8>,
}

pub const MAX_PAYLOAD_BYTES: usize = 4096;
/// Must accommodate ML-DSA-44 signatures (2,420 bytes).
pub const MAX_SIGNATURE_BYTES: usize = 2560;

pub const HMAC_MIN_KEY_LEN: usize = 32;
pub const KEY_HASH_LEN: usize = 8;
pub const ED25519_SEED_LEN: usize = 32;
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
pub const HMAC_SHA256_SIG_LEN: usize = 32;
pub const ED25519_SIG_LEN: usize = 64;
pub const MLDSA44_PUBLIC_KEY_LEN: usize = 1312;
pub const MLDSA44_SIGNING_KEY_LEN: usize = 2560;
pub const MLDSA44_SIG_LEN: usize = 2420;

pub const FULL_KEY_HASH_LEN: usize = 32;
pub const GROTH16_PROOF_LEN: usize = 128;
pub const MAX_PROOF_BYTES: usize = 256;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_from_byte_all_variants() {
        assert_eq!(Algorithm::from_byte(1), Some(Algorithm::HmacSha256));
        assert_eq!(Algorithm::from_byte(2), Some(Algorithm::Ed25519));
        assert_eq!(Algorithm::from_byte(3), Some(Algorithm::MlDsa44));
        assert_eq!(Algorithm::from_byte(4), Some(Algorithm::Groth16Poseidon));
        assert_eq!(Algorithm::from_byte(5), Some(Algorithm::Groth16Hybrid));
        assert_eq!(Algorithm::from_byte(0), None);
        assert_eq!(Algorithm::from_byte(6), None);
    }

    #[test]
    fn test_algorithm_to_byte_roundtrip() {
        for b in 1..=5u8 {
            let alg = Algorithm::from_byte(b).unwrap();
            assert_eq!(alg.to_byte(), b);
        }
    }

    #[test]
    fn test_key_id_type_from_byte_all_variants() {
        assert_eq!(KeyIdType::from_byte(1), Some(KeyIdType::KeyHash));
        assert_eq!(KeyIdType::from_byte(2), Some(KeyIdType::PublicKey));
        assert_eq!(KeyIdType::from_byte(3), Some(KeyIdType::FullKeyHash));
        assert_eq!(KeyIdType::from_byte(0), None);
        assert_eq!(KeyIdType::from_byte(4), None);
    }

    #[test]
    fn test_key_id_type_to_byte_roundtrip() {
        for b in 1..=3u8 {
            let kit = KeyIdType::from_byte(b).unwrap();
            assert_eq!(kit.to_byte(), b);
        }
    }

    #[test]
    fn test_version_to_byte() {
        // Only V0 = 0 today. Check via repr roundtrip.
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
        assert_eq!(
            KeyIdentifier::FullKeyHash([0; 32]).key_id_type(),
            KeyIdType::FullKeyHash
        );
    }

    #[test]
    fn test_claims_json_skip_zero_fields() {
        // Verifies is_zero(): zero-valued not_before/issued_at are omitted from JSON.
        let claims = Claims {
            expires_at: 1000,
            not_before: 0,
            issued_at: 0,
            ..Default::default()
        };
        let json = serde_json::to_string(&claims).unwrap();
        assert!(!json.contains("not_before"));
        assert!(!json.contains("issued_at"));
        assert!(json.contains("expires_at"));
    }

    #[test]
    fn test_claims_json_includes_nonzero_fields() {
        // Verifies is_zero(): nonzero not_before/issued_at ARE present in JSON.
        let claims = Claims {
            expires_at: 1000,
            not_before: 500,
            issued_at: 500,
            ..Default::default()
        };
        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("not_before"));
        assert!(json.contains("issued_at"));
    }

    #[test]
    fn test_claims_validate_rejects_duplicate_scopes() {
        let claims = Claims {
            expires_at: 1000,
            scopes: vec!["read".into(), "read".into()],
            ..Default::default()
        };
        assert!(claims.validate().is_err());
    }

    #[test]
    fn test_claims_validate_accepts_distinct_scopes() {
        let claims = Claims {
            expires_at: 1000,
            scopes: vec!["read".into(), "write".into()],
            ..Default::default()
        };
        assert!(claims.validate().is_ok());
    }
}
