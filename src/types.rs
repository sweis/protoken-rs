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
}

impl Algorithm {
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

    /// Returns the signature length in bytes for this algorithm.
    pub fn signature_len(self) -> usize {
        match self {
            Algorithm::HmacSha256 => HMAC_SHA256_SIG_LEN,
            Algorithm::Ed25519 => ED25519_SIG_LEN,
            Algorithm::MlDsa44 => MLDSA44_SIG_LEN,
        }
    }
}

/// How the key is identified in the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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

/// Key identifier — either a truncated hash or an embedded public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum KeyIdentifier {
    /// 8-byte truncated SHA-256 hash of the key material.
    KeyHash([u8; 8]),
    /// Raw public key bytes (Ed25519: 32 B, ML-DSA-44: 1312 B).
    PublicKey(Vec<u8>),
}

impl KeyIdentifier {
    pub fn key_id_type(&self) -> KeyIdType {
        match self {
            KeyIdentifier::KeyHash(_) => KeyIdType::KeyHash,
            KeyIdentifier::PublicKey(_) => KeyIdType::PublicKey,
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
        {
            let mut seen = std::collections::HashSet::new();
            for scope in &self.scopes {
                if scope.len() > MAX_CLAIM_BYTES_LEN {
                    return Err(ProtokenError::MalformedEncoding(format!(
                        "scope entry too long: {} bytes (max {})",
                        scope.len(),
                        MAX_CLAIM_BYTES_LEN
                    )));
                }
                if !seen.insert(scope.as_str()) {
                    return Err(ProtokenError::MalformedEncoding(format!(
                        "duplicate scope: {:?}",
                        scope
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

/// A signed token: serialized payload + signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedToken {
    pub payload_bytes: Vec<u8>,
    pub signature: Vec<u8>,
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
