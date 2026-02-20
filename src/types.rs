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
    MlDsa65 = 4,
    MlDsa87 = 5,
}

impl Algorithm {
    pub fn from_byte(b: u8) -> Option<Algorithm> {
        match b {
            1 => Some(Algorithm::HmacSha256),
            2 => Some(Algorithm::Ed25519),
            3 => Some(Algorithm::MlDsa44),
            4 => Some(Algorithm::MlDsa65),
            5 => Some(Algorithm::MlDsa87),
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
            Algorithm::MlDsa65 => MLDSA65_SIG_LEN,
            Algorithm::MlDsa87 => MLDSA87_SIG_LEN,
        }
    }

    /// Returns the public key length in bytes for asymmetric algorithms.
    pub fn public_key_len(self) -> Option<usize> {
        match self {
            Algorithm::HmacSha256 => None,
            Algorithm::Ed25519 => Some(ED25519_PUBLIC_KEY_LEN),
            Algorithm::MlDsa44 => Some(MLDSA44_PUBLIC_KEY_LEN),
            Algorithm::MlDsa65 => Some(MLDSA65_PUBLIC_KEY_LEN),
            Algorithm::MlDsa87 => Some(MLDSA87_PUBLIC_KEY_LEN),
        }
    }

    /// Returns the signing key length in bytes for asymmetric algorithms.
    pub fn signing_key_len(self) -> Option<usize> {
        match self {
            Algorithm::HmacSha256 => None,
            Algorithm::Ed25519 => Some(ED25519_SEED_LEN),
            Algorithm::MlDsa44 => Some(MLDSA44_SIGNING_KEY_LEN),
            Algorithm::MlDsa65 => Some(MLDSA65_SIGNING_KEY_LEN),
            Algorithm::MlDsa87 => Some(MLDSA87_SIGNING_KEY_LEN),
        }
    }

    /// Returns true if this is an ML-DSA algorithm variant.
    pub fn is_ml_dsa(self) -> bool {
        matches!(
            self,
            Algorithm::MlDsa44 | Algorithm::MlDsa65 | Algorithm::MlDsa87
        )
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
    /// Raw public key bytes (Ed25519: 32 B, ML-DSA-44/65/87: 1312/1952/2592 B).
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

/// Must accommodate ML-DSA-87 PublicKey (2592 B) + max claims.
pub const MAX_PAYLOAD_BYTES: usize = 16384;
/// Must accommodate ML-DSA-87 signatures (4,627 bytes).
pub const MAX_SIGNATURE_BYTES: usize = 5120;

pub const HMAC_MIN_KEY_LEN: usize = 32;
pub const KEY_HASH_LEN: usize = 8;
pub const ED25519_SEED_LEN: usize = 32;
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
pub const HMAC_SHA256_SIG_LEN: usize = 32;
pub const ED25519_SIG_LEN: usize = 64;

// ML-DSA-44 (FIPS 204, security category 2)
pub const MLDSA44_PUBLIC_KEY_LEN: usize = 1312;
pub const MLDSA44_SIGNING_KEY_LEN: usize = 2560;
pub const MLDSA44_SIG_LEN: usize = 2420;

// ML-DSA-65 (FIPS 204, security category 3)
pub const MLDSA65_PUBLIC_KEY_LEN: usize = 1952;
pub const MLDSA65_SIGNING_KEY_LEN: usize = 4032;
pub const MLDSA65_SIG_LEN: usize = 3309;

// ML-DSA-87 (FIPS 204, security category 5)
pub const MLDSA87_PUBLIC_KEY_LEN: usize = 2592;
pub const MLDSA87_SIGNING_KEY_LEN: usize = 4896;
pub const MLDSA87_SIG_LEN: usize = 4627;
