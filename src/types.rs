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
}

impl Algorithm {
    pub fn from_byte(b: u8) -> Option<Algorithm> {
        match b {
            1 => Some(Algorithm::HmacSha256),
            2 => Some(Algorithm::Ed25519),
            _ => None,
        }
    }

    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// Returns the signature length in bytes for this algorithm.
    pub fn signature_len(self) -> usize {
        match self {
            Algorithm::HmacSha256 => 32,
            Algorithm::Ed25519 => 64,
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
    /// Raw public key bytes (32 bytes for Ed25519).
    PublicKey(Vec<u8>),
}

impl KeyIdentifier {
    pub fn key_id_type(&self) -> KeyIdType {
        match self {
            KeyIdentifier::KeyHash(_) => KeyIdType::KeyHash,
            KeyIdentifier::PublicKey(_) => KeyIdType::PublicKey,
        }
    }

    /// Returns the byte length of the key identifier value.
    pub fn value_len(&self) -> usize {
        match self {
            KeyIdentifier::KeyHash(_) => 8,
            KeyIdentifier::PublicKey(pk) => pk.len(),
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Claims {
    /// Expiration time as Unix timestamp (seconds since epoch).
    pub expires_at: u64,
}

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

/// Constant: key hash length in bytes.
pub const KEY_HASH_LEN: usize = 8;

/// Constant: Ed25519 public key length.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// Constant: HMAC-SHA256 signature length.
pub const HMAC_SHA256_SIG_LEN: usize = 32;

/// Constant: Ed25519 signature length.
pub const ED25519_SIG_LEN: usize = 64;
