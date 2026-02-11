use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtokenError {
    #[error("invalid version: {0}")]
    InvalidVersion(u8),

    #[error("invalid algorithm: {0}")]
    InvalidAlgorithm(u8),

    #[error("invalid key identifier type: {0}")]
    InvalidKeyIdType(u8),

    #[error("payload too short: expected at least {expected} bytes, got {actual}")]
    PayloadTooShort { expected: usize, actual: usize },

    #[error("token too short: expected at least {expected} bytes, got {actual}")]
    TokenTooShort { expected: usize, actual: usize },

    #[error("invalid key length: expected {expected} bytes, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("signing failed: {0}")]
    SigningFailed(String),

    #[error("verification failed: {0}")]
    VerificationFailed(String),

    #[error("token expired: expired at {expired_at}, current time is {now}")]
    TokenExpired { expired_at: u64, now: u64 },

    #[error("key hash mismatch")]
    KeyHashMismatch,

    #[error("malformed encoding: {0}")]
    MalformedEncoding(String),

    #[error("token not yet valid: not_before is {not_before}, current time is {now}")]
    TokenNotYetValid { not_before: u64, now: u64 },
}
