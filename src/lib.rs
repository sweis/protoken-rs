//! Protoken: minimal signed tokens using canonical proto3 wire encoding.
//!
//! A signed token is a proto3 envelope carrying signing metadata (algorithm,
//! key identifier), opaque payload bytes, and a signature over the envelope's
//! canonical encoding minus the signature field. The payload is the canonical
//! proto3 encoding of a `Claims` message.
//!
//! Supported algorithms: HMAC-SHA256, Ed25519, and ML-DSA-44 (post-quantum).

pub mod error;
pub mod keys;
pub mod proto3;
pub mod serialize;
pub mod sign;
pub mod types;
pub mod verify;

// Re-export Zeroizing so callers can construct SigningKey without depending on zeroize directly.
pub use zeroize::Zeroizing;
