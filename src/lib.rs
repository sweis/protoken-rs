//! Protoken: minimal signed tokens using canonical proto3 wire encoding.
//!
//! Supports HMAC-SHA256, Ed25519, ML-DSA-44 (post-quantum) signatures,
//! and ECVRF (RFC 9381) verifiable random function proofs
//! with compact binary payloads.

pub mod error;
pub mod keys;
pub mod proto3;
pub mod serialize;
pub mod sign;
pub mod types;
pub mod verify;

// Re-export Zeroizing so callers can construct SigningKey without depending on zeroize directly.
pub use zeroize::Zeroizing;
