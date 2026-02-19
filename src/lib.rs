//! Protoken: minimal signed tokens using canonical proto3 wire encoding.
//!
//! Supports HMAC-SHA256, Ed25519, and ML-DSA-44 (post-quantum) signatures
//! with compact binary payloads.

pub mod error;
pub mod keys;
pub mod proto3;
pub mod serialize;
pub mod sign;
pub mod types;
pub mod verify;
