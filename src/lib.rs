//! Protoken: minimal signed tokens using canonical proto3 wire encoding.
//!
//! Supports HMAC-SHA256 and Ed25519 signatures with compact binary payloads.

pub mod error;
pub mod proto3;
pub mod serialize;
pub mod sign;
pub mod types;
pub mod verify;
