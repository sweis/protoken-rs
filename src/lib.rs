//! Protoken: minimal signed tokens using canonical proto3 wire encoding.
//!
//! A signed token is a proto3 envelope carrying signing metadata (algorithm,
//! key identifier), opaque payload bytes, and a signature over the envelope's
//! canonical encoding minus the signature field. The payload is the canonical
//! proto3 encoding of a [`Claims`] message.
//!
//! Supported algorithms: HMAC-SHA256, Ed25519, and ML-DSA-44 (post-quantum).
//!
//! The usual entry points are [`SigningKey`] and [`VerifyingKey`]:
//!
//! ```
//! use protoken::{Algorithm, Claims, SigningKey};
//!
//! let key = SigningKey::generate(Algorithm::Ed25519)?;
//! let claims = Claims {
//!     expires_at: 1_800_000_000,
//!     subject: "user:alice".into(),
//!     ..Default::default()
//! };
//! let token = key.sign(&claims)?;
//!
//! let verifying_key = key.verifying_key()?;
//! let verified = verifying_key.verify(&token, 1_799_999_000)?;
//! assert_eq!(verified.claims.subject, "user:alice");
//! # Ok::<(), protoken::ProtokenError>(())
//! ```
//!
//! The `sign` and `verify` modules expose the same operations on raw key
//! material, and `serialize` exposes the wire format directly.

pub mod error;
pub mod keys;
pub mod proto3;
pub mod serialize;
pub mod sign;
pub mod types;
pub mod verify;

pub use error::ProtokenError;
pub use keys::{SigningKey, VerifyingKey};
pub use types::{Algorithm, Claims, KeyIdType, KeyIdentifier, SignedToken};
pub use verify::VerifiedToken;

// Re-exported so callers can construct a SigningKey without depending on zeroize directly.
pub use zeroize::Zeroizing;
