//! Python bindings for protoken, exposed as the `protoken._protoken` module.
//!
//! This is a thin layer over `protoken::SigningKey` and `protoken::VerifyingKey`.
//! All parsing and validation happens in the Rust library; this crate only
//! converts types and errors.
//!
//! Python cannot zeroize `bytes` objects, so secret material returned by
//! `SigningKey.to_bytes()` stays in memory until the interpreter frees it.

use std::time::{SystemTime, UNIX_EPOCH};

use pyo3::create_exception;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyTuple};

use protoken::serialize::{deserialize_claims, deserialize_signed_token};
use protoken::{Algorithm, KeyIdType, ProtokenError as RustError};

create_exception!(
    protoken,
    ProtokenError,
    PyValueError,
    "Base class for all protoken errors."
);
create_exception!(
    protoken,
    TokenExpired,
    ProtokenError,
    "The token's expires_at is in the past."
);
create_exception!(
    protoken,
    TokenNotYetValid,
    ProtokenError,
    "The token's not_before is in the future."
);
create_exception!(
    protoken,
    VerificationFailed,
    ProtokenError,
    "The token is malformed, signed by a different key, or otherwise invalid."
);

trait OrPyErr<T> {
    /// For key handling and claims construction: everything is a plain `ProtokenError`.
    fn or_py_err(self) -> PyResult<T>;
    /// For operations on a token: temporal failures get their own classes and
    /// every other problem with the token is a `VerificationFailed`.
    fn or_token_err(self) -> PyResult<T>;
}

impl<T> OrPyErr<T> for Result<T, RustError> {
    fn or_py_err(self) -> PyResult<T> {
        self.map_err(|e| ProtokenError::new_err(e.to_string()))
    }

    fn or_token_err(self) -> PyResult<T> {
        self.map_err(|e| {
            let message = e.to_string();
            match e {
                RustError::TokenExpired { .. } => TokenExpired::new_err(message),
                RustError::TokenNotYetValid { .. } => TokenNotYetValid::new_err(message),
                _ => VerificationFailed::new_err(message),
            }
        })
    }
}

fn parse_algorithm(name: &str) -> PyResult<Algorithm> {
    name.parse::<Algorithm>().or_py_err()
}

fn now_or_system_time(now: Option<u64>) -> PyResult<u64> {
    match now {
        Some(now) => Ok(now),
        None => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|_| ProtokenError::new_err("system clock is before the Unix epoch")),
    }
}

/// Token claims. All fields except `expires_at` are optional; zero or empty
/// means unset. Instances are immutable.
#[pyclass(name = "Claims", frozen, eq, skip_from_py_object, module = "protoken")]
#[derive(Clone, PartialEq, Eq)]
struct Claims(protoken::Claims);

#[pymethods]
impl Claims {
    #[new]
    #[pyo3(signature = (expires_at, *, not_before = 0, issued_at = 0, subject = String::new(), audience = String::new(), scopes = Vec::new()))]
    fn new(
        expires_at: u64,
        not_before: u64,
        issued_at: u64,
        subject: String,
        audience: String,
        scopes: Vec<String>,
    ) -> PyResult<Self> {
        let mut claims = protoken::Claims {
            expires_at,
            not_before,
            issued_at,
            subject,
            audience,
            scopes,
        };
        claims.validate().or_py_err()?;
        // Match the wire order so accessors, repr, and equality all agree.
        claims.scopes.sort_unstable();
        Ok(Claims(claims))
    }

    #[getter]
    fn expires_at(&self) -> u64 {
        self.0.expires_at
    }

    #[getter]
    fn not_before(&self) -> u64 {
        self.0.not_before
    }

    #[getter]
    fn issued_at(&self) -> u64 {
        self.0.issued_at
    }

    #[getter]
    fn subject(&self) -> &str {
        &self.0.subject
    }

    #[getter]
    fn audience(&self) -> &str {
        &self.0.audience
    }

    /// Scopes in sorted order, as a tuple.
    #[getter]
    fn scopes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyTuple>> {
        PyTuple::new(py, &self.0.scopes)
    }

    /// The claims as a dict, omitting unset fields.
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new(py);
        dict.set_item("expires_at", self.0.expires_at)?;
        if self.0.not_before != 0 {
            dict.set_item("not_before", self.0.not_before)?;
        }
        if self.0.issued_at != 0 {
            dict.set_item("issued_at", self.0.issued_at)?;
        }
        if !self.0.subject.is_empty() {
            dict.set_item("subject", &self.0.subject)?;
        }
        if !self.0.audience.is_empty() {
            dict.set_item("audience", &self.0.audience)?;
        }
        if !self.0.scopes.is_empty() {
            dict.set_item("scopes", self.scopes(py)?)?;
        }
        Ok(dict)
    }

    fn __repr__(&self) -> String {
        format!(
            "Claims(expires_at={}, not_before={}, issued_at={}, subject={:?}, audience={:?}, scopes={:?})",
            self.0.expires_at,
            self.0.not_before,
            self.0.issued_at,
            self.0.subject,
            self.0.audience,
            self.0.scopes
        )
    }
}

/// A token whose signature has been checked against a key.
#[pyclass(name = "VerifiedToken", frozen, module = "protoken")]
struct VerifiedToken {
    #[pyo3(get)]
    algorithm: &'static str,
    #[pyo3(get)]
    key_id_type: &'static str,
    key_id: Vec<u8>,
    #[pyo3(get)]
    claims: Claims,
}

impl From<protoken::VerifiedToken> for VerifiedToken {
    fn from(token: protoken::VerifiedToken) -> Self {
        VerifiedToken {
            algorithm: token.algorithm.name(),
            key_id_type: token.key_identifier.type_name(),
            key_id: token.key_identifier.as_bytes().to_vec(),
            claims: Claims(token.claims),
        }
    }
}

#[pymethods]
impl VerifiedToken {
    /// The key hash or embedded public key named by the token.
    #[getter]
    fn key_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.key_id)
    }

    fn __repr__(&self) -> String {
        format!(
            "VerifiedToken(algorithm={:?}, key_id_type={:?}, claims={})",
            self.algorithm,
            self.key_id_type,
            self.claims.__repr__()
        )
    }
}

/// The contents of a token that has NOT been verified. Nothing in it can be
/// trusted; use it to pick a key or to debug tokens.
#[pyclass(name = "UnverifiedToken", frozen, module = "protoken")]
struct UnverifiedToken {
    #[pyo3(get)]
    algorithm: &'static str,
    #[pyo3(get)]
    key_id_type: &'static str,
    key_id: Vec<u8>,
    #[pyo3(get)]
    claims: Claims,
    signature: Vec<u8>,
}

#[pymethods]
impl UnverifiedToken {
    #[getter]
    fn key_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.key_id)
    }

    #[getter]
    fn signature<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.signature)
    }

    fn __repr__(&self) -> String {
        format!(
            "UnverifiedToken(algorithm={:?}, key_id_type={:?}, claims={})",
            self.algorithm,
            self.key_id_type,
            self.claims.__repr__()
        )
    }
}

/// Decode a token without checking its signature.
#[pyfunction]
fn inspect_token(token: &[u8]) -> PyResult<UnverifiedToken> {
    let envelope = deserialize_signed_token(token).or_token_err()?;
    let claims = deserialize_claims(&envelope.payload).or_token_err()?;
    Ok(UnverifiedToken {
        algorithm: envelope.algorithm.name(),
        key_id_type: envelope.key_identifier.type_name(),
        key_id: envelope.key_identifier.as_bytes().to_vec(),
        claims: Claims(claims),
        signature: envelope.signature,
    })
}

/// A verifying (public) key for Ed25519 or ML-DSA-44.
#[pyclass(
    name = "VerifyingKey",
    frozen,
    eq,
    skip_from_py_object,
    module = "protoken"
)]
#[derive(Clone, PartialEq, Eq)]
struct VerifyingKey(protoken::VerifyingKey);

#[pymethods]
impl VerifyingKey {
    /// Decode a serialized verifying key.
    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        protoken::VerifyingKey::from_bytes(data)
            .map(VerifyingKey)
            .or_py_err()
    }

    /// Serialize the key.
    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.to_bytes())
    }

    #[getter]
    fn algorithm(&self) -> &'static str {
        self.0.algorithm.name()
    }

    #[getter]
    fn public_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.public_key)
    }

    /// The 8-byte identifier that tokens signed by the matching key carry.
    fn key_hash<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.key_hash())
    }

    /// Verify a token. `now` is a Unix timestamp; it defaults to the current time.
    #[pyo3(signature = (token, now = None))]
    fn verify(&self, token: &[u8], now: Option<u64>) -> PyResult<VerifiedToken> {
        let now = now_or_system_time(now)?;
        self.0.verify(token, now).map(Into::into).or_token_err()
    }

    fn __repr__(&self) -> String {
        format!("VerifyingKey(algorithm={:?})", self.algorithm())
    }
}

/// A signing key for HMAC-SHA256, Ed25519, or ML-DSA-44.
#[pyclass(
    name = "SigningKey",
    frozen,
    eq,
    skip_from_py_object,
    module = "protoken"
)]
#[derive(Clone, PartialEq, Eq)]
struct SigningKey(protoken::SigningKey);

#[pymethods]
impl SigningKey {
    /// Generate a new key. `algorithm` is "hmac-sha256", "ed25519" (default), or "ml-dsa-44".
    #[staticmethod]
    #[pyo3(signature = (algorithm = "ed25519"))]
    fn generate(algorithm: &str) -> PyResult<Self> {
        protoken::SigningKey::generate(parse_algorithm(algorithm)?)
            .map(SigningKey)
            .or_py_err()
    }

    /// Decode a serialized signing key.
    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        protoken::SigningKey::from_bytes(data)
            .map(SigningKey)
            .or_py_err()
    }

    /// Serialize the key, including its secret.
    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.to_bytes())
    }

    #[getter]
    fn algorithm(&self) -> &'static str {
        self.0.algorithm.name()
    }

    /// The public key; empty for HMAC.
    #[getter]
    fn public_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.public_key)
    }

    /// The verifying key. Raises for HMAC keys, which verify with the signing key itself.
    fn verifying_key(&self) -> PyResult<VerifyingKey> {
        self.0.verifying_key().map(VerifyingKey).or_py_err()
    }

    /// The 8-byte identifier that tokens signed by this key carry.
    fn key_hash<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let id = self.0.key_identifier(KeyIdType::KeyHash).or_py_err()?;
        Ok(PyBytes::new(py, id.as_bytes()))
    }

    /// Sign claims and return the token bytes. With `embed_public_key`, the
    /// token carries the full public key instead of its hash.
    #[pyo3(signature = (claims, *, embed_public_key = false))]
    fn sign<'py>(
        &self,
        py: Python<'py>,
        claims: &Claims,
        embed_public_key: bool,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let id_type = if embed_public_key {
            KeyIdType::PublicKey
        } else {
            KeyIdType::KeyHash
        };
        let token = self.0.sign_with_key_id(&claims.0, id_type).or_py_err()?;
        Ok(PyBytes::new(py, &token))
    }

    /// Verify a token signed by this key. `now` defaults to the current time.
    #[pyo3(signature = (token, now = None))]
    fn verify(&self, token: &[u8], now: Option<u64>) -> PyResult<VerifiedToken> {
        let now = now_or_system_time(now)?;
        self.0.verify(token, now).map(Into::into).or_token_err()
    }

    /// The secret is deliberately not shown.
    fn __repr__(&self) -> String {
        format!("SigningKey(algorithm={:?})", self.algorithm())
    }
}

#[pymodule]
fn _protoken(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    m.add_class::<Claims>()?;
    m.add_class::<SigningKey>()?;
    m.add_class::<VerifyingKey>()?;
    m.add_class::<VerifiedToken>()?;
    m.add_class::<UnverifiedToken>()?;
    m.add_function(wrap_pyfunction!(inspect_token, m)?)?;
    m.add("ProtokenError", py.get_type::<ProtokenError>())?;
    m.add("TokenExpired", py.get_type::<TokenExpired>())?;
    m.add("TokenNotYetValid", py.get_type::<TokenNotYetValid>())?;
    m.add("VerificationFailed", py.get_type::<VerificationFailed>())?;
    let names: Vec<&str> = Algorithm::ALL.iter().map(|a| a.name()).collect();
    m.add("ALGORITHMS", PyTuple::new(py, names)?)?;
    Ok(())
}
