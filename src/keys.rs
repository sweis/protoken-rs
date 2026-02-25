//! Proto3 key serialization for protoken signing and verifying keys.
//!
//! SigningKey proto3 fields:
//!   uint32 algorithm = 1;   tag 0x08  (1=HMAC-SHA256, 2=Ed25519, 3=ML-DSA-44)
//!   bytes secret_key = 2;   tag 0x12  (HMAC: raw key; Ed25519: 32B seed; ML-DSA-44: 2560B SK)
//!   bytes public_key = 3;   tag 0x1A  (Ed25519: 32B; ML-DSA-44: 1312B; empty for HMAC)
//!
//! VerifyingKey proto3 fields:
//!   uint32 algorithm = 1;   tag 0x08  (2=Ed25519, 3=ML-DSA-44)
//!   bytes public_key = 2;   tag 0x12  (Ed25519: 32B; ML-DSA-44: 1312B)

use zeroize::Zeroizing;

use crate::error::ProtokenError;
use crate::proto3;
use crate::types::*;

/// A serialized signing key (symmetric or asymmetric).
/// The `secret_key` field is wrapped in `Zeroizing` so it is automatically
/// zeroed from memory when dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningKey {
    pub algorithm: Algorithm,
    pub secret_key: Zeroizing<Vec<u8>>,
    pub public_key: Vec<u8>,
}

/// A serialized verifying key (asymmetric only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyingKey {
    pub algorithm: Algorithm,
    pub public_key: Vec<u8>,
}

/// Extract the VerifyingKey from a SigningKey (asymmetric keys only).
/// For ECVRF, the public key is used for proof verification.
pub fn extract_verifying_key(sk: &SigningKey) -> Result<VerifyingKey, ProtokenError> {
    if sk.algorithm == Algorithm::HmacSha256 {
        return Err(ProtokenError::MalformedEncoding(
            "HMAC-SHA256 is symmetric; no verifying key to extract".into(),
        ));
    }
    if sk.public_key.is_empty() {
        return Err(ProtokenError::MalformedEncoding(
            "signing key has no public key".into(),
        ));
    }
    Ok(VerifyingKey {
        algorithm: sk.algorithm,
        public_key: sk.public_key.clone(),
    })
}

// --- Serialization ---

/// Serialize a SigningKey into canonical proto3 bytes.
#[must_use]
pub fn serialize_signing_key(key: &SigningKey) -> Vec<u8> {
    let mut buf = Vec::with_capacity(key.secret_key.len() + key.public_key.len() + 8);
    proto3::encode_uint32(1, key.algorithm.to_byte() as u32, &mut buf);
    proto3::encode_bytes(2, &key.secret_key, &mut buf);
    proto3::encode_bytes(3, &key.public_key, &mut buf);
    buf
}

/// Serialize a VerifyingKey into canonical proto3 bytes.
#[must_use]
pub fn serialize_verifying_key(key: &VerifyingKey) -> Vec<u8> {
    let mut buf = Vec::with_capacity(key.public_key.len() + 8);
    proto3::encode_uint32(1, key.algorithm.to_byte() as u32, &mut buf);
    proto3::encode_bytes(2, &key.public_key, &mut buf);
    buf
}

// --- Deserialization ---

/// Maximum allowed secret key size (ML-DSA-44 SK = 2560 bytes).
const MAX_SECRET_KEY_BYTES: usize = 4096;

/// Maximum allowed public key size (ML-DSA-44 PK = 1312 bytes).
const MAX_PUBLIC_KEY_BYTES: usize = 2048;

/// Deserialize a SigningKey from canonical proto3 bytes.
pub fn deserialize_signing_key(data: &[u8]) -> Result<SigningKey, ProtokenError> {
    if data.is_empty() {
        return Err(ProtokenError::MalformedEncoding("empty signing key".into()));
    }

    let mut algorithm: u32 = 0;
    let mut secret_key: Vec<u8> = Vec::new();
    let mut public_key: Vec<u8> = Vec::new();

    let mut pos = 0;
    let mut last_field_number = 0u32;

    while pos < data.len() {
        let (field_number, wire_type) = proto3::decode_tag(data, &mut pos)?;
        if field_number <= last_field_number {
            return Err(ProtokenError::MalformedEncoding(format!(
                "fields not in ascending order: field {field_number} after {last_field_number}"
            )));
        }
        last_field_number = field_number;

        match (field_number, wire_type) {
            (1, 0) => algorithm = proto3::read_u32(data, &mut pos)?,
            (2, 2) => {
                let bytes = proto3::read_bytes_value(data, &mut pos)?;
                if bytes.len() > MAX_SECRET_KEY_BYTES {
                    return Err(ProtokenError::MalformedEncoding(format!(
                        "secret key too large: {} bytes (max {})",
                        bytes.len(),
                        MAX_SECRET_KEY_BYTES
                    )));
                }
                secret_key = bytes.to_vec();
            }
            (3, 2) => {
                let bytes = proto3::read_bytes_value(data, &mut pos)?;
                if bytes.len() > MAX_PUBLIC_KEY_BYTES {
                    return Err(ProtokenError::MalformedEncoding(format!(
                        "public key too large: {} bytes (max {})",
                        bytes.len(),
                        MAX_PUBLIC_KEY_BYTES
                    )));
                }
                public_key = bytes.to_vec();
            }
            (_, _) => {
                return Err(ProtokenError::MalformedEncoding(format!(
                    "unexpected field {field_number} (wire type {wire_type}) in SigningKey"
                )));
            }
        }
    }

    let algo_byte = proto3::to_u8(algorithm, "algorithm")?;
    let algorithm =
        Algorithm::from_byte(algo_byte).ok_or(ProtokenError::InvalidAlgorithm(algo_byte))?;

    // Validate key sizes
    validate_signing_key_sizes(algorithm, &secret_key, &public_key)?;

    Ok(SigningKey {
        algorithm,
        secret_key: Zeroizing::new(secret_key),
        public_key,
    })
}

/// Deserialize a VerifyingKey from canonical proto3 bytes.
pub fn deserialize_verifying_key(data: &[u8]) -> Result<VerifyingKey, ProtokenError> {
    if data.is_empty() {
        return Err(ProtokenError::MalformedEncoding(
            "empty verifying key".into(),
        ));
    }

    let mut algorithm: u32 = 0;
    let mut public_key: Vec<u8> = Vec::new();

    let mut pos = 0;
    let mut last_field_number = 0u32;

    while pos < data.len() {
        let (field_number, wire_type) = proto3::decode_tag(data, &mut pos)?;
        if field_number <= last_field_number {
            return Err(ProtokenError::MalformedEncoding(format!(
                "fields not in ascending order: field {field_number} after {last_field_number}"
            )));
        }
        last_field_number = field_number;

        match (field_number, wire_type) {
            (1, 0) => algorithm = proto3::read_u32(data, &mut pos)?,
            (2, 2) => {
                let bytes = proto3::read_bytes_value(data, &mut pos)?;
                if bytes.len() > MAX_PUBLIC_KEY_BYTES {
                    return Err(ProtokenError::MalformedEncoding(format!(
                        "public key too large: {} bytes (max {})",
                        bytes.len(),
                        MAX_PUBLIC_KEY_BYTES
                    )));
                }
                public_key = bytes.to_vec();
            }
            (_, _) => {
                return Err(ProtokenError::MalformedEncoding(format!(
                    "unexpected field {field_number} (wire type {wire_type}) in VerifyingKey"
                )));
            }
        }
    }

    let algo_byte = proto3::to_u8(algorithm, "algorithm")?;
    let algorithm =
        Algorithm::from_byte(algo_byte).ok_or(ProtokenError::InvalidAlgorithm(algo_byte))?;

    // Validate
    if algorithm == Algorithm::HmacSha256 {
        return Err(ProtokenError::MalformedEncoding(
            "HMAC-SHA256 is symmetric; cannot be a verifying key".into(),
        ));
    }
    validate_public_key_size(algorithm, &public_key)?;

    Ok(VerifyingKey {
        algorithm,
        public_key,
    })
}

fn validate_signing_key_sizes(
    algorithm: Algorithm,
    secret_key: &[u8],
    public_key: &[u8],
) -> Result<(), ProtokenError> {
    match algorithm {
        Algorithm::HmacSha256 => {
            if secret_key.len() < HMAC_MIN_KEY_LEN {
                return Err(ProtokenError::MalformedEncoding(format!(
                    "HMAC key too short: {} bytes (minimum {})",
                    secret_key.len(),
                    HMAC_MIN_KEY_LEN
                )));
            }
        }
        Algorithm::Ed25519 => {
            if secret_key.len() != ED25519_SEED_LEN {
                return Err(ProtokenError::MalformedEncoding(format!(
                    "Ed25519 seed must be {} bytes, got {}",
                    ED25519_SEED_LEN,
                    secret_key.len()
                )));
            }
            if public_key.len() != ED25519_PUBLIC_KEY_LEN {
                return Err(ProtokenError::MalformedEncoding(format!(
                    "Ed25519 public key must be {} bytes, got {}",
                    ED25519_PUBLIC_KEY_LEN,
                    public_key.len()
                )));
            }
        }
        Algorithm::MlDsa44 => {
            if secret_key.len() != MLDSA44_SIGNING_KEY_LEN {
                return Err(ProtokenError::MalformedEncoding(format!(
                    "ML-DSA-44 signing key must be {} bytes, got {}",
                    MLDSA44_SIGNING_KEY_LEN,
                    secret_key.len()
                )));
            }
            if public_key.len() != MLDSA44_PUBLIC_KEY_LEN {
                return Err(ProtokenError::MalformedEncoding(format!(
                    "ML-DSA-44 public key must be {} bytes, got {}",
                    MLDSA44_PUBLIC_KEY_LEN,
                    public_key.len()
                )));
            }
        }
        Algorithm::EcVrf => {
            if secret_key.len() != ECVRF_SECRET_KEY_LEN {
                return Err(ProtokenError::MalformedEncoding(format!(
                    "ECVRF secret key must be {} bytes, got {}",
                    ECVRF_SECRET_KEY_LEN,
                    secret_key.len()
                )));
            }
            if public_key.len() != ECVRF_PUBLIC_KEY_LEN {
                return Err(ProtokenError::MalformedEncoding(format!(
                    "ECVRF public key must be {} bytes, got {}",
                    ECVRF_PUBLIC_KEY_LEN,
                    public_key.len()
                )));
            }
        }
    }
    Ok(())
}

fn validate_public_key_size(algorithm: Algorithm, public_key: &[u8]) -> Result<(), ProtokenError> {
    let expected = match algorithm {
        Algorithm::Ed25519 => ED25519_PUBLIC_KEY_LEN,
        Algorithm::MlDsa44 => MLDSA44_PUBLIC_KEY_LEN,
        Algorithm::EcVrf => ECVRF_PUBLIC_KEY_LEN,
        Algorithm::HmacSha256 => {
            return Err(ProtokenError::MalformedEncoding(
                "HMAC-SHA256 has no public key".into(),
            ));
        }
    };
    if public_key.len() != expected {
        return Err(ProtokenError::MalformedEncoding(format!(
            "{:?} public key must be {} bytes, got {}",
            algorithm,
            expected,
            public_key.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_signing_key_hmac_roundtrip() {
        let key = SigningKey {
            algorithm: Algorithm::HmacSha256,
            secret_key: Zeroizing::new(vec![0xAB; 32]),
            public_key: Vec::new(),
        };
        let bytes = serialize_signing_key(&key);
        let decoded = deserialize_signing_key(&bytes).unwrap();
        assert_eq!(key, decoded);
    }

    #[test]
    fn test_signing_key_ed25519_roundtrip() {
        let key = SigningKey {
            algorithm: Algorithm::Ed25519,
            secret_key: Zeroizing::new(vec![0x01; 32]),
            public_key: vec![0x02; 32],
        };
        let bytes = serialize_signing_key(&key);
        let decoded = deserialize_signing_key(&bytes).unwrap();
        assert_eq!(key, decoded);
    }

    #[test]
    fn test_signing_key_mldsa44_roundtrip() {
        let key = SigningKey {
            algorithm: Algorithm::MlDsa44,
            secret_key: Zeroizing::new(vec![0x03; MLDSA44_SIGNING_KEY_LEN]),
            public_key: vec![0x04; MLDSA44_PUBLIC_KEY_LEN],
        };
        let bytes = serialize_signing_key(&key);
        let decoded = deserialize_signing_key(&bytes).unwrap();
        assert_eq!(key, decoded);
    }

    #[test]
    fn test_verifying_key_ed25519_roundtrip() {
        let key = VerifyingKey {
            algorithm: Algorithm::Ed25519,
            public_key: vec![0x02; 32],
        };
        let bytes = serialize_verifying_key(&key);
        let decoded = deserialize_verifying_key(&bytes).unwrap();
        assert_eq!(key, decoded);
    }

    #[test]
    fn test_verifying_key_mldsa44_roundtrip() {
        let key = VerifyingKey {
            algorithm: Algorithm::MlDsa44,
            public_key: vec![0x04; MLDSA44_PUBLIC_KEY_LEN],
        };
        let bytes = serialize_verifying_key(&key);
        let decoded = deserialize_verifying_key(&bytes).unwrap();
        assert_eq!(key, decoded);
    }

    #[test]
    fn test_extract_verifying_key() {
        let sk = SigningKey {
            algorithm: Algorithm::Ed25519,
            secret_key: Zeroizing::new(vec![0x01; 32]),
            public_key: vec![0x02; 32],
        };
        let vk = extract_verifying_key(&sk).unwrap();
        assert_eq!(vk.algorithm, Algorithm::Ed25519);
        assert_eq!(vk.public_key, vec![0x02; 32]);
    }

    #[test]
    fn test_extract_verifying_key_hmac_fails() {
        let sk = SigningKey {
            algorithm: Algorithm::HmacSha256,
            secret_key: Zeroizing::new(vec![0xAB; 32]),
            public_key: Vec::new(),
        };
        assert!(extract_verifying_key(&sk).is_err());
    }

    #[test]
    fn test_signing_key_deterministic() {
        let key = SigningKey {
            algorithm: Algorithm::Ed25519,
            secret_key: Zeroizing::new(vec![0x01; 32]),
            public_key: vec![0x02; 32],
        };
        let b1 = serialize_signing_key(&key);
        let b2 = serialize_signing_key(&key);
        assert_eq!(b1, b2);
    }

    #[test]
    fn test_rejects_hmac_verifying_key() {
        let mut data = Vec::new();
        proto3::encode_uint32(1, 1, &mut data); // HMAC
        proto3::encode_bytes(2, &[0; 32], &mut data);
        assert!(deserialize_verifying_key(&data).is_err());
    }

    #[test]
    fn test_rejects_wrong_ed25519_seed_size() {
        let mut data = Vec::new();
        proto3::encode_uint32(1, 2, &mut data); // Ed25519
        proto3::encode_bytes(2, &[0; 16], &mut data); // wrong size
        proto3::encode_bytes(3, &[0; 32], &mut data);
        assert!(deserialize_signing_key(&data).is_err());
    }

    #[test]
    fn test_rejects_empty_signing_key() {
        assert!(deserialize_signing_key(&[]).is_err());
    }

    #[test]
    fn test_rejects_empty_verifying_key() {
        assert!(deserialize_verifying_key(&[]).is_err());
    }

    #[test]
    fn test_signing_key_ecvrf_roundtrip() {
        let key = SigningKey {
            algorithm: Algorithm::EcVrf,
            secret_key: Zeroizing::new(vec![0x05; ECVRF_SECRET_KEY_LEN]),
            public_key: vec![0x06; ECVRF_PUBLIC_KEY_LEN],
        };
        let bytes = serialize_signing_key(&key);
        let decoded = deserialize_signing_key(&bytes).unwrap();
        assert_eq!(key, decoded);
    }

    #[test]
    fn test_verifying_key_ecvrf_roundtrip() {
        let key = VerifyingKey {
            algorithm: Algorithm::EcVrf,
            public_key: vec![0x06; ECVRF_PUBLIC_KEY_LEN],
        };
        let bytes = serialize_verifying_key(&key);
        let decoded = deserialize_verifying_key(&bytes).unwrap();
        assert_eq!(key, decoded);
    }

    #[test]
    fn test_extract_verifying_key_ecvrf() {
        let sk = SigningKey {
            algorithm: Algorithm::EcVrf,
            secret_key: Zeroizing::new(vec![0x05; ECVRF_SECRET_KEY_LEN]),
            public_key: vec![0x06; ECVRF_PUBLIC_KEY_LEN],
        };
        let vk = extract_verifying_key(&sk).unwrap();
        assert_eq!(vk.algorithm, Algorithm::EcVrf);
        assert_eq!(vk.public_key, vec![0x06; ECVRF_PUBLIC_KEY_LEN]);
    }
}
