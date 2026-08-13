//! Signing and verifying keys: proto3 serialization plus algorithm dispatch
//! for key generation, signing, and verification.
//!
//! SigningKey proto3 fields:
//!   uint32 algorithm = 1;   tag 0x08  (1=HMAC-SHA256, 2=Ed25519, 3=ML-DSA-44)
//!   bytes secret_key = 2;   tag 0x12  (HMAC: raw key; Ed25519/ML-DSA-44: 32B seed)
//!   bytes public_key = 3;   tag 0x1A  (Ed25519: 32B; ML-DSA-44: 1312B; absent for HMAC)
//!
//! VerifyingKey proto3 fields:
//!   uint32 algorithm = 1;   tag 0x08  (2=Ed25519, 3=ML-DSA-44)
//!   bytes public_key = 2;   tag 0x12  (Ed25519: 32B; ML-DSA-44: 1312B)
//!
//! Decoding a SigningKey re-derives the public key from the seed and rejects
//! the key if the stored public key differs, so a loaded key can never sign
//! tokens that its own verifying key rejects.

use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::error::ProtokenError;
use crate::proto3::{
    self, missing_field, next_field, read_bounded_bytes, unexpected_field, WIRE_LEN, WIRE_VARINT,
};
use crate::serialize::read_algorithm;
use crate::sign::{
    check_hmac_key_len, compute_key_hash, derive_public_key, fill_random, sign_ed25519, sign_hmac,
    sign_mldsa44,
};
use crate::types::*;
use crate::verify::{
    ed25519_verifying_key, verify_ed25519, verify_hmac, verify_mldsa44, VerifiedToken,
};

/// Maximum secret_key field size accepted before algorithm-specific checks.
const MAX_SECRET_KEY_BYTES: usize = 4096;
/// Maximum public_key field size accepted before algorithm-specific checks.
const MAX_PUBLIC_KEY_BYTES: usize = 2048;

/// A signing key (symmetric or asymmetric).
///
/// `secret_key` is zeroed when the key is dropped. For asymmetric algorithms
/// `public_key` holds the key derived from the seed; for HMAC it is empty.
/// Build keys with [`SigningKey::generate`], [`SigningKey::from_secret_key`],
/// or [`SigningKey::from_bytes`], which establish that invariant; a key built
/// as a struct literal should be checked with [`SigningKey::validate`].
#[derive(Clone, Eq)]
pub struct SigningKey {
    pub algorithm: Algorithm,
    pub secret_key: Zeroizing<Vec<u8>>,
    pub public_key: Vec<u8>,
}

/// Secrets are compared in constant time.
impl PartialEq for SigningKey {
    fn eq(&self, other: &SigningKey) -> bool {
        self.algorithm == other.algorithm
            && bool::from(self.secret_key.ct_eq(&other.secret_key))
            && self.public_key == other.public_key
    }
}

/// Debug output redacts the secret so it cannot leak into logs.
impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("algorithm", &self.algorithm)
            .field(
                "secret_key",
                &format_args!("[{} bytes redacted]", self.secret_key.len()),
            )
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl SigningKey {
    /// Generate a fresh key for `algorithm` from the OS random number generator.
    pub fn generate(algorithm: Algorithm) -> Result<SigningKey, ProtokenError> {
        let secret_len = match algorithm {
            Algorithm::HmacSha256 => HMAC_MIN_KEY_LEN,
            Algorithm::Ed25519 => ED25519_SEED_LEN,
            Algorithm::MlDsa44 => MLDSA44_SEED_LEN,
        };
        let mut secret_key = Zeroizing::new(vec![0u8; secret_len]);
        fill_random(&mut secret_key)?;
        SigningKey::from_secret_key(algorithm, secret_key)
    }

    /// Build a key from existing secret material: an HMAC key of at least
    /// `HMAC_MIN_KEY_LEN` bytes, or a 32-byte Ed25519 / ML-DSA-44 seed. The
    /// public key is derived from the seed.
    pub fn from_secret_key(
        algorithm: Algorithm,
        secret_key: Zeroizing<Vec<u8>>,
    ) -> Result<SigningKey, ProtokenError> {
        let public_key = if algorithm.is_symmetric() {
            check_hmac_key_len(&secret_key)?;
            Vec::new()
        } else {
            derive_public_key(algorithm, &secret_key)?
        };
        Ok(SigningKey {
            algorithm,
            secret_key,
            public_key,
        })
    }

    /// Decode from canonical proto3 bytes; see `deserialize_signing_key`.
    pub fn from_bytes(data: &[u8]) -> Result<SigningKey, ProtokenError> {
        deserialize_signing_key(data)
    }

    /// Encode as canonical proto3 bytes. The output contains the secret and is
    /// zeroed when dropped.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        serialize_signing_key(self)
    }

    /// Check key sizes and, for asymmetric algorithms, that `public_key` is
    /// the key derived from `secret_key`.
    pub fn validate(&self) -> Result<(), ProtokenError> {
        match self.algorithm {
            Algorithm::HmacSha256 => {
                check_hmac_key_len(&self.secret_key)?;
                if !self.public_key.is_empty() {
                    return Err(ProtokenError::InvalidKey(
                        "HMAC signing key must not carry a public key".into(),
                    ));
                }
            }
            Algorithm::Ed25519 | Algorithm::MlDsa44 => {
                // Also enforces the seed length.
                let derived = derive_public_key(self.algorithm, &self.secret_key)?;
                if derived != self.public_key {
                    return Err(ProtokenError::InvalidKey(format!(
                        "{} public key does not match the secret key",
                        self.algorithm
                    )));
                }
            }
        }
        Ok(())
    }

    /// The public half of an asymmetric key. Errors for HMAC keys.
    pub fn verifying_key(&self) -> Result<VerifyingKey, ProtokenError> {
        Ok(VerifyingKey {
            algorithm: self.algorithm,
            public_key: self.checked_public_key()?.to_vec(),
        })
    }

    /// The public key, after checking that this is an asymmetric key whose
    /// `public_key` field has the right length. This is the cheap guard for
    /// keys built as struct literals; `validate()` does the full derivation.
    fn checked_public_key(&self) -> Result<&[u8], ProtokenError> {
        let expected = self
            .algorithm
            .public_key_len()
            .ok_or_else(|| ProtokenError::InvalidKey("symmetric key has no public key".into()))?;
        if self.public_key.len() != expected {
            return Err(ProtokenError::InvalidKeyLength {
                expected,
                actual: self.public_key.len(),
            });
        }
        Ok(&self.public_key)
    }

    /// The material tokens identify this key by: the public key for
    /// asymmetric algorithms, the secret itself for HMAC.
    fn identifying_material(&self) -> Result<&[u8], ProtokenError> {
        if self.algorithm.is_symmetric() {
            Ok(&self.secret_key)
        } else {
            self.checked_public_key()
        }
    }

    /// Key identifier of the requested type. `PublicKey` is an error for HMAC.
    pub fn key_identifier(&self, id_type: KeyIdType) -> Result<KeyIdentifier, ProtokenError> {
        match id_type {
            KeyIdType::KeyHash => Ok(KeyIdentifier::KeyHash(compute_key_hash(
                self.identifying_material()?,
            ))),
            KeyIdType::PublicKey if self.algorithm.is_symmetric() => Err(
                ProtokenError::InvalidKeyIdType(KeyIdType::PublicKey.to_byte()),
            ),
            KeyIdType::PublicKey => Ok(KeyIdentifier::PublicKey(
                self.checked_public_key()?.to_vec(),
            )),
        }
    }

    /// Sign `claims`, identifying the key by its hash. Returns the token wire bytes.
    pub fn sign(&self, claims: &Claims) -> Result<Vec<u8>, ProtokenError> {
        self.sign_with_key_id(claims, KeyIdType::KeyHash)
    }

    /// Sign `claims` with the given key identifier type. Embedding the public
    /// key (`KeyIdType::PublicKey`) makes tokens self-describing but larger.
    pub fn sign_with_key_id(
        &self,
        claims: &Claims,
        id_type: KeyIdType,
    ) -> Result<Vec<u8>, ProtokenError> {
        match self.algorithm {
            // sign_hmac derives the key hash itself; only the identifier type
            // needs checking here.
            Algorithm::HmacSha256 if id_type == KeyIdType::KeyHash => {
                sign_hmac(&self.secret_key, claims)
            }
            Algorithm::HmacSha256 => Err(ProtokenError::InvalidKeyIdType(id_type.to_byte())),
            Algorithm::Ed25519 => {
                sign_ed25519(&self.secret_key, claims, &self.key_identifier(id_type)?)
            }
            Algorithm::MlDsa44 => {
                sign_mldsa44(&self.secret_key, claims, &self.key_identifier(id_type)?)
            }
        }
    }

    /// Verify a token produced by this key. For asymmetric keys this uses the
    /// public half; for HMAC the shared secret.
    pub fn verify(&self, token_bytes: &[u8], now: u64) -> Result<VerifiedToken, ProtokenError> {
        match self.algorithm {
            Algorithm::HmacSha256 => verify_hmac(&self.secret_key, token_bytes, now),
            Algorithm::Ed25519 => verify_ed25519(self.checked_public_key()?, token_bytes, now),
            Algorithm::MlDsa44 => verify_mldsa44(self.checked_public_key()?, token_bytes, now),
        }
    }
}

/// A verifying (public) key for an asymmetric algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyingKey {
    pub algorithm: Algorithm,
    pub public_key: Vec<u8>,
}

impl VerifyingKey {
    /// Decode from canonical proto3 bytes; see `deserialize_verifying_key`.
    pub fn from_bytes(data: &[u8]) -> Result<VerifyingKey, ProtokenError> {
        deserialize_verifying_key(data)
    }

    /// Encode as canonical proto3 bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        serialize_verifying_key(self)
    }

    /// Check that the algorithm is asymmetric and the public key is well formed.
    pub fn validate(&self) -> Result<(), ProtokenError> {
        validate_public_key(self.algorithm, &self.public_key)
    }

    /// The `KeyHash` identifier that tokens signed by the matching key carry.
    #[must_use]
    pub fn key_hash(&self) -> [u8; KEY_HASH_LEN] {
        compute_key_hash(&self.public_key)
    }

    /// Verify a token against this key. `now` is the current Unix time.
    pub fn verify(&self, token_bytes: &[u8], now: u64) -> Result<VerifiedToken, ProtokenError> {
        match self.algorithm {
            Algorithm::HmacSha256 => Err(symmetric_verifying_key_error()),
            Algorithm::Ed25519 => verify_ed25519(&self.public_key, token_bytes, now),
            Algorithm::MlDsa44 => verify_mldsa44(&self.public_key, token_bytes, now),
        }
    }
}

fn symmetric_verifying_key_error() -> ProtokenError {
    ProtokenError::InvalidKey("symmetric algorithm cannot be a verifying key".into())
}

fn validate_public_key(algorithm: Algorithm, public_key: &[u8]) -> Result<(), ProtokenError> {
    match algorithm {
        Algorithm::HmacSha256 => Err(symmetric_verifying_key_error()),
        Algorithm::Ed25519 => ed25519_verifying_key(public_key).map(drop),
        Algorithm::MlDsa44 => {
            if public_key.len() != MLDSA44_PUBLIC_KEY_LEN {
                return Err(ProtokenError::InvalidKeyLength {
                    expected: MLDSA44_PUBLIC_KEY_LEN,
                    actual: public_key.len(),
                });
            }
            Ok(())
        }
    }
}

// --- Serialization ---

/// Serialize a SigningKey into canonical proto3 bytes. The output contains
/// the secret and is zeroed when dropped.
#[must_use]
pub fn serialize_signing_key(key: &SigningKey) -> Zeroizing<Vec<u8>> {
    let mut buf = Zeroizing::new(Vec::with_capacity(
        key.secret_key.len() + key.public_key.len() + 8,
    ));
    proto3::encode_uint32(1, key.algorithm.to_byte().into(), &mut buf);
    proto3::encode_bytes(2, &key.secret_key, &mut buf);
    proto3::encode_bytes(3, &key.public_key, &mut buf);
    buf
}

/// Serialize a VerifyingKey into canonical proto3 bytes.
#[must_use]
pub fn serialize_verifying_key(key: &VerifyingKey) -> Vec<u8> {
    let mut buf = Vec::with_capacity(key.public_key.len() + 8);
    proto3::encode_uint32(1, key.algorithm.to_byte().into(), &mut buf);
    proto3::encode_bytes(2, &key.public_key, &mut buf);
    buf
}

/// Deserialize and validate a SigningKey from canonical proto3 bytes.
pub fn deserialize_signing_key(data: &[u8]) -> Result<SigningKey, ProtokenError> {
    const MESSAGE: &str = "SigningKey";
    if data.is_empty() {
        return Err(ProtokenError::MalformedEncoding("empty signing key".into()));
    }

    let mut algorithm = None;
    let mut secret_key = Zeroizing::new(Vec::new());
    let mut public_key = Vec::new();
    let mut pos = 0;
    let mut last_field_number = 0;

    while pos < data.len() {
        let (field_number, wire_type) = next_field(data, &mut pos, &mut last_field_number, None)?;
        match (field_number, wire_type) {
            (1, WIRE_VARINT) => algorithm = Some(read_algorithm(data, &mut pos)?),
            (2, WIRE_LEN) => {
                let bytes = read_bounded_bytes(data, &mut pos, MAX_SECRET_KEY_BYTES, "secret_key")?;
                secret_key.extend_from_slice(bytes);
            }
            (3, WIRE_LEN) => {
                public_key =
                    read_bounded_bytes(data, &mut pos, MAX_PUBLIC_KEY_BYTES, "public_key")?
                        .to_vec();
            }
            _ => return Err(unexpected_field(field_number, wire_type, MESSAGE)),
        }
    }

    let key = SigningKey {
        algorithm: algorithm.ok_or_else(|| missing_field("algorithm", MESSAGE))?,
        secret_key,
        public_key,
    };
    key.validate()?;
    Ok(key)
}

/// Deserialize and validate a VerifyingKey from canonical proto3 bytes.
pub fn deserialize_verifying_key(data: &[u8]) -> Result<VerifyingKey, ProtokenError> {
    const MESSAGE: &str = "VerifyingKey";
    if data.is_empty() {
        return Err(ProtokenError::MalformedEncoding(
            "empty verifying key".into(),
        ));
    }

    let mut algorithm = None;
    // A rejected input may be a signing key offered by mistake (the CLI tries
    // this decoder first), in which case field 2 is a secret: keep it in a
    // zeroizing buffer until the key is known to be a real verifying key.
    let mut public_key = Zeroizing::new(Vec::new());
    let mut pos = 0;
    let mut last_field_number = 0;

    while pos < data.len() {
        let (field_number, wire_type) = next_field(data, &mut pos, &mut last_field_number, None)?;
        match (field_number, wire_type) {
            (1, WIRE_VARINT) => algorithm = Some(read_algorithm(data, &mut pos)?),
            (2, WIRE_LEN) => {
                let bytes = read_bounded_bytes(data, &mut pos, MAX_PUBLIC_KEY_BYTES, "public_key")?;
                public_key.extend_from_slice(bytes);
            }
            _ => return Err(unexpected_field(field_number, wire_type, MESSAGE)),
        }
    }

    let algorithm = algorithm.ok_or_else(|| missing_field("algorithm", MESSAGE))?;
    validate_public_key(algorithm, &public_key)?;
    Ok(VerifyingKey {
        algorithm,
        public_key: std::mem::take(&mut *public_key),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// RFC 8032 section 7.1 test 1 key pair.
    fn ed25519_fixture() -> SigningKey {
        SigningKey {
            algorithm: Algorithm::Ed25519,
            secret_key: Zeroizing::new(
                hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                    .unwrap(),
            ),
            public_key: hex::decode(
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            )
            .unwrap(),
        }
    }

    fn hmac_fixture() -> SigningKey {
        SigningKey {
            algorithm: Algorithm::HmacSha256,
            secret_key: Zeroizing::new(vec![0xAB; 32]),
            public_key: Vec::new(),
        }
    }

    fn claims() -> Claims {
        Claims {
            expires_at: 2_000_000_000,
            subject: "user:alice".into(),
            scopes: vec!["read".into(), "write".into()],
            ..Default::default()
        }
    }

    // --- Roundtrips ---

    #[test]
    fn test_signing_key_roundtrip_all_algorithms() {
        for algorithm in Algorithm::ALL {
            let key = SigningKey::generate(algorithm).unwrap();
            assert_eq!(key.algorithm, algorithm);
            let decoded = SigningKey::from_bytes(&key.to_bytes()).unwrap();
            assert_eq!(key, decoded, "{algorithm}");
            // Free functions and methods are the same encoding.
            assert_eq!(*key.to_bytes(), *serialize_signing_key(&key));
        }
    }

    #[test]
    fn test_verifying_key_roundtrip_asymmetric_algorithms() {
        for algorithm in [Algorithm::Ed25519, Algorithm::MlDsa44] {
            let vk = SigningKey::generate(algorithm)
                .unwrap()
                .verifying_key()
                .unwrap();
            let decoded = VerifyingKey::from_bytes(&vk.to_bytes()).unwrap();
            assert_eq!(vk, decoded, "{algorithm}");
            assert_eq!(vk.to_bytes(), serialize_verifying_key(&vk));
        }
    }

    #[test]
    fn test_signing_key_wire_format() {
        let bytes = ed25519_fixture().to_bytes();
        // algorithm=2, then 32-byte secret, then 32-byte public key.
        assert_eq!(&bytes[..2], &[0x08, 0x02]);
        assert_eq!(&bytes[2..4], &[0x12, 0x20]);
        assert_eq!(&bytes[36..38], &[0x1A, 0x20]);
        assert_eq!(bytes.len(), 70);

        let bytes = hmac_fixture().to_bytes();
        assert_eq!(&bytes[..4], &[0x08, 0x01, 0x12, 0x20]);
        assert_eq!(bytes.len(), 36);
    }

    #[test]
    fn test_verifying_key_wire_format() {
        let bytes = ed25519_fixture().verifying_key().unwrap().to_bytes();
        assert_eq!(&bytes[..4], &[0x08, 0x02, 0x12, 0x20]);
        assert_eq!(bytes.len(), 36);
    }

    #[test]
    fn test_hmac_signing_key_roundtrip_max_length_secret() {
        let key = SigningKey {
            secret_key: Zeroizing::new(vec![0x5A; MAX_SECRET_KEY_BYTES]),
            ..hmac_fixture()
        };
        assert_eq!(SigningKey::from_bytes(&key.to_bytes()).unwrap(), key);
    }

    // --- Construction ---

    #[test]
    fn test_generate_secret_sizes_and_randomness() {
        for algorithm in Algorithm::ALL {
            let a = SigningKey::generate(algorithm).unwrap();
            let b = SigningKey::generate(algorithm).unwrap();
            assert_eq!(a.secret_key.len(), 32, "{algorithm}");
            assert_eq!(
                a.public_key.len(),
                algorithm.public_key_len().unwrap_or(0),
                "{algorithm}"
            );
            assert_ne!(a, b, "{algorithm}: two generated keys must differ");
            assert_ne!(*a.secret_key, vec![0u8; 32], "{algorithm}");
            assert!(a.validate().is_ok(), "{algorithm}");
        }
    }

    #[test]
    fn test_from_secret_key_matches_fixture_and_decoder() {
        let fixture = ed25519_fixture();
        let built =
            SigningKey::from_secret_key(Algorithm::Ed25519, fixture.secret_key.clone()).unwrap();
        assert_eq!(built, fixture);

        for algorithm in Algorithm::ALL {
            let generated = SigningKey::generate(algorithm).unwrap();
            let rebuilt =
                SigningKey::from_secret_key(algorithm, generated.secret_key.clone()).unwrap();
            assert_eq!(rebuilt, generated, "{algorithm}");
            assert_eq!(
                SigningKey::from_bytes(&rebuilt.to_bytes()).unwrap(),
                generated,
                "{algorithm}"
            );
        }
    }

    #[test]
    fn test_from_secret_key_rejects_bad_secrets() {
        assert!(matches!(
            SigningKey::from_secret_key(Algorithm::HmacSha256, Zeroizing::new(vec![0; 31])),
            Err(ProtokenError::InvalidKey(_))
        ));
        assert!(matches!(
            SigningKey::from_secret_key(Algorithm::Ed25519, Zeroizing::new(vec![0; 16])),
            Err(ProtokenError::InvalidKeyLength {
                expected: ED25519_SEED_LEN,
                actual: 16
            })
        ));
        assert!(matches!(
            SigningKey::from_secret_key(Algorithm::MlDsa44, Zeroizing::new(vec![0; 64])),
            Err(ProtokenError::InvalidKeyLength {
                expected: MLDSA44_SEED_LEN,
                actual: 64
            })
        ));
    }

    #[test]
    fn test_struct_literal_with_wrong_public_key_length_cannot_be_used() {
        fn is_length_error<T>(result: Result<T, ProtokenError>) -> bool {
            matches!(result, Err(ProtokenError::InvalidKeyLength { .. }))
        }
        for algorithm in [Algorithm::Ed25519, Algorithm::MlDsa44] {
            for bad_len in [0, 31, 100] {
                let key = SigningKey {
                    public_key: vec![0xAA; bad_len],
                    ..SigningKey::generate(algorithm).unwrap()
                };
                assert!(
                    is_length_error(key.verifying_key()),
                    "{algorithm}/{bad_len}"
                );
                assert!(is_length_error(key.key_identifier(KeyIdType::KeyHash)));
                assert!(is_length_error(key.key_identifier(KeyIdType::PublicKey)));
                assert!(is_length_error(key.sign(&claims())));
                assert!(is_length_error(key.verify(b"", 0)));
                assert!(key.validate().is_err());
            }
        }
    }

    #[test]
    fn test_signing_key_equality_covers_every_field() {
        let key = ed25519_fixture();
        assert_eq!(key, key.clone());

        let mut other_secret = key.clone();
        other_secret.secret_key[0] ^= 1;
        assert_ne!(key, other_secret);

        let mut other_public = key.clone();
        other_public.public_key[0] ^= 1;
        assert_ne!(key, other_public);

        let mut shorter_secret = key.clone();
        shorter_secret.secret_key.pop();
        assert_ne!(key, shorter_secret);

        let other_algorithm = SigningKey {
            algorithm: Algorithm::MlDsa44,
            ..key.clone()
        };
        assert_ne!(key, other_algorithm);
    }

    // --- Sign / verify dispatch ---

    #[test]
    fn test_sign_and_verify_all_algorithms() {
        for algorithm in Algorithm::ALL {
            let sk = SigningKey::generate(algorithm).unwrap();
            let token = sk.sign(&claims()).unwrap();

            let verified = sk.verify(&token, 1_900_000_000).unwrap();
            assert_eq!(verified.claims, claims(), "{algorithm}");
            assert_eq!(verified.algorithm, algorithm);
            assert_eq!(
                verified.key_identifier,
                sk.key_identifier(KeyIdType::KeyHash).unwrap()
            );

            if algorithm.is_symmetric() {
                assert!(matches!(
                    sk.verifying_key(),
                    Err(ProtokenError::InvalidKey(_))
                ));
            } else {
                let vk = sk.verifying_key().unwrap();
                let verified = vk.verify(&token, 1_900_000_000).unwrap();
                assert_eq!(verified.claims, claims());
                assert_eq!(
                    verified.key_identifier,
                    KeyIdentifier::KeyHash(vk.key_hash())
                );

                let other = SigningKey::generate(algorithm)
                    .unwrap()
                    .verifying_key()
                    .unwrap();
                assert!(matches!(
                    other.verify(&token, 1_900_000_000),
                    Err(ProtokenError::KeyHashMismatch)
                ));
            }
        }
    }

    #[test]
    fn test_sign_with_embedded_public_key() {
        for algorithm in [Algorithm::Ed25519, Algorithm::MlDsa44] {
            let sk = SigningKey::generate(algorithm).unwrap();
            let token = sk
                .sign_with_key_id(&claims(), KeyIdType::PublicKey)
                .unwrap();
            let verified = sk.verifying_key().unwrap().verify(&token, 0).unwrap();
            assert_eq!(
                verified.key_identifier,
                KeyIdentifier::PublicKey(sk.public_key.clone())
            );
        }
    }

    #[test]
    fn test_hmac_key_rejects_embedded_public_key_id() {
        let sk = hmac_fixture();
        assert!(matches!(
            sk.sign_with_key_id(&claims(), KeyIdType::PublicKey),
            Err(ProtokenError::InvalidKeyIdType(2))
        ));
        assert!(matches!(
            sk.key_identifier(KeyIdType::PublicKey),
            Err(ProtokenError::InvalidKeyIdType(2))
        ));
    }

    #[test]
    fn test_key_identifier_material() {
        let hmac = hmac_fixture();
        assert_eq!(
            hmac.key_identifier(KeyIdType::KeyHash).unwrap(),
            KeyIdentifier::KeyHash(compute_key_hash(&hmac.secret_key))
        );
        let ed = ed25519_fixture();
        assert_eq!(
            ed.key_identifier(KeyIdType::KeyHash).unwrap(),
            KeyIdentifier::KeyHash(ed.verifying_key().unwrap().key_hash())
        );
        assert_eq!(
            ed.key_identifier(KeyIdType::PublicKey).unwrap(),
            KeyIdentifier::PublicKey(ed.public_key.clone())
        );
    }

    #[test]
    fn test_sign_is_deterministic_for_fixture() {
        let sk = ed25519_fixture();
        assert_eq!(sk.sign(&claims()).unwrap(), sk.sign(&claims()).unwrap());
    }

    #[test]
    fn test_hmac_verifying_key_struct_cannot_verify() {
        let vk = VerifyingKey {
            algorithm: Algorithm::HmacSha256,
            public_key: vec![0; 32],
        };
        assert!(matches!(vk.validate(), Err(ProtokenError::InvalidKey(_))));
        assert!(matches!(
            vk.verify(&[], 0),
            Err(ProtokenError::InvalidKey(_))
        ));
    }

    // --- Validation on decode ---

    fn encode_signing_key(algorithm: u32, secret: &[u8], public: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        proto3::encode_uint32(1, algorithm, &mut data);
        proto3::encode_bytes(2, secret, &mut data);
        proto3::encode_bytes(3, public, &mut data);
        data
    }

    fn encode_verifying_key(algorithm: u32, public: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        proto3::encode_uint32(1, algorithm, &mut data);
        proto3::encode_bytes(2, public, &mut data);
        data
    }

    #[test]
    fn test_rejects_empty_keys() {
        assert!(deserialize_signing_key(&[]).is_err());
        assert!(deserialize_verifying_key(&[]).is_err());
    }

    #[test]
    fn test_rejects_missing_algorithm() {
        let mut data = Vec::new();
        proto3::encode_bytes(2, &[0xAB; 32], &mut data);
        let err = deserialize_signing_key(&data).unwrap_err();
        assert!(
            matches!(&err, ProtokenError::MalformedEncoding(m) if m.contains("missing algorithm")),
            "got {err:?}"
        );
        let err = deserialize_verifying_key(&data).unwrap_err();
        assert!(
            matches!(&err, ProtokenError::MalformedEncoding(m) if m.contains("missing algorithm")),
            "got {err:?}"
        );
    }

    #[test]
    fn test_rejects_unknown_and_zero_algorithm() {
        assert!(matches!(
            deserialize_signing_key(&encode_signing_key(9, &[0xAB; 32], &[])),
            Err(ProtokenError::InvalidAlgorithm(9))
        ));
        assert!(matches!(
            deserialize_verifying_key(&encode_verifying_key(9, &[0; 32])),
            Err(ProtokenError::InvalidAlgorithm(9))
        ));
        // Explicit zero is non-canonical.
        let data = [0x08, 0x00, 0x12, 0x01, 0xAA];
        assert!(matches!(
            deserialize_signing_key(&data),
            Err(ProtokenError::MalformedEncoding(_))
        ));
        assert!(matches!(
            deserialize_verifying_key(&data),
            Err(ProtokenError::MalformedEncoding(_))
        ));
    }

    #[test]
    fn test_rejects_hmac_verifying_key() {
        assert!(matches!(
            deserialize_verifying_key(&encode_verifying_key(1, &[0; 32])),
            Err(ProtokenError::InvalidKey(_))
        ));
    }

    #[test]
    fn test_rejects_short_hmac_key() {
        assert!(matches!(
            deserialize_signing_key(&encode_signing_key(1, &[0; 16], &[])),
            Err(ProtokenError::InvalidKey(_))
        ));
    }

    #[test]
    fn test_rejects_hmac_key_with_public_key() {
        let err =
            deserialize_signing_key(&encode_signing_key(1, &[0xAB; 32], &[0; 32])).unwrap_err();
        assert!(
            matches!(&err, ProtokenError::InvalidKey(m) if m.contains("public key")),
            "got {err:?}"
        );
    }

    #[test]
    fn test_rejects_wrong_seed_length() {
        let pk = ed25519_fixture().public_key;
        assert!(matches!(
            deserialize_signing_key(&encode_signing_key(2, &[0; 16], &pk)),
            Err(ProtokenError::InvalidKeyLength {
                expected: ED25519_SEED_LEN,
                actual: 16
            })
        ));
        assert!(matches!(
            deserialize_signing_key(&encode_signing_key(
                3,
                &[0; 31],
                &[0; MLDSA44_PUBLIC_KEY_LEN]
            )),
            Err(ProtokenError::InvalidKeyLength {
                expected: MLDSA44_SEED_LEN,
                actual: 31
            })
        ));
    }

    #[test]
    fn test_rejects_mismatched_public_key() {
        for algorithm in [Algorithm::Ed25519, Algorithm::MlDsa44] {
            let real = SigningKey::generate(algorithm).unwrap();
            let other = SigningKey::generate(algorithm).unwrap();

            let mismatched = SigningKey {
                public_key: other.public_key.clone(),
                ..real.clone()
            };
            let err = deserialize_signing_key(&mismatched.to_bytes()).unwrap_err();
            assert!(
                matches!(&err, ProtokenError::InvalidKey(m) if m.contains("does not match")),
                "{algorithm}: got {err:?}"
            );

            // A missing or truncated public key is also a mismatch.
            let missing = SigningKey {
                public_key: Vec::new(),
                ..real.clone()
            };
            assert!(deserialize_signing_key(&missing.to_bytes()).is_err());
        }
    }

    #[test]
    fn test_accepts_known_ed25519_pair() {
        let key = ed25519_fixture();
        assert!(key.validate().is_ok());
        assert_eq!(SigningKey::from_bytes(&key.to_bytes()).unwrap(), key);
    }

    #[test]
    fn test_rejects_wrong_length_verifying_keys() {
        assert!(matches!(
            deserialize_verifying_key(&encode_verifying_key(2, &[0; 31])),
            Err(ProtokenError::InvalidKeyLength {
                expected: ED25519_PUBLIC_KEY_LEN,
                actual: 31
            })
        ));
        assert!(matches!(
            deserialize_verifying_key(&encode_verifying_key(3, &[0; 1000])),
            Err(ProtokenError::InvalidKeyLength {
                expected: MLDSA44_PUBLIC_KEY_LEN,
                actual: 1000
            })
        ));
    }

    #[test]
    fn test_rejects_invalid_ed25519_point_in_verifying_key() {
        let not_on_curve = crate::verify::tests::NOT_ON_CURVE;
        assert!(matches!(
            deserialize_verifying_key(&encode_verifying_key(2, &not_on_curve)),
            Err(ProtokenError::InvalidKey(_))
        ));
    }

    #[test]
    fn test_field_size_limits() {
        // Over the raw limits: rejected while reading the field.
        let too_big_secret = encode_signing_key(1, &vec![0; MAX_SECRET_KEY_BYTES + 1], &[]);
        assert!(matches!(
            deserialize_signing_key(&too_big_secret),
            Err(ProtokenError::MalformedEncoding(m)) if m.contains("secret_key too long")
        ));
        let too_big_public = encode_signing_key(2, &[0; 32], &vec![0; MAX_PUBLIC_KEY_BYTES + 1]);
        assert!(matches!(
            deserialize_signing_key(&too_big_public),
            Err(ProtokenError::MalformedEncoding(m)) if m.contains("public_key too long")
        ));
        let too_big_vk = encode_verifying_key(2, &vec![0; MAX_PUBLIC_KEY_BYTES + 1]);
        assert!(matches!(
            deserialize_verifying_key(&too_big_vk),
            Err(ProtokenError::MalformedEncoding(m)) if m.contains("public_key too long")
        ));

        // At the raw limits: passes the read and fails algorithm-specific checks.
        let max_public = encode_signing_key(2, &[0; 32], &vec![0; MAX_PUBLIC_KEY_BYTES]);
        assert!(matches!(
            deserialize_signing_key(&max_public),
            Err(ProtokenError::InvalidKey(_))
        ));
        let max_vk = encode_verifying_key(3, &vec![0; MAX_PUBLIC_KEY_BYTES]);
        assert!(matches!(
            deserialize_verifying_key(&max_vk),
            Err(ProtokenError::InvalidKeyLength { .. })
        ));
    }

    #[test]
    fn test_rejects_unknown_and_out_of_order_fields() {
        let mut data = encode_signing_key(1, &[0xAB; 32], &[]);
        proto3::encode_bytes(4, &[1], &mut data);
        assert!(deserialize_signing_key(&data).is_err());

        let mut data = Vec::new();
        proto3::encode_bytes(2, &[0xAB; 32], &mut data);
        proto3::encode_uint32(1, 1, &mut data);
        assert!(deserialize_signing_key(&data).is_err());

        let mut data = encode_verifying_key(2, &ed25519_fixture().public_key);
        proto3::encode_bytes(3, &[1], &mut data);
        assert!(deserialize_verifying_key(&data).is_err());
    }

    #[test]
    fn test_rejects_empty_secret_field() {
        // An explicit empty bytes field is non-canonical.
        let data = [0x08, 0x01, 0x12, 0x00];
        assert!(matches!(
            deserialize_signing_key(&data),
            Err(ProtokenError::MalformedEncoding(m)) if m.contains("empty")
        ));
    }

    #[test]
    fn test_signing_key_debug_redacts_secret() {
        let debug = format!("{:?}", hmac_fixture());
        assert!(debug.contains("[32 bytes redacted]"), "got: {debug}");
        assert!(debug.contains("HmacSha256"));
        assert!(!debug.contains("171"), "secret byte leaked: {debug}");
    }
}
