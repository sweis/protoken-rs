//! Signing and verifying keys.
//!
//! SigningKey proto3 fields:
//!   uint32 algorithm = 1;   tag 0x08
//!   bytes secret_key = 2;   tag 0x12
//!   bytes public_key = 3;   tag 0x1A  (absent for HMAC)
//!
//! VerifyingKey proto3 fields:
//!   uint32 algorithm = 1;   tag 0x08
//!   bytes public_key = 2;   tag 0x12
//!
//! Every constructor validates, and the fields are private, so a key that
//! exists is well formed.

use std::fmt;

use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::crypto::scheme;
use crate::error::ProtokenError;
use crate::proto3::{self, missing_field, unexpected_field, Reader, WIRE_LEN, WIRE_VARINT};
use crate::serialize::read_algorithm;
use crate::sign::{compute_key_hash, sign_token};
use crate::types::*;
use crate::verify::{verify_token, VerifiedToken};

/// Upper bound on the tag and length bytes in a serialized key.
const KEY_FRAMING_BYTES: usize = 8;

/// A signing key (symmetric or asymmetric). The secret is zeroed on drop.
#[derive(Clone, Eq)]
pub struct SigningKey {
    algorithm: Algorithm,
    secret_key: Zeroizing<Vec<u8>>,
    /// Derived from `secret_key`; empty for HMAC.
    public_key: Vec<u8>,
}

/// Secrets are compared in constant time.
impl PartialEq for SigningKey {
    fn eq(&self, other: &SigningKey) -> bool {
        self.algorithm == other.algorithm && bool::from(self.secret_key.ct_eq(&other.secret_key))
    }
}

/// Redacts the secret so it cannot leak into logs.
impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// Generate a fresh key from the OS random number generator.
    pub fn generate(algorithm: Algorithm) -> Result<SigningKey, ProtokenError> {
        let secret_key = scheme(algorithm).generate_secret_key(algorithm.secret_key_len())?;
        SigningKey::from_secret_key(algorithm, secret_key)
    }

    /// Build a key from existing secret material: a 48 to 128 byte HMAC key,
    /// a 32-byte ML-DSA seed, or an encoded SLH-DSA or FN-DSA private key.
    pub fn from_secret_key(
        algorithm: Algorithm,
        secret_key: Zeroizing<Vec<u8>>,
    ) -> Result<SigningKey, ProtokenError> {
        check_secret_key_len(algorithm, &secret_key)?;
        let public_key = scheme(algorithm).public_key(&secret_key)?;
        Ok(SigningKey {
            algorithm,
            secret_key,
            public_key,
        })
    }

    /// Decode from canonical proto3 bytes. The public key is re-derived and
    /// must match the stored one, so a corrupted key cannot sign tokens that
    /// its own verifying key rejects.
    pub fn from_bytes(data: &[u8]) -> Result<SigningKey, ProtokenError> {
        const MESSAGE: &str = "SigningKey";
        let mut algorithm = None;
        let mut secret_key: &[u8] = &[];
        let mut public_key: &[u8] = &[];

        let mut reader = Reader::new(data);
        while !reader.is_at_end() {
            match reader.next_field(None)? {
                (1, WIRE_VARINT) => algorithm = Some(read_algorithm(&mut reader)?),
                (2, WIRE_LEN) => {
                    secret_key = reader.read_bytes(MAX_SECRET_KEY_BYTES, "secret_key")?;
                }
                (3, WIRE_LEN) => {
                    public_key = reader.read_bytes(MAX_PUBLIC_KEY_BYTES, "public_key")?;
                }
                (field, wire_type) => return Err(unexpected_field(field, wire_type, MESSAGE)),
            }
        }

        let algorithm = algorithm.ok_or_else(|| missing_field("algorithm", MESSAGE))?;
        let key = SigningKey::from_secret_key(algorithm, Zeroizing::new(secret_key.to_vec()))?;
        if key.public_key != public_key {
            return Err(ProtokenError::InvalidKey(format!(
                "{algorithm} public key does not match the secret key"
            )));
        }
        Ok(key)
    }

    /// Encode as canonical proto3 bytes. The output contains the secret.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        // Sized up front: growing would leave copies of the secret behind.
        let mut buf = Zeroizing::new(Vec::with_capacity(
            self.secret_key.len() + self.public_key.len() + KEY_FRAMING_BYTES,
        ));
        proto3::encode_uint32(1, self.algorithm as u32, &mut buf);
        proto3::encode_bytes(2, &self.secret_key, &mut buf);
        proto3::encode_bytes(3, &self.public_key, &mut buf);
        buf
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    pub fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }

    /// Empty for HMAC.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// The public half of an asymmetric key. Errors for HMAC keys.
    pub fn verifying_key(&self) -> Result<VerifyingKey, ProtokenError> {
        VerifyingKey::new(self.algorithm, self.public_key.clone())
    }

    /// What a verifier holds: the secret for HMAC, otherwise the public key.
    fn verifier_material(&self) -> &[u8] {
        if self.algorithm.is_symmetric() {
            &self.secret_key
        } else {
            &self.public_key
        }
    }

    /// Key identifier of the requested type. `PublicKey` is an error for HMAC.
    pub fn key_identifier(&self, id_type: KeyIdType) -> Result<KeyIdentifier, ProtokenError> {
        match id_type {
            KeyIdType::KeyHash => Ok(KeyIdentifier::KeyHash(compute_key_hash(
                self.verifier_material(),
            ))),
            KeyIdType::PublicKey if self.algorithm.is_symmetric() => {
                Err(ProtokenError::InvalidKeyIdType(id_type as u8))
            }
            KeyIdType::PublicKey => Ok(KeyIdentifier::PublicKey(self.public_key.clone())),
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
        let key_id = self.key_identifier(id_type)?;
        sign_token(self.algorithm, &self.secret_key, &key_id, claims)
    }

    /// Verify a token produced by this key. `now` is the current Unix time.
    pub fn verify(&self, token_bytes: &[u8], now: u64) -> Result<VerifiedToken, ProtokenError> {
        verify_token(self.algorithm, self.verifier_material(), token_bytes, now)
    }
}

/// A verifying (public) key for an asymmetric algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyingKey {
    algorithm: Algorithm,
    public_key: Vec<u8>,
}

impl VerifyingKey {
    /// Build a key from the algorithm's standard public key encoding.
    pub fn new(algorithm: Algorithm, public_key: Vec<u8>) -> Result<VerifyingKey, ProtokenError> {
        check_public_key(algorithm, &public_key)?;
        Ok(VerifyingKey {
            algorithm,
            public_key,
        })
    }

    /// Decode from canonical proto3 bytes.
    pub fn from_bytes(data: &[u8]) -> Result<VerifyingKey, ProtokenError> {
        const MESSAGE: &str = "VerifyingKey";
        let mut algorithm = None;
        let mut public_key: &[u8] = &[];

        let mut reader = Reader::new(data);
        while !reader.is_at_end() {
            match reader.next_field(None)? {
                (1, WIRE_VARINT) => algorithm = Some(read_algorithm(&mut reader)?),
                (2, WIRE_LEN) => {
                    public_key = reader.read_bytes(MAX_PUBLIC_KEY_BYTES, "public_key")?;
                }
                (field, wire_type) => return Err(unexpected_field(field, wire_type, MESSAGE)),
            }
        }

        let algorithm = algorithm.ok_or_else(|| missing_field("algorithm", MESSAGE))?;
        // Check before copying: in a signing key offered by mistake, field 2 is a secret.
        check_public_key(algorithm, public_key)?;
        Ok(VerifyingKey {
            algorithm,
            public_key: public_key.to_vec(),
        })
    }

    /// Encode as canonical proto3 bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.public_key.len() + KEY_FRAMING_BYTES);
        proto3::encode_uint32(1, self.algorithm as u32, &mut buf);
        proto3::encode_bytes(2, &self.public_key, &mut buf);
        buf
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// The `KeyHash` identifier that tokens signed by the matching key carry.
    #[must_use]
    pub fn key_hash(&self) -> [u8; KEY_HASH_LEN] {
        compute_key_hash(&self.public_key)
    }

    /// Verify a token against this key. `now` is the current Unix time.
    pub fn verify(&self, token_bytes: &[u8], now: u64) -> Result<VerifiedToken, ProtokenError> {
        verify_token(self.algorithm, &self.public_key, token_bytes, now)
    }
}

fn check_len(expected: usize, key: &[u8]) -> Result<(), ProtokenError> {
    if key.len() != expected {
        return Err(ProtokenError::InvalidKeyLength {
            expected,
            actual: key.len(),
        });
    }
    Ok(())
}

fn check_secret_key_len(algorithm: Algorithm, secret_key: &[u8]) -> Result<(), ProtokenError> {
    if !algorithm.is_symmetric() {
        return check_len(algorithm.secret_key_len(), secret_key);
    }
    if !(HMAC_MIN_KEY_LEN..=HMAC_MAX_KEY_LEN).contains(&secret_key.len()) {
        return Err(ProtokenError::InvalidKey(format!(
            "HMAC key must be {HMAC_MIN_KEY_LEN} to {HMAC_MAX_KEY_LEN} bytes, got {}",
            secret_key.len()
        )));
    }
    Ok(())
}

fn check_public_key(algorithm: Algorithm, public_key: &[u8]) -> Result<(), ProtokenError> {
    let expected = algorithm
        .public_key_len()
        .ok_or_else(|| ProtokenError::InvalidKey(format!("{algorithm} has no verifying key")))?;
    check_len(expected, public_key)?;
    if !scheme(algorithm).is_valid_public_key(public_key) {
        return Err(ProtokenError::InvalidKey(format!(
            "malformed {algorithm} public key"
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
pub(crate) mod tests {
    use std::sync::LazyLock;

    use super::*;

    pub(crate) const ASYMMETRIC: [Algorithm; 8] = [
        Algorithm::MlDsa44,
        Algorithm::MlDsa65,
        Algorithm::MlDsa87,
        Algorithm::SlhDsaSha2_128s,
        Algorithm::SlhDsaSha2_192s,
        Algorithm::SlhDsaSha2_256s,
        Algorithm::FnDsa512,
        Algorithm::FnDsa1024,
    ];

    /// One key per algorithm, shared by all tests because SLH-DSA key generation is slow.
    pub(crate) fn fixed_key(algorithm: Algorithm) -> SigningKey {
        static KEYS: LazyLock<[SigningKey; 9]> =
            LazyLock::new(|| Algorithm::ALL.map(|a| SigningKey::generate(a).unwrap()));
        let key = KEYS.iter().find(|key| key.algorithm == algorithm);
        key.unwrap().clone()
    }

    fn claims() -> Claims {
        Claims {
            expires_at: 2_000_000_000,
            subject: "user:alice".into(),
            scopes: vec!["read".into(), "write".into()],
            ..Default::default()
        }
    }

    fn secret(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(bytes.to_vec())
    }

    fn encode_key(algorithm: Algorithm, field2: &[u8], field3: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        proto3::encode_uint32(1, algorithm as u32, &mut data);
        proto3::encode_bytes(2, field2, &mut data);
        proto3::encode_bytes(3, field3, &mut data);
        data
    }

    fn is_malformed<T>(result: Result<T, ProtokenError>, needle: &str) -> bool {
        matches!(result, Err(ProtokenError::MalformedEncoding(m)) if m.contains(needle))
    }

    fn is_invalid_key<T>(result: Result<T, ProtokenError>, needle: &str) -> bool {
        matches!(result, Err(ProtokenError::InvalidKey(m)) if m.contains(needle))
    }

    fn is_length_error<T>(result: Result<T, ProtokenError>, want: usize, got: usize) -> bool {
        matches!(
            result,
            Err(ProtokenError::InvalidKeyLength { expected, actual })
                if expected == want && actual == got
        )
    }

    // --- Construction ---

    #[test]
    fn test_generate() {
        for algorithm in Algorithm::ALL {
            let key = fixed_key(algorithm);
            assert_eq!(key.algorithm(), algorithm);
            assert_eq!(key.secret_key().len(), algorithm.secret_key_len());
            assert_eq!(
                key.public_key().len(),
                algorithm.public_key_len().unwrap_or(0)
            );
            let other = SigningKey::generate(algorithm).unwrap();
            assert_ne!(key, other);
            // No 16-byte stretch of the secret may be constant across keys.
            let (a, b) = (
                key.secret_key().as_chunks::<16>().0,
                other.secret_key().as_chunks().0,
            );
            assert!(a.iter().zip(b).all(|(a, b)| a != b), "{algorithm}");
        }
    }

    #[test]
    fn test_from_secret_key_rejects_wrong_lengths() {
        for algorithm in ASYMMETRIC {
            let expected = algorithm.secret_key_len();
            for len in [0, expected - 1, expected + 1] {
                let result = SigningKey::from_secret_key(algorithm, secret(&vec![0; len]));
                assert!(is_length_error(result, expected, len), "{algorithm}");
            }
        }
        for (len, ok) in [
            (0, false),
            (47, false),
            (48, true),
            (128, true),
            (129, false),
        ] {
            let result = SigningKey::from_secret_key(Algorithm::HmacSha384, secret(&vec![7; len]));
            assert_eq!(result.is_ok(), ok, "{len}");
            assert!(ok || is_invalid_key(result, "HMAC key must be"));
        }
    }

    #[test]
    fn test_slh_dsa_secret_key_must_contain_its_own_root() {
        for algorithm in &ASYMMETRIC[3..6] {
            let key = fixed_key(*algorithm);
            assert!(key.secret_key().ends_with(key.public_key()));
            let n = key.secret_key().len() / 4;
            // SK.seed, PK.seed, and PK.root. SK.prf does not affect the root.
            for i in [0, 2 * n, 4 * n - 1] {
                let mut corrupted = secret(key.secret_key());
                corrupted[i] ^= 1;
                let result = SigningKey::from_secret_key(*algorithm, corrupted);
                assert!(is_invalid_key(result, "root does not match"), "{algorithm}");
            }
        }
    }

    #[test]
    fn test_fn_dsa_keys_are_validated() {
        for algorithm in [Algorithm::FnDsa512, Algorithm::FnDsa1024] {
            let key = fixed_key(algorithm);
            let len = key.secret_key().len();
            // The header, f, F, and the trailing hash of the public key.
            for i in [0, 1, len - 100, len - 1] {
                let mut corrupted = secret(key.secret_key());
                corrupted[i] ^= 1;
                let result = SigningKey::from_secret_key(algorithm, corrupted);
                assert!(is_invalid_key(result, "FN-DSA"), "{algorithm}: {i}");
            }
            // A wrong header, and coefficients that are not reduced modulo q.
            for range in [0..1, 1..8] {
                let mut corrupted = key.public_key().to_vec();
                corrupted[range].fill(0xFF);
                let result = VerifyingKey::new(algorithm, corrupted);
                assert!(is_invalid_key(result, "malformed"), "{algorithm}");
            }
        }
    }

    #[test]
    fn test_loading_a_degenerate_fn_dsa_key_does_not_sign() {
        // With F = 0 the key decodes but has no usable basis. Signing with
        // such keys can run without bound, so loading must not try.
        let key = fixed_key(Algorithm::FnDsa512);
        let mut degenerate = secret(key.secret_key());
        degenerate[769..1281].fill(0);
        assert!(SigningKey::from_secret_key(key.algorithm(), degenerate).is_ok());
    }

    #[test]
    fn test_ml_dsa_rejects_zero_t1() {
        for algorithm in &ASYMMETRIC[..3] {
            let mut public_key = vec![0; algorithm.public_key_len().unwrap()];
            public_key[31] = 1;
            let result = VerifyingKey::new(*algorithm, public_key.clone());
            assert!(is_invalid_key(result, "malformed"), "{algorithm}");
            public_key[32] = 1;
            assert!(VerifyingKey::new(*algorithm, public_key).is_ok());
        }
    }

    #[test]
    fn test_only_fn_dsa_signing_is_randomized() {
        for algorithm in Algorithm::ALL {
            let key = fixed_key(algorithm);
            let repeats = key.sign(&claims()).unwrap() == key.sign(&claims()).unwrap();
            assert_eq!(repeats, !algorithm.name().starts_with("fn-dsa"));
        }
    }

    #[test]
    fn test_verifying_key_new_checks_algorithm_and_length() {
        for algorithm in ASYMMETRIC {
            let expected = algorithm.public_key_len().unwrap();
            for len in [0, expected - 1, expected + 1] {
                let result = VerifyingKey::new(algorithm, vec![0; len]);
                assert!(is_length_error(result, expected, len), "{algorithm}");
            }
        }
        let result = VerifyingKey::new(Algorithm::HmacSha384, vec![0; 48]);
        assert!(is_invalid_key(result, "no verifying key"));
        let result = fixed_key(Algorithm::HmacSha384).verifying_key();
        assert!(is_invalid_key(result, "no verifying key"));
    }

    #[test]
    fn test_signing_key_equality() {
        let build = |algorithm, byte| SigningKey::from_secret_key(algorithm, secret(&[byte; 32]));
        let key = build(Algorithm::MlDsa44, 1).unwrap();
        assert_eq!(key, build(Algorithm::MlDsa44, 1).unwrap());
        assert_ne!(key, build(Algorithm::MlDsa44, 2).unwrap());
        assert_ne!(key, build(Algorithm::MlDsa65, 1).unwrap());
    }

    #[test]
    fn test_signing_key_debug_redacts_secret() {
        assert_eq!(
            format!("{:?}", fixed_key(Algorithm::HmacSha384)),
            "SigningKey { algorithm: HmacSha384, .. }"
        );
    }

    // --- Sign and verify ---

    #[test]
    fn test_sign_and_verify_with_both_key_id_types() {
        for algorithm in ASYMMETRIC {
            let sk = fixed_key(algorithm);
            let vk = sk.verifying_key().unwrap();
            assert_eq!(vk.algorithm(), algorithm);
            let other = SigningKey::generate(algorithm).unwrap();
            for key_id in [
                KeyIdentifier::KeyHash(vk.key_hash()),
                KeyIdentifier::PublicKey(vk.public_key().to_vec()),
            ] {
                let token = sk
                    .sign_with_key_id(&claims(), key_id.key_id_type())
                    .unwrap();
                for verified in [sk.verify(&token, 0), vk.verify(&token, 0)] {
                    let verified = verified.unwrap();
                    assert_eq!(verified.algorithm, algorithm);
                    assert_eq!(verified.key_identifier, key_id);
                    assert_eq!(verified.claims, claims());
                }
                assert!(matches!(
                    other.verify(&token, 0),
                    Err(ProtokenError::KeyHashMismatch)
                ));
            }
        }
    }

    #[test]
    fn test_hmac_is_identified_by_the_hash_of_its_secret() {
        let key = fixed_key(Algorithm::HmacSha384);
        let verified = key.verify(&key.sign(&claims()).unwrap(), 0).unwrap();
        assert_eq!(
            verified.key_identifier,
            KeyIdentifier::KeyHash(compute_key_hash(key.secret_key()))
        );
        assert!(matches!(
            key.sign_with_key_id(&claims(), KeyIdType::PublicKey),
            Err(ProtokenError::InvalidKeyIdType(2))
        ));
    }

    // --- Serialization ---

    #[test]
    fn test_key_roundtrips() {
        let longest_hmac =
            SigningKey::from_secret_key(Algorithm::HmacSha384, secret(&[5; HMAC_MAX_KEY_LEN]));
        for key in Algorithm::ALL
            .map(fixed_key)
            .into_iter()
            .chain(longest_hmac)
        {
            let bytes = key.to_bytes();
            let fields = key.secret_key().len() + key.public_key().len();
            assert!(bytes.len() <= fields + KEY_FRAMING_BYTES);
            assert_eq!(
                *bytes,
                encode_key(key.algorithm(), key.secret_key(), key.public_key())
            );
            assert_eq!(SigningKey::from_bytes(&bytes).unwrap(), key);
            assert!(VerifyingKey::from_bytes(&bytes).is_err());

            if let Ok(vk) = key.verifying_key() {
                let bytes = vk.to_bytes();
                assert_eq!(bytes, encode_key(key.algorithm(), key.public_key(), &[]));
                assert_eq!(VerifyingKey::from_bytes(&bytes).unwrap(), vk);
                assert!(SigningKey::from_bytes(&bytes).is_err());
            }
        }
    }

    #[test]
    fn test_decoders_reject_bad_structure() {
        let cases: [(&[u8], &str); 5] = [
            (&[], "missing algorithm"),
            (&[0x12, 0x01, 0xAA], "missing algorithm"),
            (&[0x08, 0x00], "zero"),
            (&[0x08, 0x01, 0x12, 0x00], "empty"),
            (&[0x12, 0x01, 0xAA, 0x08, 0x01], "ascending"),
        ];
        for (data, needle) in cases {
            assert!(is_malformed(SigningKey::from_bytes(data), needle));
            assert!(is_malformed(VerifyingKey::from_bytes(data), needle));
        }
        let field = |tag| [0x08, 0x01, tag, 0x01, 0xAA];
        assert!(is_malformed(
            SigningKey::from_bytes(&field(0x22)),
            "unexpected field 4"
        ));
        assert!(is_malformed(
            VerifyingKey::from_bytes(&field(0x1A)),
            "unexpected field 3"
        ));
    }

    #[test]
    fn test_decoders_reject_unknown_algorithms() {
        for byte in [10, 127] {
            let data = [&[0x08, byte, 0x12, 48], &[0xAB; 48][..]].concat();
            assert!(matches!(
                SigningKey::from_bytes(&data),
                Err(ProtokenError::InvalidAlgorithm(b)) if b == byte
            ));
            assert!(matches!(
                VerifyingKey::from_bytes(&data),
                Err(ProtokenError::InvalidAlgorithm(b)) if b == byte
            ));
        }
    }

    #[test]
    fn test_signing_key_decoder_rejects_mismatched_public_key() {
        for algorithm in Algorithm::ALL {
            let key = fixed_key(algorithm);
            let public_key = key.public_key();
            let mut wrong = vec![[public_key, &[0]].concat()];
            if let Some((first, rest)) = public_key.split_first() {
                wrong = vec![[&[first ^ 1], rest].concat(), rest.to_vec(), Vec::new()];
            }
            for public_key in wrong {
                let data = encode_key(algorithm, key.secret_key(), &public_key);
                assert!(
                    is_invalid_key(SigningKey::from_bytes(&data), "does not match"),
                    "{algorithm}"
                );
            }
        }
    }

    #[test]
    fn test_decoders_check_key_lengths() {
        let data = encode_key(Algorithm::MlDsa44, &[0; 31], &[0; 1312]);
        assert!(is_length_error(SigningKey::from_bytes(&data), 32, 31));
        let data = encode_key(Algorithm::HmacSha384, &[0; 47], &[]);
        assert!(is_invalid_key(SigningKey::from_bytes(&data), "HMAC"));
        let data = encode_key(Algorithm::MlDsa44, &[0; 1000], &[]);
        assert!(is_length_error(VerifyingKey::from_bytes(&data), 1312, 1000));
        let data = encode_key(Algorithm::HmacSha384, &[0; 48], &[]);
        assert!(is_invalid_key(
            VerifyingKey::from_bytes(&data),
            "no verifying key"
        ));
    }

    #[test]
    fn test_field_size_limits() {
        let too_long_secret = [0; MAX_SECRET_KEY_BYTES + 1];
        let too_long_public = [0; MAX_PUBLIC_KEY_BYTES + 1];
        let data = encode_key(Algorithm::HmacSha384, &too_long_secret, &[]);
        assert!(is_malformed(
            SigningKey::from_bytes(&data),
            "secret_key too long"
        ));
        let data = encode_key(Algorithm::MlDsa87, &[0; 32], &too_long_public);
        assert!(is_malformed(
            SigningKey::from_bytes(&data),
            "public_key too long"
        ));
        let data = encode_key(Algorithm::MlDsa87, &too_long_public, &[]);
        assert!(is_malformed(
            VerifyingKey::from_bytes(&data),
            "public_key too long"
        ));
    }
}
