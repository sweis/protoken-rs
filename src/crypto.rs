//! The cryptographic primitives behind each [`Algorithm`]. This is the only
//! module that names an algorithm's implementation.

use std::fmt::Display;
use std::marker::PhantomData;

use fn_dsa::{
    KeyPairGenerator, KeyPairGenerator1024, KeyPairGenerator512, SigningKey1024, SigningKey512,
    VerifyingKey1024, VerifyingKey512, DOMAIN_NONE, HASH_ID_RAW,
};
use hmac::{Hmac, Mac as _};
use ml_dsa::{KeyInit as _, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Signer as _, Verifier as _};
use sha2::Sha384;
use slh_dsa::{ParameterSet, Sha2_128s, Sha2_192s, Sha2_256s};
use zeroize::Zeroizing;

use crate::error::ProtokenError;
use crate::types::Algorithm;

/// A MAC or signature scheme over raw key bytes. Callers check key lengths
/// first. Signatures use an empty context string.
pub(crate) trait Scheme {
    fn generate_secret_key(&self, len: usize) -> Result<Zeroizing<Vec<u8>>, ProtokenError> {
        random_bytes(len)
    }

    /// Empty for symmetric schemes.
    fn public_key(&self, secret_key: &[u8]) -> Result<Vec<u8>, ProtokenError>;

    /// Whether a public key of the right length is well formed.
    fn is_valid_public_key(&self, _public_key: &[u8]) -> bool {
        true
    }

    fn sign(&self, secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, ProtokenError>;

    /// `key` is the public key, or the secret key for symmetric schemes.
    fn verify(&self, key: &[u8], message: &[u8], signature: &[u8]) -> bool;
}

pub(crate) fn scheme(algorithm: Algorithm) -> &'static dyn Scheme {
    match algorithm {
        Algorithm::MlDsa44 => &MlDsa::<MlDsa44>(PhantomData),
        Algorithm::MlDsa65 => &MlDsa::<MlDsa65>(PhantomData),
        Algorithm::MlDsa87 => &MlDsa::<MlDsa87>(PhantomData),
        Algorithm::HmacSha384 => &HmacSha384,
        Algorithm::SlhDsaSha2_128s => &SlhDsa::<Sha2_128s>(PhantomData),
        Algorithm::SlhDsaSha2_192s => &SlhDsa::<Sha2_192s>(PhantomData),
        Algorithm::SlhDsaSha2_256s => &SlhDsa::<Sha2_256s>(PhantomData),
        Algorithm::FnDsa512 => &FnDsa512 { 0: PhantomData },
        Algorithm::FnDsa1024 => &FnDsa1024 { 0: PhantomData },
    }
}

fn random_bytes(len: usize) -> Result<Zeroizing<Vec<u8>>, ProtokenError> {
    let mut bytes = Zeroizing::new(vec![0; len]);
    getrandom::fill(&mut bytes).map_err(rng_failed)?;
    Ok(bytes)
}

fn rng_failed(e: getrandom::Error) -> ProtokenError {
    ProtokenError::RngFailed(e.to_string())
}

fn invalid_key(e: impl Display) -> ProtokenError {
    ProtokenError::InvalidKey(e.to_string())
}

fn signing_failed(e: impl Display) -> ProtokenError {
    ProtokenError::SigningFailed(e.to_string())
}

struct HmacSha384;

impl HmacSha384 {
    fn mac(key: &[u8], message: &[u8]) -> Result<Hmac<Sha384>, ProtokenError> {
        let mac = Hmac::<Sha384>::new_from_slice(key).map_err(invalid_key)?;
        Ok(mac.chain_update(message))
    }
}

impl Scheme for HmacSha384 {
    fn public_key(&self, _secret_key: &[u8]) -> Result<Vec<u8>, ProtokenError> {
        Ok(Vec::new())
    }

    fn sign(&self, secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, ProtokenError> {
        let tag = Self::mac(secret_key, message)?.finalize();
        Ok(tag.into_bytes().to_vec())
    }

    fn verify(&self, key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        Self::mac(key, message).is_ok_and(|mac| mac.verify_slice(signature).is_ok())
    }
}

/// FIPS 204, deterministic variant. The secret key is the 32-byte seed.
struct MlDsa<P>(PhantomData<P>);

impl<P: MlDsaParams> Scheme for MlDsa<P> {
    fn public_key(&self, secret_key: &[u8]) -> Result<Vec<u8>, ProtokenError> {
        let key = ml_dsa::SigningKey::<P>::new_from_slice(secret_key).map_err(invalid_key)?;
        Ok(key.as_ref().encode().to_vec())
    }

    /// Anyone can sign for a key whose `t1` (all but the 32-byte `rho`) is
    /// zero, such as a zero-filled placeholder.
    fn is_valid_public_key(&self, public_key: &[u8]) -> bool {
        public_key.iter().skip(32).any(|&byte| byte != 0)
    }

    fn sign(&self, secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, ProtokenError> {
        let key = ml_dsa::SigningKey::<P>::new_from_slice(secret_key).map_err(invalid_key)?;
        let signature = key.try_sign(message).map_err(signing_failed)?;
        Ok(signature.encode().to_vec())
    }

    fn verify(&self, key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        // Decode the signature first: decoding the key expands it, which costs more.
        ml_dsa::Signature::<P>::try_from(signature).is_ok_and(|signature| {
            ml_dsa::VerifyingKey::<P>::new_from_slice(key)
                .is_ok_and(|key| key.verify(message, &signature).is_ok())
        })
    }
}

/// FIPS 205, deterministic variant. The secret key is
/// `SK.seed || SK.prf || PK.seed || PK.root`, so its second half is the public key.
struct SlhDsa<P>(PhantomData<P>);

impl<P: ParameterSet> SlhDsa<P> {
    /// Recompute the public key from the three seeds, ignoring the stored `PK.root`.
    fn derive_public_key(secret_key: &[u8]) -> Result<Vec<u8>, ProtokenError> {
        // `slh_keygen_internal` panics on a wrong length; decoding checks it.
        slh_dsa::SigningKey::<P>::try_from(secret_key).map_err(invalid_key)?;
        let n = secret_key.len() / 4;
        let (sk_seed, rest) = secret_key.split_at(n);
        let (sk_prf, rest) = rest.split_at(n);
        let (pk_seed, _pk_root) = rest.split_at(n);
        let key = slh_dsa::SigningKey::<P>::slh_keygen_internal(sk_seed, sk_prf, pk_seed);
        Ok(key.as_ref().to_vec())
    }
}

impl<P: ParameterSet> Scheme for SlhDsa<P> {
    fn generate_secret_key(&self, len: usize) -> Result<Zeroizing<Vec<u8>>, ProtokenError> {
        let mut secret_key = random_bytes(len)?;
        let public_key = Self::derive_public_key(&secret_key)?;
        let (_, public_half) = secret_key.split_at_mut(len / 2);
        public_half.copy_from_slice(&public_key);
        Ok(secret_key)
    }

    fn public_key(&self, secret_key: &[u8]) -> Result<Vec<u8>, ProtokenError> {
        let public_key = Self::derive_public_key(secret_key)?;
        if !secret_key.ends_with(&public_key) {
            return Err(invalid_key("SLH-DSA root does not match the secret seed"));
        }
        Ok(public_key)
    }

    fn sign(&self, secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, ProtokenError> {
        let key = slh_dsa::SigningKey::<P>::try_from(secret_key).map_err(invalid_key)?;
        let signature = key.try_sign(message).map_err(signing_failed)?;
        Ok(signature.to_vec())
    }

    fn verify(&self, key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        slh_dsa::Signature::<P>::try_from(signature).is_ok_and(|signature| {
            slh_dsa::VerifyingKey::<P>::try_from(key)
                .is_ok_and(|key| key.verify(message, &signature).is_ok())
        })
    }
}

/// The expected FIPS 206, of degree `2^LOGN`. Signing is always randomized:
/// two different signatures from the same random input reveal the key, and
/// floating-point results can differ between machines.
struct FnDsa<G, S, V, const LOGN: u32>(PhantomData<(G, S, V)>);

type FnDsa512 = FnDsa<KeyPairGenerator512, SigningKey512, VerifyingKey512, 9>;
type FnDsa1024 = FnDsa<KeyPairGenerator1024, SigningKey1024, VerifyingKey1024, 10>;

/// Lends the decoded key to `f`: moving it would leave unwiped copies on the stack.
fn with_fn_dsa_key<S: fn_dsa::SigningKey, T>(
    secret_key: &[u8],
    f: impl FnOnce(&mut S) -> T,
) -> Result<T, ProtokenError> {
    S::decode(secret_key)
        .as_mut()
        .map(f)
        .ok_or_else(|| invalid_key("malformed FN-DSA secret key"))
}

impl<G, S, V, const LOGN: u32> Scheme for FnDsa<G, S, V, LOGN>
where
    G: KeyPairGenerator,
    S: fn_dsa::SigningKey,
    V: fn_dsa::VerifyingKey,
{
    fn generate_secret_key(&self, len: usize) -> Result<Zeroizing<Vec<u8>>, ProtokenError> {
        let mut secret_key = Zeroizing::new(vec![0; len]);
        let mut public_key = vec![0; fn_dsa::vrfy_key_size(LOGN)];
        with_os_rng(|rng| G::default().keygen(LOGN, rng, &mut secret_key, &mut public_key))?;
        Ok(secret_key)
    }

    fn public_key(&self, secret_key: &[u8]) -> Result<Vec<u8>, ProtokenError> {
        let mut public_key = vec![0; fn_dsa::vrfy_key_size(LOGN)];
        with_fn_dsa_key(secret_key, |key: &mut S| {
            key.to_verifying_key(&mut public_key);
        })?;
        // Decoding does not check this hash, and a wrong one gives invalid signatures.
        if !secret_key.ends_with(&fn_dsa::hashed_vrfykey_from_vrfykey(&public_key)) {
            return Err(invalid_key("FN-DSA public key hash does not match"));
        }
        Ok(public_key)
    }

    fn is_valid_public_key(&self, public_key: &[u8]) -> bool {
        V::decode(public_key).is_some()
    }

    fn sign(&self, secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, ProtokenError> {
        let mut signature = vec![0; fn_dsa::signature_size(LOGN)];
        with_fn_dsa_key(secret_key, |key: &mut S| {
            with_os_rng(|rng| key.sign(rng, &DOMAIN_NONE, &HASH_ID_RAW, message, &mut signature))
        })??
        .ok_or_else(|| signing_failed("invalid FN-DSA key"))?;
        Ok(signature)
    }

    fn verify(&self, key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        V::decode(key).is_some_and(|key| key.verify(signature, &DOMAIN_NONE, &HASH_ID_RAW, message))
    }
}

/// Run `f` with the OS random number generator. `fn-dsa` has no way to report
/// an RNG failure, so the failure is recorded and the result discarded.
fn with_os_rng<T>(f: impl FnOnce(&mut OsRng) -> T) -> Result<T, ProtokenError> {
    let mut rng = OsRng(Ok(()));
    let value = f(&mut rng);
    rng.0.map(|()| value).map_err(rng_failed)
}

struct OsRng(Result<(), getrandom::Error>);

impl fn_dsa::CryptoRng for OsRng {}

impl fn_dsa::RngCore for OsRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0 = self.0.and(getrandom::fill(dest));
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), fn_dsa::RngError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    struct VectorFile {
        vectors: Vec<Vector>,
    }

    #[derive(Deserialize)]
    struct Vector {
        name: String,
        algorithm: Algorithm,
        secret_key: Option<String>,
        public_key: String,
        message: Option<String>,
        signature: Option<String>,
    }

    #[test]
    fn test_nist_acvp_vectors() {
        let json = include_str!("../testdata/acvp_vectors.json");
        let vectors = serde_json::from_str::<VectorFile>(json).unwrap().vectors;
        assert_eq!(vectors.len(), 9);

        let decode = |text: String| URL_SAFE_NO_PAD.decode(text).unwrap();
        for v in vectors {
            let scheme = scheme(v.algorithm);
            let secret_key = v.secret_key.map(decode);
            let public_key = decode(v.public_key);
            let signed = v.message.map(decode).zip(v.signature.map(decode));

            if let Some(secret_key) = &secret_key {
                assert_eq!(scheme.public_key(secret_key).unwrap(), public_key);
            }
            if let Some((message, signature)) = &signed {
                assert!(scheme.verify(&public_key, message, signature), "{}", v.name);
            }
            if let (Some(secret_key), Some((message, signature))) = (secret_key, signed) {
                assert_eq!(scheme.sign(&secret_key, &message).unwrap(), signature);
            }
        }
    }

    #[test]
    fn test_hmac_sha384_rfc4231_case_2() {
        let scheme = scheme(Algorithm::HmacSha384);
        let tag = scheme
            .sign(b"Jefe", b"what do ya want for nothing?")
            .unwrap();
        assert_eq!(
            hex::encode(tag),
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47\
             e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"
        );
    }

    #[test]
    fn test_fn_dsa_rejects_keys_of_the_other_degree() {
        let small = crate::keys::tests::fixed_key(Algorithm::FnDsa512);
        let signature = scheme(small.algorithm()).sign(small.secret_key(), b"m");
        let large = scheme(Algorithm::FnDsa1024);
        assert!(large.sign(small.secret_key(), b"m").is_err());
        assert!(!large.is_valid_public_key(small.public_key()));
        assert!(!large.verify(small.public_key(), b"m", &signature.unwrap()));
    }

    #[test]
    fn test_with_os_rng() {
        use fn_dsa::RngCore as _;
        let draw = || {
            with_os_rng(|rng| {
                let mut bytes = [0; 16];
                rng.try_fill_bytes(&mut bytes).unwrap();
                (rng.next_u32(), rng.next_u64(), bytes)
            })
        };
        let (a, b) = (draw().unwrap(), draw().unwrap());
        assert!(a.0 != b.0 && a.1 != b.1 && a.2 != b.2);

        // A failure is kept even if later draws succeed.
        let result = with_os_rng(|rng| {
            rng.0 = Err(getrandom::Error::UNEXPECTED);
            rng.next_u32()
        });
        assert!(matches!(result, Err(ProtokenError::RngFailed(_))));
    }

    #[test]
    fn test_wrong_lengths_are_errors_not_panics() {
        for algorithm in crate::keys::tests::ASYMMETRIC {
            let scheme = scheme(algorithm);
            for len in [0, 1, algorithm.secret_key_len() + 1] {
                let bytes = vec![0; len];
                assert!(scheme.public_key(&bytes).is_err());
                assert!(scheme.sign(&bytes, b"message").is_err());
                assert!(!scheme.verify(&bytes, b"message", &vec![0; algorithm.signature_len()]));
                let key = vec![0; algorithm.public_key_len().unwrap()];
                assert!(!scheme.verify(&key, b"message", &bytes));
            }
        }
    }
}
