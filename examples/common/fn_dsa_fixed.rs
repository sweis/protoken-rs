//! FN-DSA with a fixed random stream, so that generated test data is
//! reproducible. Never sign this way with a real key.

use fn_dsa::{KeyPairGenerator as _, SigningKey as _, SHAKE256};
use protoken::Algorithm;

struct FixedRng(SHAKE256);

impl FixedRng {
    fn new(seed: &[u8]) -> Self {
        let mut shake = SHAKE256::new();
        shake.inject(seed);
        shake.flip();
        FixedRng(shake)
    }
}

impl fn_dsa::CryptoRng for FixedRng {}

impl fn_dsa::RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }

    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.extract(dest);
    }

    fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), fn_dsa::RngError> {
        unimplemented!()
    }
}

pub fn secret_key(algorithm: Algorithm, seed: &[u8]) -> Vec<u8> {
    let logn = match algorithm {
        Algorithm::FnDsa512 => fn_dsa::FN_DSA_LOGN_512,
        _ => fn_dsa::FN_DSA_LOGN_1024,
    };
    let mut secret_key = vec![0; fn_dsa::sign_key_size(logn)];
    let mut public_key = vec![0; fn_dsa::vrfy_key_size(logn)];
    fn_dsa::KeyPairGeneratorStandard::default().keygen(
        logn,
        &mut FixedRng::new(seed),
        &mut secret_key,
        &mut public_key,
    );
    secret_key
}

pub fn sign(secret_key: &[u8], context: &[u8], message: &[u8]) -> Option<Vec<u8>> {
    let mut key = fn_dsa::SigningKeyStandard::decode(secret_key)?;
    let mut signature = vec![0; fn_dsa::signature_size(key.get_logn())];
    key.sign(
        &mut FixedRng::new(b""),
        &fn_dsa::DomainContext(context),
        &fn_dsa::HASH_ID_RAW,
        message,
        &mut signature,
    )?;
    Some(signature)
}
