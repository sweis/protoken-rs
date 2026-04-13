//! Security audit proof-of-concept tests.
//!
//! These tests reproduce attacks found during security review and assert that
//! they are now blocked. A passing test means the attack is rejected.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use protoken::sign::{compute_full_key_hash, sign_groth16};
use protoken::snark;
use protoken::types::Claims;
use protoken::verify::verify_groth16;

/// PoC: Groth16 auth bypass via attacker-controlled key hash.
///
/// Before the fix, `verify_groth16` read the key hash from the token payload
/// (attacker-controlled) instead of from the verifier. Since the SNARK proof
/// only proves "I know K such that Poseidon(K) = key_hash", and the proving key
/// (CRS) is public, an attacker could mint a token under any key K' of their
/// choosing, embed Poseidon(K') as the key hash, and produce a valid proof.
///
/// After the fix, the verifier supplies the expected key hash and the forged
/// token is rejected with KeyHashMismatch.
#[test]
fn poc_groth16_auth_bypass() {
    // Public CRS shared by everyone (including attacker).
    let (pk, vk) = snark::setup().expect("setup");

    // The legitimate issuer's key, known only to the issuer.
    // The verifier knows only its hash.
    let issuer_key = [0x11u8; 32];
    let trusted_key_hash = compute_full_key_hash(&issuer_key);

    // Attacker forges a token with arbitrary claims under their own key.
    let attacker_key = [0xAAu8; 32];
    let forged_claims = Claims {
        expires_at: u64::MAX,
        subject: "root".into(),
        scopes: vec!["admin".into()],
        ..Default::default()
    };
    let forged_token = sign_groth16(&pk, &attacker_key, forged_claims).expect("sign");

    // Verification against the trusted issuer's key hash MUST fail.
    let result = verify_groth16(&vk, &trusted_key_hash, &forged_token, 1_700_000_000);
    assert!(
        result.is_err(),
        "SECURITY: forged Groth16 token accepted! attacker can mint arbitrary tokens"
    );
}
