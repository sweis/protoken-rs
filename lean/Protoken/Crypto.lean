import Protoken.Types

/-!
# Cryptographic primitives

The primitives come from the RustCrypto crates and are not verified here. They
appear as the fields of a `Crypto` structure, so every theorem holds for any
implementation of them.

`Crypto` also records output lengths. In Rust these are facts about fixed-size
array types. `Crypto.Correct` states that honest signatures verify. Only the
theorems that say "a token you signed will verify" assume it.

No theorem assumes unforgeability. The results say which bytes a signature or MAC
was checked over, and that those bytes determine everything the verifier returns.
Concluding that an attacker cannot produce such bytes is the job of the standard
security definitions for HMAC, Ed25519, and ML-DSA.
-/

namespace Protoken

structure Crypto where
  /-- `Sha256::digest` -/
  sha256 : Bytes → Bytes
  sha256_length : ∀ m, (sha256 m).length = 32
  /-- `Hmac<Sha256>` over `msg`, finalized. -/
  hmacSha256 : (key msg : Bytes) → Bytes
  hmacSha256_length : ∀ key msg, (hmacSha256 key msg).length = HMAC_SHA256_SIG_LEN
  /-- `SigningKey::from_bytes(seed).verifying_key().to_bytes()` -/
  ed25519PublicKey : (seed : Bytes) → Bytes
  ed25519PublicKey_length : ∀ seed, (ed25519PublicKey seed).length = ED25519_PUBLIC_KEY_LEN
  /-- `SigningKey::from_bytes(seed).sign(msg).to_bytes()` -/
  ed25519Sign : (seed msg : Bytes) → Bytes
  ed25519Sign_length : ∀ seed msg, (ed25519Sign seed msg).length = ED25519_SIG_LEN
  /-- `VerifyingKey::from_bytes(pk).is_ok()` for a 32-byte `pk`. -/
  ed25519PointValid : (pk : Bytes) → Bool
  /-- `Signature::from_slice(sig)` succeeds and `verify_strict(msg, sig)` accepts. -/
  ed25519VerifyStrict : (pk msg sig : Bytes) → Bool
  /-- `SigningKey::<MlDsa44>::from_seed(seed)`, then the encoded verifying key. -/
  mldsa44PublicKey : (seed : Bytes) → Bytes
  mldsa44PublicKey_length : ∀ seed, (mldsa44PublicKey seed).length = MLDSA44_PUBLIC_KEY_LEN
  /-- `try_sign(msg)`, encoded. `none` models a signing error. -/
  mldsa44Sign : (seed msg : Bytes) → Option Bytes
  mldsa44Sign_length : ∀ seed msg sig, mldsa44Sign seed msg = some sig →
    sig.length = MLDSA44_SIG_LEN
  /-- `Signature::try_from(sig)` succeeds and `verify(msg, sig)` accepts. -/
  mldsa44Verify : (pk msg sig : Bytes) → Bool

/-- Honest keys are well formed and honest signatures verify. -/
structure Crypto.Correct (C : Crypto) : Prop where
  ed25519_point : ∀ seed, C.ed25519PointValid (C.ed25519PublicKey seed) = true
  ed25519_verify : ∀ seed msg,
    C.ed25519VerifyStrict (C.ed25519PublicKey seed) msg (C.ed25519Sign seed msg) = true
  mldsa44_verify : ∀ seed msg sig, C.mldsa44Sign seed msg = some sig →
    C.mldsa44Verify (C.mldsa44PublicKey seed) msg sig = true

end Protoken
