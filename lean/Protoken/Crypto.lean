import Protoken.Types

/-!
# Cryptographic primitives

Model of `src/crypto.rs`. The primitives come from other crates and are not
verified here. They appear as the fields of a `Crypto` structure, so every
theorem holds for any implementation of them.

`Crypto` also records output lengths. In Rust these are facts about fixed-size
array types. `Crypto.Correct` states that honest signatures verify. Only the
theorems that say "a token you signed will verify" assume it.

FN-DSA signing is randomized. Its random input is part of `Crypto.sign`, so a
theorem about one signature holds for every random input.

No theorem assumes unforgeability. The results say which bytes a signature or MAC
was checked over, and that those bytes determine everything the verifier returns.
Concluding that an attacker cannot produce such bytes is the job of the standard
security definitions for HMAC, ML-DSA, SLH-DSA, and FN-DSA.
-/

namespace Protoken

structure Crypto where
  /-- `Sha256::digest` -/
  sha256 : Bytes → Bytes
  sha256_length : ∀ m, (sha256 m).length = 32
  /-- `Hmac<Sha384>` over `msg`, finalized. -/
  hmacSha384 : (key msg : Bytes) → Bytes
  hmacSha384_length : ∀ key msg, (hmacSha384 key msg).length = 48
  /-- `Scheme::public_key` of a signature scheme. `none` models a rejected secret. -/
  publicKey : Algorithm → (secret : Bytes) → Option Bytes
  publicKey_length : ∀ a secret pk, publicKey a secret = some pk →
    a.publicKeyLen = some pk.length
  /-- `Scheme::is_valid_public_key` -/
  publicKeyValid : Algorithm → (pk : Bytes) → Bool
  /-- `Scheme::sign` of a signature scheme. `none` models a signing error. -/
  sign : Algorithm → (secret msg : Bytes) → Option Bytes
  sign_length : ∀ a secret msg sig, sign a secret msg = some sig → sig.length = a.signatureLen
  /-- `Scheme::verify` of a signature scheme. -/
  verify : Algorithm → (pk msg sig : Bytes) → Bool

/-- Honest keys are well formed and honest signatures verify. -/
structure Crypto.Correct (C : Crypto) : Prop where
  publicKey_valid : ∀ a secret pk, C.publicKey a secret = some pk → C.publicKeyValid a pk = true
  verify_sign : ∀ a secret pk msg sig, C.publicKey a secret = some pk →
    C.sign a secret msg = some sig → C.verify a pk msg sig = true

variable (C : Crypto)

/-- Models `scheme(algorithm).public_key(secret_key)`. -/
def schemePublicKey (algorithm : Algorithm) (secretKey : Bytes) : Result Bytes :=
  if algorithm.isSymmetric then
    .ok []
  else
    match C.publicKey algorithm secretKey with
    | some pk => .ok pk
    | none => .error .invalidKey

/-- Models `scheme(algorithm).sign(secret_key, message)`. -/
def schemeSign (algorithm : Algorithm) (secretKey message : Bytes) : Result Bytes :=
  if algorithm.isSymmetric then
    .ok (C.hmacSha384 secretKey message)
  else
    match C.sign algorithm secretKey message with
    | some sig => .ok sig
    | none => .error .signingFailed

/-- Models `scheme(algorithm).verify(key, message, signature)`. HMAC's `verify_slice`
accepts exactly the tag that HMAC produces. -/
def schemeVerify (algorithm : Algorithm) (key message signature : Bytes) : Bool :=
  if algorithm.isSymmetric then
    C.hmacSha384 key message == signature
  else
    C.verify algorithm key message signature

variable {C}

theorem schemePublicKey_eq_ok_iff {a : Algorithm} {secret pk : Bytes} :
    schemePublicKey C a secret = .ok pk ↔
      if a.isSymmetric then pk = [] else C.publicKey a secret = some pk := by
  unfold schemePublicKey
  split
  · simp [eq_comm]
  · split <;> simp_all

theorem schemeSign_length {a : Algorithm} {secret msg sig : Bytes}
    (h : schemeSign C a secret msg = .ok sig) : sig.length = a.signatureLen := by
  unfold schemeSign at h
  split at h
  · rename_i hsym
    cases h
    rw [Algorithm.isSymmetric_iff.mp hsym]
    exact C.hmacSha384_length _ _
  · split at h <;> cases h
    exact C.sign_length _ _ _ _ (by assumption)

/-- A signature verifies under the secret (HMAC) or the derived public key. -/
theorem schemeVerify_schemeSign (hc : C.Correct) {a : Algorithm} {secret pk msg sig : Bytes}
    (hpk : schemePublicKey C a secret = .ok pk) (h : schemeSign C a secret msg = .ok sig) :
    schemeVerify C a (if a.isSymmetric then secret else pk) msg sig = true := by
  rw [schemePublicKey_eq_ok_iff] at hpk
  unfold schemeSign at h
  unfold schemeVerify
  split at h
  · rename_i hsym
    cases h
    simp [hsym]
  · rename_i hsym
    simp only [hsym, Bool.false_eq_true, ite_false] at hpk ⊢
    split at h <;> cases h
    exact hc.verify_sign _ _ _ _ _ hpk (by assumption)

end Protoken
