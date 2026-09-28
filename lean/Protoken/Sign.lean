import Protoken.Crypto
import Protoken.Serialize

/-!
# Signing

Model of `src/sign.rs`. Key generation is omitted because it only feeds random
bytes to `SigningKey::from_secret_key`.
-/

namespace Protoken

def HMAC_MAX_KEY_LEN : Nat := 4096

variable (C : Crypto)

/-- Models `compute_key_hash`. -/
def computeKeyHash (keyMaterial : Bytes) : KeyHash :=
  ⟨(C.sha256 keyMaterial).take KEY_HASH_LEN, by
    simp [C.sha256_length, KEY_HASH_LEN]⟩

/-- Models `check_hmac_key_len`. -/
def checkHmacKeyLen (key : Bytes) : Result Unit := do
  if key.length < HMAC_MIN_KEY_LEN then
    throw .invalidKey
  if key.length > HMAC_MAX_KEY_LEN then
    throw .invalidKey
  pure ()

/-- Models the length check in `seed_array::<N>`. -/
def checkSeedLen (n : Nat) (seed : Bytes) : Result Unit :=
  if seed.length ≠ n then .error (.invalidKeyLength n seed.length) else .ok ()

/-- Models `sign_claims`. -/
def signClaims (algorithm : Algorithm) (keyId : KeyIdentifier) (claims : Claims)
    (sign : Bytes → Result Bytes) : Result Bytes := do
  claims.validate
  let payload := serializeClaims claims
  if payload.length > MAX_PAYLOAD_BYTES then
    throw .malformedEncoding
  let signingInput := serializeSigningInput .v0 algorithm keyId payload
  let signature ← sign signingInput
  pure (appendSignature signingInput signature)

/-- Models `sign_hmac`. -/
def signHmac (key : Bytes) (claims : Claims) : Result Bytes := do
  checkHmacKeyLen key
  let keyId := KeyIdentifier.keyHash (computeKeyHash C key)
  signClaims .hmacSha256 keyId claims fun input => pure (C.hmacSha256 key input)

/-- Models `sign_ed25519`. -/
def signEd25519 (seed : Bytes) (claims : Claims) (keyId : KeyIdentifier) : Result Bytes := do
  checkSeedLen ED25519_SEED_LEN seed
  signClaims .ed25519 keyId claims fun input => pure (C.ed25519Sign seed input)

/-- Models `sign_mldsa44`. -/
def signMldsa44 (seed : Bytes) (claims : Claims) (keyId : KeyIdentifier) : Result Bytes := do
  checkSeedLen MLDSA44_SEED_LEN seed
  signClaims .mlDsa44 keyId claims fun input =>
    match C.mldsa44Sign seed input with
    | some sig => pure sig
    | none => throw .signingFailed

/-- Models `derive_public_key`. -/
def derivePublicKey (algorithm : Algorithm) (seed : Bytes) : Result Bytes :=
  match algorithm with
  | .hmacSha256 => .error .invalidKey
  | .ed25519 => do
    checkSeedLen ED25519_SEED_LEN seed
    pure (C.ed25519PublicKey seed)
  | .mlDsa44 => do
    checkSeedLen MLDSA44_SEED_LEN seed
    pure (C.mldsa44PublicKey seed)

end Protoken
