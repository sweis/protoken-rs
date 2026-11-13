import Protoken.Crypto
import Protoken.Serialize

/-!
# Signing

Model of `src/sign.rs`.
-/

namespace Protoken

variable (C : Crypto)

/-- Models `compute_key_hash`. -/
def computeKeyHash (keyMaterial : Bytes) : KeyHash :=
  ⟨(C.sha256 keyMaterial).take KEY_HASH_LEN, by
    simp [C.sha256_length, KEY_HASH_LEN]⟩

/-- Models `sign_token`. -/
def signToken (algorithm : Algorithm) (secretKey : Bytes) (keyId : KeyIdentifier)
    (claims : Claims) : Result Bytes := do
  claims.validate
  let payload := serializeClaims claims
  if payload.length > MAX_PAYLOAD_BYTES then
    throw .malformedEncoding
  let signingInput := serializeSigningInput .v0 algorithm keyId payload
  let signature ← schemeSign C algorithm secretKey signingInput
  pure (appendSignature signingInput signature)

end Protoken
