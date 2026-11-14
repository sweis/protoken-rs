import Protoken.Sign

/-!
# Verification

Model of `src/verify.rs`. The theorems are in `VerifyProofs.lean`.
-/

namespace Protoken

/-- Models `VerifiedToken`. -/
structure VerifiedToken where
  algorithm : Algorithm
  keyIdentifier : KeyIdentifier
  claims : Claims
  deriving DecidableEq, Repr

variable (C : Crypto)

/-- Models `check_key_identity`. The Rust comparison is constant time; the model
only records its result. -/
def checkKeyIdentity (id : KeyIdentifier) (keyMaterial : Bytes) : Result Unit :=
  let isMatch :=
    match id with
    | .keyHash hash => decide (hash = computeKeyHash C keyMaterial)
    | .publicKey pk => decide (pk = keyMaterial)
  if isMatch then .ok () else .error .keyHashMismatch

/-- Models `parse_envelope`. Returns the token and the signed bytes. -/
def parseEnvelope (tokenBytes : Bytes) (expectedAlgorithm : Algorithm) (keyMaterial : Bytes) :
    Result (SignedToken × Bytes) := do
  let (token, signedLen) ← deserializeSignedTokenAt tokenBytes
  if token.algorithm ≠ expectedAlgorithm then
    throw .verificationFailed
  checkKeyIdentity C token.keyIdentifier keyMaterial
  if token.signature.length ≠ expectedAlgorithm.signatureLen then
    throw .verificationFailed
  -- `token_bytes.get(..signed_len)`
  if signedLen > tokenBytes.length then
    throw .malformedEncoding
  pure (token, tokenBytes.take signedLen)

/-- Models `check_temporal_claims`. -/
def checkTemporalClaims (claims : Claims) (now : UInt64) : Result Unit := do
  if now > claims.expiresAt then
    throw (.tokenExpired claims.expiresAt now)
  if now < claims.notBefore then
    throw (.tokenNotYetValid claims.notBefore now)
  pure ()

/-- Models `finish_verification`. -/
def finishVerification (token : SignedToken) (now : UInt64) : Result VerifiedToken := do
  let claims ← deserializeClaims token.payload
  claims.validate
  checkTemporalClaims claims now
  pure { algorithm := token.algorithm, keyIdentifier := token.keyIdentifier, claims }

/-- Models `verify_token`. -/
def verifyToken (algorithm : Algorithm) (keyMaterial tokenBytes : Bytes) (now : UInt64) :
    Result VerifiedToken := do
  let (token, signingInput) ← parseEnvelope C tokenBytes algorithm keyMaterial
  if !schemeVerify C algorithm keyMaterial CONTEXT signingInput token.signature then
    throw .verificationFailed
  finishVerification token now

end Protoken
