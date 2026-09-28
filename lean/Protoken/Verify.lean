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

/-- Models `ed25519_verifying_key(..)`, keeping only success or the error. -/
def checkEd25519PublicKey (publicKey : Bytes) : Result Unit := do
  if publicKey.length ≠ ED25519_PUBLIC_KEY_LEN then
    throw (.invalidKeyLength ED25519_PUBLIC_KEY_LEN publicKey.length)
  if !C.ed25519PointValid publicKey then
    throw .invalidKey
  pure ()

/-- Models `mldsa44_verifying_key(..)`, keeping only success or the error. -/
def checkMldsa44PublicKey (publicKey : Bytes) : Result Unit :=
  if publicKey.length ≠ MLDSA44_PUBLIC_KEY_LEN then
    .error (.invalidKeyLength MLDSA44_PUBLIC_KEY_LEN publicKey.length)
  else
    .ok ()

/-- Models `verify_hmac`. `verify_slice` accepts exactly the tag that HMAC produces. -/
def verifyHmac (key tokenBytes : Bytes) (now : UInt64) : Result VerifiedToken := do
  checkHmacKeyLen key
  let (token, signingInput) ← parseEnvelope C tokenBytes .hmacSha256 key
  if C.hmacSha256 key signingInput ≠ token.signature then
    throw .verificationFailed
  finishVerification token now

/-- Models `verify_ed25519`. -/
def verifyEd25519 (publicKey tokenBytes : Bytes) (now : UInt64) : Result VerifiedToken := do
  let (token, signingInput) ← parseEnvelope C tokenBytes .ed25519 publicKey
  checkEd25519PublicKey C publicKey
  if !C.ed25519VerifyStrict publicKey signingInput token.signature then
    throw .verificationFailed
  finishVerification token now

/-- Models `verify_mldsa44`. -/
def verifyMldsa44 (publicKey tokenBytes : Bytes) (now : UInt64) : Result VerifiedToken := do
  let (token, signingInput) ← parseEnvelope C tokenBytes .mlDsa44 publicKey
  checkMldsa44PublicKey publicKey
  if !C.mldsa44Verify publicKey signingInput token.signature then
    throw .verificationFailed
  finishVerification token now

end Protoken
