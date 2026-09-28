import Lean
import Protoken

/-!
# Axiom audit

Fails the build if a headline theorem depends on anything beyond Lean's three
standard axioms. That rules out `sorry`, added axioms, and proofs that trust
compiled code (`native_decide`, `bv_decide`).
-/

open Lean Elab Command in
elab "#assert_standard_axioms " ids:ident+ : command => do
  for id in ids do
    let name ← liftCoreM <| realizeGlobalConstNoOverload id
    for ax in ← liftCoreM <| collectAxioms name do
      unless ax ∈ [``propext, ``Classical.choice, ``Quot.sound] do
        throwErrorAt id "{name} depends on the axiom {ax}"

open Protoken

#assert_standard_axioms
  -- Varints
  decodeVarint_sound
  decodeVarint_complete
  -- Claims
  Claims.validate_eq_ok_iff
  deserializeClaims_canonical
  deserializeClaims_injective
  deserializeClaims_serializeClaims
  serializeClaims_injective
  -- SignedToken
  deserializeSignedTokenAt_canonical
  deserializeSignedTokenAt_injective
  deserializeSignedTokenAt_serialize
  serializeSigningInput_injective
  serializeSignedToken_length_le
  -- Verification
  verifyHmac_sound
  verifyEd25519_sound
  verifyMldsa44_sound
  verifyHmac_unique_token
  accepted_tokens_differ_only_in_signature
  accepted_result_determined_by_signing_input
  accepted_same_token
  verifyHmac_signHmac
  verifyEd25519_signEd25519
  verifyMldsa44_signMldsa44
  verifyHmac_bad_signature
  verifyEd25519_bad_signature
  verifyMldsa44_bad_signature
  -- Keys
  SigningKey.validate_eq_ok_iff
  VerifyingKey.validate_eq_ok_iff
  deserializeSigningKey_canonical
  deserializeSigningKey_serialize
  deserializeVerifyingKey_canonical
  deserializeVerifyingKey_serialize
  signing_key_is_not_verifying_key
  SigningKey.fromSecretKey_valid
  SigningKey.verifyingKey_valid
  SigningKey.verify_sound
  VerifyingKey.verify_sound
  SigningKey.verify_signWithKeyId
  VerifyingKey.verify_signWithKeyId
