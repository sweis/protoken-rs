import Protoken.Verify
import Protoken.ClaimsProofs
import Protoken.TokenProofs

/-!
# Verification theorems

* `verifyHmac_sound`, `verifyEd25519_sound`, `verifyMldsa44_sound`: what an
  accepted token guarantees (`Accepted`).
* `verifyHmac_signHmac`, `verifyEd25519_signEd25519`, `verifyMldsa44_signMldsa44`:
  a token that signing produced verifies, inside its time window.
* `verifyHmac_unique_token`, `accepted_tokens_differ_only_in_signature`: tokens are
  not malleable.
* `accepted_result_determined_by_signing_input`: the signed bytes determine the result.
* `accepted_same_token`: a byte string has one result and one algorithm, whatever
  keys are used.
* `verify*_bad_signature`: a bad signature is rejected before the payload is read.
-/

namespace Protoken

variable {C : Crypto}

/-- The key identifier names this key material. -/
def KeyIdentifier.Matches (C : Crypto) (id : KeyIdentifier) (keyMaterial : Bytes) : Prop :=
  match id with
  | .keyHash hash => hash = computeKeyHash C keyMaterial
  | .publicKey pk => pk = keyMaterial

/-- The signing input rebuilt from a verification result. -/
def VerifiedToken.signingInput (vt : VerifiedToken) : Bytes :=
  serializeSigningInput .v0 vt.algorithm vt.keyIdentifier (serializeClaims vt.claims)

/-- What holds when a verifier for `algorithm` accepts `tokenBytes` and returns `vt`.
`sigOk msg sig` is the primitive's check under the caller's key. -/
structure Accepted (C : Crypto) (algorithm : Algorithm) (keyMaterial tokenBytes : Bytes)
    (now : UInt64) (vt : VerifiedToken) (sigOk : Bytes → Bytes → Prop) : Prop where
  algorithm_eq : vt.algorithm = algorithm
  key_matches : vt.keyIdentifier.Matches C keyMaterial
  claims_valid : vt.claims.Valid
  claims_wire : vt.claims.WireValid
  not_expired : now ≤ vt.claims.expiresAt
  not_early : vt.claims.notBefore ≤ now
  /-- An embedded public key has the length the algorithm requires. -/
  key_id_wf : ∀ pk, vt.keyIdentifier = .publicKey pk → vt.algorithm.publicKeyLen = some pk.length
  payload_len : (serializeClaims vt.claims).length ≤ MAX_PAYLOAD_BYTES
  /-- The token is the signing input rebuilt from the result, followed by a
  signature field, and the primitive accepted that signature over that input. -/
  signed : ∃ sig, sig.length = algorithm.signatureLen ∧
    tokenBytes = vt.signingInput ++ encodeBytes 6 sig ∧ sigOk vt.signingInput sig

/-! ## Building blocks -/

theorem checkKeyIdentity_eq_ok_iff {id : KeyIdentifier} {km : Bytes} :
    checkKeyIdentity C id km = .ok () ↔ id.Matches C km := by
  cases id <;> simp only [checkKeyIdentity, KeyIdentifier.Matches] <;> split <;> simp_all

theorem checkTemporalClaims_eq_ok_iff {c : Claims} {now : UInt64} :
    checkTemporalClaims c now = .ok () ↔ now ≤ c.expiresAt ∧ c.notBefore ≤ now := by
  simp [checkTemporalClaims, UInt64.not_lt]

theorem checkHmacKeyLen_eq_ok_iff {key : Bytes} :
    checkHmacKeyLen key = .ok () ↔
      HMAC_MIN_KEY_LEN ≤ key.length ∧ key.length ≤ HMAC_MAX_KEY_LEN := by
  simp [checkHmacKeyLen]

theorem checkSeedLen_eq_ok_iff {n : Nat} {seed : Bytes} :
    checkSeedLen n seed = .ok () ↔ seed.length = n := by
  simp [checkSeedLen]

theorem parseEnvelope_sound {tb km input : Bytes} {alg : Algorithm} {t : SignedToken}
    (h : parseEnvelope C tb alg km = .ok (t, input)) :
    t.version = .v0 ∧ t.algorithm = alg ∧ t.keyIdentifier.Matches C km ∧
      t.signature.length = alg.signatureLen ∧ t.WireValid ∧
      input = serializeSigningInput .v0 alg t.keyIdentifier t.payload ∧
      tb = input ++ encodeBytes 6 t.signature := by
  simp only [parseEnvelope, bind_eq_ok, Prod.exists, throw_eq_error, error_bind, pure_eq_ok,
    ok_bind, ite_error_eq_ok, exists_unit, checkKeyIdentity_eq_ok_iff, Except.ok.injEq,
    Prod.mk.injEq, ne_eq, Decidable.not_not] at h
  obtain ⟨t', n, hparse, halg, hkey, hsig, _, rfl, rfl⟩ := h
  obtain ⟨hser, hprefix, hw⟩ := deserializeSignedTokenAt_canonical hparse
  have hv : t'.version = .v0 := by cases t'.version; rfl
  rw [hv, halg] at hprefix
  refine ⟨hv, halg, hkey, hsig, hw, hprefix, ?_⟩
  rw [hprefix, ← hser, serializeSignedToken, appendSignature, hv, halg]

theorem finishVerification_sound {t : SignedToken} {now : UInt64} {vt : VerifiedToken}
    (h : finishVerification t now = .ok vt) :
    vt.algorithm = t.algorithm ∧ vt.keyIdentifier = t.keyIdentifier ∧
      serializeClaims vt.claims = t.payload ∧ vt.claims.Valid ∧ vt.claims.WireValid ∧
      now ≤ vt.claims.expiresAt ∧ vt.claims.notBefore ≤ now := by
  simp only [finishVerification, bind_eq_ok, exists_unit, Claims.validate_eq_ok_iff,
    checkTemporalClaims_eq_ok_iff, pure_eq_ok, Except.ok.injEq] at h
  obtain ⟨c, hc, hvalid, ⟨h1, h2⟩, rfl⟩ := h
  obtain ⟨hser, hw⟩ := deserializeClaims_canonical hc
  exact ⟨rfl, rfl, hser, hvalid, hw, h1, h2⟩

/-- Combine the envelope facts, the primitive's answer, and the claims facts. -/
theorem accepted_of_parts {tb km input : Bytes} {alg : Algorithm} {t : SignedToken}
    {now : UInt64} {vt : VerifiedToken} {sigOk : Bytes → Bytes → Prop}
    (hp : parseEnvelope C tb alg km = .ok (t, input)) (hs : sigOk input t.signature)
    (hf : finishVerification t now = .ok vt) : Accepted C alg km tb now vt sigOk := by
  obtain ⟨_, halg, hkey, hlen, hw, hinput, htb⟩ := parseEnvelope_sound hp
  obtain ⟨h1, h2, h3, h4, h5, h6, h7⟩ := finishVerification_sound hf
  have hin : vt.signingInput = input := by
    rw [VerifiedToken.signingInput, h1, h2, h3, halg, hinput]
  exact ⟨h1.trans halg, h2 ▸ hkey, h4, h5, h6, h7, h1 ▸ h2 ▸ hw.key_id, h3 ▸ hw.payload_len,
    t.signature, hlen, hin ▸ htb, hin ▸ hs⟩

/-! ## Soundness -/

/-- **HMAC soundness.** An accepted token is the canonical encoding of the returned
algorithm, key identifier, and claims, followed by the HMAC of exactly those bytes
under the caller's key. The claims are valid and inside their time window. -/
theorem verifyHmac_sound {key tb : Bytes} {now : UInt64} {vt : VerifiedToken}
    (h : verifyHmac C key tb now = .ok vt) :
    Accepted C .hmacSha256 key tb now vt (fun msg sig => C.hmacSha256 key msg = sig) := by
  simp only [verifyHmac, exists_unit, bind_eq_ok, Prod.exists, throw_eq_error, error_bind,
    pure_eq_ok, ok_bind, ite_error_eq_ok, ne_eq, Decidable.not_not] at h
  obtain ⟨_, t, input, hp, hs, hf⟩ := h
  exact accepted_of_parts hp hs hf

/-- **Ed25519 soundness.** As `verifyHmac_sound`, with `verify_strict` under the
caller's public key. -/
theorem verifyEd25519_sound {pk tb : Bytes} {now : UInt64} {vt : VerifiedToken}
    (h : verifyEd25519 C pk tb now = .ok vt) :
    Accepted C .ed25519 pk tb now vt
      (fun msg sig => C.ed25519VerifyStrict pk msg sig = true) := by
  simp only [verifyEd25519, exists_unit, bind_eq_ok, Prod.exists, throw_eq_error, error_bind,
    pure_eq_ok, ok_bind, ite_error_eq_ok, Bool.not_eq_true', Bool.not_eq_false] at h
  obtain ⟨t, input, hp, _, hs, hf⟩ := h
  exact accepted_of_parts hp hs hf

/-- **ML-DSA-44 soundness.** As `verifyHmac_sound`, with ML-DSA verification under
the caller's public key. -/
theorem verifyMldsa44_sound {pk tb : Bytes} {now : UInt64} {vt : VerifiedToken}
    (h : verifyMldsa44 C pk tb now = .ok vt) :
    Accepted C .mlDsa44 pk tb now vt (fun msg sig => C.mldsa44Verify pk msg sig = true) := by
  simp only [verifyMldsa44, exists_unit, bind_eq_ok, Prod.exists, throw_eq_error, error_bind,
    pure_eq_ok, ok_bind, ite_error_eq_ok, Bool.not_eq_true', Bool.not_eq_false] at h
  obtain ⟨t, input, hp, _, hs, hf⟩ := h
  exact accepted_of_parts hp hs hf

/-! ## Non-malleability -/

/-- Two accepted tokens with the same verification result share every byte before
the signature field. -/
theorem accepted_tokens_differ_only_in_signature {alg : Algorithm} {km tb1 tb2 : Bytes}
    {now1 now2 : UInt64} {vt : VerifiedToken} {ok1 ok2 : Bytes → Bytes → Prop}
    (h1 : Accepted C alg km tb1 now1 vt ok1) (h2 : Accepted C alg km tb2 now2 vt ok2) :
    ∃ sig1 sig2, tb1 = vt.signingInput ++ encodeBytes 6 sig1 ∧
      tb2 = vt.signingInput ++ encodeBytes 6 sig2 := by
  obtain ⟨s1, _, e1, _⟩ := h1.signed
  obtain ⟨s2, _, e2, _⟩ := h2.signed
  exact ⟨s1, s2, e1, e2⟩

/-- **HMAC tokens are unique.** Under one key, one verification result has exactly
one accepted byte string. -/
theorem verifyHmac_unique_token {key tb1 tb2 : Bytes} {now1 now2 : UInt64} {vt : VerifiedToken}
    (h1 : verifyHmac C key tb1 now1 = .ok vt) (h2 : verifyHmac C key tb2 now2 = .ok vt) :
    tb1 = tb2 := by
  obtain ⟨s1, _, e1, m1⟩ := (verifyHmac_sound h1).signed
  obtain ⟨s2, _, e2, m2⟩ := (verifyHmac_sound h2).signed
  rw [e1, e2, ← m1, ← m2]

/-- **The signed bytes determine the result.** If two accepted tokens carry the same
signing input, the verifiers returned the same algorithm, key identifier, and
claims. This holds across algorithms and keys, so a signature or MAC over one
result can never stand for a different result. -/
theorem accepted_result_determined_by_signing_input {alg1 alg2 : Algorithm}
    {km1 km2 tb1 tb2 : Bytes} {now1 now2 : UInt64} {vt1 vt2 : VerifiedToken}
    {ok1 ok2 : Bytes → Bytes → Prop}
    (h1 : Accepted C alg1 km1 tb1 now1 vt1 ok1) (h2 : Accepted C alg2 km2 tb2 now2 vt2 ok2)
    (heq : vt1.signingInput = vt2.signingInput) : vt1 = vt2 := by
  have hne1 := serializeClaims_ne_nil h1.claims_valid.expiresAt_ne_zero
  have hne2 := serializeClaims_ne_nil h2.claims_valid.expiresAt_ne_zero
  obtain ⟨ha, hk, hp⟩ := serializeSigningInput_injective h1.key_id_wf h2.key_id_wf
    ⟨hne1, h1.payload_len⟩ ⟨hne2, h2.payload_len⟩ heq
  have hc := serializeClaims_injective h1.claims_wire h2.claims_wire hne1 h1.payload_len hp
  cases vt1
  cases vt2
  simp_all

theorem Algorithm.signatureLen_bounds (a : Algorithm) :
    0 < a.signatureLen ∧ a.signatureLen ≤ MAX_SIGNATURE_BYTES := by
  cases a <;> simp [Algorithm.signatureLen, HMAC_SHA256_SIG_LEN, ED25519_SIG_LEN,
    MLDSA44_SIG_LEN, MAX_SIGNATURE_BYTES]

/-- A token built from valid claims and a full-length signature is well formed. -/
theorem wireValid_of_signed {alg : Algorithm} {kid : KeyIdentifier} {c : Claims} {sig : Bytes}
    {sigAlg : Algorithm}
    (hk : ∀ pk, kid = .publicKey pk → alg.publicKeyLen = some pk.length) (hv : c.Valid)
    (hsize : (serializeClaims c).length ≤ MAX_PAYLOAD_BYTES)
    (hsig : sig.length = sigAlg.signatureLen) :
    SignedToken.WireValid ⟨.v0, alg, kid, serializeClaims c, sig⟩ := by
  have := sigAlg.signatureLen_bounds
  refine ⟨hk, serializeClaims_ne_nil hv.expiresAt_ne_zero, hsize, ?_, by simp only; omega⟩
  intro hnil
  simp only at hnil
  rw [hnil] at hsig
  simp at hsig
  omega

/-- **One meaning per token.** A byte string that is accepted twice, under any keys
and any algorithms, was accepted under one algorithm and gave one result. In
particular there is no algorithm confusion. -/
theorem accepted_same_token {alg1 alg2 : Algorithm} {km1 km2 tb : Bytes}
    {now1 now2 : UInt64} {vt1 vt2 : VerifiedToken} {ok1 ok2 : Bytes → Bytes → Prop}
    (h1 : Accepted C alg1 km1 tb now1 vt1 ok1) (h2 : Accepted C alg2 km2 tb now2 vt2 ok2) :
    alg1 = alg2 ∧ vt1 = vt2 := by
  obtain ⟨s1, l1, e1, _⟩ := h1.signed
  obtain ⟨s2, l2, e2, _⟩ := h2.signed
  have d1 := deserializeSignedTokenAt_serialize
    (wireValid_of_signed h1.key_id_wf h1.claims_valid h1.payload_len l1)
  have d2 := deserializeSignedTokenAt_serialize
    (wireValid_of_signed h2.key_id_wf h2.claims_valid h2.payload_len l2)
  simp only [serializeSignedToken, appendSignature] at d1 d2
  rw [← VerifiedToken.signingInput, ← e1] at d1
  rw [← VerifiedToken.signingInput, ← e2, d1] at d2
  simp only [Except.ok.injEq, Prod.mk.injEq, SignedToken.mk.injEq, true_and] at d2
  have hin : vt1.signingInput = vt2.signingInput := by
    simp only [VerifiedToken.signingInput, d2.1.1, d2.1.2.1, d2.1.2.2.1]
  have hvt := accepted_result_determined_by_signing_input h1 h2 hin
  exact ⟨by rw [← h1.algorithm_eq, ← h2.algorithm_eq, hvt], hvt⟩

/-! ## Completeness -/

theorem parseEnvelope_complete {t : SignedToken} {alg : Algorithm} {km : Bytes}
    (hw : t.WireValid) (halg : t.algorithm = alg) (hkey : t.keyIdentifier.Matches C km)
    (hsig : t.signature.length = alg.signatureLen) :
    parseEnvelope C (serializeSignedToken t) alg km
      = .ok (t, serializeSigningInput t.version t.algorithm t.keyIdentifier t.payload) := by
  simp only [parseEnvelope, deserializeSignedTokenAt_serialize hw, ok_bind, halg, hsig,
    checkKeyIdentity_eq_ok_iff.mpr hkey, ne_eq, not_true_eq_false, if_false, pure_eq_ok]
  simp [serializeSignedToken, appendSignature, halg]

theorem finishVerification_complete {t : SignedToken} {c : Claims} {now : UInt64}
    (hp : t.payload = serializeClaims c) (hv : c.Valid) (hu : c.Utf8)
    (hsize : (serializeClaims c).length ≤ MAX_PAYLOAD_BYTES)
    (h1 : now ≤ c.expiresAt) (h2 : c.notBefore ≤ now) :
    finishVerification t now
      = .ok ⟨t.algorithm, t.keyIdentifier, { c with scopes := sortScopes c.scopes }⟩ := by
  have ht : checkTemporalClaims { c with scopes := sortScopes c.scopes } now = .ok () :=
    checkTemporalClaims_eq_ok_iff.mpr ⟨h1, h2⟩
  simp only [finishVerification, hp, deserializeClaims_serializeClaims hv hu hsize, ok_bind,
    (Claims.validate_eq_ok_iff _).mpr hv.sorted, pure_eq_ok, ht]

theorem signClaims_eq_ok_iff {alg : Algorithm} {kid : KeyIdentifier} {c : Claims}
    {sign : Bytes → Result Bytes} {tb : Bytes} :
    signClaims alg kid c sign = .ok tb ↔
      c.Valid ∧ (serializeClaims c).length ≤ MAX_PAYLOAD_BYTES ∧
      ∃ sig, sign (serializeSigningInput .v0 alg kid (serializeClaims c)) = .ok sig ∧
        tb = serializeSignedToken ⟨.v0, alg, kid, serializeClaims c, sig⟩ := by
  simp only [signClaims, bind_eq_ok, exists_unit, Claims.validate_eq_ok_iff, throw_eq_error,
    error_bind, pure_eq_ok, ok_bind, ite_error_eq_ok, Nat.not_lt, gt_iff_lt, Except.ok.injEq,
    serializeSignedToken]
  constructor
  · rintro ⟨h1, h2, sig, h3, rfl⟩
    exact ⟨h1, h2, sig, h3, rfl⟩
  · rintro ⟨h1, h2, sig, h3, rfl⟩
    exact ⟨h1, h2, sig, h3, rfl⟩

/-- **HMAC sign then verify.** Every token `sign_hmac` returns is accepted by
`verify_hmac` under the same key, at any time inside the claims' window. The result
carries the signed claims with sorted scopes. -/
theorem verifyHmac_signHmac {key tb : Bytes} {c : Claims} {now : UInt64}
    (hs : signHmac C key c = .ok tb) (hu : c.Utf8)
    (h1 : now ≤ c.expiresAt) (h2 : c.notBefore ≤ now) :
    verifyHmac C key tb now = .ok ⟨.hmacSha256, .keyHash (computeKeyHash C key),
      { c with scopes := sortScopes c.scopes }⟩ := by
  simp only [signHmac, bind_eq_ok, exists_unit, signClaims_eq_ok_iff, pure_eq_ok,
    Except.ok.injEq] at hs
  obtain ⟨hkey, hv, hsize, sig, rfl, rfl⟩ := hs
  have hlen := C.hmacSha256_length key
    (serializeSigningInput .v0 .hmacSha256 (.keyHash (computeKeyHash C key)) (serializeClaims c))
  have hw := wireValid_of_signed (alg := .hmacSha256) (kid := .keyHash (computeKeyHash C key))
    (sigAlg := .hmacSha256) (by simp) hv hsize hlen
  simp only [verifyHmac, hkey, ok_bind,
    parseEnvelope_complete (C := C) (km := key) hw rfl rfl hlen,
    ne_eq, not_true_eq_false, if_false, pure_eq_ok]
  exact finishVerification_complete rfl hv hu hsize h1 h2

/-- **Ed25519 sign then verify.** Every token `sign_ed25519` returns, with a key
identifier that names the seed's public key, is accepted by `verify_ed25519` under
that public key. Assumes honest Ed25519 signatures verify. -/
theorem verifyEd25519_signEd25519 (hc : C.Correct) {seed tb : Bytes} {c : Claims}
    {kid : KeyIdentifier} {now : UInt64}
    (hs : signEd25519 C seed c kid = .ok tb) (hk : kid.Matches C (C.ed25519PublicKey seed))
    (hu : c.Utf8) (h1 : now ≤ c.expiresAt) (h2 : c.notBefore ≤ now) :
    verifyEd25519 C (C.ed25519PublicKey seed) tb now
      = .ok ⟨.ed25519, kid, { c with scopes := sortScopes c.scopes }⟩ := by
  simp only [signEd25519, bind_eq_ok, exists_unit, signClaims_eq_ok_iff, pure_eq_ok,
    Except.ok.injEq] at hs
  obtain ⟨_, hv, hsize, sig, rfl, rfl⟩ := hs
  have hkid : ∀ pk, kid = .publicKey pk → Algorithm.ed25519.publicKeyLen = some pk.length := by
    rintro pk rfl
    simp only [KeyIdentifier.Matches] at hk
    rw [hk, C.ed25519PublicKey_length]
    rfl
  have hlen := C.ed25519Sign_length seed
    (serializeSigningInput .v0 .ed25519 kid (serializeClaims c))
  have hw := wireValid_of_signed (sigAlg := .ed25519) hkid hv hsize hlen
  simp only [verifyEd25519, ok_bind, parseEnvelope_complete (C := C) hw rfl hk hlen,
    checkEd25519PublicKey, C.ed25519PublicKey_length, hc.ed25519_point, hc.ed25519_verify,
    ne_eq, not_true_eq_false, if_false, pure_eq_ok, Bool.not_true, Bool.false_eq_true]
  exact finishVerification_complete rfl hv hu hsize h1 h2

/-- **ML-DSA-44 sign then verify.** As `verifyEd25519_signEd25519`. -/
theorem verifyMldsa44_signMldsa44 (hc : C.Correct) {seed tb : Bytes} {c : Claims}
    {kid : KeyIdentifier} {now : UInt64}
    (hs : signMldsa44 C seed c kid = .ok tb) (hk : kid.Matches C (C.mldsa44PublicKey seed))
    (hu : c.Utf8) (h1 : now ≤ c.expiresAt) (h2 : c.notBefore ≤ now) :
    verifyMldsa44 C (C.mldsa44PublicKey seed) tb now
      = .ok ⟨.mlDsa44, kid, { c with scopes := sortScopes c.scopes }⟩ := by
  simp only [signMldsa44, bind_eq_ok, exists_unit, signClaims_eq_ok_iff] at hs
  obtain ⟨_, hv, hsize, sig, hsig, rfl⟩ := hs
  have hsig : C.mldsa44Sign seed
      (serializeSigningInput .v0 .mlDsa44 kid (serializeClaims c)) = some sig := by
    split at hsig
    · rename_i s hs
      simp only [pure_eq_ok, Except.ok.injEq] at hsig
      rw [hs, hsig]
    · simp at hsig
  have hkid : ∀ pk, kid = .publicKey pk → Algorithm.mlDsa44.publicKeyLen = some pk.length := by
    rintro pk rfl
    simp only [KeyIdentifier.Matches] at hk
    rw [hk, C.mldsa44PublicKey_length]
    rfl
  have hlen := C.mldsa44Sign_length _ _ _ hsig
  have hw := wireValid_of_signed (sigAlg := .mlDsa44) hkid hv hsize hlen
  simp only [verifyMldsa44, ok_bind, parseEnvelope_complete (C := C) hw rfl hk hlen,
    checkMldsa44PublicKey, C.mldsa44PublicKey_length, hc.mldsa44_verify _ _ _ hsig,
    ne_eq, not_true_eq_false, if_false, pure_eq_ok, Bool.not_true, Bool.false_eq_true]
  exact finishVerification_complete rfl hv hu hsize h1 h2

/-! ## The payload is not read before the signature verifies

`SignedToken.WireValid` says nothing about the payload's content. So these hold for
every payload, including bytes that are not a Claims message: a structurally valid
envelope with a bad signature gets `verificationFailed`, never an error about claims. -/

theorem verifyHmac_bad_signature {key : Bytes} {t : SignedToken} {now : UInt64}
    (hkey : checkHmacKeyLen key = .ok ()) (hw : t.WireValid) (halg : t.algorithm = .hmacSha256)
    (hid : t.keyIdentifier.Matches C key) (hlen : t.signature.length = HMAC_SHA256_SIG_LEN)
    (hbad : C.hmacSha256 key
      (serializeSigningInput t.version t.algorithm t.keyIdentifier t.payload) ≠ t.signature) :
    verifyHmac C key (serializeSignedToken t) now = .error .verificationFailed := by
  simp only [verifyHmac, hkey, ok_bind, parseEnvelope_complete (C := C) hw halg hid hlen]
  simp [hbad]

theorem verifyEd25519_bad_signature {pk : Bytes} {t : SignedToken} {now : UInt64}
    (hpk : checkEd25519PublicKey C pk = .ok ()) (hw : t.WireValid) (halg : t.algorithm = .ed25519)
    (hid : t.keyIdentifier.Matches C pk) (hlen : t.signature.length = ED25519_SIG_LEN)
    (hbad : C.ed25519VerifyStrict pk
      (serializeSigningInput t.version t.algorithm t.keyIdentifier t.payload) t.signature = false) :
    verifyEd25519 C pk (serializeSignedToken t) now = .error .verificationFailed := by
  simp only [verifyEd25519, ok_bind, parseEnvelope_complete (C := C) hw halg hid hlen, hpk]
  simp [hbad]

theorem verifyMldsa44_bad_signature {pk : Bytes} {t : SignedToken} {now : UInt64}
    (hpk : checkMldsa44PublicKey pk = .ok ()) (hw : t.WireValid) (halg : t.algorithm = .mlDsa44)
    (hid : t.keyIdentifier.Matches C pk) (hlen : t.signature.length = MLDSA44_SIG_LEN)
    (hbad : C.mldsa44Verify pk
      (serializeSigningInput t.version t.algorithm t.keyIdentifier t.payload) t.signature = false) :
    verifyMldsa44 C pk (serializeSignedToken t) now = .error .verificationFailed := by
  simp only [verifyMldsa44, ok_bind, parseEnvelope_complete (C := C) hw halg hid hlen, hpk]
  simp [hbad]

end Protoken
