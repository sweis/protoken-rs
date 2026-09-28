import Protoken.FieldLoop
import Protoken.Types

/-!
# Claims and SignedToken serialization

Model of `src/serialize.rs`. The theorems about it are in `ClaimsProofs.lean` and
`TokenProofs.lean`. This file only proves what the definitions need: each loop
body consumes input, so each loop terminates.

In the `match` on `(field_number, wire_type)`, wire type `0` is `WIRE_VARINT` and
`2` is `WIRE_LEN`.
-/

namespace Protoken

/-! ## Claims -/

/-- The `for scope in sorted_scopes` loop in `serialize_claims`. -/
def encodeScopes (scopes : List Bytes) : Bytes :=
  scopes.flatMap (encodeBytes 6)

/-- `serialize_claims` without the sort. -/
def serializeClaimsUnsorted (c : Claims) : Bytes :=
  encodeUint64 1 c.expiresAt ++ encodeUint64 2 c.notBefore ++ encodeUint64 3 c.issuedAt ++
    encodeBytes 4 c.subject ++ encodeBytes 5 c.audience ++ encodeScopes c.scopes

/-- Models `serialize_claims`. -/
def serializeClaims (c : Claims) : Bytes :=
  serializeClaimsUnsorted { c with scopes := sortScopes c.scopes }

/-- Models `read_algorithm`. -/
def readAlgorithm (data : Bytes) (pos : Nat) : Result (Algorithm × Nat) := do
  let (byte, pos) ← readNonzeroU8 data pos
  match Algorithm.fromByte byte with
  | some algorithm => pure (algorithm, pos)
  | none => throw (.invalidAlgorithm byte)

/-- Models `read_claim_string`. -/
def readClaimString (data : Bytes) (pos : Nat) : Result (Bytes × Nat) := do
  let (bytes, pos) ← readBoundedBytes data pos MAX_CLAIM_BYTES_LEN
  if !validUtf8 bytes then
    throw .malformedEncoding
  pure (bytes, pos)

def SCOPE_FIELD : Nat := 6

/-- The loop body of `deserialize_claims`. -/
def claimsStep (data : Bytes) : Step Claims := fun pos last claims => do
  let (fieldNumber, wireType, pos) ← nextField data pos last (some SCOPE_FIELD)
  match fieldNumber, wireType with
  | 1, 0 =>
    let (v, pos) ← readNonzeroVarint data pos
    pure (pos, fieldNumber, { claims with expiresAt := v })
  | 2, 0 =>
    let (v, pos) ← readNonzeroVarint data pos
    pure (pos, fieldNumber, { claims with notBefore := v })
  | 3, 0 =>
    let (v, pos) ← readNonzeroVarint data pos
    pure (pos, fieldNumber, { claims with issuedAt := v })
  | 4, 2 =>
    let (s, pos) ← readClaimString data pos
    pure (pos, fieldNumber, { claims with subject := s })
  | 5, 2 =>
    let (s, pos) ← readClaimString data pos
    pure (pos, fieldNumber, { claims with audience := s })
  | 6, 2 =>
    let (scope, pos) ← readClaimString data pos
    if claims.scopes.length ≥ MAX_SCOPES then
      throw .malformedEncoding
    -- Strictly ascending, which also rules out duplicates.
    match claims.scopes.getLast? with
    | some prev =>
      if scope ≤ prev then
        throw .malformedEncoding
      pure (pos, fieldNumber, { claims with scopes := claims.scopes ++ [scope] })
    | none =>
      pure (pos, fieldNumber, { claims with scopes := claims.scopes ++ [scope] })
  | _, _ => throw .malformedEncoding

theorem readAlgorithm_sound {data : Bytes} {pos pos' : Nat} {a : Algorithm}
    (h : readAlgorithm data pos = .ok (a, pos')) :
    pos < pos' ∧ pos' ≤ data.length ∧
      data.take pos' = data.take pos ++ encodeVarint a.toByte.toUInt64 := by
  simp only [readAlgorithm, bind_eq_ok, Prod.exists] at h
  obtain ⟨b, p, hv, h⟩ := h
  split at h
  · rename_i a' ha
    simp only [pure_eq_ok, Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    rw [Algorithm.toByte_of_fromByte ha]
    exact (readNonzeroU8_sound hv).2
  · simp at h

theorem readAlgorithm_complete {data : Bytes} {pos : Nat} {a : Algorithm} {rest : Bytes}
    (h : data.drop pos = encodeVarint a.toByte.toUInt64 ++ rest) :
    readAlgorithm data pos = .ok (a, pos + (encodeVarint a.toByte.toUInt64).length) := by
  simp [readAlgorithm, readNonzeroU8_complete a.toByte_ne_zero h]

theorem readClaimString_sound {data : Bytes} {pos pos' : Nat} {s : Bytes}
    (h : readClaimString data pos = .ok (s, pos')) :
    validUtf8 s = true ∧ s ≠ [] ∧ s.length ≤ MAX_CLAIM_BYTES_LEN ∧ pos < pos' ∧
      pos' ≤ data.length ∧
      data.take pos' = data.take pos ++ encodeVarint (UInt64.ofNat s.length) ++ s := by
  simp only [readClaimString, bind_eq_ok, Prod.exists] at h
  obtain ⟨b, p, hv, h⟩ := h
  split at h
  · simp at h
  · rename_i hutf
    simp only [pure_eq_ok, ok_bind, Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    exact ⟨by simpa using hutf, readBoundedBytes_sound hv⟩

theorem readClaimString_complete {data : Bytes} {pos : Nat} {s rest : Bytes}
    (hdata : data.length < 2 ^ 64) (hutf : validUtf8 s = true) (hne : s ≠ [])
    (hle : s.length ≤ MAX_CLAIM_BYTES_LEN)
    (h : data.drop pos = encodeVarint (UInt64.ofNat s.length) ++ s ++ rest) :
    readClaimString data pos
      = .ok (s, pos + (encodeVarint (UInt64.ofNat s.length)).length + s.length) := by
  simp [readClaimString, readBoundedBytes_complete hdata hne hle h, hutf]

/-- What one successful iteration of the Claims loop did. -/
theorem claimsStep_sound {data : Bytes} {pos last pos' last' : Nat} {c c' : Claims}
    (h : claimsStep data pos last c = .ok (pos', last', c')) :
    pos < pos' ∧ pos' ≤ data.length ∧ (last < last' ∨ (last' = last ∧ last' = 6)) ∧
    ((last' = 1 ∧ ∃ v, v ≠ 0 ∧ c' = { c with expiresAt := v } ∧
        data.take pos' = data.take pos ++ encodeUint64 1 v) ∨
     (last' = 2 ∧ ∃ v, v ≠ 0 ∧ c' = { c with notBefore := v } ∧
        data.take pos' = data.take pos ++ encodeUint64 2 v) ∨
     (last' = 3 ∧ ∃ v, v ≠ 0 ∧ c' = { c with issuedAt := v } ∧
        data.take pos' = data.take pos ++ encodeUint64 3 v) ∨
     (last' = 4 ∧ ∃ s, validUtf8 s = true ∧ s ≠ [] ∧ s.length ≤ MAX_CLAIM_BYTES_LEN ∧
        c' = { c with subject := s } ∧ data.take pos' = data.take pos ++ encodeBytes 4 s) ∨
     (last' = 5 ∧ ∃ s, validUtf8 s = true ∧ s ≠ [] ∧ s.length ≤ MAX_CLAIM_BYTES_LEN ∧
        c' = { c with audience := s } ∧ data.take pos' = data.take pos ++ encodeBytes 5 s) ∨
     (last' = 6 ∧ ∃ s, validUtf8 s = true ∧ s ≠ [] ∧ s.length ≤ MAX_CLAIM_BYTES_LEN ∧
        c.scopes.length < MAX_SCOPES ∧ (∀ prev, c.scopes.getLast? = some prev → prev < s) ∧
        c' = { c with scopes := c.scopes ++ [s] } ∧
        data.take pos' = data.take pos ++ encodeBytes 6 s)) := by
  simp only [claimsStep, bind_eq_ok, Prod.exists] at h
  obtain ⟨f, w, p, hf, h⟩ := h
  obtain ⟨hord, hp1, hp2, htag⟩ := nextField_sound hf
  have hord : last < f ∨ (f = last ∧ f = 6) := by
    rcases hord with h | ⟨h1, h2⟩
    · exact .inl h
    · simp only [SCOPE_FIELD, Option.some.injEq] at h2
      exact .inr ⟨h1, h2.symm⟩
  split at h
  · simp only [bind_eq_ok, Prod.exists, pure_eq_ok, Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨v, q, hv, rfl, rfl, rfl⟩ := h
    obtain ⟨hv0, hq1, hq2, hval⟩ := readNonzeroVarint_sound hv
    refine ⟨by omega, hq2, hord, .inl ⟨rfl, v, hv0, rfl, ?_⟩⟩
    rw [hval, htag, encodeUint64_of_ne hv0, List.append_assoc]; rfl
  · simp only [bind_eq_ok, Prod.exists, pure_eq_ok, Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨v, q, hv, rfl, rfl, rfl⟩ := h
    obtain ⟨hv0, hq1, hq2, hval⟩ := readNonzeroVarint_sound hv
    refine ⟨by omega, hq2, hord, .inr (.inl ⟨rfl, v, hv0, rfl, ?_⟩)⟩
    rw [hval, htag, encodeUint64_of_ne hv0, List.append_assoc]; rfl
  · simp only [bind_eq_ok, Prod.exists, pure_eq_ok, Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨v, q, hv, rfl, rfl, rfl⟩ := h
    obtain ⟨hv0, hq1, hq2, hval⟩ := readNonzeroVarint_sound hv
    refine ⟨by omega, hq2, hord, .inr (.inr (.inl ⟨rfl, v, hv0, rfl, ?_⟩))⟩
    rw [hval, htag, encodeUint64_of_ne hv0, List.append_assoc]; rfl
  · simp only [bind_eq_ok, Prod.exists, pure_eq_ok, Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨s, q, hs, rfl, rfl, rfl⟩ := h
    obtain ⟨hutf, hne, hle, hq1, hq2, hval⟩ := readClaimString_sound hs
    refine ⟨by omega, hq2, hord, .inr (.inr (.inr (.inl ⟨rfl, s, hutf, hne, hle, rfl, ?_⟩)))⟩
    rw [hval, htag, encodeBytes_of_ne hne]; simp [WIRE_LEN]
  · simp only [bind_eq_ok, Prod.exists, pure_eq_ok, Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨s, q, hs, rfl, rfl, rfl⟩ := h
    obtain ⟨hutf, hne, hle, hq1, hq2, hval⟩ := readClaimString_sound hs
    refine ⟨by omega, hq2, hord,
      .inr (.inr (.inr (.inr (.inl ⟨rfl, s, hutf, hne, hle, rfl, ?_⟩))))⟩
    rw [hval, htag, encodeBytes_of_ne hne]; simp [WIRE_LEN]
  · simp only [bind_eq_ok, Prod.exists, throw_eq_error, error_bind, ok_bind, pure_eq_ok,
      ite_error_eq_ok] at h
    obtain ⟨s, q, hs, hcount, h⟩ := h
    obtain ⟨hutf, hne, hle, hq1, hq2, hval⟩ := readClaimString_sound hs
    have henc : data.take q = data.take pos ++ encodeBytes 6 s := by
      rw [hval, htag, encodeBytes_of_ne hne]; simp [WIRE_LEN]
    split at h
    · rename_i prev hprev
      simp only [ite_error_eq_ok, Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨hlt, rfl, rfl, rfl⟩ := h
      refine ⟨by omega, hq2, hord,
        .inr (.inr (.inr (.inr (.inr ⟨rfl, s, hutf, hne, hle, by omega, ?_, rfl, henc⟩))))⟩
      intro prev' hprev'
      rw [hprev] at hprev'
      cases hprev'
      exact List.not_le.mp hlt
    · rename_i hnone
      simp only [Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl, rfl⟩ := h
      refine ⟨by omega, hq2, hord,
        .inr (.inr (.inr (.inr (.inr ⟨rfl, s, hutf, hne, hle, by omega, ?_, rfl, henc⟩))))⟩
      intro prev' hprev'
      rw [hnone] at hprev'
      cases hprev'
  · simp at h

theorem claimsStep_progress (data : Bytes) : (claimsStep data).Progress :=
  fun _ _ _ _ _ _ h => (claimsStep_sound h).1

/-- Models `deserialize_claims`. -/
def deserializeClaims (data : Bytes) : Result Claims := do
  if data.isEmpty then
    throw .malformedEncoding
  if data.length > MAX_PAYLOAD_BYTES then
    throw .malformedEncoding
  fieldLoop data.length (claimsStep data) (claimsStep_progress data) 0 0 {}

/-! ## SignedToken -/

def MAX_SIGNED_TOKEN_BYTES : Nat :=
  MAX_PAYLOAD_BYTES + MAX_SIGNATURE_BYTES + MLDSA44_PUBLIC_KEY_LEN + 32

/-- Models `serialize_signing_input`. -/
def serializeSigningInput (version : Version) (algorithm : Algorithm)
    (keyIdentifier : KeyIdentifier) (payload : Bytes) : Bytes :=
  encodeUint32 1 version.toByte.toUInt32 ++ encodeUint32 2 algorithm.toByte.toUInt32 ++
    encodeUint32 3 keyIdentifier.keyIdType.toByte.toUInt32 ++
    encodeBytes 4 keyIdentifier.asBytes ++ encodeBytes 5 payload

/-- Models `append_signature`. -/
def appendSignature (signingInput signature : Bytes) : Bytes :=
  signingInput ++ encodeBytes 6 signature

/-- Models `serialize_signed_token`. -/
def serializeSignedToken (token : SignedToken) : Bytes :=
  appendSignature
    (serializeSigningInput token.version token.algorithm token.keyIdentifier token.payload)
    token.signature

/-- The local variables of `deserialize_signed_token_at`. -/
structure TokenFields where
  algorithm : Option Algorithm := none
  keyIdType : Option KeyIdType := none
  keyId : Bytes := []
  payload : Option Bytes := none
  /-- The signature and the offset at which its field starts. -/
  signature : Option (Bytes × Nat) := none

/-- The loop body of `deserialize_signed_token_at`. -/
def tokenStep (data : Bytes) : Step TokenFields := fun pos last st => do
  let fieldStart := pos
  let (fieldNumber, wireType, pos) ← nextField data pos last none
  match fieldNumber, wireType with
  | 1, 0 =>
    let (v, _) ← readU8Value data pos
    throw (.invalidVersion v)
  | 2, 0 =>
    let (algorithm, pos) ← readAlgorithm data pos
    pure (pos, fieldNumber, { st with algorithm := some algorithm })
  | 3, 0 =>
    let (byte, pos) ← readNonzeroU8 data pos
    match KeyIdType.fromByte byte with
    | some keyIdType => pure (pos, fieldNumber, { st with keyIdType := some keyIdType })
    | none => throw (.invalidKeyIdType byte)
  | 4, 2 =>
    let (keyId, pos) ← readBoundedBytes data pos MLDSA44_PUBLIC_KEY_LEN
    pure (pos, fieldNumber, { st with keyId := keyId })
  | 5, 2 =>
    let (payload, pos) ← readBoundedBytes data pos MAX_PAYLOAD_BYTES
    pure (pos, fieldNumber, { st with payload := some payload })
  | 6, 2 =>
    let (sig, pos) ← readBoundedBytes data pos MAX_SIGNATURE_BYTES
    pure (pos, fieldNumber, { st with signature := some (sig, fieldStart) })
  | _, _ => throw .malformedEncoding

/-- An enum byte written as a `uint32` field. -/
theorem encodeUint32_u8 {field : Nat} {b : UInt8} (h : b ≠ 0) :
    encodeUint32 field b.toUInt32 = encodeTag field WIRE_VARINT ++ encodeVarint b.toUInt64 := by
  have h0 : b.toUInt32 ≠ 0 := by
    intro h0
    apply h
    apply UInt8.toNat_inj.mp
    have := congrArg UInt32.toNat h0
    simpa using this
  rw [encodeUint32_of_ne h0]
  simp

/-- What one successful iteration of the SignedToken loop did. -/
theorem tokenStep_sound {data : Bytes} {pos last pos' last' : Nat} {st st' : TokenFields}
    (h : tokenStep data pos last st = .ok (pos', last', st')) :
    pos < pos' ∧ pos' ≤ data.length ∧ last < last' ∧
    ((last' = 2 ∧ ∃ a : Algorithm, st' = { st with algorithm := some a } ∧
        data.take pos' = data.take pos ++ encodeUint32 2 a.toByte.toUInt32) ∨
     (last' = 3 ∧ ∃ t : KeyIdType, st' = { st with keyIdType := some t } ∧
        data.take pos' = data.take pos ++ encodeUint32 3 t.toByte.toUInt32) ∨
     (last' = 4 ∧ ∃ b, b ≠ [] ∧ b.length ≤ MLDSA44_PUBLIC_KEY_LEN ∧
        st' = { st with keyId := b } ∧ data.take pos' = data.take pos ++ encodeBytes 4 b) ∨
     (last' = 5 ∧ ∃ b, b ≠ [] ∧ b.length ≤ MAX_PAYLOAD_BYTES ∧
        st' = { st with payload := some b } ∧
        data.take pos' = data.take pos ++ encodeBytes 5 b) ∨
     (last' = 6 ∧ ∃ b, b ≠ [] ∧ b.length ≤ MAX_SIGNATURE_BYTES ∧
        st' = { st with signature := some (b, pos) } ∧
        data.take pos' = data.take pos ++ encodeBytes 6 b)) := by
  simp only [tokenStep, bind_eq_ok, Prod.exists] at h
  obtain ⟨f, w, p, hf, h⟩ := h
  obtain ⟨hord, hp1, hp2, htag⟩ := nextField_sound hf
  have hord : last < f := by
    rcases hord with h | ⟨_, h2⟩
    · exact h
    · cases h2
  split at h
  · simp at h
  · simp only [bind_eq_ok, Prod.exists, pure_eq_ok, Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨a, q, ha, rfl, rfl, rfl⟩ := h
    obtain ⟨hq1, hq2, hval⟩ := readAlgorithm_sound ha
    refine ⟨by omega, hq2, hord, .inl ⟨rfl, a, rfl, ?_⟩⟩
    rw [hval, htag, encodeUint32_u8 a.toByte_ne_zero, List.append_assoc]; rfl
  · simp only [bind_eq_ok, Prod.exists] at h
    obtain ⟨b, q, hb, h⟩ := h
    obtain ⟨hb0, hq1, hq2, hval⟩ := readNonzeroU8_sound hb
    split at h
    · rename_i t ht
      simp only [pure_eq_ok, Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl, rfl⟩ := h
      refine ⟨by omega, hq2, hord, .inr (.inl ⟨rfl, t, rfl, ?_⟩)⟩
      rw [hval, htag, encodeUint32_u8 t.toByte_ne_zero, KeyIdType.toByte_of_fromByte ht,
        List.append_assoc]; rfl
    · simp at h
  · simp only [bind_eq_ok, Prod.exists, pure_eq_ok, Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨b, q, hb, rfl, rfl, rfl⟩ := h
    obtain ⟨hne, hle, hq1, hq2, hval⟩ := readBoundedBytes_sound hb
    refine ⟨by omega, hq2, hord, .inr (.inr (.inl ⟨rfl, b, hne, hle, rfl, ?_⟩))⟩
    rw [hval, htag, encodeBytes_of_ne hne]; simp [WIRE_LEN]
  · simp only [bind_eq_ok, Prod.exists, pure_eq_ok, Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨b, q, hb, rfl, rfl, rfl⟩ := h
    obtain ⟨hne, hle, hq1, hq2, hval⟩ := readBoundedBytes_sound hb
    refine ⟨by omega, hq2, hord, .inr (.inr (.inr (.inl ⟨rfl, b, hne, hle, rfl, ?_⟩)))⟩
    rw [hval, htag, encodeBytes_of_ne hne]; simp [WIRE_LEN]
  · simp only [bind_eq_ok, Prod.exists, pure_eq_ok, Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨b, q, hb, rfl, rfl, rfl⟩ := h
    obtain ⟨hne, hle, hq1, hq2, hval⟩ := readBoundedBytes_sound hb
    refine ⟨by omega, hq2, hord, .inr (.inr (.inr (.inr ⟨rfl, b, hne, hle, rfl, ?_⟩)))⟩
    rw [hval, htag, encodeBytes_of_ne hne]; simp [WIRE_LEN]
  · simp at h

theorem tokenStep_progress (data : Bytes) : (tokenStep data).Progress :=
  fun _ _ _ _ _ _ h => (tokenStep_sound h).1

/-- Models `key_identifier_from_wire`. -/
def keyIdentifierFromWire (algorithm : Algorithm) (keyIdType : KeyIdType) (keyId : Bytes) :
    Result KeyIdentifier :=
  match keyIdType with
  | .keyHash =>
    if h : keyId.length = KEY_HASH_LEN then
      .ok (.keyHash ⟨keyId, h⟩)
    else
      .error (.invalidKeyLength KEY_HASH_LEN keyId.length)
  | .publicKey =>
    -- Symmetric algorithms have no public key to embed.
    match algorithm.publicKeyLen with
    | none => .error (.invalidKeyIdType keyIdType.toByte)
    | some expected =>
      if keyId.length ≠ expected then
        .error (.invalidKeyLength expected keyId.length)
      else
        .ok (.publicKey keyId)

/-- Models `Option::ok_or_else(|| missing_field(..))`. -/
def required {α : Type} : Option α → Result α
  | some a => .ok a
  | none => .error .malformedEncoding

/-- Models `deserialize_signed_token_at`. Returns the token and the length of the
signed prefix. -/
def deserializeSignedTokenAt (data : Bytes) : Result (SignedToken × Nat) := do
  if data.isEmpty then
    throw .malformedEncoding
  if data.length > MAX_SIGNED_TOKEN_BYTES then
    throw .malformedEncoding
  let st ← fieldLoop data.length (tokenStep data) (tokenStep_progress data) 0 0 {}
  let algorithm ← required st.algorithm
  let keyIdType ← required st.keyIdType
  let keyIdentifier ← keyIdentifierFromWire algorithm keyIdType st.keyId
  let payload ← required st.payload
  let (signature, signedLen) ← required st.signature
  pure ({ version := .v0, algorithm, keyIdentifier, payload, signature }, signedLen)

/-- Models `deserialize_signed_token`. -/
def deserializeSignedToken (data : Bytes) : Result SignedToken := do
  let (token, _) ← deserializeSignedTokenAt data
  pure token

end Protoken
