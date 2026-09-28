import Protoken.Verify

/-!
# Signing and verifying keys

Model of `src/keys.rs`: the key types, algorithm dispatch, and key serialization.
`SigningKey::generate` is omitted; it passes 32 random bytes to `from_secret_key`.
Zeroization has no counterpart here because the model has no memory. The theorems
are in `KeysProofs.lean`.
-/

namespace Protoken

def MAX_SECRET_KEY_BYTES : Nat := HMAC_MAX_KEY_LEN
def MAX_PUBLIC_KEY_BYTES : Nat := 2048

structure SigningKey where
  algorithm : Algorithm
  secretKey : Bytes
  publicKey : Bytes
  deriving DecidableEq, Repr

structure VerifyingKey where
  algorithm : Algorithm
  publicKey : Bytes
  deriving DecidableEq, Repr

variable (C : Crypto)

/-! ## SigningKey -/

namespace SigningKey

/-- Models `SigningKey::from_secret_key`. -/
def fromSecretKey (algorithm : Algorithm) (secretKey : Bytes) : Result SigningKey := do
  let publicKey ←
    if algorithm.isSymmetric then do
      checkHmacKeyLen secretKey
      pure []
    else
      derivePublicKey C algorithm secretKey
  pure { algorithm, secretKey, publicKey }

/-- Models `SigningKey::validate`. -/
def validate (k : SigningKey) : Result Unit :=
  match k.algorithm with
  | .hmacSha256 => do
    checkHmacKeyLen k.secretKey
    if !k.publicKey.isEmpty then
      throw .invalidKey
    pure ()
  | .ed25519 | .mlDsa44 => do
    let derived ← derivePublicKey C k.algorithm k.secretKey
    if derived ≠ k.publicKey then
      throw .invalidKey
    pure ()

/-- Models `SigningKey::checked_public_key`. -/
def checkedPublicKey (k : SigningKey) : Result Bytes :=
  match k.algorithm.publicKeyLen with
  | none => .error .invalidKey
  | some expected =>
    if k.publicKey.length ≠ expected then
      .error (.invalidKeyLength expected k.publicKey.length)
    else
      .ok k.publicKey

/-- Models `SigningKey::verifying_key`. -/
def verifyingKey (k : SigningKey) : Result VerifyingKey := do
  let publicKey ← k.checkedPublicKey
  pure { algorithm := k.algorithm, publicKey }

/-- Models `SigningKey::identifying_material`. -/
def identifyingMaterial (k : SigningKey) : Result Bytes :=
  if k.algorithm.isSymmetric then .ok k.secretKey else k.checkedPublicKey

/-- Models `SigningKey::key_identifier`. -/
def keyIdentifier (k : SigningKey) (idType : KeyIdType) : Result KeyIdentifier :=
  match idType with
  | .keyHash => do
    let material ← k.identifyingMaterial
    pure (.keyHash (computeKeyHash C material))
  | .publicKey =>
    if k.algorithm.isSymmetric then
      .error (.invalidKeyIdType KeyIdType.publicKey.toByte)
    else do
      let publicKey ← k.checkedPublicKey
      pure (.publicKey publicKey)

/-- Models `SigningKey::sign_with_key_id`. -/
def signWithKeyId (k : SigningKey) (claims : Claims) (idType : KeyIdType) : Result Bytes :=
  match k.algorithm with
  | .hmacSha256 =>
    if idType = .keyHash then
      signHmac C k.secretKey claims
    else
      .error (.invalidKeyIdType idType.toByte)
  | .ed25519 => do
    let keyId ← k.keyIdentifier C idType
    signEd25519 C k.secretKey claims keyId
  | .mlDsa44 => do
    let keyId ← k.keyIdentifier C idType
    signMldsa44 C k.secretKey claims keyId

/-- Models `SigningKey::sign`. -/
def sign (k : SigningKey) (claims : Claims) : Result Bytes :=
  k.signWithKeyId C claims .keyHash

/-- Models `SigningKey::verify`. -/
def verify (k : SigningKey) (tokenBytes : Bytes) (now : UInt64) : Result VerifiedToken :=
  match k.algorithm with
  | .hmacSha256 => verifyHmac C k.secretKey tokenBytes now
  | .ed25519 => do
    let publicKey ← k.checkedPublicKey
    verifyEd25519 C publicKey tokenBytes now
  | .mlDsa44 => do
    let publicKey ← k.checkedPublicKey
    verifyMldsa44 C publicKey tokenBytes now

end SigningKey

/-! ## VerifyingKey -/

/-- Models `validate_public_key`. -/
def validatePublicKey (algorithm : Algorithm) (publicKey : Bytes) : Result Unit :=
  match algorithm with
  | .hmacSha256 => .error .invalidKey
  | .ed25519 => checkEd25519PublicKey C publicKey
  | .mlDsa44 => checkMldsa44PublicKey publicKey

namespace VerifyingKey

/-- Models `VerifyingKey::validate`. -/
def validate (k : VerifyingKey) : Result Unit :=
  validatePublicKey C k.algorithm k.publicKey

/-- Models `VerifyingKey::key_hash`. -/
def keyHash (k : VerifyingKey) : KeyHash :=
  computeKeyHash C k.publicKey

/-- Models `VerifyingKey::verify`. -/
def verify (k : VerifyingKey) (tokenBytes : Bytes) (now : UInt64) : Result VerifiedToken :=
  match k.algorithm with
  | .hmacSha256 => .error .invalidKey
  | .ed25519 => verifyEd25519 C k.publicKey tokenBytes now
  | .mlDsa44 => verifyMldsa44 C k.publicKey tokenBytes now

end VerifyingKey

/-! ## Serialization -/

/-- Models `serialize_signing_key`. -/
def serializeSigningKey (k : SigningKey) : Bytes :=
  encodeUint32 1 k.algorithm.toByte.toUInt32 ++ encodeBytes 2 k.secretKey ++
    encodeBytes 3 k.publicKey

/-- Models `serialize_verifying_key`. -/
def serializeVerifyingKey (k : VerifyingKey) : Bytes :=
  encodeUint32 1 k.algorithm.toByte.toUInt32 ++ encodeBytes 2 k.publicKey

/-- The local variables of `deserialize_signing_key`. -/
structure SigningKeyFields where
  algorithm : Option Algorithm := none
  secretKey : Bytes := []
  publicKey : Bytes := []

/-- The loop body of `deserialize_signing_key`. -/
def signingKeyStep (data : Bytes) : Step SigningKeyFields := fun pos last st => do
  let (fieldNumber, wireType, pos) ← nextField data pos last none
  match fieldNumber, wireType with
  | 1, 0 =>
    let (algorithm, pos) ← readAlgorithm data pos
    pure (pos, fieldNumber, { st with algorithm := some algorithm })
  | 2, 2 =>
    let (bytes, pos) ← readBoundedBytes data pos MAX_SECRET_KEY_BYTES
    -- `extend_from_slice`
    pure (pos, fieldNumber, { st with secretKey := st.secretKey ++ bytes })
  | 3, 2 =>
    let (bytes, pos) ← readBoundedBytes data pos MAX_PUBLIC_KEY_BYTES
    pure (pos, fieldNumber, { st with publicKey := bytes })
  | _, _ => throw .malformedEncoding

/-- What one successful iteration of the SigningKey loop did. -/
theorem signingKeyStep_sound {data : Bytes} {pos last pos' last' : Nat}
    {st st' : SigningKeyFields}
    (h : signingKeyStep data pos last st = .ok (pos', last', st')) :
    pos < pos' ∧ pos' ≤ data.length ∧ last < last' ∧
    ((last' = 1 ∧ ∃ a : Algorithm, st' = { st with algorithm := some a } ∧
        data.take pos' = data.take pos ++ encodeUint32 1 a.toByte.toUInt32) ∨
     (last' = 2 ∧ ∃ b, b ≠ [] ∧ b.length ≤ MAX_SECRET_KEY_BYTES ∧
        st' = { st with secretKey := st.secretKey ++ b } ∧
        data.take pos' = data.take pos ++ encodeBytes 2 b) ∨
     (last' = 3 ∧ ∃ b, b ≠ [] ∧ b.length ≤ MAX_PUBLIC_KEY_BYTES ∧
        st' = { st with publicKey := b } ∧
        data.take pos' = data.take pos ++ encodeBytes 3 b)) := by
  simp only [signingKeyStep, bind_eq_ok, Prod.exists] at h
  obtain ⟨f, w, p, hf, h⟩ := h
  obtain ⟨hord, hp1, hp2, htag⟩ := nextField_sound hf
  have hord : last < f := by
    rcases hord with h | ⟨_, h2⟩
    · exact h
    · cases h2
  split at h
  · simp only [bind_eq_ok, Prod.exists, pure_eq_ok, Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨a, q, ha, rfl, rfl, rfl⟩ := h
    obtain ⟨hq1, hq2, hval⟩ := readAlgorithm_sound ha
    refine ⟨by omega, hq2, hord, .inl ⟨rfl, a, rfl, ?_⟩⟩
    rw [hval, htag, encodeUint32_u8 a.toByte_ne_zero, List.append_assoc]; rfl
  · simp only [bind_eq_ok, Prod.exists, pure_eq_ok, Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨b, q, hb, rfl, rfl, rfl⟩ := h
    obtain ⟨hne, hle, hq1, hq2, hval⟩ := readBoundedBytes_sound hb
    refine ⟨by omega, hq2, hord, .inr (.inl ⟨rfl, b, hne, hle, rfl, ?_⟩)⟩
    rw [hval, htag, encodeBytes_of_ne hne]; simp [WIRE_LEN]
  · simp only [bind_eq_ok, Prod.exists, pure_eq_ok, Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨b, q, hb, rfl, rfl, rfl⟩ := h
    obtain ⟨hne, hle, hq1, hq2, hval⟩ := readBoundedBytes_sound hb
    refine ⟨by omega, hq2, hord, .inr (.inr ⟨rfl, b, hne, hle, rfl, ?_⟩)⟩
    rw [hval, htag, encodeBytes_of_ne hne]; simp [WIRE_LEN]
  · simp at h

theorem signingKeyStep_progress (data : Bytes) : (signingKeyStep data).Progress :=
  fun _ _ _ _ _ _ h => (signingKeyStep_sound h).1

/-- Models `deserialize_signing_key`. -/
def deserializeSigningKey (data : Bytes) : Result SigningKey := do
  if data.isEmpty then
    throw .malformedEncoding
  let st ← fieldLoop data.length (signingKeyStep data) (signingKeyStep_progress data) 0 0 {}
  let algorithm ← required st.algorithm
  let key : SigningKey := { algorithm, secretKey := st.secretKey, publicKey := st.publicKey }
  key.validate C
  pure key

/-- The local variables of `deserialize_verifying_key`. -/
structure VerifyingKeyFields where
  algorithm : Option Algorithm := none
  publicKey : Bytes := []

/-- The loop body of `deserialize_verifying_key`. -/
def verifyingKeyStep (data : Bytes) : Step VerifyingKeyFields := fun pos last st => do
  let (fieldNumber, wireType, pos) ← nextField data pos last none
  match fieldNumber, wireType with
  | 1, 0 =>
    let (algorithm, pos) ← readAlgorithm data pos
    pure (pos, fieldNumber, { st with algorithm := some algorithm })
  | 2, 2 =>
    let (bytes, pos) ← readBoundedBytes data pos MAX_PUBLIC_KEY_BYTES
    -- `extend_from_slice`
    pure (pos, fieldNumber, { st with publicKey := st.publicKey ++ bytes })
  | _, _ => throw .malformedEncoding

/-- What one successful iteration of the VerifyingKey loop did. -/
theorem verifyingKeyStep_sound {data : Bytes} {pos last pos' last' : Nat}
    {st st' : VerifyingKeyFields}
    (h : verifyingKeyStep data pos last st = .ok (pos', last', st')) :
    pos < pos' ∧ pos' ≤ data.length ∧ last < last' ∧
    ((last' = 1 ∧ ∃ a : Algorithm, st' = { st with algorithm := some a } ∧
        data.take pos' = data.take pos ++ encodeUint32 1 a.toByte.toUInt32) ∨
     (last' = 2 ∧ ∃ b, b ≠ [] ∧ b.length ≤ MAX_PUBLIC_KEY_BYTES ∧
        st' = { st with publicKey := st.publicKey ++ b } ∧
        data.take pos' = data.take pos ++ encodeBytes 2 b)) := by
  simp only [verifyingKeyStep, bind_eq_ok, Prod.exists] at h
  obtain ⟨f, w, p, hf, h⟩ := h
  obtain ⟨hord, hp1, hp2, htag⟩ := nextField_sound hf
  have hord : last < f := by
    rcases hord with h | ⟨_, h2⟩
    · exact h
    · cases h2
  split at h
  · simp only [bind_eq_ok, Prod.exists, pure_eq_ok, Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨a, q, ha, rfl, rfl, rfl⟩ := h
    obtain ⟨hq1, hq2, hval⟩ := readAlgorithm_sound ha
    refine ⟨by omega, hq2, hord, .inl ⟨rfl, a, rfl, ?_⟩⟩
    rw [hval, htag, encodeUint32_u8 a.toByte_ne_zero, List.append_assoc]; rfl
  · simp only [bind_eq_ok, Prod.exists, pure_eq_ok, Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨b, q, hb, rfl, rfl, rfl⟩ := h
    obtain ⟨hne, hle, hq1, hq2, hval⟩ := readBoundedBytes_sound hb
    refine ⟨by omega, hq2, hord, .inr ⟨rfl, b, hne, hle, rfl, ?_⟩⟩
    rw [hval, htag, encodeBytes_of_ne hne]; simp [WIRE_LEN]
  · simp at h

theorem verifyingKeyStep_progress (data : Bytes) : (verifyingKeyStep data).Progress :=
  fun _ _ _ _ _ _ h => (verifyingKeyStep_sound h).1

/-- Models `deserialize_verifying_key`. -/
def deserializeVerifyingKey (data : Bytes) : Result VerifyingKey := do
  if data.isEmpty then
    throw .malformedEncoding
  let st ← fieldLoop data.length (verifyingKeyStep data) (verifyingKeyStep_progress data) 0 0 {}
  let algorithm ← required st.algorithm
  validatePublicKey C algorithm st.publicKey
  pure { algorithm, publicKey := st.publicKey }

end Protoken
