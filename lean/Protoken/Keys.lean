import Protoken.Verify

/-!
# Signing and verifying keys

Model of `src/keys.rs`. The Rust fields are private, so a Rust key always comes from
a constructor. Here the structures are unconstrained, and `KeysProofs.lean` proves
that every constructor returns a `Valid` key.

`SigningKey::generate` is omitted; it passes its secret to `from_secret_key`.
Zeroization has no counterpart here because the model has no memory.
-/

namespace Protoken

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

/-- Models `check_len`. -/
def checkLen (expected : Nat) (key : Bytes) : Result Unit :=
  if key.length ≠ expected then .error (.invalidKeyLength expected key.length) else .ok ()

/-- Models `check_secret_key_len`. -/
def checkSecretKeyLen (algorithm : Algorithm) (secretKey : Bytes) : Result Unit :=
  if !algorithm.isSymmetric then
    checkLen algorithm.secretKeyLen secretKey
  else if ¬(HMAC_MIN_KEY_LEN ≤ secretKey.length ∧ secretKey.length ≤ HMAC_MAX_KEY_LEN) then
    .error .invalidKey
  else
    .ok ()

/-- Models `check_public_key`. -/
def checkPublicKey (algorithm : Algorithm) (publicKey : Bytes) : Result Unit :=
  match algorithm.publicKeyLen with
  | none => .error .invalidKey
  | some expected => do
    checkLen expected publicKey
    if !C.publicKeyValid algorithm publicKey then
      throw .invalidKey
    pure ()

/-! ## VerifyingKey -/

namespace VerifyingKey

/-- Models `VerifyingKey::new`. -/
def new (algorithm : Algorithm) (publicKey : Bytes) : Result VerifyingKey := do
  checkPublicKey C algorithm publicKey
  pure { algorithm, publicKey }

/-- Models `VerifyingKey::key_hash`. -/
def keyHash (k : VerifyingKey) : KeyHash :=
  computeKeyHash C k.publicKey

/-- Models `VerifyingKey::verify`. -/
def verify (k : VerifyingKey) (tokenBytes : Bytes) (now : UInt64) : Result VerifiedToken :=
  verifyToken C k.algorithm k.publicKey tokenBytes now

end VerifyingKey

/-! ## SigningKey -/

namespace SigningKey

/-- Models `SigningKey::from_secret_key`. -/
def fromSecretKey (algorithm : Algorithm) (secretKey : Bytes) : Result SigningKey := do
  checkSecretKeyLen algorithm secretKey
  let publicKey ← schemePublicKey C algorithm secretKey
  pure { algorithm, secretKey, publicKey }

/-- Models `SigningKey::verifying_key`. -/
def verifyingKey (k : SigningKey) : Result VerifyingKey :=
  VerifyingKey.new C k.algorithm k.publicKey

/-- Models `SigningKey::verifier_material`. -/
def verifierMaterial (k : SigningKey) : Bytes :=
  if k.algorithm.isSymmetric then k.secretKey else k.publicKey

/-- Models `SigningKey::key_identifier`. -/
def keyIdentifier (k : SigningKey) (idType : KeyIdType) : Result KeyIdentifier :=
  match idType with
  | .keyHash => .ok (.keyHash (computeKeyHash C k.verifierMaterial))
  | .publicKey =>
    if k.algorithm.isSymmetric then
      .error (.invalidKeyIdType idType.toByte)
    else
      .ok (.publicKey k.publicKey)

/-- Models `SigningKey::sign_with_key_id`. -/
def signWithKeyId (k : SigningKey) (claims : Claims) (idType : KeyIdType) : Result Bytes := do
  let keyId ← k.keyIdentifier C idType
  signToken C k.algorithm k.secretKey keyId claims

/-- Models `SigningKey::sign`. -/
def sign (k : SigningKey) (claims : Claims) : Result Bytes :=
  k.signWithKeyId C claims .keyHash

/-- Models `SigningKey::verify`. -/
def verify (k : SigningKey) (tokenBytes : Bytes) (now : UInt64) : Result VerifiedToken :=
  verifyToken C k.algorithm k.verifierMaterial tokenBytes now

end SigningKey

/-! ## Serialization -/

/-- Models `SigningKey::to_bytes`. -/
def serializeSigningKey (k : SigningKey) : Bytes :=
  encodeUint32 1 k.algorithm.toByte.toUInt32 ++ encodeBytes 2 k.secretKey ++
    encodeBytes 3 k.publicKey

/-- Models `VerifyingKey::to_bytes`. -/
def serializeVerifyingKey (k : VerifyingKey) : Bytes :=
  encodeUint32 1 k.algorithm.toByte.toUInt32 ++ encodeBytes 2 k.publicKey

/-- The local variables of `SigningKey::from_bytes`. -/
structure SigningKeyFields where
  algorithm : Option Algorithm := none
  secretKey : Bytes := []
  publicKey : Bytes := []

/-- The loop body of `SigningKey::from_bytes`. -/
def signingKeyStep (data : Bytes) : Step SigningKeyFields := fun pos last st => do
  let (fieldNumber, wireType, pos) ← nextField data pos last none
  match fieldNumber, wireType with
  | 1, 0 =>
    let (algorithm, pos) ← readAlgorithm data pos
    pure (pos, fieldNumber, { st with algorithm := some algorithm })
  | 2, 2 =>
    let (bytes, pos) ← readBoundedBytes data pos MAX_SECRET_KEY_BYTES
    pure (pos, fieldNumber, { st with secretKey := bytes })
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
        st' = { st with secretKey := b } ∧
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

/-- Models `SigningKey::from_bytes`. -/
def deserializeSigningKey (data : Bytes) : Result SigningKey := do
  let st ← fieldLoop data.length (signingKeyStep data) (signingKeyStep_progress data) 0 0 {}
  let algorithm ← required st.algorithm
  let key ← SigningKey.fromSecretKey C algorithm st.secretKey
  if key.publicKey ≠ st.publicKey then
    throw .invalidKey
  pure key

/-- The local variables of `VerifyingKey::from_bytes`. -/
structure VerifyingKeyFields where
  algorithm : Option Algorithm := none
  publicKey : Bytes := []

/-- The loop body of `VerifyingKey::from_bytes`. -/
def verifyingKeyStep (data : Bytes) : Step VerifyingKeyFields := fun pos last st => do
  let (fieldNumber, wireType, pos) ← nextField data pos last none
  match fieldNumber, wireType with
  | 1, 0 =>
    let (algorithm, pos) ← readAlgorithm data pos
    pure (pos, fieldNumber, { st with algorithm := some algorithm })
  | 2, 2 =>
    let (bytes, pos) ← readBoundedBytes data pos MAX_PUBLIC_KEY_BYTES
    pure (pos, fieldNumber, { st with publicKey := bytes })
  | _, _ => throw .malformedEncoding

/-- What one successful iteration of the VerifyingKey loop did. -/
theorem verifyingKeyStep_sound {data : Bytes} {pos last pos' last' : Nat}
    {st st' : VerifyingKeyFields}
    (h : verifyingKeyStep data pos last st = .ok (pos', last', st')) :
    pos < pos' ∧ pos' ≤ data.length ∧ last < last' ∧
    ((last' = 1 ∧ ∃ a : Algorithm, st' = { st with algorithm := some a } ∧
        data.take pos' = data.take pos ++ encodeUint32 1 a.toByte.toUInt32) ∨
     (last' = 2 ∧ ∃ b, b ≠ [] ∧ b.length ≤ MAX_PUBLIC_KEY_BYTES ∧
        st' = { st with publicKey := b } ∧
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

/-- Models `VerifyingKey::from_bytes`. -/
def deserializeVerifyingKey (data : Bytes) : Result VerifyingKey := do
  let st ← fieldLoop data.length (verifyingKeyStep data) (verifyingKeyStep_progress data) 0 0 {}
  let algorithm ← required st.algorithm
  checkPublicKey C algorithm st.publicKey
  pure { algorithm, publicKey := st.publicKey }

end Protoken
