import Protoken.Keys
import Protoken.VerifyProofs

/-!
# Key theorems

* `deserializeSigningKey_canonical`, `deserializeVerifyingKey_canonical`: accepted
  key bytes are the canonical encoding of a valid key.
* `deserializeSigningKey_serialize`, `deserializeVerifyingKey_serialize`: every valid
  key survives encoding and decoding.
* `signing_key_is_not_verifying_key`: no byte string decodes as both key types.
* `SigningKey.verify_signWithKeyId`, `VerifyingKey.verify_signWithKeyId`: a token
  signed through the key API verifies through the key API.
* `SigningKey.verify_sound`, `VerifyingKey.verify_sound`: what acceptance guarantees.
-/

namespace Protoken

variable {C : Crypto}

/-! ## What `validate` checks -/

/-- The rules `SigningKey::validate` enforces. -/
def SigningKey.Valid (C : Crypto) (k : SigningKey) : Prop :=
  match k.algorithm with
  | .hmacSha256 =>
    HMAC_MIN_KEY_LEN ≤ k.secretKey.length ∧ k.secretKey.length ≤ HMAC_MAX_KEY_LEN ∧
      k.publicKey = []
  | .ed25519 =>
    k.secretKey.length = ED25519_SEED_LEN ∧ k.publicKey = C.ed25519PublicKey k.secretKey
  | .mlDsa44 =>
    k.secretKey.length = MLDSA44_SEED_LEN ∧ k.publicKey = C.mldsa44PublicKey k.secretKey

/-- The rules `VerifyingKey::validate` enforces. -/
def VerifyingKey.Valid (C : Crypto) (k : VerifyingKey) : Prop :=
  match k.algorithm with
  | .hmacSha256 => False
  | .ed25519 =>
    k.publicKey.length = ED25519_PUBLIC_KEY_LEN ∧ C.ed25519PointValid k.publicKey = true
  | .mlDsa44 => k.publicKey.length = MLDSA44_PUBLIC_KEY_LEN

theorem SigningKey.validate_eq_ok_iff (k : SigningKey) : k.validate C = .ok () ↔ k.Valid C := by
  obtain ⟨a, s, p⟩ := k
  cases a
  · simp only [SigningKey.validate, SigningKey.Valid, bind_eq_ok, exists_unit,
      checkHmacKeyLen_eq_ok_iff, throw_eq_error, error_bind, pure_eq_ok, ite_error_eq_ok]
    simp [and_assoc]
  · simp [SigningKey.validate, SigningKey.Valid, derivePublicKey, checkSeedLen_eq_ok_iff]
    exact fun _ => eq_comm
  · simp [SigningKey.validate, SigningKey.Valid, derivePublicKey, checkSeedLen_eq_ok_iff]
    exact fun _ => eq_comm

theorem checkEd25519PublicKey_eq_ok_iff {pk : Bytes} :
    checkEd25519PublicKey C pk = .ok () ↔
      pk.length = ED25519_PUBLIC_KEY_LEN ∧ C.ed25519PointValid pk = true := by
  simp only [checkEd25519PublicKey, throw_eq_error, error_bind, pure_eq_ok, ok_bind,
    ite_error_eq_ok]
  simp

theorem checkMldsa44PublicKey_eq_ok_iff {pk : Bytes} :
    checkMldsa44PublicKey pk = .ok () ↔ pk.length = MLDSA44_PUBLIC_KEY_LEN := by
  simp [checkMldsa44PublicKey]

theorem validatePublicKey_eq_ok_iff {a : Algorithm} {pk : Bytes} :
    validatePublicKey C a pk = .ok () ↔ VerifyingKey.Valid C ⟨a, pk⟩ := by
  cases a
  · simp [validatePublicKey, VerifyingKey.Valid]
  · simp [validatePublicKey, VerifyingKey.Valid, checkEd25519PublicKey_eq_ok_iff]
  · simp [validatePublicKey, VerifyingKey.Valid, checkMldsa44PublicKey_eq_ok_iff]

theorem VerifyingKey.validate_eq_ok_iff (k : VerifyingKey) :
    k.validate C = .ok () ↔ k.Valid C :=
  validatePublicKey_eq_ok_iff

/-- Field sizes of a valid signing key. -/
theorem SigningKey.Valid.bounds {k : SigningKey} (h : k.Valid C) :
    k.secretKey.length ≤ MAX_SECRET_KEY_BYTES ∧ k.publicKey.length ≤ MAX_PUBLIC_KEY_BYTES := by
  obtain ⟨a, s, p⟩ := k
  cases a <;> simp only [SigningKey.Valid] at h
  · obtain ⟨_, h2, rfl⟩ := h
    exact ⟨h2, by simp⟩
  · obtain ⟨h1, rfl⟩ := h
    simp only [C.ed25519PublicKey_length, h1]
    decide
  · obtain ⟨h1, rfl⟩ := h
    simp only [C.mldsa44PublicKey_length, h1]
    decide

theorem VerifyingKey.Valid.bounds {k : VerifyingKey} (h : k.Valid C) :
    k.publicKey.length ≤ MAX_PUBLIC_KEY_BYTES := by
  obtain ⟨a, p⟩ := k
  cases a <;> simp only [VerifyingKey.Valid] at h
  · rw [h.1]; decide
  · rw [h]; decide

/-! ## SigningKey: soundness -/

/-- The invariant of the SigningKey decoding loop. -/
structure SigningKeyInv (data : Bytes) (pos last : Nat) (st : SigningKeyFields) : Prop where
  pos_le : pos ≤ data.length
  consumed : data.take pos = encodeUint32 1 (optByte32 Algorithm.toByte st.algorithm) ++
    encodeBytes 2 st.secretKey ++ encodeBytes 3 st.publicKey
  d1 : last < 1 → st.algorithm = none
  d2 : last < 2 → st.secretKey = []
  d3 : last < 3 → st.publicKey = []

theorem signingKeyInv_step {data : Bytes} {pos last pos' last' : Nat}
    {st st' : SigningKeyFields} (hinv : SigningKeyInv data pos last st)
    (h : signingKeyStep data pos last st = .ok (pos', last', st')) :
    SigningKeyInv data pos' last' st' := by
  obtain ⟨_, hle, hord, hcase⟩ := signingKeyStep_sound h
  obtain ⟨_, hcons, d1, d2, d3⟩ := hinv
  rcases hcase with ⟨rfl, a, rfl, htake⟩ | ⟨rfl, b, _, _, rfl, htake⟩ | ⟨rfl, b, _, _, rfl, htake⟩
  · refine ⟨hle, ?_, by omega, fun _ => d2 (by omega), fun _ => d3 (by omega)⟩
    rw [htake, hcons]
    simp [optByte32, d1 (by omega), d2 (by omega), d3 (by omega)]
  · refine ⟨hle, ?_, by omega, by omega, fun _ => d3 (by omega)⟩
    rw [htake, hcons]
    simp [d2 (by omega), d3 (by omega)]
  · refine ⟨hle, ?_, by omega, by omega, by omega⟩
    rw [htake, hcons]
    simp [d3 (by omega)]

/-- **Canonical signing keys.** Accepted bytes are exactly `serializeSigningKey` of
the decoded key, and the decoded key passes `validate`. -/
theorem deserializeSigningKey_canonical {data : Bytes} {k : SigningKey}
    (h : deserializeSigningKey C data = .ok k) : serializeSigningKey k = data ∧ k.Valid C := by
  simp only [deserializeSigningKey, throw_eq_error, error_bind, pure_eq_ok, ok_bind,
    ite_error_eq_ok, bind_eq_ok, exists_unit, required_eq_ok, SigningKey.validate_eq_ok_iff,
    Except.ok.injEq] at h
  obtain ⟨_, st, hloop, a, ha, hvalid, rfl⟩ := h
  obtain ⟨pos, last, hpos, hinv⟩ := fieldLoop_invariant (SigningKeyInv data)
    (fun _ _ _ _ _ _ _ hinv hs => signingKeyInv_step hinv hs) data.length 0 0 {} st (by omega)
    ⟨by omega, by simp [optByte32], fun _ => rfl, fun _ => rfl, fun _ => rfl⟩ hloop
  refine ⟨?_, hvalid⟩
  have := hinv.consumed
  rw [List.take_of_length_le hpos, ha] at this
  simp [serializeSigningKey, this, optByte32]

/-! ## SigningKey: completeness -/

section Complete

variable {data : Bytes} {pos last : Nat} {rest : Bytes}

theorem signingKeyStep_algorithm {st : SigningKeyFields} {a : Algorithm} (hlast : last < 1)
    (h : data.drop pos = encodeUint32 1 a.toByte.toUInt32 ++ rest) :
    signingKeyStep data pos last st
      = .ok (pos + (encodeUint32 1 a.toByte.toUInt32).length, 1,
          { st with algorithm := some a }) := by
  rw [encodeUint32_u8 a.toByte_ne_zero, List.append_assoc] at h
  have h1 := nextField_complete (repeated := none) (last := last) (by omega)
    (by simp [WIRE_VARINT]) (.inl hlast) h
  have h2 := readAlgorithm_complete (drop_add_of_drop_eq_append h)
  simp only [WIRE_VARINT] at h1 h2
  simp [signingKeyStep, h1, h2, encodeUint32_u8 a.toByte_ne_zero, WIRE_VARINT, Nat.add_assoc]

theorem signingKeyStep_secretKey {st : SigningKeyFields} {b : Bytes}
    (hdata : data.length < 2 ^ 64) (hne : b ≠ []) (hle : b.length ≤ MAX_SECRET_KEY_BYTES)
    (hlast : last < 2) (h : data.drop pos = encodeBytes 2 b ++ rest) :
    signingKeyStep data pos last st
      = .ok (pos + (encodeBytes 2 b).length, 2, { st with secretKey := st.secretKey ++ b }) := by
  rw [encodeBytes_of_ne hne, List.append_assoc, List.append_assoc] at h
  have h1 := nextField_complete (repeated := none) (last := last) (by omega)
    (by simp [WIRE_LEN]) (.inl hlast) h
  have h2 := readBoundedBytes_complete hdata hne hle
    (by rw [drop_add_of_drop_eq_append h, List.append_assoc])
  simp only [WIRE_LEN] at h1 h2
  simp [signingKeyStep, h1, h2, encodeBytes_of_ne hne, WIRE_LEN, Nat.add_assoc]

theorem signingKeyStep_publicKey {st : SigningKeyFields} {b : Bytes}
    (hdata : data.length < 2 ^ 64) (hne : b ≠ []) (hle : b.length ≤ MAX_PUBLIC_KEY_BYTES)
    (hlast : last < 3) (h : data.drop pos = encodeBytes 3 b ++ rest) :
    signingKeyStep data pos last st
      = .ok (pos + (encodeBytes 3 b).length, 3, { st with publicKey := b }) := by
  rw [encodeBytes_of_ne hne, List.append_assoc, List.append_assoc] at h
  have h1 := nextField_complete (repeated := none) (last := last) (by omega)
    (by simp [WIRE_LEN]) (.inl hlast) h
  have h2 := readBoundedBytes_complete hdata hne hle
    (by rw [drop_add_of_drop_eq_append h, List.append_assoc])
  simp only [WIRE_LEN] at h1 h2
  simp [signingKeyStep, h1, h2, encodeBytes_of_ne hne, WIRE_LEN, Nat.add_assoc]

theorem verifyingKeyStep_algorithm {st : VerifyingKeyFields} {a : Algorithm} (hlast : last < 1)
    (h : data.drop pos = encodeUint32 1 a.toByte.toUInt32 ++ rest) :
    verifyingKeyStep data pos last st
      = .ok (pos + (encodeUint32 1 a.toByte.toUInt32).length, 1,
          { st with algorithm := some a }) := by
  rw [encodeUint32_u8 a.toByte_ne_zero, List.append_assoc] at h
  have h1 := nextField_complete (repeated := none) (last := last) (by omega)
    (by simp [WIRE_VARINT]) (.inl hlast) h
  have h2 := readAlgorithm_complete (drop_add_of_drop_eq_append h)
  simp only [WIRE_VARINT] at h1 h2
  simp [verifyingKeyStep, h1, h2, encodeUint32_u8 a.toByte_ne_zero, WIRE_VARINT, Nat.add_assoc]

theorem verifyingKeyStep_publicKey {st : VerifyingKeyFields} {b : Bytes}
    (hdata : data.length < 2 ^ 64) (hne : b ≠ []) (hle : b.length ≤ MAX_PUBLIC_KEY_BYTES)
    (hlast : last < 2) (h : data.drop pos = encodeBytes 2 b ++ rest) :
    verifyingKeyStep data pos last st
      = .ok (pos + (encodeBytes 2 b).length, 2, { st with publicKey := st.publicKey ++ b }) := by
  rw [encodeBytes_of_ne hne, List.append_assoc, List.append_assoc] at h
  have h1 := nextField_complete (repeated := none) (last := last) (by omega)
    (by simp [WIRE_LEN]) (.inl hlast) h
  have h2 := readBoundedBytes_complete hdata hne hle
    (by rw [drop_add_of_drop_eq_append h, List.append_assoc])
  simp only [WIRE_LEN] at h1 h2
  simp [verifyingKeyStep, h1, h2, encodeBytes_of_ne hne, WIRE_LEN, Nat.add_assoc]

end Complete

theorem encodeUint32_u8_ne_nil {f : Nat} {b : UInt8} (hb : b ≠ 0) :
    encodeUint32 f b.toUInt32 ≠ [] := by
  intro h
  rw [encodeUint32_u8 hb] at h
  have h1 := congrArg List.length h
  have h2 := encodeVarint_length_pos b.toUInt64
  simp only [List.length_append, List.length_nil] at h1
  omega

theorem serializeSigningKey_length_lt {k : SigningKey}
    (hs : k.secretKey.length ≤ MAX_SECRET_KEY_BYTES)
    (hp : k.publicKey.length ≤ MAX_PUBLIC_KEY_BYTES) :
    (serializeSigningKey k).length < 2 ^ 64 := by
  simp only [MAX_SECRET_KEY_BYTES, HMAC_MAX_KEY_LEN, MAX_PUBLIC_KEY_BYTES] at hs hp
  have h1 := encodeUint32_u8_length_le (f := 1) (by omega) k.algorithm.toByte_toNat_lt
  have h2 := encodeBytes_length_le (f := 2) (by omega) (b := k.secretKey) (by omega)
  have h3 := encodeBytes_length_le (f := 3) (by omega) (b := k.publicKey) (by omega)
  simp only [serializeSigningKey, List.length_append]
  omega

/-- The loop recovers the three fields of any key within the field size limits. -/
theorem signingKeyLoop_complete {k : SigningKey}
    (hs : k.secretKey.length ≤ MAX_SECRET_KEY_BYTES)
    (hp : k.publicKey.length ≤ MAX_PUBLIC_KEY_BYTES) :
    fieldLoop (serializeSigningKey k).length (signingKeyStep (serializeSigningKey k))
      (signingKeyStep_progress _) 0 0 {} = .ok ⟨some k.algorithm, k.secretKey, k.publicKey⟩ := by
  have hdata := serializeSigningKey_length_lt hs hp
  generalize hd : serializeSigningKey k = data at *
  have h0 : data.drop 0 = encodeUint32 1 k.algorithm.toByte.toUInt32 ++
      (encodeBytes 2 k.secretKey ++ (encodeBytes 3 k.publicKey ++ [])) := by
    simp [← hd, serializeSigningKey]
  have hprog := signingKeyStep_progress data
  obtain ⟨p1, l1, hl1, h1, e1⟩ := fieldLoop_optional (hstep := hprog) (pos := 0) (last := 0)
    (f := 1) (s := ({} : SigningKeyFields)) (s' := { algorithm := some k.algorithm }) h0
    (by omega) (fun he => absurd he (encodeUint32_u8_ne_nil k.algorithm.toByte_ne_zero))
    (fun _ => signingKeyStep_algorithm (by omega) h0)
  obtain ⟨p2, l2, hl2, h2, e2⟩ := fieldLoop_optional (hstep := hprog) (last := l1) (f := 2)
    (s := { algorithm := some k.algorithm })
    (s' := { algorithm := some k.algorithm, secretKey := k.secretKey }) h1 (by omega)
    (fun he => by rw [encodeBytes_eq_nil_iff.mp he])
    (fun he => signingKeyStep_secretKey hdata (mt encodeBytes_eq_nil_iff.mpr he) hs (by omega) h1)
  obtain ⟨p3, l3, hl3, h3, e3⟩ := fieldLoop_optional (hstep := hprog) (last := l2) (f := 3)
    (s := { algorithm := some k.algorithm, secretKey := k.secretKey })
    (s' := { algorithm := some k.algorithm, secretKey := k.secretKey, publicKey := k.publicKey })
    h2 (by omega) (fun he => by rw [encodeBytes_eq_nil_iff.mp he])
    (fun he => signingKeyStep_publicKey hdata (mt encodeBytes_eq_nil_iff.mpr he) hp (by omega) h2)
  have hend : data.length ≤ p3 := by
    have := congrArg List.length h3
    simp at this
    omega
  exact e1.trans (e2.trans (e3.trans (fieldLoop_done hend)))

theorem serializeSigningKey_ne_nil (k : SigningKey) : serializeSigningKey k ≠ [] := by
  intro h
  simp only [serializeSigningKey, List.append_eq_nil_iff] at h
  exact encodeUint32_u8_ne_nil k.algorithm.toByte_ne_zero h.1.1

/-- **Signing key round trip.** Every key that passes `validate` decodes to itself. -/
theorem deserializeSigningKey_serialize {k : SigningKey} (h : k.Valid C) :
    deserializeSigningKey C (serializeSigningKey k) = .ok k := by
  obtain ⟨hs, hp⟩ := h.bounds
  simp only [deserializeSigningKey, throw_eq_error, error_bind, pure_eq_ok, ok_bind,
    List.isEmpty_iff, serializeSigningKey_ne_nil, if_false, signingKeyLoop_complete hs hp,
    required, (SigningKey.validate_eq_ok_iff _).mpr h]

/-- Keys within the field size limits with the same encoding are equal. -/
theorem serializeSigningKey_injective {k1 k2 : SigningKey}
    (hs1 : k1.secretKey.length ≤ MAX_SECRET_KEY_BYTES)
    (hp1 : k1.publicKey.length ≤ MAX_PUBLIC_KEY_BYTES)
    (hs2 : k2.secretKey.length ≤ MAX_SECRET_KEY_BYTES)
    (hp2 : k2.publicKey.length ≤ MAX_PUBLIC_KEY_BYTES)
    (heq : serializeSigningKey k1 = serializeSigningKey k2) : k1 = k2 := by
  have e1 := signingKeyLoop_complete hs1 hp1
  have e2 := signingKeyLoop_complete hs2 hp2
  simp only [heq] at e1
  rw [e2] at e1
  cases k1
  cases k2
  simp_all

/-! ## VerifyingKey -/

/-- The invariant of the VerifyingKey decoding loop. -/
structure VerifyingKeyInv (data : Bytes) (pos last : Nat) (st : VerifyingKeyFields) : Prop where
  pos_le : pos ≤ data.length
  consumed : data.take pos = encodeUint32 1 (optByte32 Algorithm.toByte st.algorithm) ++
    encodeBytes 2 st.publicKey
  d1 : last < 1 → st.algorithm = none
  d2 : last < 2 → st.publicKey = []

theorem verifyingKeyInv_step {data : Bytes} {pos last pos' last' : Nat}
    {st st' : VerifyingKeyFields} (hinv : VerifyingKeyInv data pos last st)
    (h : verifyingKeyStep data pos last st = .ok (pos', last', st')) :
    VerifyingKeyInv data pos' last' st' := by
  obtain ⟨_, hle, hord, hcase⟩ := verifyingKeyStep_sound h
  obtain ⟨_, hcons, d1, d2⟩ := hinv
  rcases hcase with ⟨rfl, a, rfl, htake⟩ | ⟨rfl, b, _, _, rfl, htake⟩
  · refine ⟨hle, ?_, by omega, fun _ => d2 (by omega)⟩
    rw [htake, hcons]
    simp [optByte32, d1 (by omega), d2 (by omega)]
  · refine ⟨hle, ?_, by omega, by omega⟩
    rw [htake, hcons]
    simp [d2 (by omega)]

/-- **Canonical verifying keys.** Accepted bytes are exactly `serializeVerifyingKey`
of the decoded key, and the decoded key passes `validate`. -/
theorem deserializeVerifyingKey_canonical {data : Bytes} {k : VerifyingKey}
    (h : deserializeVerifyingKey C data = .ok k) :
    serializeVerifyingKey k = data ∧ k.Valid C := by
  simp only [deserializeVerifyingKey, throw_eq_error, error_bind, pure_eq_ok, ok_bind,
    ite_error_eq_ok, bind_eq_ok, exists_unit, required_eq_ok, validatePublicKey_eq_ok_iff,
    Except.ok.injEq] at h
  obtain ⟨_, st, hloop, a, ha, hvalid, rfl⟩ := h
  obtain ⟨pos, last, hpos, hinv⟩ := fieldLoop_invariant (VerifyingKeyInv data)
    (fun _ _ _ _ _ _ _ hinv hs => verifyingKeyInv_step hinv hs) data.length 0 0 {} st (by omega)
    ⟨by omega, by simp [optByte32], fun _ => rfl, fun _ => rfl⟩ hloop
  refine ⟨?_, hvalid⟩
  have := hinv.consumed
  rw [List.take_of_length_le hpos, ha] at this
  simp [serializeVerifyingKey, this, optByte32]

/-- A verifying key has the same bytes as a signing key with no public key field. -/
theorem serializeVerifyingKey_eq (k : VerifyingKey) :
    serializeVerifyingKey k = serializeSigningKey ⟨k.algorithm, k.publicKey, []⟩ := by
  simp [serializeVerifyingKey, serializeSigningKey]

/-- **Verifying key round trip.** Every key that passes `validate` decodes to itself. -/
theorem deserializeVerifyingKey_serialize {k : VerifyingKey} (h : k.Valid C) :
    deserializeVerifyingKey C (serializeVerifyingKey k) = .ok k := by
  have hp := h.bounds
  have hdata : (serializeVerifyingKey k).length < 2 ^ 64 := by
    rw [serializeVerifyingKey_eq]
    exact serializeSigningKey_length_lt
      (by simp only [MAX_SECRET_KEY_BYTES, HMAC_MAX_KEY_LEN, MAX_PUBLIC_KEY_BYTES] at *; omega)
      (by simp)
  have hne : serializeVerifyingKey k ≠ [] := by
    rw [serializeVerifyingKey_eq]
    exact serializeSigningKey_ne_nil _
  generalize hd : serializeVerifyingKey k = data at *
  have h0 : data.drop 0 = encodeUint32 1 k.algorithm.toByte.toUInt32 ++
      (encodeBytes 2 k.publicKey ++ []) := by
    simp [← hd, serializeVerifyingKey]
  have hprog := verifyingKeyStep_progress data
  obtain ⟨p1, l1, hl1, h1, e1⟩ := fieldLoop_optional (hstep := hprog) (pos := 0) (last := 0)
    (f := 1) (s := ({} : VerifyingKeyFields)) (s' := { algorithm := some k.algorithm }) h0
    (by omega) (fun he => absurd he (encodeUint32_u8_ne_nil k.algorithm.toByte_ne_zero))
    (fun _ => verifyingKeyStep_algorithm (by omega) h0)
  obtain ⟨p2, l2, hl2, h2, e2⟩ := fieldLoop_optional (hstep := hprog) (last := l1) (f := 2)
    (s := { algorithm := some k.algorithm })
    (s' := { algorithm := some k.algorithm, publicKey := k.publicKey }) h1 (by omega)
    (fun he => by rw [encodeBytes_eq_nil_iff.mp he])
    (fun he => verifyingKeyStep_publicKey hdata (mt encodeBytes_eq_nil_iff.mpr he) hp
      (by omega) h1)
  have hend : data.length ≤ p2 := by
    have := congrArg List.length h2
    simp at this
    omega
  have hloop := e1.trans (e2.trans (fieldLoop_done hend))
  simp only [deserializeVerifyingKey, throw_eq_error, error_bind, pure_eq_ok, ok_bind,
    List.isEmpty_iff, hne, if_false, hloop, required, validatePublicKey_eq_ok_iff.mpr h]

/-! ## The two key types never share an encoding -/

/-- **No key type confusion.** Bytes that decode as a signing key do not decode as a
verifying key. The CLI's `verify` tries the verifying-key decoder first, so this
means a signing key file is never mistaken for a public key. -/
theorem signing_key_is_not_verifying_key {data : Bytes} {sk : SigningKey} {vk : VerifyingKey}
    (h1 : deserializeSigningKey C data = .ok sk) (h2 : deserializeVerifyingKey C data = .ok vk) :
    False := by
  obtain ⟨e1, v1⟩ := deserializeSigningKey_canonical h1
  obtain ⟨e2, v2⟩ := deserializeVerifyingKey_canonical h2
  obtain ⟨hs, hp⟩ := v1.bounds
  have hvp := v2.bounds
  have heq : sk = ⟨vk.algorithm, vk.publicKey, []⟩ :=
    serializeSigningKey_injective hs hp
      (by simp only [MAX_SECRET_KEY_BYTES, HMAC_MAX_KEY_LEN, MAX_PUBLIC_KEY_BYTES] at *; omega)
      (by simp) (by rw [e1, ← serializeVerifyingKey_eq, e2])
  subst heq
  obtain ⟨a, pk⟩ := vk
  cases a
  · exact v2
  · have := C.ed25519PublicKey_length pk
    simp only [SigningKey.Valid] at v1
    rw [← v1.2] at this
    simp [ED25519_PUBLIC_KEY_LEN] at this
  · have := C.mldsa44PublicKey_length pk
    simp only [SigningKey.Valid] at v1
    rw [← v1.2] at this
    simp [MLDSA44_PUBLIC_KEY_LEN] at this

/-! ## Key API -/

/-- `from_secret_key` only returns keys that pass `validate`. -/
theorem SigningKey.fromSecretKey_valid {a : Algorithm} {secret : Bytes} {k : SigningKey}
    (h : SigningKey.fromSecretKey C a secret = .ok k) : k.Valid C := by
  cases a <;>
    simp [SigningKey.fromSecretKey, Algorithm.isSymmetric, derivePublicKey,
      checkHmacKeyLen_eq_ok_iff, checkSeedLen_eq_ok_iff] at h
  · obtain ⟨⟨h1, h2⟩, rfl⟩ := h
    exact ⟨h1, h2, rfl⟩
  · obtain ⟨h1, rfl⟩ := h
    exact ⟨h1, rfl⟩
  · obtain ⟨h1, rfl⟩ := h
    exact ⟨h1, rfl⟩

/-- The primitive's acceptance check for each algorithm. -/
def Crypto.sigOk (C : Crypto) : Algorithm → (keyMaterial msg sig : Bytes) → Prop
  | .hmacSha256, key, msg, sig => C.hmacSha256 key msg = sig
  | .ed25519, pk, msg, sig => C.ed25519VerifyStrict pk msg sig = true
  | .mlDsa44, pk, msg, sig => C.mldsa44Verify pk msg sig = true

/-- **`VerifyingKey::verify` soundness.** -/
theorem VerifyingKey.verify_sound {k : VerifyingKey} {tb : Bytes} {now : UInt64}
    {vt : VerifiedToken} (h : k.verify C tb now = .ok vt) :
    Accepted C k.algorithm k.publicKey tb now vt (C.sigOk k.algorithm k.publicKey) := by
  obtain ⟨a, pk⟩ := k
  cases a
  · simp [VerifyingKey.verify] at h
  · exact verifyEd25519_sound h
  · exact verifyMldsa44_sound h

/-- The material tokens identify a signing key by. -/
def SigningKey.material (k : SigningKey) : Bytes :=
  if k.algorithm.isSymmetric then k.secretKey else k.publicKey

theorem SigningKey.checkedPublicKey_eq_ok {k : SigningKey} {pk : Bytes}
    (h : k.checkedPublicKey = .ok pk) : pk = k.publicKey := by
  unfold SigningKey.checkedPublicKey at h
  split at h
  · cases h
  · split at h
    · cases h
    · cases h
      rfl

/-- **`SigningKey::verify` soundness.** -/
theorem SigningKey.verify_sound {k : SigningKey} {tb : Bytes} {now : UInt64}
    {vt : VerifiedToken} (h : k.verify C tb now = .ok vt) :
    Accepted C k.algorithm k.material tb now vt (C.sigOk k.algorithm k.material) := by
  obtain ⟨a, s, p⟩ := k
  cases a
  · exact verifyHmac_sound h
  · simp only [SigningKey.verify, bind_eq_ok] at h
    obtain ⟨pk, hpk, h⟩ := h
    rw [SigningKey.checkedPublicKey_eq_ok hpk] at h
    exact verifyEd25519_sound h
  · simp only [SigningKey.verify, bind_eq_ok] at h
    obtain ⟨pk, hpk, h⟩ := h
    rw [SigningKey.checkedPublicKey_eq_ok hpk] at h
    exact verifyMldsa44_sound h

theorem SigningKey.Valid.checkedPublicKey_ed25519 {s p : Bytes}
    (h : SigningKey.Valid C ⟨.ed25519, s, p⟩) :
    SigningKey.checkedPublicKey ⟨.ed25519, s, p⟩ = .ok (C.ed25519PublicKey s) := by
  simp only [SigningKey.Valid] at h
  simp [SigningKey.checkedPublicKey, Algorithm.publicKeyLen, h.2, C.ed25519PublicKey_length]

theorem SigningKey.Valid.checkedPublicKey_mldsa44 {s p : Bytes}
    (h : SigningKey.Valid C ⟨.mlDsa44, s, p⟩) :
    SigningKey.checkedPublicKey ⟨.mlDsa44, s, p⟩ = .ok (C.mldsa44PublicKey s) := by
  simp only [SigningKey.Valid] at h
  simp [SigningKey.checkedPublicKey, Algorithm.publicKeyLen, h.2, C.mldsa44PublicKey_length]

/-- The identifier a valid key puts in its tokens names that key's material. -/
theorem SigningKey.keyIdentifier_matches {k : SigningKey} {t : KeyIdType} {kid : KeyIdentifier}
    (h : k.keyIdentifier C t = .ok kid) : kid.Matches C k.material := by
  obtain ⟨a, s, p⟩ := k
  cases t <;> cases a <;>
    simp only [SigningKey.keyIdentifier, SigningKey.identifyingMaterial, Algorithm.isSymmetric,
      beq_self_eq_true, if_true, bind_eq_ok, pure_eq_ok, Except.ok.injEq,
      show (Algorithm.ed25519 == Algorithm.hmacSha256) = false from rfl,
      show (Algorithm.mlDsa44 == Algorithm.hmacSha256) = false from rfl,
      Bool.false_eq_true, if_false, reduceCtorEq] at h
  · obtain ⟨_, rfl, rfl⟩ := h
    rfl
  all_goals
    obtain ⟨pk, hpk, rfl⟩ := h
    rw [SigningKey.checkedPublicKey_eq_ok hpk]
    rfl

/-- **Sign then verify with the same `SigningKey`.** For a key that passes
`validate`, every token `sign_with_key_id` returns is accepted by `verify` on that
key, at any time inside the claims' window. -/
theorem SigningKey.verify_signWithKeyId (hc : C.Correct) {k : SigningKey} (hk : k.Valid C)
    {c : Claims} {t : KeyIdType} {tb : Bytes} {now : UInt64}
    (hs : k.signWithKeyId C c t = .ok tb) (hu : c.Utf8)
    (h1 : now ≤ c.expiresAt) (h2 : c.notBefore ≤ now) :
    ∃ kid, k.keyIdentifier C t = .ok kid ∧
      k.verify C tb now = .ok ⟨k.algorithm, kid, { c with scopes := sortScopes c.scopes }⟩ := by
  obtain ⟨a, s, p⟩ := k
  cases a
  · simp only [SigningKey.signWithKeyId] at hs
    split at hs
    · rename_i ht
      subst ht
      exact ⟨.keyHash (computeKeyHash C s), rfl, verifyHmac_signHmac hs hu h1 h2⟩
    · cases hs
  · simp only [SigningKey.signWithKeyId, bind_eq_ok] at hs
    obtain ⟨kid, hkid, hs⟩ := hs
    have hm := SigningKey.keyIdentifier_matches hkid
    have hp : p = C.ed25519PublicKey s := hk.2
    simp only [SigningKey.material, Algorithm.isSymmetric,
      show (Algorithm.ed25519 == Algorithm.hmacSha256) = false from rfl, Bool.false_eq_true,
      if_false, hp] at hm
    refine ⟨kid, hkid, ?_⟩
    simp only [SigningKey.verify, hk.checkedPublicKey_ed25519, ok_bind]
    exact verifyEd25519_signEd25519 hc hs hm hu h1 h2
  · simp only [SigningKey.signWithKeyId, bind_eq_ok] at hs
    obtain ⟨kid, hkid, hs⟩ := hs
    have hm := SigningKey.keyIdentifier_matches hkid
    have hp : p = C.mldsa44PublicKey s := hk.2
    simp only [SigningKey.material, Algorithm.isSymmetric,
      show (Algorithm.mlDsa44 == Algorithm.hmacSha256) = false from rfl, Bool.false_eq_true,
      if_false, hp] at hm
    refine ⟨kid, hkid, ?_⟩
    simp only [SigningKey.verify, hk.checkedPublicKey_mldsa44, ok_bind]
    exact verifyMldsa44_signMldsa44 hc hs hm hu h1 h2

/-- **Sign with a `SigningKey`, verify with its `VerifyingKey`.** -/
theorem VerifyingKey.verify_signWithKeyId (hc : C.Correct) {k : SigningKey} (hk : k.Valid C)
    {vk : VerifyingKey} (hvk : k.verifyingKey = .ok vk)
    {c : Claims} {t : KeyIdType} {tb : Bytes} {now : UInt64}
    (hs : k.signWithKeyId C c t = .ok tb) (hu : c.Utf8)
    (h1 : now ≤ c.expiresAt) (h2 : c.notBefore ≤ now) :
    ∃ kid, k.keyIdentifier C t = .ok kid ∧
      vk.verify C tb now = .ok ⟨k.algorithm, kid, { c with scopes := sortScopes c.scopes }⟩ := by
  obtain ⟨kid, hkid, hv⟩ := SigningKey.verify_signWithKeyId hc hk hs hu h1 h2
  refine ⟨kid, hkid, ?_⟩
  simp only [SigningKey.verifyingKey, bind_eq_ok, pure_eq_ok, Except.ok.injEq] at hvk
  obtain ⟨pk, hpk, rfl⟩ := hvk
  obtain ⟨a, s, p⟩ := k
  cases a
  · simp [SigningKey.checkedPublicKey, Algorithm.publicKeyLen] at hpk
  · simpa only [SigningKey.verify, VerifyingKey.verify, hpk, ok_bind] using hv
  · simpa only [SigningKey.verify, VerifyingKey.verify, hpk, ok_bind] using hv

/-- The verifying key of a valid signing key passes `validate`, so it can be
serialized and loaded again. -/
theorem SigningKey.verifyingKey_valid (hc : C.Correct) {k : SigningKey} (hk : k.Valid C)
    {vk : VerifyingKey} (hvk : k.verifyingKey = .ok vk) : vk.Valid C := by
  simp only [SigningKey.verifyingKey, bind_eq_ok, pure_eq_ok, Except.ok.injEq] at hvk
  obtain ⟨pk, hpk, rfl⟩ := hvk
  obtain ⟨a, s, p⟩ := k
  cases a
  · simp [SigningKey.checkedPublicKey, Algorithm.publicKeyLen] at hpk
  · rw [hk.checkedPublicKey_ed25519] at hpk
    cases hpk
    exact ⟨C.ed25519PublicKey_length s, hc.ed25519_point s⟩
  · rw [hk.checkedPublicKey_mldsa44] at hpk
    cases hpk
    exact C.mldsa44PublicKey_length s

end Protoken
