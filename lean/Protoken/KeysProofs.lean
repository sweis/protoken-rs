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
* `VerifyingKey.verify_asymmetric`: a public key is never used as an HMAC secret.
-/

namespace Protoken

variable {C : Crypto}

/-! ## What the constructors check -/

/-- The invariant of a Rust `SigningKey`. -/
def SigningKey.Valid (C : Crypto) (k : SigningKey) : Prop :=
  if k.algorithm.isSymmetric then
    HMAC_MIN_KEY_LEN ≤ k.secretKey.length ∧ k.secretKey.length ≤ HMAC_MAX_KEY_LEN ∧
      k.publicKey = []
  else
    k.secretKey.length = k.algorithm.secretKeyLen ∧
      C.publicKey k.algorithm k.secretKey = some k.publicKey

/-- The invariant of a Rust `VerifyingKey`. It rules out HMAC. -/
def VerifyingKey.Valid (C : Crypto) (k : VerifyingKey) : Prop :=
  k.algorithm.publicKeyLen = some k.publicKey.length ∧
    C.publicKeyValid k.algorithm k.publicKey = true

theorem checkLen_eq_ok_iff {n : Nat} {key : Bytes} : checkLen n key = .ok () ↔ key.length = n := by
  simp [checkLen]

theorem checkPublicKey_eq_ok_iff {a : Algorithm} {pk : Bytes} :
    checkPublicKey C a pk = .ok () ↔ VerifyingKey.Valid C ⟨a, pk⟩ := by
  unfold checkPublicKey VerifyingKey.Valid
  split
  · simp [*]
  · simp only [*, bind_unit_eq_ok, checkLen_eq_ok_iff, throw_eq_error, error_bind, pure_eq_ok,
      ite_error_eq_ok, Option.some.injEq, Bool.not_eq_true', Bool.not_eq_false, and_true]
    rw [eq_comm]

theorem VerifyingKey.Valid.asymmetric {k : VerifyingKey} (h : k.Valid C) :
    k.algorithm.isSymmetric = false := by
  simp [Algorithm.isSymmetric, h.1]

/-- `VerifyingKey::new` accepts exactly the valid keys. -/
theorem VerifyingKey.new_eq_ok_iff {a : Algorithm} {pk : Bytes} {k : VerifyingKey} :
    VerifyingKey.new C a pk = .ok k ↔ k = ⟨a, pk⟩ ∧ k.Valid C := by
  simp only [VerifyingKey.new, bind_unit_eq_ok, checkPublicKey_eq_ok_iff, pure_eq_ok,
    Except.ok.injEq]
  constructor
  · rintro ⟨h, rfl⟩
    exact ⟨rfl, h⟩
  · rintro ⟨rfl, h⟩
    exact ⟨h, rfl⟩

/-- `from_secret_key` returns exactly the valid key with that algorithm and secret. -/
theorem SigningKey.fromSecretKey_eq_ok_iff {a : Algorithm} {secret : Bytes} {k : SigningKey} :
    SigningKey.fromSecretKey C a secret = .ok k ↔
      k.algorithm = a ∧ k.secretKey = secret ∧ k.Valid C := by
  obtain ⟨a', s', p⟩ := k
  simp only [SigningKey.fromSecretKey, bind_eq_ok, exists_unit, schemePublicKey_eq_ok_iff,
    pure_eq_ok, Except.ok.injEq, SigningKey.mk.injEq, SigningKey.Valid, checkSecretKeyLen]
  constructor
  · rintro ⟨h1, pk, h2, rfl, rfl, rfl⟩
    cases hsym : a.isSymmetric <;> simp_all [checkLen_eq_ok_iff]
  · rintro ⟨rfl, rfl, h⟩
    cases hsym : a'.isSymmetric <;> simp_all [checkLen_eq_ok_iff]

theorem SigningKey.Valid.schemePublicKey {k : SigningKey} (h : k.Valid C) :
    schemePublicKey C k.algorithm k.secretKey = .ok k.publicKey := by
  rw [schemePublicKey_eq_ok_iff]
  unfold SigningKey.Valid at h
  split <;> simp_all

theorem SigningKey.Valid.publicKeyLen {k : SigningKey} (h : k.Valid C)
    (hasym : k.algorithm.isSymmetric = false) :
    k.algorithm.publicKeyLen = some k.publicKey.length := by
  simp only [SigningKey.Valid, hasym, Bool.false_eq_true, ite_false] at h
  exact C.publicKey_length _ _ _ h.2

/-- Field sizes of a valid signing key. -/
theorem SigningKey.Valid.bounds {k : SigningKey} (h : k.Valid C) :
    k.secretKey ≠ [] ∧ k.secretKey.length ≤ MAX_SECRET_KEY_BYTES ∧
      k.publicKey.length ≤ MAX_PUBLIC_KEY_BYTES := by
  rw [← List.length_pos_iff]
  cases hsym : k.algorithm.isSymmetric
  · have h1 := k.algorithm.secretKeyLen_bounds
    have h2 := Algorithm.publicKeyLen_bounds (h.publicKeyLen hsym)
    simp only [SigningKey.Valid, hsym, Bool.false_eq_true, ite_false] at h
    omega
  · simp only [SigningKey.Valid, hsym, ite_true, HMAC_MIN_KEY_LEN, HMAC_MAX_KEY_LEN] at h
    simp only [h.2.2, MAX_SECRET_KEY_BYTES, List.length_nil]
    omega

theorem VerifyingKey.Valid.bounds {k : VerifyingKey} (h : k.Valid C) :
    k.publicKey ≠ [] ∧ k.publicKey.length ≤ MAX_PUBLIC_KEY_BYTES := by
  rw [← List.length_pos_iff]
  exact Algorithm.publicKeyLen_bounds h.1

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
the decoded key, and the decoded key is valid. -/
theorem deserializeSigningKey_canonical {data : Bytes} {k : SigningKey}
    (h : deserializeSigningKey C data = .ok k) : serializeSigningKey k = data ∧ k.Valid C := by
  simp only [deserializeSigningKey, throw_eq_error, error_bind, pure_eq_ok,
    ite_error_eq_ok, bind_eq_ok, required_eq_ok, SigningKey.fromSecretKey_eq_ok_iff,
    Except.ok.injEq, ne_eq, Decidable.not_not] at h
  obtain ⟨st, hloop, a, ha, k, ⟨h1, h2, hvalid⟩, h3, rfl⟩ := h
  obtain ⟨pos, last, hpos, hinv⟩ := fieldLoop_invariant (SigningKeyInv data)
    (fun _ _ _ _ _ _ _ hinv hs => signingKeyInv_step hinv hs) data.length 0 0 {} st (by omega)
    ⟨by omega, by simp [optByte32], fun _ => rfl, fun _ => rfl, fun _ => rfl⟩ hloop
  refine ⟨?_, hvalid⟩
  have := hinv.consumed
  rw [List.take_of_length_le hpos, ha] at this
  simp [serializeSigningKey, this, optByte32, h1, h2, h3]

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
      = .ok (pos + (encodeBytes 2 b).length, 2, { st with secretKey := b }) := by
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
      = .ok (pos + (encodeBytes 2 b).length, 2, { st with publicKey := b }) := by
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
  simp only [MAX_SECRET_KEY_BYTES, MAX_PUBLIC_KEY_BYTES] at hs hp
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

/-- **Signing key round trip.** Every valid key decodes to itself. -/
theorem deserializeSigningKey_serialize {k : SigningKey} (h : k.Valid C) :
    deserializeSigningKey C (serializeSigningKey k) = .ok k := by
  obtain ⟨_, hs, hp⟩ := h.bounds
  simp only [deserializeSigningKey, pure_eq_ok, ok_bind, signingKeyLoop_complete hs hp, required,
    SigningKey.fromSecretKey_eq_ok_iff.mpr ⟨rfl, rfl, h⟩, ne_eq, not_true_eq_false, ite_false]

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
of the decoded key, and the decoded key is valid. -/
theorem deserializeVerifyingKey_canonical {data : Bytes} {k : VerifyingKey}
    (h : deserializeVerifyingKey C data = .ok k) :
    serializeVerifyingKey k = data ∧ k.Valid C := by
  simp only [deserializeVerifyingKey, pure_eq_ok, bind_eq_ok, exists_unit, required_eq_ok,
    checkPublicKey_eq_ok_iff, Except.ok.injEq] at h
  obtain ⟨st, hloop, a, ha, hvalid, rfl⟩ := h
  obtain ⟨pos, last, hpos, hinv⟩ := fieldLoop_invariant (VerifyingKeyInv data)
    (fun _ _ _ _ _ _ _ hinv hs => verifyingKeyInv_step hinv hs) data.length 0 0 {} st (by omega)
    ⟨by omega, by simp [optByte32], fun _ => rfl, fun _ => rfl⟩ hloop
  refine ⟨?_, hvalid⟩
  have := hinv.consumed
  rw [List.take_of_length_le hpos, ha] at this
  simp [serializeVerifyingKey, this, optByte32]

theorem serializeVerifyingKey_length_lt {k : VerifyingKey}
    (hp : k.publicKey.length ≤ MAX_PUBLIC_KEY_BYTES) :
    (serializeVerifyingKey k).length < 2 ^ 64 := by
  simp only [MAX_PUBLIC_KEY_BYTES] at hp
  have h1 := encodeUint32_u8_length_le (f := 1) (by omega) k.algorithm.toByte_toNat_lt
  have h2 := encodeBytes_length_le (f := 2) (by omega) (b := k.publicKey) (by omega)
  simp only [serializeVerifyingKey, List.length_append]
  omega

/-- **Verifying key round trip.** Every valid key decodes to itself. -/
theorem deserializeVerifyingKey_serialize {k : VerifyingKey} (h : k.Valid C) :
    deserializeVerifyingKey C (serializeVerifyingKey k) = .ok k := by
  have hp := h.bounds.2
  have hdata := serializeVerifyingKey_length_lt hp
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
  simp only [deserializeVerifyingKey, pure_eq_ok, ok_bind, hloop, required,
    checkPublicKey_eq_ok_iff.mpr h]

/-! ## The two key types never share an encoding -/

/-- **No key type confusion.** Bytes that decode as a signing key do not decode as a
verifying key. The CLI's `verify` tries the verifying-key decoder first, so this
means a signing key file is never mistaken for a public key. -/
theorem signing_key_is_not_verifying_key {data : Bytes} {sk : SigningKey} {vk : VerifyingKey}
    (h1 : deserializeSigningKey C data = .ok sk) (h2 : deserializeVerifyingKey C data = .ok vk) :
    False := by
  obtain ⟨e1, v1⟩ := deserializeSigningKey_canonical h1
  obtain ⟨e2, v2⟩ := deserializeVerifyingKey_canonical h2
  obtain ⟨hsne, hs, _⟩ := v1.bounds
  obtain ⟨hpne, hp⟩ := v2.bounds
  have hdata := e2 ▸ serializeVerifyingKey_length_lt hp
  have hs : sk.secretKey.length ≤ MAX_PUBLIC_KEY_BYTES := Nat.le_trans hs (by decide)
  -- Run the verifying-key loop body over both readings of `data`.
  have d1 : data.drop 0 = encodeUint32 1 sk.algorithm.toByte.toUInt32 ++
      (encodeBytes 2 sk.secretKey ++ encodeBytes 3 sk.publicKey) := by
    simp [← e1, serializeSigningKey]
  have d2 : data.drop 0 = encodeUint32 1 vk.algorithm.toByte.toUInt32 ++
      (encodeBytes 2 vk.publicKey ++ []) := by
    simp [← e2, serializeVerifyingKey]
  have ha := (verifyingKeyStep_algorithm (st := {}) (last := 0) (by omega) d1).symm.trans
    (verifyingKeyStep_algorithm (by omega) d2)
  simp only [Except.ok.injEq, Prod.mk.injEq, VerifyingKeyFields.mk.injEq,
    Option.some.injEq] at ha
  have ha : sk.algorithm = vk.algorithm := ha.2.2.1
  rw [ha] at d1
  have d1 := drop_add_of_drop_eq_append d1
  have d2 := drop_add_of_drop_eq_append d2
  have hk := (verifyingKeyStep_publicKey (st := {}) (last := 1) hdata hsne hs (by omega)
    d1).symm.trans (verifyingKeyStep_publicKey hdata hpne hp (by omega) d2)
  simp only [Except.ok.injEq, Prod.mk.injEq, VerifyingKeyFields.mk.injEq] at hk
  rw [hk.2.2.2, d2] at d1
  -- So the signing key has no public key, yet its algorithm is asymmetric.
  have hnil := encodeBytes_eq_nil_iff.mp (List.append_cancel_left d1).symm
  have := Algorithm.publicKeyLen_bounds (v1.publicKeyLen (ha ▸ v2.asymmetric))
  simp [hnil] at this

/-! ## Key API -/

/-- **`VerifyingKey::verify` soundness.** -/
theorem VerifyingKey.verify_sound {k : VerifyingKey} {tb : Bytes} {now : UInt64}
    {vt : VerifiedToken} (h : k.verify C tb now = .ok vt) :
    Accepted C k.algorithm k.publicKey tb now vt :=
  verifyToken_sound h

/-- **`SigningKey::verify` soundness.** -/
theorem SigningKey.verify_sound {k : SigningKey} {tb : Bytes} {now : UInt64}
    {vt : VerifiedToken} (h : k.verify C tb now = .ok vt) :
    Accepted C k.algorithm k.verifierMaterial tb now vt :=
  verifyToken_sound h

/-- **A public key is never used as an HMAC secret.** A valid verifying key accepts no
HMAC token, and acceptance means the signature scheme's own check passed. -/
theorem VerifyingKey.verify_asymmetric {k : VerifyingKey} (hk : k.Valid C) {tb : Bytes}
    {now : UInt64} {vt : VerifiedToken} (h : k.verify C tb now = .ok vt) :
    vt.algorithm ≠ .hmacSha384 ∧ ∃ sig, tb = vt.signingInput ++ encodeBytes 6 sig ∧
      C.verify k.algorithm k.publicKey vt.signingInput sig = true := by
  have hacc := VerifyingKey.verify_sound h
  have hasym := hk.asymmetric
  obtain ⟨sig, _, htb, hsig⟩ := hacc.signed
  refine ⟨?_, sig, htb, by simpa [schemeVerify, hasym] using hsig⟩
  rw [hacc.algorithm_eq, ne_eq, ← Algorithm.isSymmetric_iff, hasym]
  simp

/-- The identifier a valid key puts in its tokens names that key's material and has
the length the decoder requires. -/
theorem SigningKey.keyIdentifier_sound {k : SigningKey} (hk : k.Valid C) {t : KeyIdType}
    {kid : KeyIdentifier} (h : k.keyIdentifier C t = .ok kid) :
    kid.Matches C k.verifierMaterial ∧
      ∀ pk, kid = .publicKey pk → k.algorithm.publicKeyLen = some pk.length := by
  cases t <;> simp only [SigningKey.keyIdentifier] at h
  · cases h
    exact ⟨rfl, by simp⟩
  · split at h <;> cases h
    rename_i hsym
    refine ⟨by simp [KeyIdentifier.Matches, SigningKey.verifierMaterial, hsym], ?_⟩
    rintro pk ⟨rfl⟩
    exact hk.publicKeyLen (by simpa using hsym)

/-- **Sign then verify with the same `SigningKey`.** For a valid key, every token
`sign_with_key_id` returns is accepted by `verify` on that key, at any time inside
the claims' window. -/
theorem SigningKey.verify_signWithKeyId (hc : C.Correct) {k : SigningKey} (hk : k.Valid C)
    {c : Claims} {t : KeyIdType} {tb : Bytes} {now : UInt64}
    (hs : k.signWithKeyId C c t = .ok tb) (hu : c.Utf8)
    (h1 : now ≤ c.expiresAt) (h2 : c.notBefore ≤ now) :
    ∃ kid, k.keyIdentifier C t = .ok kid ∧
      k.verify C tb now = .ok ⟨k.algorithm, kid, { c with scopes := sortScopes c.scopes }⟩ := by
  simp only [SigningKey.signWithKeyId, bind_eq_ok] at hs
  obtain ⟨kid, hkid, hs⟩ := hs
  obtain ⟨hm, hlen⟩ := SigningKey.keyIdentifier_sound hk hkid
  exact ⟨kid, hkid, verifyToken_signToken hs hm hlen
    (fun _ _ => schemeVerify_schemeSign hc hk.schemePublicKey) hu h1 h2⟩

/-- **Sign with a `SigningKey`, verify with its `VerifyingKey`.** -/
theorem VerifyingKey.verify_signWithKeyId (hc : C.Correct) {k : SigningKey} (hk : k.Valid C)
    {vk : VerifyingKey} (hvk : k.verifyingKey C = .ok vk)
    {c : Claims} {t : KeyIdType} {tb : Bytes} {now : UInt64}
    (hs : k.signWithKeyId C c t = .ok tb) (hu : c.Utf8)
    (h1 : now ≤ c.expiresAt) (h2 : c.notBefore ≤ now) :
    ∃ kid, k.keyIdentifier C t = .ok kid ∧
      vk.verify C tb now = .ok ⟨k.algorithm, kid, { c with scopes := sortScopes c.scopes }⟩ := by
  obtain ⟨kid, hkid, hv⟩ := SigningKey.verify_signWithKeyId hc hk hs hu h1 h2
  obtain ⟨rfl, hvalid⟩ := VerifyingKey.new_eq_ok_iff.mp hvk
  have hasym : k.algorithm.isSymmetric = false := hvalid.asymmetric
  exact ⟨kid, hkid, by
    simpa [SigningKey.verify, SigningKey.verifierMaterial, hasym, VerifyingKey.verify] using hv⟩

/-- Every valid asymmetric signing key has a verifying key. -/
theorem SigningKey.verifyingKey_complete (hc : C.Correct) {k : SigningKey} (hk : k.Valid C)
    (hasym : k.algorithm.isSymmetric = false) :
    k.verifyingKey C = .ok ⟨k.algorithm, k.publicKey⟩ := by
  refine VerifyingKey.new_eq_ok_iff.mpr ⟨rfl, hk.publicKeyLen hasym, ?_⟩
  simp only [SigningKey.Valid, hasym, Bool.false_eq_true, ite_false] at hk
  exact hc.publicKey_valid _ _ _ hk.2

end Protoken
