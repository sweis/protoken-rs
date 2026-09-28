import Protoken.Serialize

/-!
# SignedToken: canonical encoding, signed prefix, and round trip

* `deserializeSignedTokenAt_canonical`: accepted bytes are exactly
  `serializeSignedToken` of the decoded token, and the first `signedLen` bytes are
  exactly `serializeSigningInput` of its fields (design guideline 9).
* `deserializeSignedTokenAt_serialize`: encoding then decoding returns the token.
* `serializeSigningInput_injective`: the signed bytes determine the algorithm, the
  key identifier, and the payload.
-/

namespace Protoken

/-- The structural rules for a token that the decoder accepts. -/
structure SignedToken.WireValid (t : SignedToken) : Prop where
  /-- An embedded public key has the length the algorithm requires. HMAC has none. -/
  key_id : ∀ pk, t.keyIdentifier = .publicKey pk → t.algorithm.publicKeyLen = some pk.length
  payload_ne : t.payload ≠ []
  payload_len : t.payload.length ≤ MAX_PAYLOAD_BYTES
  signature_ne : t.signature ≠ []
  signature_len : t.signature.length ≤ MAX_SIGNATURE_BYTES

/-! ## Soundness -/

def optByte32 {α : Type} (toByte : α → UInt8) : Option α → UInt32
  | some a => (toByte a).toUInt32
  | none => 0

/-- Encoding of the fields covered by the signature, from the decoder's local variables. -/
def TokenFields.signedBytes (st : TokenFields) : Bytes :=
  encodeUint32 2 (optByte32 Algorithm.toByte st.algorithm) ++
    encodeUint32 3 (optByte32 KeyIdType.toByte st.keyIdType) ++
    encodeBytes 4 st.keyId ++ encodeBytes 5 (st.payload.getD [])

/-- The invariant of the SignedToken decoding loop. -/
structure TokenInv (data : Bytes) (pos last : Nat) (st : TokenFields) : Prop where
  pos_le : pos ≤ data.length
  /-- The consumed bytes are the encoding of the fields decoded so far. -/
  consumed : data.take pos = st.signedBytes ++ encodeBytes 6 ((st.signature.map (·.1)).getD [])
  /-- Fields after the last one seen are still unset. -/
  d2 : last < 2 → st.algorithm = none
  d3 : last < 3 → st.keyIdType = none
  d4 : last < 4 → st.keyId = []
  d5 : last < 5 → st.payload = none
  d6 : last < 6 → st.signature = none
  key_id_len : st.keyId.length ≤ MLDSA44_PUBLIC_KEY_LEN
  payload_ok : ∀ p, st.payload = some p → p ≠ [] ∧ p.length ≤ MAX_PAYLOAD_BYTES
  /-- The recorded offset is where the signed fields end. -/
  signature_ok : ∀ sig start, st.signature = some (sig, start) →
    sig ≠ [] ∧ sig.length ≤ MAX_SIGNATURE_BYTES ∧ data.take start = st.signedBytes

theorem tokenInv_init (data : Bytes) : TokenInv data 0 0 {} where
  pos_le := by omega
  consumed := by simp [TokenFields.signedBytes, optByte32]
  d2 := fun _ => rfl
  d3 := fun _ => rfl
  d4 := fun _ => rfl
  d5 := fun _ => rfl
  d6 := fun _ => rfl
  key_id_len := by simp
  payload_ok := by simp
  signature_ok := by simp

theorem tokenInv_step {data : Bytes} {pos last pos' last' : Nat} {st st' : TokenFields}
    (hinv : TokenInv data pos last st)
    (h : tokenStep data pos last st = .ok (pos', last', st')) :
    TokenInv data pos' last' st' := by
  obtain ⟨_, hle, hord, hcase⟩ := tokenStep_sound h
  obtain ⟨_, hcons, d2, d3, d4, d5, d6, hk, hp, hs⟩ := hinv
  rcases hcase with ⟨rfl, a, rfl, htake⟩ | ⟨rfl, t, rfl, htake⟩ | ⟨rfl, b, _, hlen, rfl, htake⟩ |
    ⟨rfl, b, hne, hlen, rfl, htake⟩ | ⟨rfl, b, hne, hlen, rfl, htake⟩
  · refine ⟨hle, ?_, by omega, fun _ => d3 (by omega), fun _ => d4 (by omega),
      fun _ => d5 (by omega), fun _ => d6 (by omega), hk, hp, ?_⟩
    · rw [htake, hcons]
      simp [TokenFields.signedBytes, optByte32, d2 (by omega), d3 (by omega), d4 (by omega),
        d5 (by omega), d6 (by omega)]
    · simp [d6 (by omega)]
  · refine ⟨hle, ?_, by omega, by omega, fun _ => d4 (by omega),
      fun _ => d5 (by omega), fun _ => d6 (by omega), hk, hp, ?_⟩
    · rw [htake, hcons]
      simp [TokenFields.signedBytes, optByte32, d3 (by omega), d4 (by omega),
        d5 (by omega), d6 (by omega)]
    · simp [d6 (by omega)]
  · refine ⟨hle, ?_, by omega, by omega, by omega,
      fun _ => d5 (by omega), fun _ => d6 (by omega), hlen, hp, ?_⟩
    · rw [htake, hcons]
      simp [TokenFields.signedBytes, d4 (by omega), d5 (by omega), d6 (by omega)]
    · simp [d6 (by omega)]
  · refine ⟨hle, ?_, by omega, by omega, by omega, by omega, fun _ => d6 (by omega), hk, ?_, ?_⟩
    · rw [htake, hcons]
      simp [TokenFields.signedBytes, d5 (by omega), d6 (by omega)]
    · intro p hp'
      simp only [Option.some.injEq] at hp'
      subst hp'
      exact ⟨hne, hlen⟩
    · simp [d6 (by omega)]
  · refine ⟨hle, ?_, by omega, by omega, by omega, by omega, by omega, hk, hp, ?_⟩
    · rw [htake, hcons]
      simp [TokenFields.signedBytes, d6 (by omega)]
    · intro sig start hsig
      simp only [Option.some.injEq, Prod.mk.injEq] at hsig
      obtain ⟨rfl, rfl⟩ := hsig
      refine ⟨hne, hlen, ?_⟩
      rw [hcons]
      simp [TokenFields.signedBytes, d6 (by omega)]

theorem required_eq_ok {α : Type} {o : Option α} {a : α} : required o = .ok a ↔ o = some a := by
  cases o <;> simp [required]

theorem keyIdentifierFromWire_sound {a : Algorithm} {t : KeyIdType} {keyId : Bytes}
    {k : KeyIdentifier} (h : keyIdentifierFromWire a t keyId = .ok k) :
    k.keyIdType = t ∧ k.asBytes = keyId ∧
      ∀ pk, k = .publicKey pk → a.publicKeyLen = some pk.length := by
  unfold keyIdentifierFromWire at h
  split at h
  · split at h
    · cases h
      exact ⟨rfl, rfl, by simp⟩
    · cases h
  · split at h
    · cases h
    · rename_i expected hexp
      split at h
      · cases h
      · rename_i hlen
        cases h
        refine ⟨rfl, rfl, ?_⟩
        intro pk hpk
        cases hpk
        rw [hexp]
        simp only [ne_eq, Decidable.not_not] at hlen
        rw [hlen]

/-- **Canonical tokens and the signed prefix.** If the decoder accepts `data`:
* `data` is exactly `serializeSignedToken` of the decoded token, and
* the first `signedLen` bytes of `data` are exactly the signing input built from
  the decoded version, algorithm, key identifier, and payload. -/
theorem deserializeSignedTokenAt_canonical {data : Bytes} {t : SignedToken} {signedLen : Nat}
    (h : deserializeSignedTokenAt data = .ok (t, signedLen)) :
    serializeSignedToken t = data ∧
      data.take signedLen
        = serializeSigningInput t.version t.algorithm t.keyIdentifier t.payload ∧
      t.WireValid := by
  simp only [deserializeSignedTokenAt, throw_eq_error, error_bind, pure_eq_ok, ok_bind,
    ite_error_eq_ok, bind_eq_ok, required_eq_ok, Prod.exists, Except.ok.injEq,
    Prod.mk.injEq] at h
  obtain ⟨_, _, st, hloop, a, ha, kt, hkt, k, hk, p, hp, sig, start, hsig, rfl, rfl⟩ := h
  obtain ⟨pos, last, hpos, hinv⟩ := fieldLoop_invariant (TokenInv data)
    (fun _ _ _ _ _ _ _ hinv hs => tokenInv_step hinv hs) data.length 0 0 {} st (by omega)
    (tokenInv_init data) hloop
  obtain ⟨hk1, hk2, hk3⟩ := keyIdentifierFromWire_sound hk
  obtain ⟨hs1, hs2, hs3⟩ := hinv.signature_ok sig start hsig
  obtain ⟨hp1, hp2⟩ := hinv.payload_ok p hp
  have hsigned : st.signedBytes = serializeSigningInput .v0 a k p := by
    simp [TokenFields.signedBytes, serializeSigningInput, optByte32, ha, hkt, hp, hk1, hk2,
      Version.toByte]
  refine ⟨?_, ?_, ⟨hk3, hp1, hp2, hs1, hs2⟩⟩
  · have := hinv.consumed
    rw [List.take_of_length_le hpos, hsigned, hsig] at this
    simp [serializeSignedToken, appendSignature, this]
  · rw [hs3, hsigned]

/-- Two accepted encodings of the same token are the same bytes. -/
theorem deserializeSignedTokenAt_injective {d1 d2 : Bytes} {t : SignedToken} {n1 n2 : Nat}
    (h1 : deserializeSignedTokenAt d1 = .ok (t, n1))
    (h2 : deserializeSignedTokenAt d2 = .ok (t, n2)) : d1 = d2 := by
  rw [← (deserializeSignedTokenAt_canonical h1).1, ← (deserializeSignedTokenAt_canonical h2).1]

/-! ## Completeness -/

section Complete

variable {data : Bytes} {pos last : Nat} {st : TokenFields} {rest : Bytes}

theorem tokenStep_algorithm {a : Algorithm} (hlast : last < 2)
    (h : data.drop pos = encodeUint32 2 a.toByte.toUInt32 ++ rest) :
    tokenStep data pos last st
      = .ok (pos + (encodeUint32 2 a.toByte.toUInt32).length, 2,
          { st with algorithm := some a }) := by
  rw [encodeUint32_u8 a.toByte_ne_zero, List.append_assoc] at h
  have h1 := nextField_complete (repeated := none) (last := last) (by omega)
    (by simp [WIRE_VARINT]) (.inl hlast) h
  have h2 := readAlgorithm_complete (drop_add_of_drop_eq_append h)
  simp only [WIRE_VARINT] at h1 h2
  simp [tokenStep, h1, h2, encodeUint32_u8 a.toByte_ne_zero, WIRE_VARINT, Nat.add_assoc]

theorem tokenStep_keyIdType {t : KeyIdType} (hlast : last < 3)
    (h : data.drop pos = encodeUint32 3 t.toByte.toUInt32 ++ rest) :
    tokenStep data pos last st
      = .ok (pos + (encodeUint32 3 t.toByte.toUInt32).length, 3,
          { st with keyIdType := some t }) := by
  rw [encodeUint32_u8 t.toByte_ne_zero, List.append_assoc] at h
  have h1 := nextField_complete (repeated := none) (last := last) (by omega)
    (by simp [WIRE_VARINT]) (.inl hlast) h
  have h2 := readNonzeroU8_complete t.toByte_ne_zero (drop_add_of_drop_eq_append h)
  simp only [WIRE_VARINT] at h1 h2
  simp [tokenStep, h1, h2, encodeUint32_u8 t.toByte_ne_zero, WIRE_VARINT, Nat.add_assoc]

theorem tokenStep_keyId {b : Bytes} (hdata : data.length < 2 ^ 64) (hne : b ≠ [])
    (hle : b.length ≤ MLDSA44_PUBLIC_KEY_LEN) (hlast : last < 4)
    (h : data.drop pos = encodeBytes 4 b ++ rest) :
    tokenStep data pos last st
      = .ok (pos + (encodeBytes 4 b).length, 4, { st with keyId := b }) := by
  rw [encodeBytes_of_ne hne, List.append_assoc, List.append_assoc] at h
  have h1 := nextField_complete (repeated := none) (last := last) (by omega)
    (by simp [WIRE_LEN]) (.inl hlast) h
  have h2 := readBoundedBytes_complete hdata hne hle
    (by rw [drop_add_of_drop_eq_append h, List.append_assoc])
  simp only [WIRE_LEN] at h1 h2
  simp [tokenStep, h1, h2, encodeBytes_of_ne hne, WIRE_LEN, Nat.add_assoc]

theorem tokenStep_payload {b : Bytes} (hdata : data.length < 2 ^ 64) (hne : b ≠ [])
    (hle : b.length ≤ MAX_PAYLOAD_BYTES) (hlast : last < 5)
    (h : data.drop pos = encodeBytes 5 b ++ rest) :
    tokenStep data pos last st
      = .ok (pos + (encodeBytes 5 b).length, 5, { st with payload := some b }) := by
  rw [encodeBytes_of_ne hne, List.append_assoc, List.append_assoc] at h
  have h1 := nextField_complete (repeated := none) (last := last) (by omega)
    (by simp [WIRE_LEN]) (.inl hlast) h
  have h2 := readBoundedBytes_complete hdata hne hle
    (by rw [drop_add_of_drop_eq_append h, List.append_assoc])
  simp only [WIRE_LEN] at h1 h2
  simp [tokenStep, h1, h2, encodeBytes_of_ne hne, WIRE_LEN, Nat.add_assoc]

theorem tokenStep_signature {b : Bytes} (hdata : data.length < 2 ^ 64) (hne : b ≠ [])
    (hle : b.length ≤ MAX_SIGNATURE_BYTES) (hlast : last < 6)
    (h : data.drop pos = encodeBytes 6 b ++ rest) :
    tokenStep data pos last st
      = .ok (pos + (encodeBytes 6 b).length, 6, { st with signature := some (b, pos) }) := by
  rw [encodeBytes_of_ne hne, List.append_assoc, List.append_assoc] at h
  have h1 := nextField_complete (repeated := none) (last := last) (by omega)
    (by simp [WIRE_LEN]) (.inl hlast) h
  have h2 := readBoundedBytes_complete hdata hne hle
    (by rw [drop_add_of_drop_eq_append h, List.append_assoc])
  simp only [WIRE_LEN] at h1 h2
  simp [tokenStep, h1, h2, encodeBytes_of_ne hne, WIRE_LEN, Nat.add_assoc]

end Complete

theorem Algorithm.toByte_toNat_lt (a : Algorithm) : a.toByte.toNat < 128 := by
  cases a <;> decide

theorem KeyIdType.toByte_toNat_lt (t : KeyIdType) : t.toByte.toNat < 128 := by
  cases t <;> decide

theorem SignedToken.WireValid.keyId_bounds {t : SignedToken} (hw : t.WireValid) :
    t.keyIdentifier.asBytes ≠ [] ∧ t.keyIdentifier.asBytes.length ≤ MLDSA44_PUBLIC_KEY_LEN := by
  cases hk : t.keyIdentifier with
  | keyHash hash =>
    have := hash.property
    simp only [KeyIdentifier.asBytes]
    refine ⟨?_, by simp only [KEY_HASH_LEN, MLDSA44_PUBLIC_KEY_LEN] at *; omega⟩
    intro h
    rw [h] at this
    simp [KEY_HASH_LEN] at this
  | publicKey pk =>
    have := hw.key_id pk hk
    simp only [KeyIdentifier.asBytes]
    cases ha : t.algorithm <;>
      simp [ha, Algorithm.publicKeyLen, ED25519_PUBLIC_KEY_LEN, MLDSA44_PUBLIC_KEY_LEN] at this ⊢
    all_goals
      refine ⟨?_, by omega⟩
      intro h
      rw [h] at this
      simp at this

/-- The largest well-formed token fits in `MAX_SIGNED_TOKEN_BYTES`. -/
theorem serializeSignedToken_length_le {t : SignedToken} (hw : t.WireValid) :
    (serializeSignedToken t).length ≤ MAX_SIGNED_TOKEN_BYTES := by
  obtain ⟨_, hk⟩ := hw.keyId_bounds
  have hp := hw.payload_len
  have hs := hw.signature_len
  simp only [MLDSA44_PUBLIC_KEY_LEN, MAX_PAYLOAD_BYTES, MAX_SIGNATURE_BYTES,
    MAX_SIGNED_TOKEN_BYTES] at *
  have h2 := encodeUint32_u8_length_le (f := 2) (by omega) t.algorithm.toByte_toNat_lt
  have h3 := encodeUint32_u8_length_le (f := 3) (by omega) t.keyIdentifier.keyIdType.toByte_toNat_lt
  have h4 := encodeBytes_length_le (f := 4) (by omega) (b := t.keyIdentifier.asBytes) (by omega)
  have h5 := encodeBytes_length_le (f := 5) (by omega) (b := t.payload) (by omega)
  have h6 := encodeBytes_length_le (f := 6) (by omega) (b := t.signature) (by omega)
  cases hver : t.version
  simp only [serializeSignedToken, appendSignature, serializeSigningInput, Version.toByte,
    List.length_append]
  simp
  omega

theorem keyIdentifierFromWire_complete {a : Algorithm} {k : KeyIdentifier}
    (h : ∀ pk, k = .publicKey pk → a.publicKeyLen = some pk.length) :
    keyIdentifierFromWire a k.keyIdType k.asBytes = .ok k := by
  cases k with
  | keyHash hash => simp [keyIdentifierFromWire, KeyIdentifier.keyIdType, KeyIdentifier.asBytes,
      hash.property]
  | publicKey pk =>
    simp [keyIdentifierFromWire, KeyIdentifier.keyIdType, KeyIdentifier.asBytes, h pk rfl]

/-- **Token round trip.** A well-formed token decodes to itself, and the reported
signed length is the length of its signing input. -/
theorem deserializeSignedTokenAt_serialize {t : SignedToken} (hw : t.WireValid) :
    deserializeSignedTokenAt (serializeSignedToken t)
      = .ok (t, (serializeSigningInput t.version t.algorithm t.keyIdentifier t.payload).length) := by
  obtain ⟨version, a, k, p, sig⟩ := t
  cases version
  have hsize := serializeSignedToken_length_le hw
  obtain ⟨hkne, hklen⟩ := hw.keyId_bounds
  simp only at hkne hklen
  generalize hd : serializeSignedToken ⟨.v0, a, k, p, sig⟩ = data at *
  have hdata : data.length < 2 ^ 64 := by
    simp only [MAX_SIGNED_TOKEN_BYTES, MAX_PAYLOAD_BYTES, MAX_SIGNATURE_BYTES,
      MLDSA44_PUBLIC_KEY_LEN] at hsize
    omega
  have hsplit : data = serializeSigningInput .v0 a k p ++ encodeBytes 6 sig := by
    simp [← hd, serializeSignedToken, appendSignature]
  have h0 : data.drop 0 = encodeUint32 2 a.toByte.toUInt32 ++
      (encodeUint32 3 k.keyIdType.toByte.toUInt32 ++ (encodeBytes 4 k.asBytes ++
      (encodeBytes 5 p ++ (encodeBytes 6 sig ++ [])))) := by
    simp [hsplit, serializeSigningInput, Version.toByte]
  have hp := tokenStep_progress data
  have hnil32 : ∀ {f : Nat} {b : UInt8}, b ≠ 0 → encodeUint32 f b.toUInt32 ≠ [] := by
    intro f b hb h
    rw [encodeUint32_u8 hb] at h
    have h1 := congrArg List.length h
    have h2 := encodeVarint_length_pos b.toUInt64
    simp only [List.length_append, List.length_nil] at h1
    omega
  obtain ⟨p1, l1, hl1, h1, e1⟩ := fieldLoop_optional (hstep := hp) (pos := 0) (last := 0) (f := 2)
    (s := ({} : TokenFields)) (s' := { algorithm := some a }) h0 (by omega)
    (fun he => absurd he (hnil32 a.toByte_ne_zero))
    (fun _ => tokenStep_algorithm (by omega) h0)
  obtain ⟨p2, l2, hl2, h2, e2⟩ := fieldLoop_optional (hstep := hp) (last := l1) (f := 3)
    (s := { algorithm := some a })
    (s' := { algorithm := some a, keyIdType := some k.keyIdType }) h1 (by omega)
    (fun he => absurd he (hnil32 k.keyIdType.toByte_ne_zero))
    (fun _ => tokenStep_keyIdType (by omega) h1)
  obtain ⟨p3, l3, hl3, h3, e3⟩ := fieldLoop_optional (hstep := hp) (last := l2) (f := 4)
    (s := { algorithm := some a, keyIdType := some k.keyIdType })
    (s' := { algorithm := some a, keyIdType := some k.keyIdType, keyId := k.asBytes })
    h2 (by omega) (fun he => absurd (encodeBytes_eq_nil_iff.mp he) hkne)
    (fun _ => tokenStep_keyId hdata hkne hklen (by omega) h2)
  obtain ⟨p4, l4, hl4, h4, e4⟩ := fieldLoop_optional (hstep := hp) (last := l3) (f := 5)
    (s := { algorithm := some a, keyIdType := some k.keyIdType, keyId := k.asBytes })
    (s' := { algorithm := some a, keyIdType := some k.keyIdType, keyId := k.asBytes,
             payload := some p })
    h3 (by omega) (fun he => absurd (encodeBytes_eq_nil_iff.mp he) hw.payload_ne)
    (fun _ => tokenStep_payload hdata hw.payload_ne hw.payload_len (by omega) h3)
  obtain ⟨p5, l5, hl5, h5, e5⟩ := fieldLoop_optional (hstep := hp) (last := l4) (f := 6)
    (s := { algorithm := some a, keyIdType := some k.keyIdType, keyId := k.asBytes,
            payload := some p })
    (s' := { algorithm := some a, keyIdType := some k.keyIdType, keyId := k.asBytes,
             payload := some p, signature := some (sig, p4) })
    h4 (by omega) (fun he => absurd (encodeBytes_eq_nil_iff.mp he) hw.signature_ne)
    (fun _ => tokenStep_signature hdata hw.signature_ne hw.signature_len (by omega) h4)
  have hend : data.length ≤ p5 := by
    have := congrArg List.length h5
    simp at this
    omega
  -- The signature field starts where the signing input ends.
  have hstart : p4 = (serializeSigningInput .v0 a k p).length := by
    have hsigne : (encodeBytes 6 sig).length ≠ 0 := by
      intro h
      exact hw.signature_ne (encodeBytes_eq_nil_iff.mp (List.length_eq_zero_iff.mp h))
    have h1 := congrArg List.length h4
    have h2 := congrArg List.length hsplit
    simp only [List.length_drop, List.length_append, List.length_nil] at h1 h2
    omega
  have hne : data ≠ [] := by
    intro h
    rw [h] at hsplit
    exact hw.signature_ne (encodeBytes_eq_nil_iff.mp (List.append_eq_nil_iff.mp hsplit.symm).2)
  have hsize' : ¬ data.length > MAX_SIGNED_TOKEN_BYTES := by omega
  have hloop := e1.trans (e2.trans (e3.trans (e4.trans (e5.trans (fieldLoop_done hend)))))
  simp only [deserializeSignedTokenAt, throw_eq_error, error_bind, pure_eq_ok, ok_bind,
    List.isEmpty_iff, hne, hsize', if_false, hloop, required,
    keyIdentifierFromWire_complete hw.key_id]
  rw [hstart]

/-! ## The signing input determines what was signed -/

/-- **Injective signing input.** If two signing inputs are equal, they were built
from the same algorithm, key identifier, and payload. A signature over one
`(algorithm, key identifier, payload)` triple is never a signature over another,
which rules out algorithm confusion and key substitution at the encoding level. -/
theorem serializeSigningInput_injective {a a' : Algorithm} {k k' : KeyIdentifier}
    {p p' : Bytes}
    (hk : ∀ pk, k = .publicKey pk → a.publicKeyLen = some pk.length)
    (hk' : ∀ pk, k' = .publicKey pk → a'.publicKeyLen = some pk.length)
    (hp : p ≠ [] ∧ p.length ≤ MAX_PAYLOAD_BYTES) (hp' : p' ≠ [] ∧ p'.length ≤ MAX_PAYLOAD_BYTES)
    (h : serializeSigningInput .v0 a k p = serializeSigningInput .v0 a' k' p') :
    a = a' ∧ k = k' ∧ p = p' := by
  -- Complete both to tokens with the same dummy signature and decode them.
  have hw : SignedToken.WireValid ⟨.v0, a, k, p, [0]⟩ :=
    ⟨hk, hp.1, hp.2, by simp, by simp [MAX_SIGNATURE_BYTES]⟩
  have hw' : SignedToken.WireValid ⟨.v0, a', k', p', [0]⟩ :=
    ⟨hk', hp'.1, hp'.2, by simp, by simp [MAX_SIGNATURE_BYTES]⟩
  have h1 := deserializeSignedTokenAt_serialize hw
  have h2 := deserializeSignedTokenAt_serialize hw'
  have heq : serializeSignedToken ⟨.v0, a, k, p, [0]⟩ = serializeSignedToken ⟨.v0, a', k', p', [0]⟩ := by
    simp only [serializeSignedToken, h]
  rw [heq, h2] at h1
  simp only [Except.ok.injEq, Prod.mk.injEq, SignedToken.mk.injEq] at h1
  exact ⟨h1.1.2.1.symm, h1.1.2.2.1.symm, h1.1.2.2.2.1.symm⟩

end Protoken
