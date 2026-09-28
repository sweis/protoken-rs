import Protoken.Varint

/-!
# Proto3 wire helpers

Model of the rest of `src/proto3.rs`: tags, field encoders, and the readers that
the message decoders are built from.

Each reader has two lemmas.
* `_sound`: if it accepts, the bytes it consumed are the canonical encoding of
  what it returned. Stated as `data.take pos' = data.take pos ++ encoding`.
* `_complete`: if the unread input `data.drop pos` starts with a canonical
  encoding, it accepts and returns the encoded value.

Positions, lengths, and field numbers are natural numbers. Where Rust checks that
a value fits a machine type, the model has the same check.
-/

namespace Protoken

/-! ## Model -/

def WIRE_VARINT : Nat := 0
def WIRE_LEN : Nat := 2

/-- Models `encode_tag`. -/
def encodeTag (fieldNumber wireType : Nat) : Bytes :=
  encodeVarint ((UInt64.ofNat fieldNumber <<< 3) ||| UInt64.ofNat wireType)

/-- Models `encode_uint32`. -/
def encodeUint32 (field : Nat) (value : UInt32) : Bytes :=
  if value == 0 then [] else encodeTag field WIRE_VARINT ++ encodeVarint value.toUInt64

/-- Models `encode_uint64`. -/
def encodeUint64 (field : Nat) (value : UInt64) : Bytes :=
  if value == 0 then [] else encodeTag field WIRE_VARINT ++ encodeVarint value

/-- Models `encode_bytes`. -/
def encodeBytes (field : Nat) (value : Bytes) : Bytes :=
  if value.isEmpty then []
  else encodeTag field WIRE_LEN ++ encodeVarint (UInt64.ofNat value.length) ++ value

/-- Models `decode_tag`. Returns `(field_number, wire_type, pos)`. -/
def decodeTag (data : Bytes) (pos : Nat) : Result (Nat × Nat × Nat) := do
  let (tag, pos) ← decodeVarint data pos
  let wireType := (tag &&& 0x07).toNat
  let fieldNumber := (tag >>> 3).toNat
  if fieldNumber == 0 then
    throw .malformedEncoding
  -- `u32::try_from`
  if fieldNumber ≥ 2 ^ 32 then
    throw .malformedEncoding
  pure (fieldNumber, wireType, pos)

/-- Models `read_u8_value`. -/
def readU8Value (data : Bytes) (pos : Nat) : Result (UInt8 × Nat) := do
  let (v, pos) ← decodeVarint data pos
  -- `u8::try_from`
  if v.toNat ≥ 2 ^ 8 then
    throw .malformedEncoding
  pure (v.toUInt8, pos)

/-- Models `read_bytes_value`. `usize` is taken to be 64 bits. On a 32-bit target
`usize::try_from` can fail where this model continues, but then the length
exceeds `data.len()`, so both return the same error. -/
def readBytesValue (data : Bytes) (pos : Nat) : Result (Bytes × Nat) := do
  let (len64, pos) ← decodeVarint data pos
  let len := len64.toNat
  -- `checked_add`
  if pos + len ≥ 2 ^ 64 then
    throw .malformedEncoding
  if pos + len > data.length then
    throw .malformedEncoding
  pure ((data.drop pos).take len, pos + len)

/-- Models `read_nonzero_varint`. -/
def readNonzeroVarint (data : Bytes) (pos : Nat) : Result (UInt64 × Nat) := do
  let (v, pos) ← decodeVarint data pos
  if v == 0 then
    throw .malformedEncoding
  pure (v, pos)

/-- Models `read_nonzero_u8`. -/
def readNonzeroU8 (data : Bytes) (pos : Nat) : Result (UInt8 × Nat) := do
  let (v, pos) ← readU8Value data pos
  if v == 0 then
    throw .malformedEncoding
  pure (v, pos)

/-- Models `next_field`. Returns `(field_number, wire_type, pos)`. The Rust
function also stores `field_number` into `last_field_number`; callers of this
model do that themselves. -/
def nextField (data : Bytes) (pos lastFieldNumber : Nat) (repeated : Option Nat) :
    Result (Nat × Nat × Nat) := do
  let (fieldNumber, wireType, pos) ← decodeTag data pos
  let isRepeat := fieldNumber == lastFieldNumber
  if fieldNumber < lastFieldNumber || (isRepeat && repeated != some fieldNumber) then
    throw .malformedEncoding
  pure (fieldNumber, wireType, pos)

/-- Models `read_bounded_bytes`. -/
def readBoundedBytes (data : Bytes) (pos maxLen : Nat) : Result (Bytes × Nat) := do
  let (bytes, pos) ← readBytesValue data pos
  if bytes.isEmpty then
    throw .malformedEncoding
  if bytes.length > maxLen then
    throw .malformedEncoding
  pure (bytes, pos)

/-! ## Encoders -/

theorem encodeUint64_of_ne {field : Nat} {value : UInt64} (h : value ≠ 0) :
    encodeUint64 field value = encodeTag field WIRE_VARINT ++ encodeVarint value := by
  simp [encodeUint64, h]

@[simp] theorem encodeUint64_zero (field : Nat) : encodeUint64 field 0 = [] := by
  simp [encodeUint64]

theorem encodeUint32_of_ne {field : Nat} {value : UInt32} (h : value ≠ 0) :
    encodeUint32 field value = encodeTag field WIRE_VARINT ++ encodeVarint value.toUInt64 := by
  simp [encodeUint32, h]

@[simp] theorem encodeUint32_zero (field : Nat) : encodeUint32 field 0 = [] := by
  simp [encodeUint32]

theorem encodeBytes_of_ne {field : Nat} {value : Bytes} (h : value ≠ []) :
    encodeBytes field value
      = encodeTag field WIRE_LEN ++ encodeVarint (UInt64.ofNat value.length) ++ value := by
  simp [encodeBytes, h]

@[simp] theorem encodeBytes_nil (field : Nat) : encodeBytes field [] = [] := by
  simp [encodeBytes]

theorem encodeUint64_eq_nil_iff {field : Nat} {value : UInt64} :
    encodeUint64 field value = [] ↔ value = 0 := by
  constructor
  · intro h
    apply Classical.byContradiction
    intro hne
    rw [encodeUint64_of_ne hne] at h
    have h1 := congrArg List.length h
    have h2 := encodeVarint_length_pos value
    simp only [List.length_append, List.length_nil] at h1
    omega
  · rintro rfl
    simp

theorem encodeBytes_eq_nil_iff {field : Nat} {value : Bytes} :
    encodeBytes field value = [] ↔ value = [] := by
  constructor
  · intro h
    apply Classical.byContradiction
    intro hne
    rw [encodeBytes_of_ne hne] at h
    have h1 := congrArg List.length h
    have h2 := encodeVarint_length_pos (UInt64.ofNat value.length)
    simp only [List.length_append, List.length_nil] at h1
    omega
  · rintro rfl
    simp

/-! ## Tags -/

theorem tag_split (tag : UInt64) : ((tag >>> 3) <<< 3) ||| (tag &&& 0x07) = tag := by
  have hlt := tag.toNat_lt
  have hlow : tag.toNat &&& 7 = tag.toNat % 8 := Nat.and_two_pow_sub_one_eq_mod tag.toNat 3
  have hor := Nat.two_pow_add_eq_or_of_lt (i := 3) (b := tag.toNat % 8) (by omega) (tag.toNat / 8)
  apply UInt64.toNat_inj.mp
  rw [UInt64.toNat_or, UInt64.toNat_shiftLeft, UInt64.toNat_shiftRight, UInt64.toNat_and,
    Nat.shiftLeft_eq, Nat.shiftRight_eq_div_pow]
  simp only [UInt64.toNat_ofNat, Nat.reducePow, Nat.reduceMod] at hor ⊢
  rw [hlow, Nat.mod_eq_of_lt (by omega), Nat.mul_comm, ← hor]
  omega

theorem decodeTag_sound {data : Bytes} {pos f w pos' : Nat}
    (h : decodeTag data pos = .ok (f, w, pos')) :
    pos < pos' ∧ pos' ≤ data.length ∧ data.take pos' = data.take pos ++ encodeTag f w := by
  simp only [decodeTag, bind_eq_ok, Prod.exists] at h
  obtain ⟨tag, p, hv, h⟩ := h
  split at h
  · simp at h
  · split at h
    · simp at h
    · simp only [pure_eq_ok, ok_bind, Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl, rfl⟩ := h
      obtain ⟨h1, h2, h3⟩ := decodeVarint_sound hv
      refine ⟨h1, h2, ?_⟩
      rw [h3, encodeTag, UInt64.ofNat_toNat, UInt64.ofNat_toNat, tag_split]

/-- The tag value for a field number that fits in a `u32`. -/
theorem tag_toNat {f w : Nat} (hf : f < 2 ^ 32) (hw : w < 8) :
    ((UInt64.ofNat f <<< 3) ||| UInt64.ofNat w).toNat = 8 * f + w := by
  have h1 : (UInt64.ofNat f).toNat = f := by
    simp [UInt64.toNat_ofNat']; omega
  have h2 : (UInt64.ofNat w).toNat = w := by
    simp [UInt64.toNat_ofNat']; omega
  have h3 := Nat.two_pow_add_eq_or_of_lt (i := 3) (b := w) (by omega) f
  rw [UInt64.toNat_or, UInt64.toNat_shiftLeft, h1, h2, Nat.shiftLeft_eq]
  simp only [UInt64.toNat_ofNat, Nat.reducePow, Nat.reduceMod] at h3 ⊢
  rw [Nat.mod_eq_of_lt (by omega), Nat.mul_comm, ← h3]

/-! ## Encoded sizes -/

theorem encodeVarint_length_one {v : UInt64} (h : v.toNat < 128) :
    (encodeVarint v).length = 1 := by
  rw [encodeVarint_eq_varintNat, varintNat_of_lt h]
  rfl

theorem encodeVarint_length_le_two {v : UInt64} (h : v.toNat < 16384) :
    (encodeVarint v).length ≤ 2 := by
  rw [encodeVarint_eq_varintNat]
  by_cases h1 : v.toNat < 128
  · rw [varintNat_of_lt h1]
    simp
  · rw [varintNat_of_ge (by omega), varintNat_of_lt (by omega)]
    simp

/-- All field numbers are at most 15, so tags are single bytes. -/
theorem encodeTag_length {f w : Nat} (hf : f < 16) (hw : w < 8) : (encodeTag f w).length = 1 :=
  encodeVarint_length_one (by rw [tag_toNat (by omega) hw]; omega)

theorem encodeUint32_u8_length_le {f : Nat} (hf : f < 16) {b : UInt8} (hb : b.toNat < 128) :
    (encodeUint32 f b.toUInt32).length ≤ 2 := by
  unfold encodeUint32
  split
  · simp
  · rw [List.length_append, encodeTag_length hf (by simp [WIRE_VARINT]),
      encodeVarint_length_one (by simpa using hb)]
    omega

theorem encodeBytes_length_le {f : Nat} (hf : f < 16) {b : Bytes} (hb : b.length < 16384) :
    (encodeBytes f b).length ≤ 3 + b.length := by
  unfold encodeBytes
  split
  · simp
  · have h1 := encodeTag_length hf (w := WIRE_LEN) (by simp [WIRE_LEN])
    have h2 := encodeVarint_length_le_two (v := UInt64.ofNat b.length)
      (by simp [UInt64.toNat_ofNat']; omega)
    simp only [List.length_append]
    omega

theorem decodeTag_complete {data : Bytes} {pos f w : Nat} {rest : Bytes}
    (hf0 : f ≠ 0) (hf : f < 2 ^ 32) (hw : w < 8)
    (h : data.drop pos = encodeTag f w ++ rest) :
    decodeTag data pos = .ok (f, w, pos + (encodeTag f w).length) := by
  have ht := tag_toNat hf hw
  have hw' : (((UInt64.ofNat f <<< 3) ||| UInt64.ofNat w) &&& 0x07).toNat = w := by
    have := Nat.and_two_pow_sub_one_eq_mod (8 * f + w) 3
    rw [UInt64.toNat_and, ht]
    simp only [UInt64.toNat_ofNat, Nat.reducePow, Nat.reduceSub, Nat.reduceMod] at this ⊢
    omega
  have hf' : (((UInt64.ofNat f <<< 3) ||| UInt64.ofNat w) >>> 3).toNat = f := by
    rw [UInt64.toNat_shiftRight, ht, Nat.shiftRight_eq_div_pow]
    simp only [UInt64.toNat_ofNat, Nat.reducePow, Nat.reduceMod]
    omega
  simp only [decodeTag, encodeTag] at h ⊢
  rw [decodeVarint_complete h]
  simp only [ok_bind, hw', hf']
  simp [hf0]
  omega

/-! ## Value readers -/

theorem readNonzeroVarint_sound {data : Bytes} {pos pos' : Nat} {v : UInt64}
    (h : readNonzeroVarint data pos = .ok (v, pos')) :
    v ≠ 0 ∧ pos < pos' ∧ pos' ≤ data.length ∧
      data.take pos' = data.take pos ++ encodeVarint v := by
  simp only [readNonzeroVarint, bind_eq_ok, Prod.exists] at h
  obtain ⟨v', p, hv, h⟩ := h
  split at h
  · simp at h
  · rename_i hne
    simp only [pure_eq_ok, ok_bind, Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    exact ⟨by simpa using hne, decodeVarint_sound hv⟩

theorem readNonzeroVarint_complete {data : Bytes} {pos : Nat} {v : UInt64} {rest : Bytes}
    (hv : v ≠ 0) (h : data.drop pos = encodeVarint v ++ rest) :
    readNonzeroVarint data pos = .ok (v, pos + (encodeVarint v).length) := by
  simp [readNonzeroVarint, decodeVarint_complete h, hv]

theorem readU8Value_sound {data : Bytes} {pos pos' : Nat} {v : UInt8}
    (h : readU8Value data pos = .ok (v, pos')) :
    pos < pos' ∧ pos' ≤ data.length ∧
      data.take pos' = data.take pos ++ encodeVarint v.toUInt64 := by
  simp only [readU8Value, bind_eq_ok, Prod.exists] at h
  obtain ⟨v', p, hv, h⟩ := h
  split at h
  · simp at h
  · rename_i hlt
    simp only [pure_eq_ok, ok_bind, Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    have : v'.toUInt8.toUInt64 = v' := by
      apply UInt64.toNat_inj.mp
      simp
      omega
    rw [this]
    exact decodeVarint_sound hv

theorem readU8Value_complete {data : Bytes} {pos : Nat} {v : UInt8} {rest : Bytes}
    (h : data.drop pos = encodeVarint v.toUInt64 ++ rest) :
    readU8Value data pos = .ok (v, pos + (encodeVarint v.toUInt64).length) := by
  have := v.toNat_lt
  simp [readU8Value, decodeVarint_complete h]
  omega

theorem readNonzeroU8_sound {data : Bytes} {pos pos' : Nat} {v : UInt8}
    (h : readNonzeroU8 data pos = .ok (v, pos')) :
    v ≠ 0 ∧ pos < pos' ∧ pos' ≤ data.length ∧
      data.take pos' = data.take pos ++ encodeVarint v.toUInt64 := by
  simp only [readNonzeroU8, bind_eq_ok, Prod.exists] at h
  obtain ⟨v', p, hv, h⟩ := h
  split at h
  · simp at h
  · rename_i hne
    simp only [pure_eq_ok, ok_bind, Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    exact ⟨by simpa using hne, readU8Value_sound hv⟩

theorem readNonzeroU8_complete {data : Bytes} {pos : Nat} {v : UInt8} {rest : Bytes}
    (hv : v ≠ 0) (h : data.drop pos = encodeVarint v.toUInt64 ++ rest) :
    readNonzeroU8 data pos = .ok (v, pos + (encodeVarint v.toUInt64).length) := by
  simp [readNonzeroU8, readU8Value_complete h, hv]

theorem readBytesValue_sound {data : Bytes} {pos pos' : Nat} {bytes : Bytes}
    (h : readBytesValue data pos = .ok (bytes, pos')) :
    pos < pos' ∧ pos' ≤ data.length ∧
      data.take pos' = data.take pos ++ encodeVarint (UInt64.ofNat bytes.length) ++ bytes := by
  simp only [readBytesValue, bind_eq_ok, Prod.exists] at h
  obtain ⟨len64, p, hv, h⟩ := h
  split at h
  · simp at h
  · split at h
    · simp at h
    · simp only [pure_eq_ok, ok_bind, Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      obtain ⟨h1, h2, h3⟩ := decodeVarint_sound hv
      have hlen : ((data.drop p).take len64.toNat).length = len64.toNat := by
        simp
        omega
      refine ⟨by omega, by omega, ?_⟩
      rw [hlen, UInt64.ofNat_toNat, List.take_add, h3]

theorem readBytesValue_complete {data : Bytes} {pos : Nat} {bytes rest : Bytes}
    (hdata : data.length < 2 ^ 64)
    (h : data.drop pos = encodeVarint (UInt64.ofNat bytes.length) ++ bytes ++ rest) :
    readBytesValue data pos
      = .ok (bytes, pos + (encodeVarint (UInt64.ofNat bytes.length)).length + bytes.length) := by
  rw [List.append_assoc] at h
  have hdrop := drop_add_of_drop_eq_append h
  have hlen : pos + (encodeVarint (UInt64.ofNat bytes.length)).length + bytes.length
      ≤ data.length := by
    have := congrArg List.length h
    have := encodeVarint_length_pos (UInt64.ofNat bytes.length)
    simp at *
    omega
  have hb : (UInt64.ofNat bytes.length).toNat = bytes.length := by
    simp [UInt64.toNat_ofNat']
    omega
  simp only [readBytesValue, decodeVarint_complete h, ok_bind, hb, hdrop]
  rw [if_neg (by omega), if_neg (by omega)]
  simp

theorem readBoundedBytes_sound {data : Bytes} {pos maxLen pos' : Nat} {bytes : Bytes}
    (h : readBoundedBytes data pos maxLen = .ok (bytes, pos')) :
    bytes ≠ [] ∧ bytes.length ≤ maxLen ∧ pos < pos' ∧ pos' ≤ data.length ∧
      data.take pos' = data.take pos ++ encodeVarint (UInt64.ofNat bytes.length) ++ bytes := by
  simp only [readBoundedBytes, bind_eq_ok, Prod.exists] at h
  obtain ⟨b, p, hv, h⟩ := h
  split at h
  · simp at h
  · split at h
    · simp at h
    · rename_i hne hle
      simp only [pure_eq_ok, ok_bind, Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      exact ⟨by simpa using hne, by omega, readBytesValue_sound hv⟩

theorem readBoundedBytes_complete {data : Bytes} {pos maxLen : Nat} {bytes rest : Bytes}
    (hdata : data.length < 2 ^ 64) (hne : bytes ≠ []) (hle : bytes.length ≤ maxLen)
    (h : data.drop pos = encodeVarint (UInt64.ofNat bytes.length) ++ bytes ++ rest) :
    readBoundedBytes data pos maxLen
      = .ok (bytes, pos + (encodeVarint (UInt64.ofNat bytes.length)).length + bytes.length) := by
  simp only [readBoundedBytes, readBytesValue_complete hdata h, ok_bind]
  simp [hne]
  omega

/-! ## Field order -/

theorem nextField_sound {data : Bytes} {pos last f w pos' : Nat} {repeated : Option Nat}
    (h : nextField data pos last repeated = .ok (f, w, pos')) :
    (last < f ∨ (f = last ∧ repeated = some f)) ∧ pos < pos' ∧ pos' ≤ data.length ∧
      data.take pos' = data.take pos ++ encodeTag f w := by
  simp only [nextField, bind_eq_ok, Prod.exists] at h
  obtain ⟨f', w', p, hv, h⟩ := h
  split at h
  · simp at h
  · rename_i hord
    simp only [pure_eq_ok] at h
    obtain ⟨rfl, rfl, rfl⟩ := h
    refine ⟨?_, decodeTag_sound hv⟩
    simp only [Bool.or_eq_true, decide_eq_true_eq, Bool.and_eq_true, beq_iff_eq, bne_iff_ne,
      not_or, not_and, Decidable.not_not] at hord
    by_cases heq : f = last
    · exact .inr ⟨heq, hord.2 heq⟩
    · exact .inl (by omega)

theorem nextField_complete {data : Bytes} {pos last f w : Nat} {repeated : Option Nat}
    {rest : Bytes} (hf : f < 2 ^ 32) (hw : w < 8)
    (hord : last < f ∨ (f = last ∧ f ≠ 0 ∧ repeated = some f))
    (h : data.drop pos = encodeTag f w ++ rest) :
    nextField data pos last repeated = .ok (f, w, pos + (encodeTag f w).length) := by
  have hf0 : f ≠ 0 := by
    rcases hord with h | h <;> omega
  simp only [nextField, decodeTag_complete hf0 hf hw h, ok_bind]
  rcases hord with h | ⟨h1, _, h2⟩
  · have h1 : ¬ f < last := by omega
    have h2 : f ≠ last := by omega
    simp [h1, h2]
  · subst h1
    simp [h2]

end Protoken
