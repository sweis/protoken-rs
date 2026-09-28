import Protoken.Basic

/-!
# Varints

Model of `encode_varint` and `decode_varint` in `src/proto3.rs`, and the proof
that the decoder accepts exactly the encoder's output.
-/

namespace Protoken

/-! ## Model -/

/-- Models `encode_varint`. The Rust function appends to a buffer; this returns
the appended bytes. -/
def encodeVarint (value : UInt64) : Bytes :=
  if value ≤ 0x7F then
    [value.toUInt8]
  else
    ((value.toUInt8 &&& 0x7F) ||| 0x80) :: encodeVarint (value >>> 7)
termination_by value.toNat
decreasing_by
  rename_i h
  have h : 0x7F < value.toNat := by
    simpa [UInt64.le_iff_toNat_le] using h
  simp [UInt64.toNat_shiftRight, Nat.shiftRight_eq_div_pow]
  omega

/-- The loop of `decode_varint`. `start` is the position of the first byte. -/
def decodeVarintLoop (data : Bytes) (start pos : Nat) (value : UInt64) (shift : Nat) :
    Result (UInt64 × Nat) :=
  if h : pos ≥ data.length then
    .error .malformedEncoding
  else
    let byte := data[pos]
    let pos := pos + 1
    -- On the 10th byte only bit 0 fits in a u64.
    if shift == 63 && byte > 1 then
      .error .malformedEncoding
    else
      let value := value ||| ((byte &&& 0x7F).toUInt64 <<< UInt64.ofNat shift)
      if byte &&& 0x80 == 0 then
        -- A trailing zero byte is a non-minimal encoding.
        if byte == 0 && pos - start > 1 then
          .error .malformedEncoding
        else
          .ok (value, pos)
      else
        let shift := shift + 7
        if shift > 63 then
          .error .malformedEncoding
        else
          decodeVarintLoop data start pos value shift
termination_by data.length - pos

/-- Models `decode_varint`. Returns the value and the new position. -/
def decodeVarint (data : Bytes) (pos : Nat) : Result (UInt64 × Nat) :=
  decodeVarintLoop data pos pos 0 0

theorem encodeVarint_length_pos (value : UInt64) : 0 < (encodeVarint value).length := by
  rw [encodeVarint]
  split <;> simp

/-! ## Arithmetic specification -/

/-- Base-128 little-endian digits of `n`, with the continuation bit set on
every byte but the last. -/
def varintNat (n : Nat) : Bytes :=
  if n < 128 then [UInt8.ofNat n] else UInt8.ofNat (n % 128 + 128) :: varintNat (n / 128)

theorem varintNat_of_lt {n : Nat} (h : n < 128) : varintNat n = [UInt8.ofNat n] := by
  rw [varintNat, if_pos h]

theorem varintNat_of_ge {n : Nat} (h : 128 ≤ n) :
    varintNat n = UInt8.ofNat (n % 128 + 128) :: varintNat (n / 128) := by
  rw [varintNat, if_neg (by omega)]

theorem low7_or_continue (value : UInt64) :
    (value.toUInt8 &&& 0x7F) ||| 0x80 = UInt8.ofNat (value.toNat % 128 + 128) := by
  apply UInt8.toNat_inj.mp
  have h1 : value.toNat % 256 &&& 127 = value.toNat % 128 := by
    have := Nat.and_two_pow_sub_one_eq_mod (value.toNat % 256) 7
    simp at this
    omega
  have h2 : value.toNat % 128 ||| 128 = value.toNat % 128 + 128 := by
    have := Nat.two_pow_add_eq_or_of_lt (i := 7) (b := value.toNat % 128) (by omega) 1
    rw [show 2 ^ 7 * 1 = 128 from rfl] at this
    rw [Nat.or_comm]
    omega
  simp [UInt8.toNat_or, UInt8.toNat_and, h1, h2]
  omega

theorem encodeVarint_eq_varintNat (value : UInt64) :
    encodeVarint value = varintNat value.toNat := by
  induction h : value.toNat using Nat.strongRecOn generalizing value with
  | ind n ih =>
    subst h
    rw [encodeVarint]
    split
    · rename_i hle
      have hle : value.toNat ≤ 0x7F := by simpa [UInt64.le_iff_toNat_le] using hle
      rw [varintNat_of_lt (by omega)]
      congr 1
    · rename_i hgt
      have hgt : 0x7F < value.toNat := by simpa [UInt64.le_iff_toNat_le] using hgt
      have hshift : (value >>> 7).toNat = value.toNat / 128 := by
        simp [UInt64.toNat_shiftRight, Nat.shiftRight_eq_div_pow]
      rw [varintNat_of_ge (by omega), low7_or_continue,
        ih (value >>> 7).toNat (by omega) (value >>> 7) rfl, hshift]

/-! ## Decoder step -/

theorem and_0x80_eq_zero_iff (byte : UInt8) : byte &&& 0x80 = 0 ↔ byte.toNat < 128 := by
  -- Checked for all 256 byte values.
  have hall : ∀ n, n < 256 → (n &&& 128 = 0 ↔ n < 128) := by
    set_option maxRecDepth 4096 in decide
  rw [← UInt8.toNat_inj, UInt8.toNat_and]
  exact hall byte.toNat byte.toNat_lt

/-- Adding the next 7-bit group with `|` and `<<` is addition of `digit * 2^shift`,
as long as the group fits in 64 bits. -/
theorem or_shift_toNat (value : UInt64) (byte : UInt8) (shift : Nat) (hs : shift ≤ 63)
    (hv : value.toNat < 2 ^ shift) (hfit : byte.toNat % 128 * 2 ^ shift < 2 ^ 64) :
    (value ||| ((byte &&& 0x7F).toUInt64 <<< UInt64.ofNat shift)).toNat
      = value.toNat + byte.toNat % 128 * 2 ^ shift := by
  have h1 : (byte &&& 0x7F).toUInt64.toNat = byte.toNat % 128 := by
    simpa [UInt8.toNat_and] using Nat.and_two_pow_sub_one_eq_mod byte.toNat 7
  have h2 : (UInt64.ofNat shift).toNat % 64 = shift := by
    simp [UInt64.toNat_ofNat']
    omega
  rw [UInt64.toNat_or, UInt64.toNat_shiftLeft, h1, h2, Nat.shiftLeft_eq, Nat.mod_eq_of_lt hfit,
    Nat.or_comm, Nat.mul_comm, ← Nat.two_pow_add_eq_or_of_lt hv, Nat.add_comm]

/-- One iteration of the decoder loop, as a logical statement. -/
theorem decodeVarintLoop_eq_ok_iff {data : Bytes} {start pos shift : Nat} {value v : UInt64}
    {pos' : Nat} :
    decodeVarintLoop data start pos value shift = .ok (v, pos') ↔
      ∃ h : pos < data.length,
        ¬(shift = 63 ∧ 1 < data[pos].toNat) ∧
        ((data[pos].toNat < 128 ∧ ¬(data[pos].toNat = 0 ∧ pos + 1 - start > 1) ∧
            v = value ||| ((data[pos] &&& 0x7F).toUInt64 <<< UInt64.ofNat shift) ∧
            pos' = pos + 1) ∨
         (128 ≤ data[pos].toNat ∧ shift + 7 ≤ 63 ∧
            decodeVarintLoop data start (pos + 1)
              (value ||| ((data[pos] &&& 0x7F).toUInt64 <<< UInt64.ofNat shift)) (shift + 7)
              = .ok (v, pos'))) := by
  rw [decodeVarintLoop]
  by_cases hlen : pos ≥ data.length
  · simp [hlen]
    omega
  · have hlt : pos < data.length := by omega
    have hzero : data[pos] = 0 ↔ data[pos].toNat = 0 := by
      rw [← UInt8.toNat_inj]; rfl
    simp only [hlen, dite_false, hlt, exists_true_left, beq_iff_eq, Bool.and_eq_true,
      decide_eq_true_eq, and_0x80_eq_zero_iff, hzero, UInt8.lt_iff_toNat_lt]
    by_cases h63 : shift = 63 ∧ (1 : UInt8).toNat < data[pos].toNat
    · have h63' : shift = 63 ∧ 1 < data[pos].toNat := h63
      simp [h63, h63']
    · have h63' : ¬(shift = 63 ∧ 1 < data[pos].toNat) := h63
      simp only [h63, if_false, h63', not_false_eq_true, true_and]
      by_cases hb : data[pos].toNat < 128
      · simp only [hb, if_true]
        by_cases hz : data[pos].toNat = 0 ∧ pos + 1 - start > 1
        · simp [hz]
        · simp only [hz, if_false, not_false_eq_true, true_and, Except.ok.injEq, Prod.mk.injEq]
          constructor
          · rintro ⟨rfl, rfl⟩
            exact .inl ⟨rfl, rfl⟩
          · rintro (⟨rfl, rfl⟩ | ⟨h, _⟩)
            · exact ⟨rfl, rfl⟩
            · omega
      · simp only [hb, if_false, false_and, false_or]
        by_cases hs : shift + 7 > 63
        · simp [hs]
          omega
        · simp only [hs, if_false]
          constructor
          · intro h
            exact ⟨by omega, by omega, h⟩
          · rintro ⟨_, _, h⟩
            exact h

/-! ## Soundness: accepted bytes are the canonical encoding -/

theorem two_pow_succ7 (k : Nat) : 2 ^ (7 * (k + 1)) = 128 * 2 ^ (7 * k) := by
  rw [Nat.mul_add, Nat.pow_add]
  omega

/-- A 7-bit group at position `k ≤ 8`, or a single bit at position 9, fits in 64 bits. -/
theorem digit_fits {k d : Nat} (hk : k ≤ 9) (hd : d < 128) (h9 : k = 9 → d ≤ 1) :
    d * 2 ^ (7 * k) < 2 ^ 64 := by
  by_cases h : k = 9
  · subst h
    have := h9 rfl
    omega
  · have h1 : 2 ^ (7 * k) ≤ 2 ^ 56 := Nat.pow_le_pow_right (by omega) (by omega)
    calc d * 2 ^ (7 * k) ≤ 127 * 2 ^ 56 := Nat.mul_le_mul (by omega) h1
      _ < 2 ^ 64 := by omega

theorem decodeVarintLoop_sound {data : Bytes} {start : Nat} {v : UInt64} {pos' : Nat} :
    ∀ (j k pos : Nat) (value : UInt64), k + j = 9 → pos = start + k →
      value.toNat < 2 ^ (7 * k) →
      decodeVarintLoop data start pos value (7 * k) = .ok (v, pos') →
      ∃ n, v.toNat = value.toNat + n * 2 ^ (7 * k) ∧ (0 < k → n ≠ 0) ∧ pos < pos' ∧
        pos' ≤ data.length ∧ data.take pos' = data.take pos ++ varintNat n := by
  intro j
  induction j with
  | zero =>
    intro k pos value hk hpos hv h
    obtain ⟨hlt, h63, h⟩ := decodeVarintLoop_eq_ok_iff.mp h
    have hfit := digit_fits (k := k) (d := data[pos].toNat % 128) (by omega) (by omega)
      (by omega)
    rcases h with ⟨hb, hz, rfl, rfl⟩ | ⟨_, hs, _⟩
    · refine ⟨data[pos].toNat, ?_, by omega, by omega, by omega, ?_⟩
      · rw [or_shift_toNat _ _ _ (by omega) hv hfit, Nat.mod_eq_of_lt hb]
      · rw [take_succ_eq _ _ hlt, varintNat_of_lt hb, UInt8.ofNat_toNat]
    · omega
  | succ j ih =>
    intro k pos value hk hpos hv h
    obtain ⟨hlt, h63, h⟩ := decodeVarintLoop_eq_ok_iff.mp h
    have hfit := digit_fits (k := k) (d := data[pos].toNat % 128) (by omega) (by omega)
      (by omega)
    have hstep := or_shift_toNat value data[pos] (7 * k) (by omega) hv hfit
    rcases h with ⟨hb, hz, rfl, rfl⟩ | ⟨hb, hs, h⟩
    · refine ⟨data[pos].toNat, ?_, by omega, by omega, by omega, ?_⟩
      · rw [hstep, Nat.mod_eq_of_lt hb]
      · rw [take_succ_eq _ _ hlt, varintNat_of_lt hb, UInt8.ofNat_toNat]
    · have hpow := two_pow_succ7 k
      have hlt256 := data[pos].toNat_lt
      have hd : data[pos].toNat % 128 * 2 ^ (7 * k) ≤ 127 * 2 ^ (7 * k) :=
        Nat.mul_le_mul_right _ (by omega)
      obtain ⟨n, hn, hn0, hp1, hp2, htake⟩ :=
        ih (k + 1) (pos + 1) _ (by omega) (by omega) (by rw [hstep, hpow]; omega) h
      refine ⟨data[pos].toNat % 128 + 128 * n, ?_, by omega, by omega, hp2, ?_⟩
      · rw [hn, hstep, hpow, Nat.add_mul, Nat.mul_assoc, Nat.mul_left_comm, Nat.add_assoc]
      · have hn0 := hn0 (by omega)
        have e1 : (data[pos].toNat % 128 + 128 * n) % 128 + 128 = data[pos].toNat := by omega
        have e2 : (data[pos].toNat % 128 + 128 * n) / 128 = n := by omega
        rw [htake, take_succ_eq _ _ hlt,
          varintNat_of_ge (n := data[pos].toNat % 128 + 128 * n) (by omega), e1, e2,
          UInt8.ofNat_toNat, List.append_assoc]
        rfl

/-- **Canonical varints.** If the decoder accepts, the bytes it consumed are
exactly `encodeVarint` of the value it returned. -/
theorem decodeVarint_sound {data : Bytes} {pos pos' : Nat} {v : UInt64}
    (h : decodeVarint data pos = .ok (v, pos')) :
    pos < pos' ∧ pos' ≤ data.length ∧ data.take pos' = data.take pos ++ encodeVarint v := by
  obtain ⟨n, hn, _, h1, h2, h3⟩ :=
    decodeVarintLoop_sound 9 0 pos 0 (by omega) (by omega) (by simp) h
  have : n = v.toNat := by simpa using hn.symm
  subst this
  exact ⟨h1, h2, by rw [h3, encodeVarint_eq_varintNat]⟩

/-! ## Completeness: every encoding is accepted -/

theorem decodeVarintLoop_complete {data : Bytes} {start : Nat} :
    ∀ (n k pos : Nat) (value : UInt64) (rest : Bytes), pos = start + k →
      value.toNat < 2 ^ (7 * k) → value.toNat + n * 2 ^ (7 * k) < 2 ^ 64 → (0 < k → n ≠ 0) →
      data.drop pos = varintNat n ++ rest →
      decodeVarintLoop data start pos value (7 * k)
        = .ok (UInt64.ofNat (value.toNat + n * 2 ^ (7 * k)), pos + (varintNat n).length) := by
  intro n
  induction n using Nat.strongRecOn with
  | ind n ih =>
    intro k pos value rest hpos hv hbound hn0 hdrop
    have hpowpos : 0 < 2 ^ (7 * k) := Nat.pow_pos (by omega)
    -- `k ≤ 9`, since a non-zero digit at position 10 or later overflows.
    have hk : k ≤ 9 := by
      apply Classical.byContradiction
      intro hk
      have h1 : 2 ^ 64 ≤ 2 ^ (7 * k) := Nat.pow_le_pow_right (by omega) (by omega)
      have h2 : 1 * 2 ^ (7 * k) ≤ n * 2 ^ (7 * k) :=
        Nat.mul_le_mul_right _ (Nat.pos_of_ne_zero (hn0 (by omega)))
      omega
    rw [decodeVarintLoop_eq_ok_iff]
    by_cases hsmall : n < 128
    · rw [varintNat_of_lt hsmall] at hdrop ⊢
      obtain ⟨hlt, hbyte, _⟩ := drop_eq_cons hdrop
      have hb : data[pos].toNat = n := by
        rw [hbyte]; simp; omega
      have hfit : data[pos].toNat % 128 * 2 ^ (7 * k) < 2 ^ 64 := by
        rw [hb, Nat.mod_eq_of_lt hsmall]; omega
      refine ⟨hlt, ?_, .inl ⟨by omega, ?_, ?_, rfl⟩⟩
      · rintro ⟨h63, h1⟩
        have : k = 9 := by omega
        subst this
        omega
      · rintro ⟨h0, h1⟩
        exact hn0 (by omega) (by omega)
      · apply UInt64.toNat_inj.mp
        rw [or_shift_toNat _ _ _ (by omega) hv hfit, hb, Nat.mod_eq_of_lt hsmall]
        simp
        omega
    · have hge : 128 ≤ n := by omega
      rw [varintNat_of_ge hge] at hdrop ⊢
      obtain ⟨hlt, hbyte, hdrop'⟩ := drop_eq_cons hdrop
      have hb : data[pos].toNat = n % 128 + 128 := by
        rw [hbyte]; simp; omega
      have hpow := two_pow_succ7 k
      have hsplit : n * 2 ^ (7 * k) = n % 128 * 2 ^ (7 * k) + n / 128 * 2 ^ (7 * (k + 1)) := by
        rw [hpow, ← Nat.mul_assoc, ← Nat.add_mul]
        congr 1
        omega
      have hdigit : n % 128 * 2 ^ (7 * k) ≤ 127 * 2 ^ (7 * k) :=
        Nat.mul_le_mul_right _ (by omega)
      have hhigh : 1 * 2 ^ (7 * (k + 1)) ≤ n / 128 * 2 ^ (7 * (k + 1)) :=
        Nat.mul_le_mul_right _ (by omega)
      have hfit : data[pos].toNat % 128 * 2 ^ (7 * k) < 2 ^ 64 := by
        rw [hb]
        have : (n % 128 + 128) % 128 = n % 128 := by omega
        rw [this]; omega
      have hstep := or_shift_toNat value data[pos] (7 * k) (by omega) hv hfit
      have hmod : data[pos].toNat % 128 = n % 128 := by omega
      -- The next group exists, so `k ≤ 8`.
      have hk8 : k ≤ 8 := by
        apply Classical.byContradiction
        intro hk8
        have : k = 9 := by omega
        subst this
        omega
      refine ⟨hlt, by omega, .inr ⟨by omega, by omega, ?_⟩⟩
      have := ih (n / 128) (by omega) (k + 1) (pos + 1) _ rest (by omega)
        (by rw [hstep, hpow, hmod]; omega) (by rw [hstep, hmod]; omega) (by omega) hdrop'
      rw [show 7 * k + 7 = 7 * (k + 1) by omega, this, hstep, hmod, hsplit]
      simp [Nat.add_assoc, Nat.add_comm]

/-- **Varint round trip.** If the unread input starts with `encodeVarint v`, the
decoder returns `v` and consumes exactly those bytes. -/
theorem decodeVarint_complete {data : Bytes} {pos : Nat} {v : UInt64} {rest : Bytes}
    (h : data.drop pos = encodeVarint v ++ rest) :
    decodeVarint data pos = .ok (v, pos + (encodeVarint v).length) := by
  rw [encodeVarint_eq_varintNat] at h ⊢
  have := decodeVarintLoop_complete (start := pos) v.toNat 0 pos 0 rest (by omega) (by simp)
    (by simpa using v.toNat_lt) (by omega) h
  simpa [decodeVarint] using this

end Protoken
