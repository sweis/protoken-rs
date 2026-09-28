import Protoken.Serialize

/-!
# Claims: canonical encoding and round trip

* `deserializeClaims_canonical`: accepted bytes are exactly `serializeClaims` of
  the decoded claims. So each `Claims` value has one accepted encoding.
* `deserializeClaims_serializeClaims`: encoding then decoding returns the claims
  with sorted scopes, provided the encoding fits in `MAX_PAYLOAD_BYTES`.
-/

namespace Protoken

/-- What the decoder guarantees about the claims it returns. These are size and
form rules only. The semantic rules are in `Claims.Valid`. -/
structure Claims.WireValid (c : Claims) : Prop where
  subject_len : c.subject.length ≤ MAX_CLAIM_BYTES_LEN
  subject_utf8 : validUtf8 c.subject = true
  audience_len : c.audience.length ≤ MAX_CLAIM_BYTES_LEN
  audience_utf8 : validUtf8 c.audience = true
  scopes_count : c.scopes.length ≤ MAX_SCOPES
  scope_entries : ∀ s ∈ c.scopes,
    s ≠ [] ∧ s.length ≤ MAX_CLAIM_BYTES_LEN ∧ validUtf8 s = true
  scopes_sorted : c.scopes.Pairwise (· < ·)

@[simp] theorem encodeScopes_nil : encodeScopes [] = [] := rfl

theorem encodeScopes_append (a b : List Bytes) :
    encodeScopes (a ++ b) = encodeScopes a ++ encodeScopes b := by
  simp [encodeScopes]

@[simp] theorem encodeScopes_cons (s : Bytes) (l : List Bytes) :
    encodeScopes (s :: l) = encodeBytes 6 s ++ encodeScopes l := by
  simp [encodeScopes]

/-- Appending a larger element keeps a list strictly ascending. -/
theorem pairwise_lt_append_singleton {l : List Bytes} {s : Bytes} (hl : l.Pairwise (· < ·))
    (hs : ∀ prev, l.getLast? = some prev → prev < s) : (l ++ [s]).Pairwise (· < ·) := by
  refine List.pairwise_append.mpr ⟨hl, by simp, ?_⟩
  intro a ha b hb
  simp only [List.mem_singleton] at hb
  subst hb
  cases hlast : l.getLast? with
  | none =>
    rw [List.getLast?_eq_none_iff] at hlast
    subst hlast
    cases ha
  | some prev =>
    obtain ⟨init, rfl⟩ := List.getLast?_eq_some_iff.mp hlast
    have hprev := hs prev hlast
    rcases List.mem_append.mp ha with ha | ha
    · exact List.lt_trans ((List.pairwise_append.mp hl).2.2 a ha prev (by simp)) hprev
    · simp only [List.mem_singleton] at ha
      subst ha
      exact hprev

/-! ## Soundness -/

/-- The invariant of the Claims decoding loop. -/
structure ClaimsInv (data : Bytes) (pos last : Nat) (c : Claims) : Prop where
  pos_le : pos ≤ data.length
  /-- The consumed bytes are the encoding of the fields decoded so far. -/
  consumed : data.take pos = serializeClaimsUnsorted c
  /-- Fields after the last one seen still have their default value. -/
  d1 : last < 1 → c.expiresAt = 0
  d2 : last < 2 → c.notBefore = 0
  d3 : last < 3 → c.issuedAt = 0
  d4 : last < 4 → c.subject = []
  d5 : last < 5 → c.audience = []
  d6 : last < 6 → c.scopes = []
  wire : c.WireValid

theorem claimsInv_init (data : Bytes) : ClaimsInv data 0 0 {} where
  pos_le := by omega
  consumed := by simp [serializeClaimsUnsorted]
  d1 := fun _ => rfl
  d2 := fun _ => rfl
  d3 := fun _ => rfl
  d4 := fun _ => rfl
  d5 := fun _ => rfl
  d6 := fun _ => rfl
  wire := by constructor <;> simp [validUtf8]

theorem claimsInv_step {data : Bytes} {pos last pos' last' : Nat} {c c' : Claims}
    (hinv : ClaimsInv data pos last c)
    (h : claimsStep data pos last c = .ok (pos', last', c')) : ClaimsInv data pos' last' c' := by
  obtain ⟨_, hle, hord, hcase⟩ := claimsStep_sound h
  obtain ⟨_, hcons, d1, d2, d3, d4, d5, d6, hw⟩ := hinv
  rcases hcase with ⟨rfl, v, _, rfl, htake⟩ | ⟨rfl, v, _, rfl, htake⟩ | ⟨rfl, v, _, rfl, htake⟩ |
    ⟨rfl, s, hutf, _, hlen, rfl, htake⟩ | ⟨rfl, s, hutf, _, hlen, rfl, htake⟩ |
    ⟨rfl, s, hutf, hne, hlen, hcount, hprev, rfl, htake⟩
  · have hlast : last < 1 := by omega
    refine ⟨hle, ?_, by omega, fun _ => d2 (by omega), fun _ => d3 (by omega),
      fun _ => d4 (by omega), fun _ => d5 (by omega), fun _ => d6 (by omega), ⟨hw.1, hw.2, hw.3,
      hw.4, hw.5, hw.6, hw.7⟩⟩
    rw [htake, hcons]
    simp [serializeClaimsUnsorted, d1 (by omega), d2 (by omega), d3 (by omega), d4 (by omega),
      d5 (by omega), d6 (by omega)]
  · have hlast : last < 2 := by omega
    refine ⟨hle, ?_, by omega, by omega, fun _ => d3 (by omega),
      fun _ => d4 (by omega), fun _ => d5 (by omega), fun _ => d6 (by omega), ⟨hw.1, hw.2, hw.3,
      hw.4, hw.5, hw.6, hw.7⟩⟩
    rw [htake, hcons]
    simp [serializeClaimsUnsorted, d2 (by omega), d3 (by omega), d4 (by omega),
      d5 (by omega), d6 (by omega)]
  · have hlast : last < 3 := by omega
    refine ⟨hle, ?_, by omega, by omega, by omega,
      fun _ => d4 (by omega), fun _ => d5 (by omega), fun _ => d6 (by omega), ⟨hw.1, hw.2, hw.3,
      hw.4, hw.5, hw.6, hw.7⟩⟩
    rw [htake, hcons]
    simp [serializeClaimsUnsorted, d3 (by omega), d4 (by omega), d5 (by omega), d6 (by omega)]
  · have hlast : last < 4 := by omega
    refine ⟨hle, ?_, by omega, by omega, by omega, by omega,
      fun _ => d5 (by omega), fun _ => d6 (by omega), ⟨hlen, hutf, hw.3, hw.4, hw.5, hw.6, hw.7⟩⟩
    rw [htake, hcons]
    simp [serializeClaimsUnsorted, d4 (by omega), d5 (by omega), d6 (by omega)]
  · have hlast : last < 5 := by omega
    refine ⟨hle, ?_, by omega, by omega, by omega, by omega, by omega,
      fun _ => d6 (by omega), ⟨hw.1, hw.2, hlen, hutf, hw.5, hw.6, hw.7⟩⟩
    rw [htake, hcons]
    simp [serializeClaimsUnsorted, d5 (by omega), d6 (by omega)]
  · refine ⟨hle, ?_, by omega, by omega, by omega, by omega, by omega, by omega,
      ⟨hw.1, hw.2, hw.3, hw.4, ?_, ?_, pairwise_lt_append_singleton hw.7 hprev⟩⟩
    · rw [htake, hcons]
      simp [serializeClaimsUnsorted, encodeScopes_append]
    · simp only [List.length_append, List.length_singleton]
      omega
    · intro x hx
      rcases List.mem_append.mp hx with hx | hx
      · exact hw.6 x hx
      · simp only [List.mem_singleton] at hx
        subst hx
        exact ⟨hne, hlen, hutf⟩

/-- **Canonical Claims.** If `deserializeClaims` accepts `data`, then `data` is
exactly `serializeClaims` of the result, and the result meets the wire limits. -/
theorem deserializeClaims_canonical {data : Bytes} {c : Claims}
    (h : deserializeClaims data = .ok c) : serializeClaims c = data ∧ c.WireValid := by
  simp only [deserializeClaims, throw_eq_error, error_bind, pure_eq_ok, ok_bind,
    ite_error_eq_ok] at h
  obtain ⟨_, _, h⟩ := h
  obtain ⟨pos, last, hpos, hinv⟩ := fieldLoop_invariant (ClaimsInv data)
    (fun _ _ _ _ _ _ _ hinv hs => claimsInv_step hinv hs) data.length 0 0 {} c (by omega)
    (claimsInv_init data) h
  refine ⟨?_, hinv.wire⟩
  have hsorted : sortScopes c.scopes = c.scopes := sortScopes_of_pairwise_lt hinv.wire.scopes_sorted
  rw [serializeClaims, hsorted, ← hinv.consumed, List.take_of_length_le hpos]

/-- Two accepted encodings of the same claims are the same bytes. -/
theorem deserializeClaims_injective {d1 d2 : Bytes} {c : Claims}
    (h1 : deserializeClaims d1 = .ok c) (h2 : deserializeClaims d2 = .ok c) : d1 = d2 := by
  rw [← (deserializeClaims_canonical h1).1, ← (deserializeClaims_canonical h2).1]

/-! ## Completeness -/

section Complete

variable {data : Bytes} {pos last : Nat} {c : Claims} {rest : Bytes}

theorem claimsStep_expiresAt {v : UInt64} (hv : v ≠ 0) (hlast : last < 1)
    (h : data.drop pos = encodeUint64 1 v ++ rest) :
    claimsStep data pos last c
      = .ok (pos + (encodeUint64 1 v).length, 1, { c with expiresAt := v }) := by
  rw [encodeUint64_of_ne hv, List.append_assoc] at h
  have h1 := nextField_complete (repeated := some SCOPE_FIELD) (last := last) (by omega)
    (by simp [WIRE_VARINT]) (.inl hlast) h
  have h2 := readNonzeroVarint_complete hv (drop_add_of_drop_eq_append h)
  simp only [WIRE_VARINT] at h1 h2
  simp [claimsStep, h1, h2, encodeUint64_of_ne hv, WIRE_VARINT, Nat.add_assoc]

theorem claimsStep_notBefore {v : UInt64} (hv : v ≠ 0) (hlast : last < 2)
    (h : data.drop pos = encodeUint64 2 v ++ rest) :
    claimsStep data pos last c
      = .ok (pos + (encodeUint64 2 v).length, 2, { c with notBefore := v }) := by
  rw [encodeUint64_of_ne hv, List.append_assoc] at h
  have h1 := nextField_complete (repeated := some SCOPE_FIELD) (last := last) (by omega)
    (by simp [WIRE_VARINT]) (.inl hlast) h
  have h2 := readNonzeroVarint_complete hv (drop_add_of_drop_eq_append h)
  simp only [WIRE_VARINT] at h1 h2
  simp [claimsStep, h1, h2, encodeUint64_of_ne hv, WIRE_VARINT, Nat.add_assoc]

theorem claimsStep_issuedAt {v : UInt64} (hv : v ≠ 0) (hlast : last < 3)
    (h : data.drop pos = encodeUint64 3 v ++ rest) :
    claimsStep data pos last c
      = .ok (pos + (encodeUint64 3 v).length, 3, { c with issuedAt := v }) := by
  rw [encodeUint64_of_ne hv, List.append_assoc] at h
  have h1 := nextField_complete (repeated := some SCOPE_FIELD) (last := last) (by omega)
    (by simp [WIRE_VARINT]) (.inl hlast) h
  have h2 := readNonzeroVarint_complete hv (drop_add_of_drop_eq_append h)
  simp only [WIRE_VARINT] at h1 h2
  simp [claimsStep, h1, h2, encodeUint64_of_ne hv, WIRE_VARINT, Nat.add_assoc]

theorem claimsStep_subject {s : Bytes} (hdata : data.length < 2 ^ 64)
    (hutf : validUtf8 s = true) (hne : s ≠ []) (hle : s.length ≤ MAX_CLAIM_BYTES_LEN)
    (hlast : last < 4) (h : data.drop pos = encodeBytes 4 s ++ rest) :
    claimsStep data pos last c
      = .ok (pos + (encodeBytes 4 s).length, 4, { c with subject := s }) := by
  rw [encodeBytes_of_ne hne, List.append_assoc, List.append_assoc] at h
  have h1 := nextField_complete (repeated := some SCOPE_FIELD) (last := last) (by omega)
    (by simp [WIRE_LEN]) (.inl hlast) h
  have h2 := readClaimString_complete hdata hutf hne hle
    (by rw [drop_add_of_drop_eq_append h, List.append_assoc])
  simp only [WIRE_LEN] at h1 h2
  simp [claimsStep, h1, h2, encodeBytes_of_ne hne, WIRE_LEN, Nat.add_assoc]

theorem claimsStep_audience {s : Bytes} (hdata : data.length < 2 ^ 64)
    (hutf : validUtf8 s = true) (hne : s ≠ []) (hle : s.length ≤ MAX_CLAIM_BYTES_LEN)
    (hlast : last < 5) (h : data.drop pos = encodeBytes 5 s ++ rest) :
    claimsStep data pos last c
      = .ok (pos + (encodeBytes 5 s).length, 5, { c with audience := s }) := by
  rw [encodeBytes_of_ne hne, List.append_assoc, List.append_assoc] at h
  have h1 := nextField_complete (repeated := some SCOPE_FIELD) (last := last) (by omega)
    (by simp [WIRE_LEN]) (.inl hlast) h
  have h2 := readClaimString_complete hdata hutf hne hle
    (by rw [drop_add_of_drop_eq_append h, List.append_assoc])
  simp only [WIRE_LEN] at h1 h2
  simp [claimsStep, h1, h2, encodeBytes_of_ne hne, WIRE_LEN, Nat.add_assoc]

theorem claimsStep_scope {s : Bytes} (hdata : data.length < 2 ^ 64)
    (hutf : validUtf8 s = true) (hne : s ≠ []) (hle : s.length ≤ MAX_CLAIM_BYTES_LEN)
    (hlast : last ≤ 6) (hcount : c.scopes.length < MAX_SCOPES)
    (hprev : ∀ prev, c.scopes.getLast? = some prev → prev < s)
    (h : data.drop pos = encodeBytes 6 s ++ rest) :
    claimsStep data pos last c
      = .ok (pos + (encodeBytes 6 s).length, 6, { c with scopes := c.scopes ++ [s] }) := by
  rw [encodeBytes_of_ne hne, List.append_assoc, List.append_assoc] at h
  have hord : last < 6 ∨ (6 = last ∧ 6 ≠ 0 ∧ some SCOPE_FIELD = some 6) := by
    by_cases h6 : last = 6
    · exact .inr ⟨h6.symm, by omega, rfl⟩
    · exact .inl (by omega)
  have h1 := nextField_complete (repeated := some SCOPE_FIELD) (last := last) (by omega)
    (by simp [WIRE_LEN]) hord h
  have h2 := readClaimString_complete hdata hutf hne hle
    (by rw [drop_add_of_drop_eq_append h, List.append_assoc])
  simp only [WIRE_LEN] at h1 h2
  cases hl : c.scopes.getLast? with
  | none => simp [claimsStep, h1, h2, hl, hcount, encodeBytes_of_ne hne, WIRE_LEN, Nat.add_assoc]
  | some prev =>
    have : ¬ s ≤ prev := List.not_le.mpr (hprev prev hl)
    simp [claimsStep, h1, h2, hl, hcount, this, encodeBytes_of_ne hne, WIRE_LEN, Nat.add_assoc]

/-- The loop consumes a run of scope fields. -/
theorem claimsLoop_scopes (hdata : data.length < 2 ^ 64) :
    ∀ (l : List Bytes) (pos last : Nat) (c : Claims), last ≤ 6 →
      data.drop pos = encodeScopes l →
      (c.scopes ++ l).length ≤ MAX_SCOPES → (c.scopes ++ l).Pairwise (· < ·) →
      (∀ s ∈ l, s ≠ [] ∧ s.length ≤ MAX_CLAIM_BYTES_LEN ∧ validUtf8 s = true) →
      fieldLoop data.length (claimsStep data) (claimsStep_progress data) pos last c
        = .ok { c with scopes := c.scopes ++ l } := by
  intro l
  induction l with
  | nil =>
    intro pos last c _ hdrop _ _ _
    have : data.length ≤ pos := by
      have := congrArg List.length hdrop
      simp at this
      omega
    rw [fieldLoop_done this]
    simp
  | cons s l ih =>
    intro pos last c hlast hdrop hcount hsorted hentries
    obtain ⟨hne, hle, hutf⟩ := hentries s (by simp)
    rw [encodeScopes_cons] at hdrop
    have hlen : c.scopes.length < MAX_SCOPES := by
      simp only [List.length_append, List.length_cons] at hcount
      omega
    have hprev : ∀ prev, c.scopes.getLast? = some prev → prev < s := by
      intro prev hp
      exact (List.pairwise_append.mp hsorted).2.2 prev (List.mem_of_getLast? hp) s (by simp)
    have hstep := claimsStep_scope (c := c) hdata hutf hne hle hlast hlen hprev hdrop
    have hpos : pos < data.length := by
      apply Classical.byContradiction
      intro hge
      rw [List.drop_of_length_le (by omega), encodeBytes_of_ne hne] at hdrop
      have := congrArg List.length hdrop
      have := encodeVarint_length_pos (UInt64.ofNat s.length)
      simp at *
      omega
    rw [fieldLoop_step hpos hstep,
      ih _ 6 _ (by omega) (drop_add_of_drop_eq_append hdrop) (by simpa using hcount)
        (by simpa using hsorted) (fun x hx => hentries x (by simp [hx]))]
    simp

end Complete

/-- The loop decodes the unsorted encoding of any claims that meet the wire limits. -/
theorem claimsLoop_complete {c : Claims} (hw : c.WireValid)
    (hdata : (serializeClaimsUnsorted c).length < 2 ^ 64) :
    fieldLoop (serializeClaimsUnsorted c).length (claimsStep (serializeClaimsUnsorted c))
      (claimsStep_progress _) 0 0 {} = .ok c := by
  generalize hd : serializeClaimsUnsorted c = data at *
  have h0 : data.drop 0 = encodeUint64 1 c.expiresAt ++ (encodeUint64 2 c.notBefore ++
      (encodeUint64 3 c.issuedAt ++ (encodeBytes 4 c.subject ++ (encodeBytes 5 c.audience ++
      encodeScopes c.scopes)))) := by
    simp [← hd, serializeClaimsUnsorted]
  have hp := claimsStep_progress data
  obtain ⟨p1, l1, hl1, h1, e1⟩ := fieldLoop_optional (hstep := hp) (pos := 0) (last := 0) (f := 1)
    (s := ({} : Claims)) (s' := { expiresAt := c.expiresAt }) h0 (by omega)
    (fun he => by rw [encodeUint64_eq_nil_iff.mp he])
    (fun he => claimsStep_expiresAt (mt encodeUint64_eq_nil_iff.mpr he) (by omega) h0)
  obtain ⟨p2, l2, hl2, h2, e2⟩ := fieldLoop_optional (hstep := hp) (last := l1) (f := 2)
    (s := { expiresAt := c.expiresAt })
    (s' := { expiresAt := c.expiresAt, notBefore := c.notBefore }) h1 (by omega)
    (fun he => by rw [encodeUint64_eq_nil_iff.mp he])
    (fun he => claimsStep_notBefore (mt encodeUint64_eq_nil_iff.mpr he) (by omega) h1)
  obtain ⟨p3, l3, hl3, h3, e3⟩ := fieldLoop_optional (hstep := hp) (last := l2) (f := 3)
    (s := { expiresAt := c.expiresAt, notBefore := c.notBefore })
    (s' := { expiresAt := c.expiresAt, notBefore := c.notBefore, issuedAt := c.issuedAt })
    h2 (by omega) (fun he => by rw [encodeUint64_eq_nil_iff.mp he])
    (fun he => claimsStep_issuedAt (mt encodeUint64_eq_nil_iff.mpr he) (by omega) h2)
  obtain ⟨p4, l4, hl4, h4, e4⟩ := fieldLoop_optional (hstep := hp) (last := l3) (f := 4)
    (s := { expiresAt := c.expiresAt, notBefore := c.notBefore, issuedAt := c.issuedAt })
    (s' := { expiresAt := c.expiresAt, notBefore := c.notBefore, issuedAt := c.issuedAt,
             subject := c.subject })
    h3 (by omega) (fun he => by rw [encodeBytes_eq_nil_iff.mp he])
    (fun he => claimsStep_subject hdata hw.subject_utf8 (mt encodeBytes_eq_nil_iff.mpr he)
      hw.subject_len (by omega) h3)
  obtain ⟨p5, l5, hl5, h5, e5⟩ := fieldLoop_optional (hstep := hp) (last := l4) (f := 5)
    (s := { expiresAt := c.expiresAt, notBefore := c.notBefore, issuedAt := c.issuedAt,
            subject := c.subject })
    (s' := { expiresAt := c.expiresAt, notBefore := c.notBefore, issuedAt := c.issuedAt,
             subject := c.subject, audience := c.audience })
    h4 (by omega) (fun he => by rw [encodeBytes_eq_nil_iff.mp he])
    (fun he => claimsStep_audience hdata hw.audience_utf8 (mt encodeBytes_eq_nil_iff.mpr he)
      hw.audience_len (by omega) h4)
  rw [e1, e2, e3, e4, e5, claimsLoop_scopes hdata c.scopes p5 l5 _ (by omega) h5
    (by simpa using hw.scopes_count) (by simpa using hw.scopes_sorted) hw.scope_entries]
  simp

/-- The Rust type `String` guarantees valid UTF-8. The model states it as a hypothesis. -/
structure Claims.Utf8 (c : Claims) : Prop where
  subject : validUtf8 c.subject = true
  audience : validUtf8 c.audience = true
  scopes : ∀ s ∈ c.scopes, validUtf8 s = true

/-- Valid claims with sorted scopes meet the wire limits. -/
theorem Claims.Valid.wireValid_sorted {c : Claims} (hv : c.Valid) (hu : c.Utf8) :
    Claims.WireValid { c with scopes := sortScopes c.scopes } where
  subject_len := hv.subject_len
  subject_utf8 := hu.subject
  audience_len := hv.audience_len
  audience_utf8 := hu.audience
  scopes_count := by
    have := (sortScopes_perm c.scopes).length_eq
    have := hv.scopes_count
    simp only
    omega
  scope_entries := by
    intro s hs
    have hs : s ∈ c.scopes := (sortScopes_perm c.scopes).mem_iff.mp hs
    exact ⟨(hv.scope_entries s hs).1, (hv.scope_entries s hs).2, hu.scopes s hs⟩
  scopes_sorted := sortScopes_pairwise_lt hv.scopes_nodup

/-- Sorting the scopes keeps claims valid. -/
theorem Claims.Valid.sorted {c : Claims} (hv : c.Valid) :
    Claims.Valid { c with scopes := sortScopes c.scopes } where
  expiresAt_ne_zero := hv.expiresAt_ne_zero
  notBefore_le := hv.notBefore_le
  subject_len := hv.subject_len
  audience_len := hv.audience_len
  scopes_count := by
    have := (sortScopes_perm c.scopes).length_eq
    have := hv.scopes_count
    simp only
    omega
  scope_entries := fun s hs => hv.scope_entries s ((sortScopes_perm c.scopes).mem_iff.mp hs)
  scopes_nodup := (sortScopes_perm c.scopes).nodup_iff.mpr hv.scopes_nodup

theorem serializeClaims_ne_nil {c : Claims} (h : c.expiresAt ≠ 0) : serializeClaims c ≠ [] := by
  intro hnil
  simp only [serializeClaims, serializeClaimsUnsorted, List.append_eq_nil_iff,
    encodeUint64_eq_nil_iff] at hnil
  exact h hnil.1.1.1.1.1

/-- Round trip for claims already in wire form (scopes strictly ascending). -/
theorem deserializeClaims_serializeClaims_of_wireValid {c : Claims} (hw : c.WireValid)
    (hne : serializeClaims c ≠ []) (hsize : (serializeClaims c).length ≤ MAX_PAYLOAD_BYTES) :
    deserializeClaims (serializeClaims c) = .ok c := by
  have hsorted : ({ c with scopes := sortScopes c.scopes } : Claims) = c := by
    rw [sortScopes_of_pairwise_lt hw.scopes_sorted]
  have hsize' : ¬ (serializeClaims c).length > MAX_PAYLOAD_BYTES := by omega
  simp only [deserializeClaims, throw_eq_error, error_bind, pure_eq_ok, ok_bind,
    List.isEmpty_iff, hne, hsize', if_false]
  simp only [serializeClaims, hsorted, MAX_PAYLOAD_BYTES] at hsize ⊢
  exact claimsLoop_complete hw (by omega)

/-- **Claims round trip.** Valid claims whose encoding fits in `MAX_PAYLOAD_BYTES`
decode to themselves, with the scopes sorted. -/
theorem deserializeClaims_serializeClaims {c : Claims} (hv : c.Valid) (hu : c.Utf8)
    (hsize : (serializeClaims c).length ≤ MAX_PAYLOAD_BYTES) :
    deserializeClaims (serializeClaims c) = .ok { c with scopes := sortScopes c.scopes } := by
  have hw := hv.wireValid_sorted hu
  have heq : serializeClaims { c with scopes := sortScopes c.scopes } = serializeClaims c := by
    simp only [serializeClaims, sortScopes_of_pairwise_lt hw.scopes_sorted]
  have := deserializeClaims_serializeClaims_of_wireValid hw
    (heq ▸ serializeClaims_ne_nil hv.expiresAt_ne_zero) (heq ▸ hsize)
  rwa [heq] at this

/-- **Injective Claims encoding.** Claims in wire form with the same encoding are equal. -/
theorem serializeClaims_injective {c1 c2 : Claims} (h1 : c1.WireValid) (h2 : c2.WireValid)
    (hne : serializeClaims c1 ≠ []) (hsize : (serializeClaims c1).length ≤ MAX_PAYLOAD_BYTES)
    (heq : serializeClaims c1 = serializeClaims c2) : c1 = c2 := by
  have e1 := deserializeClaims_serializeClaims_of_wireValid h1 hne hsize
  have e2 := deserializeClaims_serializeClaims_of_wireValid h2 (heq ▸ hne) (heq ▸ hsize)
  rw [heq, e2] at e1
  exact (Except.ok.inj e1).symm

end Protoken
