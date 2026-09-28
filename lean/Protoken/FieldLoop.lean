import Protoken.Proto3

/-!
# The decoder loop

Every message decoder in the Rust code has the shape

```rust
let mut pos = 0;
let mut last_field_number = 0;
while pos < data.len() {
    let (field_number, wire_type) = next_field(data, &mut pos, &mut last_field_number, ..)?;
    match (field_number, wire_type) { .. }
}
```

`fieldLoop` models the `while`. The loop body is a `Step`.
-/

namespace Protoken

/-- A loop body: maps `(pos, last_field_number, state)` to their values after one field. -/
abbrev Step (σ : Type) := Nat → Nat → σ → Result (Nat × Nat × σ)

/-- A loop body that always consumes input, so the loop terminates. -/
def Step.Progress {σ : Type} (step : Step σ) : Prop :=
  ∀ pos last s pos' last' s', step pos last s = .ok (pos', last', s') → pos < pos'

/-- Models `while pos < len { step }`. -/
def fieldLoop {σ : Type} (len : Nat) (step : Step σ) (hstep : step.Progress)
    (pos last : Nat) (s : σ) : Result σ :=
  if pos < len then
    match _ : step pos last s with
    | .error e => .error e
    | .ok (pos', last', s') => fieldLoop len step hstep pos' last' s'
  else
    .ok s
termination_by len - pos
decreasing_by
  have := hstep _ _ _ _ _ _ (by assumption)
  omega

variable {σ : Type} {len : Nat} {step : Step σ} {hstep : step.Progress}

theorem fieldLoop_done {pos last : Nat} {s : σ} (h : len ≤ pos) :
    fieldLoop len step hstep pos last s = .ok s := by
  rw [fieldLoop, if_neg (by omega)]

theorem fieldLoop_step {pos last pos' last' : Nat} {s s' : σ} (hlt : pos < len)
    (h : step pos last s = .ok (pos', last', s')) :
    fieldLoop len step hstep pos last s = fieldLoop len step hstep pos' last' s' := by
  rw [fieldLoop, if_pos hlt]
  split
  · rename_i e he
    rw [h] at he
    cases he
  · rename_i p l t he
    rw [h] at he
    cases he
    rfl

theorem fieldLoop_error {pos last : Nat} {s : σ} {e : Error} (hlt : pos < len)
    (h : step pos last s = .error e) :
    fieldLoop len step hstep pos last s = .error e := by
  rw [fieldLoop, if_pos hlt]
  split
  · rename_i e' he
    rw [h] at he
    cases he
    rfl
  · rename_i p l t he
    rw [h] at he
    cases he

/-- Loop invariant rule. If `Inv` holds at the start and every successful step
preserves it, it holds when the loop exits. -/
theorem fieldLoop_invariant (Inv : Nat → Nat → σ → Prop)
    (hpres : ∀ pos last s pos' last' s', pos < len → Inv pos last s →
      step pos last s = .ok (pos', last', s') → Inv pos' last' s') :
    ∀ (n pos last : Nat) (s result : σ), len - pos ≤ n → Inv pos last s →
      fieldLoop len step hstep pos last s = .ok result →
      ∃ pos' last', len ≤ pos' ∧ Inv pos' last' result := by
  intro n
  induction n with
  | zero =>
    intro pos last s result hn hinv h
    rw [fieldLoop_done (by omega)] at h
    cases h
    exact ⟨pos, last, by omega, hinv⟩
  | succ n ih =>
    intro pos last s result hn hinv h
    by_cases hlt : pos < len
    · cases hs : step pos last s with
      | error e =>
        rw [fieldLoop_error hlt hs] at h
        cases h
      | ok r =>
        obtain ⟨pos', last', s'⟩ := r
        rw [fieldLoop_step hlt hs] at h
        have := hstep _ _ _ _ _ _ hs
        exact ih pos' last' s' result (by omega) (hpres _ _ _ _ _ _ hlt hinv hs) h
    · rw [fieldLoop_done (by omega)] at h
      cases h
      exact ⟨pos, last, by omega, hinv⟩

/-- Advance the loop over one optional field. `enc` is the field's encoding. It
is either empty, and then the state is unchanged, or the step consumes it. -/
theorem fieldLoop_optional {data : Bytes} {step : Step σ} {hstep : step.Progress}
    {pos last f : Nat} {s s' : σ} {enc rest : Bytes}
    (hdrop : data.drop pos = enc ++ rest) (hlast : last ≤ f)
    (hskip : enc = [] → s' = s)
    (hrun : enc ≠ [] → step pos last s = .ok (pos + enc.length, f, s')) :
    ∃ pos' last', last' ≤ f ∧ data.drop pos' = rest ∧
      fieldLoop data.length step hstep pos last s
        = fieldLoop data.length step hstep pos' last' s' := by
  by_cases henc : enc = []
  · subst henc
    exact ⟨pos, last, hlast, by simpa using hdrop, by rw [hskip rfl]⟩
  · refine ⟨pos + enc.length, f, Nat.le_refl _, drop_add_of_drop_eq_append hdrop,
      fieldLoop_step ?_ (hrun henc)⟩
    apply Classical.byContradiction
    intro hge
    rw [List.drop_of_length_le (by omega)] at hdrop
    exact henc (List.append_eq_nil_iff.mp hdrop.symm).1

end Protoken
