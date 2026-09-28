/-!
# Shared definitions

Byte strings, the error type, and small lemmas used by every other file.
-/

namespace Protoken

/-- A byte string. Models `&[u8]`, `Vec<u8>`, and the bytes of a `String`. -/
abbrev Bytes := List UInt8

/-- Models `ProtokenError` (`src/error.rs`). Message strings are dropped; the
variant and its numeric fields are kept. Variants that only the CLI or the
random number generator can produce are omitted. -/
inductive Error where
  | invalidVersion (version : UInt8)
  | invalidAlgorithm (byte : UInt8)
  | invalidKeyIdType (byte : UInt8)
  | invalidKeyLength (expected actual : Nat)
  | invalidKey
  | signingFailed
  | verificationFailed
  | tokenExpired (expiredAt now : UInt64)
  | tokenNotYetValid (notBefore now : UInt64)
  | keyHashMismatch
  | malformedEncoding
  deriving DecidableEq, Repr

/-- Models `Result<T, ProtokenError>`. -/
abbrev Result (α : Type) := Except Error α

/-- `x >>= f` succeeds exactly when both steps succeed. -/
@[simp] theorem bind_eq_ok {α β : Type} {x : Result α} {f : α → Result β} {b : β} :
    (x >>= f) = .ok b ↔ ∃ a, x = .ok a ∧ f a = .ok b := by
  cases x <;> simp [bind, Except.bind]

@[simp] theorem ok_bind {α β : Type} (a : α) (f : α → Result β) :
    ((.ok a : Result α) >>= f) = f a := rfl

@[simp] theorem error_bind {α β : Type} (e : Error) (f : α → Result β) :
    ((.error e : Result α) >>= f) = .error e := rfl

@[simp] theorem pure_eq_ok {α : Type} (a : α) : (pure a : Result α) = .ok a := rfl

@[simp] theorem throw_eq_error {α : Type} (e : Error) : (throw e : Result α) = .error e := rfl

@[simp high] theorem bind_unit_eq_ok {β : Type} {x : Result Unit} {f : Unit → Result β} {b : β} :
    (x >>= f) = .ok b ↔ x = .ok () ∧ f () = .ok b := by
  cases x <;> simp [bind, Except.bind]

@[simp] theorem exists_unit {p : Unit → Prop} : (∃ u, p u) ↔ p () :=
  ⟨fun ⟨(), h⟩ => h, fun h => ⟨(), h⟩⟩

/-- `if c { return Err(e) }` followed by `x` succeeds when `c` is false and `x` succeeds. -/
@[simp] theorem ite_error_eq_ok {α : Type} {c : Prop} [Decidable c] {e : Error} {x : Result α}
    {a : α} : (if c then .error e else x) = .ok a ↔ ¬c ∧ x = .ok a := by
  split <;> simp [*]

/-- Reading one byte at `pos` extends the consumed prefix by that byte. -/
theorem take_succ_eq (data : Bytes) (pos : Nat) (h : pos < data.length) :
    data.take (pos + 1) = data.take pos ++ [data[pos]] :=
  (List.take_append_getElem h).symm

/-- If the unread input starts with `b`, then `pos` is in bounds and holds `b`. -/
theorem drop_eq_cons {data : Bytes} {pos : Nat} {b : UInt8} {rest : Bytes}
    (h : data.drop pos = b :: rest) :
    ∃ hlt : pos < data.length, data[pos] = b ∧ data.drop (pos + 1) = rest := by
  have hlt : pos < data.length := by
    apply Classical.byContradiction
    intro hge
    rw [List.drop_of_length_le (by omega)] at h
    cases h
  rw [List.drop_eq_getElem_cons hlt] at h
  injection h with h1 h2
  exact ⟨hlt, h1, h2⟩

/-- Skipping a known prefix of the unread input leaves the rest. -/
theorem drop_add_of_drop_eq_append {data : Bytes} {pos : Nat} {xs rest : Bytes}
    (h : data.drop pos = xs ++ rest) : data.drop (pos + xs.length) = rest := by
  rw [← List.drop_drop, h]
  simp

end Protoken
