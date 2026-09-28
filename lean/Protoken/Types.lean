import Protoken.Basic

/-!
# Core types

Model of `src/types.rs`: size limits, `Algorithm`, `KeyIdType`, `KeyIdentifier`,
`Claims`, `SignedToken`, and `Claims::validate`.

A Rust `String` is modelled by its UTF-8 bytes. Rust compares strings byte by
byte, which is the lexicographic order on `List UInt8`.
-/

namespace Protoken

/-! ## Limits -/

def MAX_CLAIM_BYTES_LEN : Nat := 255
def MAX_SCOPES : Nat := 32
def MAX_PAYLOAD_BYTES : Nat := 4096
def MAX_SIGNATURE_BYTES : Nat := 2560

def HMAC_MIN_KEY_LEN : Nat := 32
def HMAC_SHA256_SIG_LEN : Nat := 32
def KEY_HASH_LEN : Nat := 8
def ED25519_SEED_LEN : Nat := 32
def ED25519_PUBLIC_KEY_LEN : Nat := 32
def ED25519_SIG_LEN : Nat := 64
def MLDSA44_SEED_LEN : Nat := 32
def MLDSA44_PUBLIC_KEY_LEN : Nat := 1312
def MLDSA44_SIG_LEN : Nat := 2420

/-! ## Enums -/

inductive Version where
  | v0
  deriving DecidableEq, Repr

def Version.toByte : Version → UInt8
  | .v0 => 0

inductive Algorithm where
  | hmacSha256
  | ed25519
  | mlDsa44
  deriving DecidableEq, Repr

namespace Algorithm

def fromByte (b : UInt8) : Option Algorithm :=
  if b == 1 then some .hmacSha256
  else if b == 2 then some .ed25519
  else if b == 3 then some .mlDsa44
  else none

def toByte : Algorithm → UInt8
  | .hmacSha256 => 1
  | .ed25519 => 2
  | .mlDsa44 => 3

def isSymmetric (a : Algorithm) : Bool := a == .hmacSha256

def publicKeyLen : Algorithm → Option Nat
  | .hmacSha256 => none
  | .ed25519 => some ED25519_PUBLIC_KEY_LEN
  | .mlDsa44 => some MLDSA44_PUBLIC_KEY_LEN

def signatureLen : Algorithm → Nat
  | .hmacSha256 => HMAC_SHA256_SIG_LEN
  | .ed25519 => ED25519_SIG_LEN
  | .mlDsa44 => MLDSA44_SIG_LEN

@[simp] theorem fromByte_toByte (a : Algorithm) : fromByte a.toByte = some a := by
  cases a <;> rfl

theorem toByte_of_fromByte {b : UInt8} {a : Algorithm} (h : fromByte b = some a) :
    a.toByte = b := by
  unfold fromByte at h
  repeat' split at h
  all_goals simp_all [toByte]
  all_goals subst h; rfl

@[simp] theorem toByte_ne_zero (a : Algorithm) : a.toByte ≠ 0 := by
  cases a <;> decide

theorem toByte_injective {a b : Algorithm} (h : a.toByte = b.toByte) : a = b := by
  have := congrArg fromByte h
  simpa using this

end Algorithm

inductive KeyIdType where
  | keyHash
  | publicKey
  deriving DecidableEq, Repr

namespace KeyIdType

def fromByte (b : UInt8) : Option KeyIdType :=
  if b == 1 then some .keyHash
  else if b == 2 then some .publicKey
  else none

def toByte : KeyIdType → UInt8
  | .keyHash => 1
  | .publicKey => 2

@[simp] theorem fromByte_toByte (t : KeyIdType) : fromByte t.toByte = some t := by
  cases t <;> rfl

theorem toByte_of_fromByte {b : UInt8} {t : KeyIdType} (h : fromByte b = some t) :
    t.toByte = b := by
  unfold fromByte at h
  repeat' split at h
  all_goals simp_all [toByte]
  all_goals subst h; rfl

@[simp] theorem toByte_ne_zero (t : KeyIdType) : t.toByte ≠ 0 := by
  cases t <;> decide

theorem toByte_injective {a b : KeyIdType} (h : a.toByte = b.toByte) : a = b := by
  have := congrArg fromByte h
  simpa using this

end KeyIdType

/-! ## Key identifier -/

/-- Models `[u8; KEY_HASH_LEN]`. -/
abbrev KeyHash := { b : Bytes // b.length = KEY_HASH_LEN }

inductive KeyIdentifier where
  | keyHash (hash : KeyHash)
  | publicKey (pk : Bytes)
  deriving DecidableEq, Repr

namespace KeyIdentifier

def keyIdType : KeyIdentifier → KeyIdType
  | .keyHash _ => .keyHash
  | .publicKey _ => .publicKey

def asBytes : KeyIdentifier → Bytes
  | .keyHash hash => hash.val
  | .publicKey pk => pk

/-- A key identifier is determined by its type and its bytes. -/
theorem ext_bytes {a b : KeyIdentifier} (ht : a.keyIdType = b.keyIdType)
    (hb : a.asBytes = b.asBytes) : a = b := by
  cases a <;> cases b <;> simp_all [keyIdType, asBytes]
  exact Subtype.ext hb

end KeyIdentifier

/-! ## Claims -/

structure Claims where
  expiresAt : UInt64 := 0
  notBefore : UInt64 := 0
  issuedAt : UInt64 := 0
  subject : Bytes := []
  audience : Bytes := []
  scopes : List Bytes := []
  deriving DecidableEq, Repr

/-- Models `sort_unstable` on a list of strings. Equal strings cannot be told
apart, so every correct sort returns this list. -/
def sortScopes (scopes : List Bytes) : List Bytes :=
  scopes.mergeSort (fun a b => decide (a ≤ b))

/-- Models `check_claim_len`. -/
def checkClaimLen (value : Bytes) : Result Unit :=
  if value.length > MAX_CLAIM_BYTES_LEN then .error .malformedEncoding else .ok ()

/-- Models `<[String]>::is_sorted`. -/
def isSorted : List Bytes → Bool
  | a :: b :: rest => decide (a ≤ b) && isSorted (b :: rest)
  | _ => true

/-- The loop of `adjacent_duplicate`. -/
def adjacentDuplicateLoop (previous : Option Bytes) : List Bytes → Option Bytes
  | [] => none
  | scope :: rest =>
    if previous = some scope then some scope else adjacentDuplicateLoop (some scope) rest

/-- Models `adjacent_duplicate`. -/
def adjacentDuplicate (sorted : List Bytes) : Option Bytes :=
  adjacentDuplicateLoop none sorted

/-- Models `first_duplicate`. -/
def firstDuplicate (scopes : List Bytes) : Option Bytes :=
  if isSorted scopes then adjacentDuplicate scopes else adjacentDuplicate (sortScopes scopes)

/-- The per-scope loop in `Claims::validate`. -/
def validateScopeEntries : List Bytes → Result Unit
  | [] => .ok ()
  | scope :: rest => do
    if scope.isEmpty then
      throw .malformedEncoding
    checkClaimLen scope
    validateScopeEntries rest

/-- Models `Claims::validate`. -/
def Claims.validate (c : Claims) : Result Unit := do
  if c.expiresAt == 0 then
    throw .malformedEncoding
  if c.notBefore > c.expiresAt then
    throw .malformedEncoding
  checkClaimLen c.subject
  checkClaimLen c.audience
  if c.scopes.length > MAX_SCOPES then
    throw .malformedEncoding
  validateScopeEntries c.scopes
  if (firstDuplicate c.scopes).isSome then
    throw .malformedEncoding
  pure ()

/-! ## Signed token -/

structure SignedToken where
  version : Version
  algorithm : Algorithm
  keyIdentifier : KeyIdentifier
  payload : Bytes
  signature : Bytes
  deriving DecidableEq, Repr

/-! ## UTF-8 -/

def isContinuation (b : UInt8) : Bool := 0x80 ≤ b && b ≤ 0xBF

/-- Models `std::str::from_utf8(..).is_ok()`: the well-formed byte sequences of
the Unicode Standard, table 3-7. -/
def validUtf8 : Bytes → Bool
  | [] => true
  | b0 :: rest =>
    if b0 ≤ 0x7F then
      validUtf8 rest
    else if 0xC2 ≤ b0 && b0 ≤ 0xDF then
      match rest with
      | b1 :: rest => isContinuation b1 && validUtf8 rest
      | _ => false
    else if 0xE0 ≤ b0 && b0 ≤ 0xEF then
      match rest with
      | b1 :: b2 :: rest =>
        (if b0 == 0xE0 then 0xA0 ≤ b1 && b1 ≤ 0xBF
         else if b0 == 0xED then 0x80 ≤ b1 && b1 ≤ 0x9F
         else isContinuation b1)
        && isContinuation b2 && validUtf8 rest
      | _ => false
    else if 0xF0 ≤ b0 && b0 ≤ 0xF4 then
      match rest with
      | b1 :: b2 :: b3 :: rest =>
        (if b0 == 0xF0 then 0x90 ≤ b1 && b1 ≤ 0xBF
         else if b0 == 0xF4 then 0x80 ≤ b1 && b1 ≤ 0x8F
         else isContinuation b1)
        && isContinuation b2 && isContinuation b3 && validUtf8 rest
      | _ => false
    else
      false

/-! ## Order and sorting lemmas -/

theorem bytes_le_trans {a b c : Bytes} (h1 : a ≤ b) (h2 : b ≤ c) : a ≤ c :=
  List.le_trans h1 h2

theorem bytes_le_antisymm {a b : Bytes} (h1 : a ≤ b) (h2 : b ≤ a) : a = b :=
  List.le_antisymm h1 h2

theorem bytes_le_of_lt {a b : Bytes} (h : a < b) : a ≤ b :=
  List.le_of_lt h

theorem bytes_lt_irrefl (a : Bytes) : ¬ a < a :=
  List.lt_irrefl a

theorem bytes_lt_of_le_of_ne {a b : Bytes} (h : a ≤ b) (hne : a ≠ b) : a < b := by
  rcases List.le_iff_lt_or_eq.mp h with h | h
  · exact h
  · exact absurd h hne

theorem sortScopes_perm (l : List Bytes) : (sortScopes l).Perm l :=
  List.mergeSort_perm l _

theorem sortScopes_pairwise_le (l : List Bytes) : (sortScopes l).Pairwise (· ≤ ·) := by
  have := List.pairwise_mergeSort (le := fun (a b : Bytes) => decide (a ≤ b))
    (fun a b c h1 h2 => by simp only [decide_eq_true_eq] at *; exact bytes_le_trans h1 h2)
    (fun a b => by simpa using List.le_total a b) l
  simpa [sortScopes] using this

/-- Sorting a sorted list changes nothing. -/
theorem sortScopes_of_pairwise_le {l : List Bytes} (h : l.Pairwise (· ≤ ·)) :
    sortScopes l = l :=
  List.mergeSort_of_pairwise (by simpa using h)

theorem sortScopes_of_pairwise_lt {l : List Bytes} (h : l.Pairwise (· < ·)) :
    sortScopes l = l :=
  sortScopes_of_pairwise_le (h.imp bytes_le_of_lt)

/-- A sorted list without duplicates is strictly ascending. -/
theorem pairwise_lt_of_le_of_nodup {l : List Bytes} (h : l.Pairwise (· ≤ ·)) (hn : l.Nodup) :
    l.Pairwise (· < ·) := by
  have := h.and hn
  exact this.imp fun ⟨h1, h2⟩ => bytes_lt_of_le_of_ne h1 h2

theorem nodup_of_pairwise_lt {l : List Bytes} (h : l.Pairwise (· < ·)) : l.Nodup :=
  h.imp fun {a b} (hlt : a < b) (heq : a = b) => bytes_lt_irrefl b (heq ▸ hlt)

theorem sortScopes_pairwise_lt {l : List Bytes} (hn : l.Nodup) :
    (sortScopes l).Pairwise (· < ·) :=
  pairwise_lt_of_le_of_nodup (sortScopes_pairwise_le l) ((sortScopes_perm l).nodup_iff.mpr hn)

theorem isSorted_iff (l : List Bytes) : isSorted l = true ↔ l.Pairwise (· ≤ ·) := by
  induction l with
  | nil => simp [isSorted]
  | cons a l ih =>
    cases l with
    | nil => simp [isSorted]
    | cons b rest =>
      simp only [isSorted, Bool.and_eq_true, decide_eq_true_eq, ih]
      constructor
      · rintro ⟨hab, hrest⟩
        refine List.pairwise_cons.mpr ⟨?_, hrest⟩
        intro x hx
        rcases List.mem_cons.mp hx with rfl | hx
        · exact hab
        · exact bytes_le_trans hab ((List.pairwise_cons.mp hrest).1 x hx)
      · intro h
        obtain ⟨h1, h2⟩ := List.pairwise_cons.mp h
        exact ⟨h1 b (by simp), h2⟩

theorem adjacentDuplicateLoop_some (p : Bytes) (l : List Bytes)
    (h : (p :: l).Pairwise (· ≤ ·)) :
    adjacentDuplicateLoop (some p) l = none ↔ (p :: l).Nodup := by
  induction l generalizing p with
  | nil => simp [adjacentDuplicateLoop]
  | cons s rest ih =>
    obtain ⟨hp, hrest⟩ := List.pairwise_cons.mp h
    simp only [adjacentDuplicateLoop, Option.some.injEq]
    by_cases hps : p = s
    · simp [hps]
    · rw [if_neg hps, ih s hrest]
      constructor
      · intro hn
        refine List.nodup_cons.mpr ⟨?_, hn⟩
        intro hmem
        rcases List.mem_cons.mp hmem with h | hmem
        · exact hps h
        · exact hps (bytes_le_antisymm (hp s (by simp)) ((List.pairwise_cons.mp hrest).1 p hmem))
      · intro hn
        exact (List.nodup_cons.mp hn).2

theorem adjacentDuplicate_eq_none_iff {l : List Bytes} (h : l.Pairwise (· ≤ ·)) :
    adjacentDuplicate l = none ↔ l.Nodup := by
  cases l with
  | nil => simp [adjacentDuplicate, adjacentDuplicateLoop]
  | cons a rest =>
    simpa [adjacentDuplicate, adjacentDuplicateLoop] using adjacentDuplicateLoop_some a rest h

/-- `first_duplicate` finds nothing exactly when the scopes are distinct. -/
theorem firstDuplicate_eq_none_iff (l : List Bytes) : firstDuplicate l = none ↔ l.Nodup := by
  unfold firstDuplicate
  split
  · rename_i h
    exact adjacentDuplicate_eq_none_iff ((isSorted_iff l).mp h)
  · rw [adjacentDuplicate_eq_none_iff (sortScopes_pairwise_le l)]
    exact (sortScopes_perm l).nodup_iff

/-! ## What `validate` checks -/

/-- The rules `Claims::validate` enforces, as a proposition. -/
structure Claims.Valid (c : Claims) : Prop where
  expiresAt_ne_zero : c.expiresAt ≠ 0
  notBefore_le : c.notBefore ≤ c.expiresAt
  subject_len : c.subject.length ≤ MAX_CLAIM_BYTES_LEN
  audience_len : c.audience.length ≤ MAX_CLAIM_BYTES_LEN
  scopes_count : c.scopes.length ≤ MAX_SCOPES
  scope_entries : ∀ s ∈ c.scopes, s ≠ [] ∧ s.length ≤ MAX_CLAIM_BYTES_LEN
  scopes_nodup : c.scopes.Nodup

theorem checkClaimLen_eq_ok_iff (v : Bytes) :
    checkClaimLen v = .ok () ↔ v.length ≤ MAX_CLAIM_BYTES_LEN := by
  unfold checkClaimLen
  split <;> simp <;> omega

theorem validateScopeEntries_eq_ok_iff (l : List Bytes) :
    validateScopeEntries l = .ok () ↔ ∀ s ∈ l, s ≠ [] ∧ s.length ≤ MAX_CLAIM_BYTES_LEN := by
  induction l with
  | nil => simp [validateScopeEntries]
  | cons s rest ih =>
    simp only [validateScopeEntries, List.mem_cons, forall_eq_or_imp]
    by_cases hs : s = []
    · simp [hs]
    · simp [hs, checkClaimLen_eq_ok_iff, ih]

theorem Claims.validate_eq_ok_iff (c : Claims) : c.validate = .ok () ↔ c.Valid := by
  have hdup : (firstDuplicate c.scopes).isSome = true ↔ ¬ c.scopes.Nodup := by
    rw [← firstDuplicate_eq_none_iff]
    cases firstDuplicate c.scopes <;> simp
  simp only [Claims.validate, throw_eq_error, error_bind, pure_eq_ok, bind_unit_eq_ok,
    ite_error_eq_ok, checkClaimLen_eq_ok_iff, validateScopeEntries_eq_ok_iff, hdup, beq_iff_eq,
    Decidable.not_not, and_true, true_and, gt_iff_lt, UInt64.not_lt, Nat.not_lt]
  constructor
  · rintro ⟨h1, h2, h3, h4, h5, h6, h7⟩
    exact ⟨h1, h2, h3, h4, h5, h6, h7⟩
  · rintro ⟨h1, h2, h3, h4, h5, h6, h7⟩
    exact ⟨h1, h2, h3, h4, h5, h6, h7⟩

end Protoken
