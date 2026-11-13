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
def MAX_SIGNATURE_BYTES : Nat := 29792
def MAX_PUBLIC_KEY_BYTES : Nat := 2592
def MAX_SECRET_KEY_BYTES : Nat := 2369

def HMAC_MIN_KEY_LEN : Nat := 48
def HMAC_MAX_KEY_LEN : Nat := 128
def KEY_HASH_LEN : Nat := 8

/-! ## Enums -/

inductive Version where
  | v0
  deriving DecidableEq, Repr

def Version.toByte : Version → UInt8
  | .v0 => 0

inductive Algorithm where
  | mlDsa44
  | mlDsa65
  | mlDsa87
  | hmacSha384
  | slhDsaSha2_128s
  | slhDsaSha2_192s
  | slhDsaSha2_256s
  | fnDsa512
  | fnDsa1024
  deriving DecidableEq, Repr

namespace Algorithm

def all : List Algorithm :=
  [.mlDsa44, .mlDsa65, .mlDsa87, .hmacSha384, .slhDsaSha2_128s, .slhDsaSha2_192s, .slhDsaSha2_256s,
    .fnDsa512, .fnDsa1024]

/-- Models `algorithm as u8`. -/
def toByte : Algorithm → UInt8
  | .mlDsa44 => 3
  | .mlDsa65 => 4
  | .mlDsa87 => 5
  | .hmacSha384 => 6
  | .slhDsaSha2_128s => 7
  | .slhDsaSha2_192s => 8
  | .slhDsaSha2_256s => 9
  | .fnDsa512 => 10
  | .fnDsa1024 => 11

/-- Models `Algorithm::try_from(u8)`. -/
def fromByte (b : UInt8) : Option Algorithm :=
  all.find? (·.toByte == b)

def secretKeyLen : Algorithm → Nat
  | .mlDsa44 | .mlDsa65 | .mlDsa87 => 32
  | .hmacSha384 => HMAC_MIN_KEY_LEN
  | .slhDsaSha2_128s => 64
  | .slhDsaSha2_192s => 96
  | .slhDsaSha2_256s => 128
  | .fnDsa512 => 1345
  | .fnDsa1024 => 2369

def publicKeyLen : Algorithm → Option Nat
  | .mlDsa44 => some 1312
  | .mlDsa65 => some 1952
  | .mlDsa87 => some 2592
  | .hmacSha384 => none
  | .slhDsaSha2_128s => some 32
  | .slhDsaSha2_192s => some 48
  | .slhDsaSha2_256s => some 64
  | .fnDsa512 => some 897
  | .fnDsa1024 => some 1793

def signatureLen : Algorithm → Nat
  | .mlDsa44 => 2420
  | .mlDsa65 => 3309
  | .mlDsa87 => 4627
  | .hmacSha384 => 48
  | .slhDsaSha2_128s => 7856
  | .slhDsaSha2_192s => 16224
  | .slhDsaSha2_256s => 29792
  | .fnDsa512 => 666
  | .fnDsa1024 => 1280

def isSymmetric (a : Algorithm) : Bool := a.publicKeyLen.isNone

theorem isSymmetric_iff {a : Algorithm} : a.isSymmetric = true ↔ a = .hmacSha384 := by
  cases a <;> decide

theorem secretKeyLen_bounds (a : Algorithm) :
    0 < a.secretKeyLen ∧ a.secretKeyLen ≤ MAX_SECRET_KEY_BYTES := by
  cases a <;> decide

theorem publicKeyLen_bounds {a : Algorithm} {n : Nat} (h : a.publicKeyLen = some n) :
    0 < n ∧ n ≤ MAX_PUBLIC_KEY_BYTES := by
  cases a <;> cases h <;> decide

theorem signatureLen_bounds (a : Algorithm) :
    0 < a.signatureLen ∧ a.signatureLen ≤ MAX_SIGNATURE_BYTES := by
  cases a <;> decide

@[simp] theorem fromByte_toByte (a : Algorithm) : fromByte a.toByte = some a := by
  cases a <;> rfl

theorem toByte_of_fromByte {b : UInt8} {a : Algorithm} (h : fromByte b = some a) :
    a.toByte = b := by
  simpa using List.find?_some h

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

/-- Models `scopes.iter().find(|scope| !seen.insert(*scope))`. -/
def firstDuplicate (seen : List Bytes) : List Bytes → Option Bytes
  | [] => none
  | scope :: rest => if scope ∈ seen then some scope else firstDuplicate (scope :: seen) rest

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
  if (firstDuplicate [] c.scopes).isSome then
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

theorem firstDuplicate_eq_none (seen l : List Bytes) :
    firstDuplicate seen l = none ↔ l.Nodup ∧ ∀ s ∈ l, s ∉ seen := by
  induction l generalizing seen with
  | nil => simp [firstDuplicate]
  | cons a rest ih =>
    by_cases h : a ∈ seen
    · simp [firstDuplicate, h]
    · simp only [firstDuplicate, h, ite_false, ih, List.nodup_cons, List.mem_cons, not_or,
        forall_eq_or_imp, not_false_eq_true, true_and]
      constructor
      · rintro ⟨hn, hs⟩
        exact ⟨⟨fun ha => (hs a ha).1 rfl, hn⟩, fun s hm => (hs s hm).2⟩
      · rintro ⟨⟨ha, hn⟩, hs⟩
        exact ⟨hn, fun s hm => ⟨fun he => ha (he ▸ hm), hs s hm⟩⟩

/-- The search finds nothing exactly when the scopes are distinct. -/
theorem firstDuplicate_eq_none_iff (l : List Bytes) : firstDuplicate [] l = none ↔ l.Nodup := by
  simp [firstDuplicate_eq_none]

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
  have hdup : (firstDuplicate [] c.scopes).isSome = true ↔ ¬ c.scopes.Nodup := by
    rw [← firstDuplicate_eq_none_iff]
    cases firstDuplicate [] c.scopes <;> simp
  simp only [Claims.validate, throw_eq_error, error_bind, pure_eq_ok, bind_unit_eq_ok,
    ite_error_eq_ok, checkClaimLen_eq_ok_iff, validateScopeEntries_eq_ok_iff, hdup, beq_iff_eq,
    Decidable.not_not, and_true, gt_iff_lt, UInt64.not_lt, Nat.not_lt]
  constructor
  · rintro ⟨h1, h2, h3, h4, h5, h6, h7⟩
    exact ⟨h1, h2, h3, h4, h5, h6, h7⟩
  · rintro ⟨h1, h2, h3, h4, h5, h6, h7⟩
    exact ⟨h1, h2, h3, h4, h5, h6, h7⟩

end Protoken
