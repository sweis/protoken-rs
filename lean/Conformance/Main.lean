import Std.Data.HashMap
import Protoken.Keys
import Conformance.Sha256

/-!
# Conformance runner

Replays cases produced by `examples/gen_lean_cases.rs` through the Lean model and
compares each result with what the Rust library returned. This is the evidence that
the model in `Protoken/` describes the Rust code.

Input is read from stdin, one case per line: an operation name, its arguments, and
the expected result, separated by spaces. Byte strings are lowercase hex, with `-`
for the empty string.

SHA-256 and HMAC run in Lean. Ed25519 and ML-DSA-44 are not implemented here, so
each case carries the answers of the primitive calls it needs (an `Oracle`).
-/

namespace Conformance

open Protoken

/-! ## Text encoding -/

def hexDigit (n : Nat) : Char :=
  if n < 10 then Char.ofNat (48 + n) else Char.ofNat (87 + n)

def hexEncode (b : Bytes) : String :=
  if b.isEmpty then "-"
  else String.ofList (b.flatMap fun x => [hexDigit (x.toNat / 16), hexDigit (x.toNat % 16)])

def hexValue (c : Char) : Option Nat :=
  if '0' ≤ c ∧ c ≤ '9' then some (c.toNat - 48)
  else if 'a' ≤ c ∧ c ≤ 'f' then some (c.toNat - 87)
  else none

def hexDecodeChars : List Char → List UInt8 → Option Bytes
  | [], acc => some acc.reverse
  | hi :: lo :: rest, acc => do
    let h ← hexValue hi
    let l ← hexValue lo
    hexDecodeChars rest (UInt8.ofNat (16 * h + l) :: acc)
  | _, _ => none

def hexDecode (s : String) : Option Bytes :=
  if s == "-" then some [] else hexDecodeChars s.toList []

def parseU64 (s : String) : Option UInt64 :=
  s.toNat?.map UInt64.ofNat

def parseBool (s : String) : Option Bool :=
  if s == "1" then some true else if s == "0" then some false else none

def parseAlgorithm (s : String) : Option Algorithm :=
  s.toNat?.bind fun n => Algorithm.fromByte (UInt8.ofNat n)

def parseKeyIdType (s : String) : Option KeyIdType :=
  s.toNat?.bind fun n => KeyIdType.fromByte (UInt8.ofNat n)

def renderError : Error → String
  | .invalidVersion v => s!"err:InvalidVersion:{v.toNat}"
  | .invalidAlgorithm b => s!"err:InvalidAlgorithm:{b.toNat}"
  | .invalidKeyIdType b => s!"err:InvalidKeyIdType:{b.toNat}"
  | .invalidKeyLength e a => s!"err:InvalidKeyLength:{e}:{a}"
  | .invalidKey => "err:InvalidKey"
  | .signingFailed => "err:SigningFailed"
  | .verificationFailed => "err:VerificationFailed"
  | .tokenExpired e n => s!"err:TokenExpired:{e.toNat}:{n.toNat}"
  | .tokenNotYetValid b n => s!"err:TokenNotYetValid:{b.toNat}:{n.toNat}"
  | .keyHashMismatch => "err:KeyHashMismatch"
  | .malformedEncoding => "err:MalformedEncoding"

def renderResult {α : Type} (render : α → String) : Result α → String
  | .ok a => "ok:" ++ render a
  | .error e => renderError e

/-- `expires_at:not_before:issued_at:subject:audience:scopes`. The scopes are joined
with commas, and `.` stands for no scopes. -/
def renderClaims (c : Claims) : String :=
  let scopes := if c.scopes.isEmpty then "." else ",".intercalate (c.scopes.map hexEncode)
  s!"{c.expiresAt.toNat}:{c.notBefore.toNat}:{c.issuedAt.toNat}:{hexEncode c.subject}:" ++
    s!"{hexEncode c.audience}:{scopes}"

def parseClaims (s : String) : Option Claims :=
  match s.splitOn ":" with
  | [exp, nbf, iat, sub, aud, scopes] => do
    let scopes ← if scopes == "." then some [] else (scopes.splitOn ",").mapM hexDecode
    some {
      expiresAt := ← parseU64 exp, notBefore := ← parseU64 nbf, issuedAt := ← parseU64 iat,
      subject := ← hexDecode sub, audience := ← hexDecode aud, scopes }
  | _ => none

def renderKeyIdentifier (k : KeyIdentifier) : String :=
  s!"{k.keyIdType.toByte.toNat}:{hexEncode k.asBytes}"

def parseKeyIdentifier (idType bytes : String) : Option KeyIdentifier := do
  let bytes ← hexDecode bytes
  match ← parseKeyIdType idType with
  | .keyHash => if h : bytes.length = KEY_HASH_LEN then some (.keyHash ⟨bytes, h⟩) else none
  | .publicKey => some (.publicKey bytes)

def renderToken (t : SignedToken) : String :=
  s!"{t.algorithm.toByte.toNat}:{renderKeyIdentifier t.keyIdentifier}:{hexEncode t.payload}:" ++
    hexEncode t.signature

def renderVerified (v : VerifiedToken) : String :=
  s!"{v.algorithm.toByte.toNat}:{renderKeyIdentifier v.keyIdentifier}:{renderClaims v.claims}"

def renderSigningKey (k : SigningKey) : String :=
  s!"{k.algorithm.toByte.toNat}:{hexEncode k.secretKey}:{hexEncode k.publicKey}"

def renderVerifyingKey (k : VerifyingKey) : String :=
  s!"{k.algorithm.toByte.toNat}:{hexEncode k.publicKey}"

/-! ## Primitives -/

/-- Answers from the Rust primitives for the calls one case can make. Each case
makes at most one call of each kind. -/
structure Oracle where
  /-- Public key derived from the case's seed. -/
  derived : Bytes := []
  /-- Whether the case's Ed25519 public key decodes to a curve point. -/
  point : Bool := false
  /-- Whether the case's signature verifies over the bytes before the signature field. -/
  sigOk : Bool := false
  /-- Signature over the case's signing input. -/
  signature : Bytes := []

def fixLen (n : Nat) (b : Bytes) : Bytes := (b ++ List.replicate n 0).take n

theorem fixLen_length (n : Nat) (b : Bytes) : (fixLen n b).length = n := by
  simp [fixLen]

def cryptoOf (o : Oracle) : Crypto where
  sha256 := sha256
  sha256_length := sha256_length
  hmacSha256 := hmacSha256
  hmacSha256_length := hmacSha256_length
  ed25519PublicKey _ := fixLen ED25519_PUBLIC_KEY_LEN o.derived
  ed25519PublicKey_length _ := fixLen_length _ _
  ed25519Sign _ _ := fixLen ED25519_SIG_LEN o.signature
  ed25519Sign_length _ _ := fixLen_length _ _
  ed25519PointValid _ := o.point
  ed25519VerifyStrict _ _ _ := o.sigOk
  mldsa44PublicKey _ := fixLen MLDSA44_PUBLIC_KEY_LEN o.derived
  mldsa44PublicKey_length _ := fixLen_length _ _
  mldsa44Sign _ _ := some (fixLen MLDSA44_SIG_LEN o.signature)
  mldsa44Sign_length _ _ _ h := by
    cases h
    exact fixLen_length _ _
  mldsa44Verify _ _ _ := o.sigOk

/-! ## Cases -/

/-- Run one case. Returns the model's result and the expected result, or `none` if
the line cannot be parsed. -/
def runCase : List String → Option (String × String)
  | ["varint", data, expected] => do
    let r := decodeVarint (← hexDecode data) 0
    some (renderResult (fun (v, pos) => s!"{v.toNat}:{pos}") r, expected)
  | ["encvarint", value, expected] => do
    some (hexEncode (encodeVarint (← parseU64 value)), expected)
  | ["utf8", data, expected] => do
    some (if validUtf8 (← hexDecode data) then "1" else "0", expected)
  | ["sha256", data, expected] => do
    some (hexEncode (sha256 (← hexDecode data)), expected)
  | ["hmac", key, data, expected] => do
    some (hexEncode (hmacSha256 (← hexDecode key) (← hexDecode data)), expected)
  | ["claims", data, expected] => do
    some (renderResult renderClaims (deserializeClaims (← hexDecode data)), expected)
  | ["validate", claims, expected] => do
    some (renderResult (fun _ => "") (← parseClaims claims).validate, expected)
  | ["serclaims", claims, expected] => do
    some (hexEncode (serializeClaims (← parseClaims claims)), expected)
  | ["token", data, expected] => do
    some (renderResult renderToken (deserializeSignedToken (← hexDecode data)), expected)
  | ["signinput", alg, idType, keyId, payload, expected] => do
    let input := serializeSigningInput .v0 (← parseAlgorithm alg)
      (← parseKeyIdentifier idType keyId) (← hexDecode payload)
    some (hexEncode input, expected)
  | ["sk", data, derived, expected] => do
    let C := cryptoOf { derived := ← hexDecode derived }
    some (renderResult renderSigningKey (deserializeSigningKey C (← hexDecode data)), expected)
  | ["vk", data, point, expected] => do
    let C := cryptoOf { point := ← parseBool point }
    some (renderResult renderVerifyingKey (deserializeVerifyingKey C (← hexDecode data)), expected)
  | ["verify", alg, key, token, now, point, sigOk, expected] => do
    let C := cryptoOf { point := ← parseBool point, sigOk := ← parseBool sigOk }
    let key ← hexDecode key
    let token ← hexDecode token
    let now ← parseU64 now
    let r := match ← parseAlgorithm alg with
      | .hmacSha256 => verifyHmac C key token now
      | .ed25519 => verifyEd25519 C key token now
      | .mlDsa44 => verifyMldsa44 C key token now
    some (renderResult renderVerified r, expected)
  | ["sign", alg, secret, pub, idType, claims, signature, expected] => do
    let C := cryptoOf { signature := ← hexDecode signature }
    let key : SigningKey := ⟨← parseAlgorithm alg, ← hexDecode secret, ← hexDecode pub⟩
    let r := key.signWithKeyId C (← parseClaims claims) (← parseKeyIdType idType)
    some (renderResult hexEncode r, expected)
  | _ => none

/-- Per-operation counts. Both columns should be non-zero for every decoder, or the
cases are not exercising it. -/
structure Tally where
  accepted : Nat := 0
  rejected : Nat := 0

def maxReported : Nat := 20

partial def loop (stdin : IO.FS.Stream) (tallies : Std.HashMap String Tally) (failures : Nat) :
    IO (Std.HashMap String Tally × Nat) := do
  let line ← stdin.getLine
  if line.isEmpty then
    return (tallies, failures)
  let fields := line.trimAscii.toString.splitOn " "
  let op := fields.headD ""
  match runCase fields with
  | none =>
    IO.eprintln s!"unreadable case: {line.take 200}"
    loop stdin tallies (failures + 1)
  | some (actual, expected) =>
    let tally := tallies.getD op {}
    let tally :=
      if expected.startsWith "err:" then { tally with rejected := tally.rejected + 1 }
      else { tally with accepted := tally.accepted + 1 }
    let tallies := tallies.insert op tally
    if actual == expected then
      loop stdin tallies failures
    else
      if failures < maxReported then
        IO.eprintln s!"MISMATCH {line.take 400}\n  rust: {expected.take 200}\n  lean: {actual.take 200}"
      loop stdin tallies (failures + 1)

end Conformance

open Conformance in
def main : IO UInt32 := do
  let (tallies, failures) ← loop (← IO.getStdin) {} 0
  let rows := tallies.toList.mergeSort (fun a b => a.1 ≤ b.1)
  let mut total := 0
  IO.println "operation    accepted  rejected"
  for (op, t) in rows do
    total := total + t.accepted + t.rejected
    let pad (s : String) (n : Nat) := s ++ String.ofList (List.replicate (n - s.length) ' ')
    IO.println s!"{pad op 12} {pad (toString t.accepted) 9} {t.rejected}"
  if total == 0 then
    IO.eprintln "no cases on stdin"
    return 1
  if failures == 0 then
    IO.println s!"{total} cases: the Lean model agrees with the Rust library on all of them"
    return 0
  IO.eprintln s!"{failures} of {total} cases disagree"
  return 1
