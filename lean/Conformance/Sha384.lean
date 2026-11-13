import Conformance.Sha256

/-!
# SHA-384 and HMAC-SHA384 for the conformance runner

Plain implementations of FIPS 180-4 and RFC 2104. They let the runner execute the
model's HMAC signing and verification without asking Rust for the answer. No theorem
depends on this file, and the runner checks it against the `sha2` and `hmac` crates.
-/

namespace Conformance

open Protoken (Bytes)

namespace Sha384

def roundConstants : Array UInt64 := #[
  0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
  0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
  0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
  0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
  0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
  0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
  0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
  0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
  0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
  0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
  0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
  0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
  0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
  0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
  0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
  0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
  0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
  0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
  0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
  0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817]

structure HashState where
  a : UInt64
  b : UInt64
  c : UInt64
  d : UInt64
  e : UInt64
  f : UInt64
  g : UInt64
  h : UInt64

def initialState : HashState :=
  ⟨0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
   0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4⟩

def rotr (x n : UInt64) : UInt64 := (x >>> n) ||| (x <<< (64 - n))

/-- SHA-384 keeps the first six words of the state. -/
def HashState.toBytes (s : HashState) : Bytes :=
  be64 s.a ++ be64 s.b ++ be64 s.c ++ be64 s.d ++ be64 s.e ++ be64 s.f

/-- Message padding: a `1` bit, zeros, and the 128-bit length, to a multiple of 128 bytes. -/
def pad (msg : Bytes) : Bytes :=
  msg ++ [0x80] ++ List.replicate ((239 - msg.length % 128) % 128) 0
    ++ be64 0 ++ be64 (UInt64.ofNat (msg.length * 8))

/-- The 80-word message schedule for the block starting at byte `offset`. -/
def schedule (data : Array UInt8) (offset : Nat) : Array UInt64 := Id.run do
  let mut w : Array UInt64 := Array.mkEmpty 80
  for i in [0:16] do
    let mut word : UInt64 := 0
    for j in [0:8] do
      word := (word <<< 8) ||| (data[offset + 8 * i + j]!).toUInt64
    w := w.push word
  for i in [16:80] do
    let w15 := w[i - 15]!
    let w2 := w[i - 2]!
    let s0 := rotr w15 1 ^^^ rotr w15 8 ^^^ (w15 >>> 7)
    let s1 := rotr w2 19 ^^^ rotr w2 61 ^^^ (w2 >>> 6)
    w := w.push (w[i - 16]! + s0 + w[i - 7]! + s1)
  return w

def compress (state : HashState) (w : Array UInt64) : HashState := Id.run do
  let mut s := state
  for i in [0:80] do
    let s1 := rotr s.e 14 ^^^ rotr s.e 18 ^^^ rotr s.e 41
    let ch := (s.e &&& s.f) ^^^ (~~~s.e &&& s.g)
    let t1 := s.h + s1 + ch + roundConstants[i]! + w[i]!
    let s0 := rotr s.a 28 ^^^ rotr s.a 34 ^^^ rotr s.a 39
    let maj := (s.a &&& s.b) ^^^ (s.a &&& s.c) ^^^ (s.b &&& s.c)
    let t2 := s0 + maj
    s := ⟨t1 + t2, s.a, s.b, s.c, s.d + t1, s.e, s.f, s.g⟩
  return ⟨state.a + s.a, state.b + s.b, state.c + s.c, state.d + s.d,
    state.e + s.e, state.f + s.f, state.g + s.g, state.h + s.h⟩

def finalState (msg : Bytes) : HashState := Id.run do
  let data := (pad msg).toArray
  let mut state := initialState
  for block in [0:data.size / 128] do
    state := compress state (schedule data (128 * block))
  return state

end Sha384

def sha384 (msg : Bytes) : Bytes := (Sha384.finalState msg).toBytes

theorem sha384_length (msg : Bytes) : (sha384 msg).length = 48 := by
  simp [sha384, Sha384.HashState.toBytes, be64, be32]

def hmacSha384 (key msg : Bytes) : Bytes :=
  let key := if key.length > 128 then sha384 key else key
  let block := key ++ List.replicate (128 - key.length) 0
  sha384 (block.map (· ^^^ 0x5c) ++ sha384 (block.map (· ^^^ 0x36) ++ msg))

theorem hmacSha384_length (key msg : Bytes) : (hmacSha384 key msg).length = 48 :=
  sha384_length _

end Conformance
