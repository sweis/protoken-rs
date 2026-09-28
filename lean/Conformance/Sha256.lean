import Protoken.Basic

/-!
# SHA-256 and HMAC-SHA256 for the conformance runner

Plain implementations of FIPS 180-4 and RFC 2104. They let the runner execute the
model's key hashing and HMAC verification without asking Rust for the answer. No
theorem depends on this file, and the runner checks it against the `sha2` and
`hmac` crates.
-/

namespace Conformance

open Protoken (Bytes)

def roundConstants : Array UInt32 := #[
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

structure HashState where
  a : UInt32
  b : UInt32
  c : UInt32
  d : UInt32
  e : UInt32
  f : UInt32
  g : UInt32
  h : UInt32

def initialState : HashState :=
  ⟨0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19⟩

def rotr (x n : UInt32) : UInt32 := (x >>> n) ||| (x <<< (32 - n))

def be32 (x : UInt32) : Bytes :=
  [(x >>> 24).toUInt8, (x >>> 16).toUInt8, (x >>> 8).toUInt8, x.toUInt8]

def be64 (x : UInt64) : Bytes :=
  be32 (x >>> 32).toUInt32 ++ be32 x.toUInt32

def HashState.toBytes (s : HashState) : Bytes :=
  be32 s.a ++ be32 s.b ++ be32 s.c ++ be32 s.d ++ be32 s.e ++ be32 s.f ++ be32 s.g ++ be32 s.h

/-- Message padding: a `1` bit, zeros, and the bit length, to a multiple of 64 bytes. -/
def pad (msg : Bytes) : Bytes :=
  msg ++ [0x80] ++ List.replicate ((119 - msg.length % 64) % 64) 0
    ++ be64 (UInt64.ofNat (msg.length * 8))

/-- The 64-word message schedule for the block starting at byte `offset`. -/
def schedule (data : Array UInt8) (offset : Nat) : Array UInt32 := Id.run do
  let mut w : Array UInt32 := Array.mkEmpty 64
  for i in [0:16] do
    let byte (j : Nat) : UInt32 := (data[offset + 4 * i + j]!).toUInt32
    w := w.push ((byte 0 <<< 24) ||| (byte 1 <<< 16) ||| (byte 2 <<< 8) ||| byte 3)
  for i in [16:64] do
    let w15 := w[i - 15]!
    let w2 := w[i - 2]!
    let s0 := rotr w15 7 ^^^ rotr w15 18 ^^^ (w15 >>> 3)
    let s1 := rotr w2 17 ^^^ rotr w2 19 ^^^ (w2 >>> 10)
    w := w.push (w[i - 16]! + s0 + w[i - 7]! + s1)
  return w

def compress (state : HashState) (w : Array UInt32) : HashState := Id.run do
  let mut s := state
  for i in [0:64] do
    let s1 := rotr s.e 6 ^^^ rotr s.e 11 ^^^ rotr s.e 25
    let ch := (s.e &&& s.f) ^^^ (~~~s.e &&& s.g)
    let t1 := s.h + s1 + ch + roundConstants[i]! + w[i]!
    let s0 := rotr s.a 2 ^^^ rotr s.a 13 ^^^ rotr s.a 22
    let maj := (s.a &&& s.b) ^^^ (s.a &&& s.c) ^^^ (s.b &&& s.c)
    let t2 := s0 + maj
    s := ⟨t1 + t2, s.a, s.b, s.c, s.d + t1, s.e, s.f, s.g⟩
  return ⟨state.a + s.a, state.b + s.b, state.c + s.c, state.d + s.d,
    state.e + s.e, state.f + s.f, state.g + s.g, state.h + s.h⟩

def sha256State (msg : Bytes) : HashState := Id.run do
  let data := (pad msg).toArray
  let mut state := initialState
  for block in [0:data.size / 64] do
    state := compress state (schedule data (64 * block))
  return state

def sha256 (msg : Bytes) : Bytes := (sha256State msg).toBytes

theorem sha256_length (msg : Bytes) : (sha256 msg).length = 32 := by
  simp [sha256, HashState.toBytes, be32]

def hmacSha256 (key msg : Bytes) : Bytes :=
  let key := if key.length > 64 then sha256 key else key
  let block := key ++ List.replicate (64 - key.length) 0
  sha256 (block.map (· ^^^ 0x5c) ++ sha256 (block.map (· ^^^ 0x36) ++ msg))

theorem hmacSha256_length (key msg : Bytes) : (hmacSha256 key msg).length = 32 :=
  sha256_length _

end Conformance
