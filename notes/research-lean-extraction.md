# Extending the Lean proofs to the Rust code

Written 2026-11-13. **This is a plan from documentation. Charon and Aeneas have not been run on
this crate**, so the construct table below is a prediction.

## The three gaps

| Gap | Today | Closes with |
|---|---|---|
| 1. Model vs. `src/*.rs` | Differential test, about 170,000 cases | Charon + Aeneas extraction and refinement proofs |
| 2. Primitive crates vs. the FIPS specs | NIST ACVP vectors; assumed in Lean | Lean reference implementations, or verified crates |
| 3. "Checked these bytes" vs. "cannot be forged" | Not stated | A reduction to EUF-CMA in VCVio |

## Gap 1: extract protoken with Charon and Aeneas (recommended next step)

[Charon](https://github.com/AeneasVerif/charon) compiles the crate's MIR to an intermediate
form, and [Aeneas](https://github.com/AeneasVerif/aeneas) turns that into pure Lean functions
that fail explicitly on panics, overflow, and out-of-bounds access. hax 0.4 reportedly uses the
same pipeline for its Lean backend.

The existing theorems stay as they are. The hand-written model becomes the specification, and
each Rust function gets one refinement theorem:

```lean
theorem read_varint_refines (r : Reader) :
    Reader.read_varint r ⦃ (res, r') => abs res r' = decodeVarint r.data.val r.pos.val ⦄
```

Such a theorem also proves the function cannot panic or overflow, which nothing proves today.

```sh
charon cargo --preset=aeneas --dest-file=protoken.llbc \
  --opaque=crate::crypto --exclude=serde -- --no-default-features
aeneas -backend lean protoken.llbc -dest lean-extracted -split-files -namespace ProtokenRs
```

Put the result in a second Lake package (`lean-extracted/`) that depends on `lean/`, so the
current package keeps its one-minute, Mathlib-free build. CI regenerates the extraction and
fails on a diff, which replaces the rule "change the model when you change the code".

### Order of work

| Step | Rust | Non-test lines | Main difficulty |
|---|---|---|---|
| 1 | `proto3.rs` | 210 | Relating Aeneas scalars and slices to `UInt64` and `List UInt8`; the varint loop |
| 2 | `serialize.rs` | 270 | Reusing `fieldLoop_invariant` for extracted loops; strings |
| 3 | `types.rs` (`validate`, tables) | 330 | `BTreeSet`, `find` |
| 4 | `sign.rs`, `verify.rs`, `keys.rs` | 455 | Stating the `crypto` boundary as axioms that match `Crypto` |

Step 1 is the feasibility test. For scale, the SymCrypt effort reports about 237,000 lines of
Lean for 16,700 lines of Rust; parsing code with an existing model should need far less per line.

### Constructs to expect trouble with

Checked against the Aeneas standard library (`backends/lean/Aeneas/Std`) on this date.

| Construct | Status | Plan |
|---|---|---|
| Slices, `Vec`, `get`, ranges, `step_by`, closures, `?`, structs holding borrows | Modelled or tested upstream | None |
| `format!` in error messages | `fmt::Arguments` is modelled, `alloc::fmt::format` was not found | Opaque function returning a `String` |
| `String`, `str::from_utf8`, `as_bytes`, `str` ordering | Type only | Hand models; `validUtf8` already exists |
| `sort_unstable`, `BTreeSet`, `Iterator::find`, `ok_or_else`, `and_then` | Not found | Hand models, or rewrite as small loops |
| `&'static dyn Scheme` | `dyn` has upstream tests; unclear for this shape | Make `crypto` opaque behind three plain functions |
| `Zeroizing`, `ct_eq`, `Sha256` | External crates | Opaque, with axioms (`Zeroizing<T>` is `T`, `ct_eq` is `==`) |
| serde and thiserror derives | Not needed | Exclude |

Each hand model or axiom is trusted, so `Audit.lean` needs an explicit allow-list for them.
Charon, Aeneas, and rustc are also trusted. Timing and zeroization stay out of scope.

### Costs

- Mathlib and the Aeneas library become dependencies of the new package.
- Pinned toolchains: on this date Aeneas needs Lean 4.36.0-rc2 and Rust nightly-2026-09-17.
  `lean/` must build on the same Lean version. Aeneas publishes nightly binaries only.

## Gap 2: the primitives

Extracting the current crates is not practical. `ml-dsa`, `slh-dsa`, and `sha2` are generic over
`typenum` and `hybrid-array` and use `unsafe` and intrinsics; `fn-dsa` signs with floating point.
Aeneas does not support most `unsafe` code, and
[one report](https://arxiv.org/abs/2605.30106) had to rewrite trait-generic code as a
monomorphic model.

| Option | Covers | Assurance | Notes |
|---|---|---|---|
| Run [VCVio](https://github.com/Verified-zkEVM/VCVio)'s executable specs in the conformance test | ML-DSA, SLH-DSA, Falcon, SHA-2, HMAC | Testing against an independent Lean implementation | Cheapest. Same Lean version as `lean/` (4.35.0). Removes the oracle answers from the cases. Check SHA2 "s" support and whether its Falcon matches `fn-dsa` 0.4. |
| Switch to [`libcrux-ml-dsa`](https://github.com/cryspen/libcrux/tree/main/libcrux-ml-dsa) | ML-DSA arithmetic, NTT, serialization | Partial proofs in F*, not Lean | A small change in `crypto.rs`. See [this critique](https://eprint.iacr.org/2026/670) of hax's F* extraction. |
| Wait for [SymCrypt's verified Rust](https://arxiv.org/abs/2609.15648) | SHA-2, HMAC, ML-DSA (experimental) | Aeneas + Lean proofs | The public branch has only ML-KEM, SHA-3, and AES so far. |
| Write and verify small portable code | SHA-384, HMAC, then SLH-DSA verify | Full proofs | Hash-only code is within reach, but replaces widely used crates with new code. |

No verified Rust implementation of SLH-DSA or FN-DSA was found.

## Gap 3: unforgeability

`accepted_result_determined_by_signing_input` and `verifyToken_sound` already give the core of
the reduction: an accepted token whose result was never signed contains a valid signature on a
new message. VCVio has the game definitions to state this as "token forgery advantage is at most
the scheme's EUF-CMA advantage". It needs no extraction, only Mathlib and VCVio.

## Outside Lean

[Kani](https://github.com/model-checking/kani) checks the real Rust for panics on bounded
inputs with no model. It would cover `proto3.rs` and the decoders quickly, but only up to a
chosen input length.

## Recommendation

1. Gap 1, step 1, as a feasibility test.
2. The rest of gap 1.
3. VCVio as the conformance oracle (gap 2), then the reduction (gap 3).
