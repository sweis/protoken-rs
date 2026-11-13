#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
//! Emits differential-test cases for the Lean model in `lean/`.
//!
//! Each output line holds an operation, its inputs, and what this library
//! returned. `lake exe conformance` replays the lines through the Lean model
//! and fails on any difference. See `lean/README.md` for the line format.
//!
//! Usage: cargo run --release --example gen_lean_cases [seed] | (cd lean && lake exe conformance)
//! (`make lean-conformance` runs this.)
//!
//! The output is a function of the seed, so a failure can be reproduced. The
//! exception is the signature bytes of FN-DSA tokens that the library signs.

#[path = "common/fn_dsa_fixed.rs"]
mod fn_dsa_fixed;

use std::io::{BufWriter, Write};

use base64::Engine as _;
use fn_dsa::{SigningKey as _, VerifyingKey as _};
use hmac::{Hmac, Mac as _};
use ml_dsa::{KeyInit as _, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Signer as _, Verifier as _};
use serde::Deserialize;
use sha2::{Digest as _, Sha256, Sha384};
use slh_dsa::{ParameterSet, Sha2_128s, Sha2_192s, Sha2_256s};

use protoken::proto3::{self, Reader};
use protoken::serialize::{
    append_signature, deserialize_claims, deserialize_signed_token, serialize_claims,
    serialize_signing_input,
};
use protoken::sign::compute_key_hash;
use protoken::types::Version;
use protoken::{
    Algorithm, Claims, KeyIdType, KeyIdentifier, ProtokenError, SigningKey, VerifiedToken,
    VerifyingKey, Zeroizing,
};

// --- Deterministic random numbers (SplitMix64) ---

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }

    /// Fewer than `n` random bytes.
    fn bytes_below(&mut self, n: usize) -> Vec<u8> {
        let len = self.below(n);
        self.bytes(len)
    }
}

// --- Text encoding shared with lean/Conformance/Main.lean ---

fn hx(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        "-".into()
    } else {
        hex::encode(bytes)
    }
}

fn bit(value: bool) -> &'static str {
    if value {
        "1"
    } else {
        "0"
    }
}

fn render_error(e: &ProtokenError) -> String {
    match e {
        ProtokenError::InvalidVersion(v) => format!("err:InvalidVersion:{v}"),
        ProtokenError::InvalidAlgorithm(b) => format!("err:InvalidAlgorithm:{b}"),
        ProtokenError::InvalidKeyIdType(b) => format!("err:InvalidKeyIdType:{b}"),
        ProtokenError::InvalidKeyLength { expected, actual } => {
            format!("err:InvalidKeyLength:{expected}:{actual}")
        }
        ProtokenError::InvalidKey(_) => "err:InvalidKey".into(),
        ProtokenError::SigningFailed(_) => "err:SigningFailed".into(),
        ProtokenError::VerificationFailed(_) => "err:VerificationFailed".into(),
        ProtokenError::TokenExpired { expired_at, now } => {
            format!("err:TokenExpired:{expired_at}:{now}")
        }
        ProtokenError::TokenNotYetValid { not_before, now } => {
            format!("err:TokenNotYetValid:{not_before}:{now}")
        }
        ProtokenError::KeyHashMismatch => "err:KeyHashMismatch".into(),
        ProtokenError::MalformedEncoding(_) => "err:MalformedEncoding".into(),
        // The model has no such variants, so these would show up as mismatches.
        ProtokenError::UnknownAlgorithmName(_) => "err:UnknownAlgorithmName".into(),
        ProtokenError::RngFailed(_) => "err:RngFailed".into(),
    }
}

fn render<T>(result: &Result<T, ProtokenError>, ok: impl Fn(&T) -> String) -> String {
    match result {
        Ok(value) => format!("ok:{}", ok(value)),
        Err(e) => render_error(e),
    }
}

fn render_claims(c: &Claims) -> String {
    let scopes = if c.scopes.is_empty() {
        ".".into()
    } else {
        let hex: Vec<String> = c.scopes.iter().map(|s| hx(s.as_bytes())).collect();
        hex.join(",")
    };
    format!(
        "{}:{}:{}:{}:{}:{scopes}",
        c.expires_at,
        c.not_before,
        c.issued_at,
        hx(c.subject.as_bytes()),
        hx(c.audience.as_bytes()),
    )
}

fn render_key_id(k: &KeyIdentifier) -> String {
    format!("{}:{}", k.key_id_type() as u8, hx(k.as_bytes()))
}

fn render_verified(v: &VerifiedToken) -> String {
    format!(
        "{}:{}:{}",
        v.algorithm as u8,
        render_key_id(&v.key_identifier),
        render_claims(&v.claims)
    )
}

// --- An independent, lenient wire walker ---
//
// Finds the field values that the library will hand to a primitive, so the
// primitive's answer can be attached to the case. It shares no code with the
// library and stops at the first thing it cannot read.

enum Value<'a> {
    Varint(u64),
    Len(&'a [u8]),
}

struct Field<'a> {
    number: u64,
    start: usize,
    value: Value<'a>,
}

fn walk_varint(data: &[u8], pos: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for i in 0..10 {
        let byte = *data.get(*pos)?;
        *pos += 1;
        value |= u64::from(byte & 0x7F).checked_shl(7 * i)?;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

fn walk(data: &[u8]) -> Vec<Field<'_>> {
    let mut fields = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let start = pos;
        let Some(tag) = walk_varint(data, &mut pos) else {
            break;
        };
        let value = match tag & 7 {
            0 => match walk_varint(data, &mut pos) {
                Some(v) => Value::Varint(v),
                None => break,
            },
            2 => {
                let Some(len) = walk_varint(data, &mut pos) else {
                    break;
                };
                let Some(bytes) = usize::try_from(len)
                    .ok()
                    .and_then(|len| pos.checked_add(len))
                    .and_then(|end| data.get(pos..end))
                else {
                    break;
                };
                pos += bytes.len();
                Value::Len(bytes)
            }
            _ => break,
        };
        fields.push(Field {
            number: tag >> 3,
            start,
            value,
        });
    }
    fields
}

fn first_varint(fields: &[Field], number: u64) -> Option<u64> {
    fields.iter().find_map(|f| match f.value {
        Value::Varint(v) if f.number == number => Some(v),
        _ => None,
    })
}

fn first_len<'a>(fields: &[Field<'a>], number: u64) -> Option<(usize, &'a [u8])> {
    fields.iter().find_map(|f| match f.value {
        Value::Len(b) if f.number == number => Some((f.start, b)),
        _ => None,
    })
}

fn key_algorithm(fields: &[Field]) -> Option<Algorithm> {
    Algorithm::try_from(u8::try_from(first_varint(fields, 1)?).ok()?).ok()
}

// --- Direct calls to the primitives ---

/// Calls `$ml_dsa::<P>`, `$slh_dsa::<P>`, or `$fn_dsa(logn, ..)` for the algorithm's parameter set.
macro_rules! dispatch {
    ($algorithm:expr, $hmac:expr, $ml_dsa:ident, $slh_dsa:ident, $fn_dsa:ident, $($arg:expr),*) => {
        match $algorithm {
            Algorithm::HmacSha384 => $hmac,
            Algorithm::MlDsa44 => $ml_dsa::<MlDsa44>($($arg),*),
            Algorithm::MlDsa65 => $ml_dsa::<MlDsa65>($($arg),*),
            Algorithm::MlDsa87 => $ml_dsa::<MlDsa87>($($arg),*),
            Algorithm::SlhDsaSha2_128s => $slh_dsa::<Sha2_128s>($($arg),*),
            Algorithm::SlhDsaSha2_192s => $slh_dsa::<Sha2_192s>($($arg),*),
            Algorithm::SlhDsaSha2_256s => $slh_dsa::<Sha2_256s>($($arg),*),
            Algorithm::FnDsa512 => $fn_dsa(9, $($arg),*),
            Algorithm::FnDsa1024 => $fn_dsa(10, $($arg),*),
        }
    };
}

/// None if the primitive rejects the secret. HMAC is computed in Lean.
fn raw_public_key(algorithm: Algorithm, secret: &[u8]) -> Option<Vec<u8>> {
    fn ml_dsa<P: MlDsaParams>(secret: &[u8]) -> Option<Vec<u8>> {
        let key = ml_dsa::SigningKey::<P>::new_from_slice(secret).ok()?;
        Some(key.as_ref().encode().to_vec())
    }
    fn slh_dsa<P: ParameterSet>(secret: &[u8]) -> Option<Vec<u8>> {
        let stored = slh_dsa::SigningKey::<P>::try_from(secret).ok()?;
        let seeds: Vec<&[u8]> = secret.chunks(secret.len() / 4).collect();
        let derived = slh_dsa::SigningKey::<P>::slh_keygen_internal(seeds[0], seeds[1], seeds[2]);
        (derived == stored).then(|| derived.as_ref().to_vec())
    }
    fn fn_dsa(logn: u32, secret: &[u8]) -> Option<Vec<u8>> {
        let key = fn_dsa::SigningKeyStandard::decode(secret).filter(|k| k.get_logn() == logn)?;
        let mut pk = vec![0; fn_dsa::vrfy_key_size(logn)];
        key.to_verifying_key(&mut pk);
        let hash = fn_dsa::hashed_vrfykey_from_vrfykey(&pk);
        (fn_dsa::hashed_vrfykey_from_signkey(secret) == hash).then_some(pk)
    }
    dispatch!(algorithm, None, ml_dsa, slh_dsa, fn_dsa, secret)
}

fn raw_sign(algorithm: Algorithm, secret: &[u8], msg: &[u8]) -> Vec<u8> {
    fn hmac(secret: &[u8], msg: &[u8]) -> Vec<u8> {
        let mac = Hmac::<Sha384>::new_from_slice(secret).unwrap();
        mac.chain_update(msg).finalize().into_bytes().to_vec()
    }
    fn ml_dsa<P: MlDsaParams>(secret: &[u8], msg: &[u8]) -> Vec<u8> {
        let key = ml_dsa::SigningKey::<P>::new_from_slice(secret).unwrap();
        key.sign(msg).encode().to_vec()
    }
    fn slh_dsa<P: ParameterSet>(secret: &[u8], msg: &[u8]) -> Vec<u8> {
        let key = slh_dsa::SigningKey::<P>::try_from(secret).unwrap();
        key.sign(msg).to_vec()
    }
    fn fn_dsa(_logn: u32, secret: &[u8], msg: &[u8]) -> Vec<u8> {
        fn_dsa_fixed::sign(secret, msg).unwrap()
    }
    dispatch!(
        algorithm,
        hmac(secret, msg),
        ml_dsa,
        slh_dsa,
        fn_dsa,
        secret,
        msg
    )
}

/// HMAC is computed in Lean.
fn raw_verify(algorithm: Algorithm, pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    fn ml_dsa<P: MlDsaParams>(pk: &[u8], msg: &[u8], sig: &[u8]) -> Option<()> {
        let key = ml_dsa::VerifyingKey::<P>::new_from_slice(pk).ok()?;
        key.verify(msg, &sig.try_into().ok()?).ok()
    }
    fn slh_dsa<P: ParameterSet>(pk: &[u8], msg: &[u8], sig: &[u8]) -> Option<()> {
        let key = slh_dsa::VerifyingKey::<P>::try_from(pk).ok()?;
        key.verify(msg, &sig.try_into().ok()?).ok()
    }
    dispatch!(
        algorithm,
        None,
        ml_dsa,
        slh_dsa,
        fn_dsa_verify,
        pk,
        msg,
        sig
    )
    .is_some()
}

fn fn_dsa_verify(logn: u32, pk: &[u8], msg: &[u8], sig: &[u8]) -> Option<()> {
    let key = fn_dsa::VerifyingKeyStandard::decode(pk).filter(|_| u32::from(pk[0]) == logn)?;
    key.verify(sig, &fn_dsa::DOMAIN_NONE, &fn_dsa::HASH_ID_RAW, msg)
        .then_some(())
}

fn raw_public_key_valid(algorithm: Algorithm, pk: &[u8]) -> bool {
    if is_fn_dsa(algorithm) {
        fn_dsa::VerifyingKeyStandard::decode(pk).is_some()
    } else {
        is_slow(algorithm) || pk.len() <= 32 || pk[32..] != vec![0; pk.len() - 32]
    }
}

fn is_fn_dsa(algorithm: Algorithm) -> bool {
    algorithm.name().starts_with("fn-dsa")
}

// --- Input generators ---

const INTERESTING_BYTES: &[u8] = &[
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x10, 0x12, 0x18, 0x1A, 0x20,
    0x22, 0x2A, 0x32, 0x38, 0x3A, 0x40, 0x7F, 0x80, 0x81, 0xFF,
];

const INTERESTING_U64: &[u64] = &[
    0,
    1,
    2,
    3,
    6,
    9,
    10,
    127,
    128,
    255,
    256,
    16383,
    16384,
    1_700_000_000,
    u32::MAX as u64,
    u32::MAX as u64 + 1,
    1 << 62,
    1 << 63,
    u64::MAX - 1,
    u64::MAX,
];

const INTERESTING_LENGTHS: &[usize] = &[
    0, 1, 2, 7, 8, 9, 31, 32, 33, 47, 48, 49, 63, 64, 65, 127, 128, 129, 254, 255, 256, 300,
];

fn put_varint(mut value: u64, out: &mut Vec<u8>) {
    while value > 0x7F {
        out.push(value as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// A varint with `extra` redundant continuation bytes.
fn put_padded_varint(value: u64, extra: usize, out: &mut Vec<u8>) {
    let start = out.len();
    put_varint(value, out);
    for _ in 0..extra {
        let last = out.len() - 1;
        if out.len() - start >= 10 {
            break;
        }
        out[last] |= 0x80;
        out.push(0);
    }
}

fn random_u64(rng: &mut Rng) -> u64 {
    match rng.below(4) {
        0 => rng.pick(INTERESTING_U64),
        1 => rng.next() >> rng.below(64),
        2 => rng.pick(INTERESTING_U64).wrapping_add(rng.below(3) as u64),
        _ => rng.below(300) as u64,
    }
}

fn random_string(rng: &mut Rng, byte_len: usize) -> String {
    const CHARS: &[char] = &[
        'a',
        'b',
        'z',
        'A',
        '0',
        ':',
        '/',
        ' ',
        '\0',
        '\u{7f}',
        'é',
        'ß',
        '\u{7ff}',
        '€',
        '\u{800}',
        '\u{d7ff}',
        '\u{e000}',
        '\u{ffff}',
        '𝄞',
        '\u{10000}',
        '\u{10ffff}',
    ];
    let mut s = String::new();
    while s.len() < byte_len {
        let c = rng.pick(CHARS);
        if s.len() + c.len_utf8() <= byte_len {
            s.push(c);
        } else {
            s.push('x');
        }
    }
    s
}

fn random_len_value(rng: &mut Rng) -> Vec<u8> {
    let len = if rng.chance(70) {
        rng.below(12)
    } else {
        rng.pick(INTERESTING_LENGTHS)
    };
    match rng.below(4) {
        0 => rng.bytes(len),
        1 => vec![rng.pick(INTERESTING_BYTES); len],
        _ => random_string(rng, len).into_bytes(),
    }
}

/// A message assembled from random fields. `varint_fields` are the field
/// numbers below which a varint is the expected wire type.
fn random_message(rng: &mut Rng, varint_fields: u64, max_field: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let count = rng.below(9);
    let ascending = rng.chance(75);
    let mut number = 0u64;
    for _ in 0..count {
        number = if ascending {
            number
                + if rng.chance(15) {
                    0
                } else {
                    1 + rng.below(2) as u64
                }
        } else {
            rng.below(max_field as usize + 3) as u64
        };
        if rng.chance(2) {
            number = rng.pick(&[
                0,
                15,
                16,
                1 << 28,
                u32::MAX as u64,
                u32::MAX as u64 + 2,
                1 << 60,
            ]);
        }
        let expected_wire = if number <= varint_fields { 0 } else { 2 };
        let wire = if rng.chance(92) {
            expected_wire
        } else {
            rng.below(8) as u64
        };
        let pad = if rng.chance(3) { 1 + rng.below(3) } else { 0 };
        put_padded_varint(number.wrapping_shl(3) | wire, pad, &mut out);
        if wire == 0 {
            let pad = if rng.chance(3) { 1 + rng.below(3) } else { 0 };
            put_padded_varint(random_u64(rng), pad, &mut out);
        } else if wire == 2 {
            let value = random_len_value(rng);
            let claimed = match rng.below(40) {
                0 => value.len() as u64 + 1,
                1 => (value.len() as u64).saturating_sub(1),
                2 => rng.pick(INTERESTING_U64),
                _ => value.len() as u64,
            };
            let pad = if rng.chance(3) { 1 } else { 0 };
            put_padded_varint(claimed, pad, &mut out);
            out.extend_from_slice(&value);
        }
    }
    out
}

/// Position biased toward the framing at the start of large inputs.
fn random_position(rng: &mut Rng, len: usize) -> usize {
    if len > 64 && rng.chance(60) {
        rng.below(64)
    } else {
        rng.below(len)
    }
}

fn mutate(rng: &mut Rng, base: &[u8]) -> Vec<u8> {
    let mut d = base.to_vec();
    for _ in 0..1 + rng.below(3) {
        if d.is_empty() {
            d.push(rng.pick(INTERESTING_BYTES));
            continue;
        }
        let i = random_position(rng, d.len());
        match rng.below(11) {
            0 => d[i] ^= 1 << rng.below(8),
            1 => d[i] = rng.pick(INTERESTING_BYTES),
            2 => d.insert(i, rng.pick(INTERESTING_BYTES)),
            3 => {
                d.remove(i);
            }
            4 => d.truncate(i),
            5 => {
                let extra = random_message(rng, 3, 7);
                d.extend_from_slice(&extra);
            }
            6 => {
                let end = (i + 1 + rng.below(12)).min(d.len());
                let chunk = d[i..end].to_vec();
                let at = random_position(rng, d.len());
                d.splice(at..at, chunk);
            }
            7 => d[i] = d[i].wrapping_add(1),
            8 => d[i] = d[i].wrapping_sub(1),
            9 => {
                // Turn a one-byte varint into a two-byte, non-minimal one.
                if d[i] < 0x80 {
                    d[i] |= 0x80;
                    d.insert(i + 1, 0);
                }
            }
            _ => {
                let fields = walk(&d);
                if fields.len() >= 2 {
                    // Swap two adjacent fields.
                    let k = rng.below(fields.len() - 1);
                    let (a, b) = (fields[k].start, fields[k + 1].start);
                    let c = fields.get(k + 2).map_or(d.len(), |f| f.start);
                    let mut swapped = d[..a].to_vec();
                    swapped.extend_from_slice(&d[b..c]);
                    swapped.extend_from_slice(&d[a..b]);
                    swapped.extend_from_slice(&d[c..]);
                    d = swapped;
                }
            }
        }
    }
    d
}

fn random_claims(rng: &mut Rng) -> Claims {
    let expires_at = if rng.chance(8) { 0 } else { random_u64(rng) };
    let not_before = match rng.below(5) {
        0 | 1 => 0,
        2 => expires_at.saturating_sub(rng.below(3) as u64),
        3 => expires_at.saturating_add(rng.below(3) as u64),
        _ => random_u64(rng),
    };
    let string_len = |rng: &mut Rng| match rng.below(10) {
        0..=2 => 0,
        3..=7 => 1 + rng.below(20),
        _ => rng.pick(&[254usize, 255, 256, 300]),
    };
    let scope_count = match rng.below(12) {
        0..=3 => 0,
        4..=8 => 1 + rng.below(5),
        _ => rng.pick(&[15usize, 16, 31, 32, 33]),
    };
    let long_scopes = rng.chance(15);
    let mut scopes: Vec<String> = (0..scope_count)
        .map(|_| {
            let len = if long_scopes {
                rng.pick(&[200usize, 255, 256])
            } else if rng.chance(3) {
                0
            } else {
                1 + rng.below(6)
            };
            random_string(rng, len)
        })
        .collect();
    if scopes.len() >= 2 && rng.chance(10) {
        let dup = scopes[0].clone();
        let at = rng.below(scopes.len());
        scopes[at] = dup;
    }
    if rng.chance(40) {
        scopes.sort();
    }
    let (subject_len, audience_len) = (string_len(rng), string_len(rng));
    Claims {
        expires_at,
        not_before,
        issued_at: if rng.chance(50) { 0 } else { random_u64(rng) },
        subject: random_string(rng, subject_len),
        audience: random_string(rng, audience_len),
        scopes,
    }
}

/// Claims that pass `validate()` and fit in a payload.
fn signable_claims(rng: &mut Rng) -> Claims {
    loop {
        let claims = random_claims(rng);
        if claims.validate().is_ok() && serialize_claims(&claims).len() <= 4096 {
            return claims;
        }
    }
}

/// Valid claims whose encoding is exactly `size` bytes (for sizes near 4096).
fn claims_of_size(size: usize) -> Claims {
    let mut claims = Claims {
        expires_at: u64::MAX,
        scopes: (0..15).map(|i| format!("{i:0>255}")).collect(),
        ..Default::default()
    };
    // The subject field costs a tag and a two-byte length.
    claims.subject = "s".repeat(size - serialize_claims(&claims).len() - 3);
    assert_eq!(serialize_claims(&claims).len(), size);
    assert!(claims.validate().is_ok());
    claims
}

// --- Stored reference vectors ---

#[derive(Deserialize)]
struct VectorFile {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    signing_key_base64: String,
    verifying_key_base64: Option<String>,
    token_base64: String,
}

// --- Case emitters ---

struct Emitter<W: Write> {
    out: W,
}

impl<W: Write> Emitter<W> {
    fn line(&mut self, fields: &[&str]) {
        writeln!(self.out, "{}", fields.join(" ")).expect("write case");
    }

    fn varint(&mut self, data: &[u8]) {
        let mut reader = Reader::new(data);
        let result = reader.read_varint().map(|v| (v, reader.position()));
        self.line(&[
            "varint",
            &hx(data),
            &render(&result, |(v, pos)| format!("{v}:{pos}")),
        ]);
    }

    fn encode_varint(&mut self, value: u64) {
        let mut buf = Vec::new();
        proto3::encode_varint(value, &mut buf);
        self.line(&["encvarint", &value.to_string(), &hx(&buf)]);
    }

    fn utf8(&mut self, data: &[u8]) {
        let valid = std::str::from_utf8(data).is_ok();
        self.line(&["utf8", &hx(data), bit(valid)]);
    }

    fn sha256(&mut self, data: &[u8]) {
        self.line(&["sha256", &hx(data), &hx(&Sha256::digest(data))]);
    }

    fn sha384(&mut self, data: &[u8]) {
        self.line(&["sha384", &hx(data), &hx(&Sha384::digest(data))]);
    }

    fn hmac(&mut self, key: &[u8], data: &[u8]) {
        let tag = raw_sign(Algorithm::HmacSha384, key, data);
        self.line(&["hmac", &hx(key), &hx(data), &hx(&tag)]);
    }

    fn claims(&mut self, data: &[u8]) {
        let result = deserialize_claims(data);
        self.line(&["claims", &hx(data), &render(&result, render_claims)]);
    }

    fn validate(&mut self, claims: &Claims) {
        let result = claims.validate();
        self.line(&[
            "validate",
            &render_claims(claims),
            &render(&result, |()| String::new()),
        ]);
    }

    fn serialize_claims(&mut self, claims: &Claims) {
        self.line(&[
            "serclaims",
            &render_claims(claims),
            &hx(&serialize_claims(claims)),
        ]);
    }

    fn token(&mut self, data: &[u8]) {
        let result = deserialize_signed_token(data);
        let rendered = render(&result, |t| {
            format!(
                "{}:{}:{}:{}",
                t.algorithm as u8,
                render_key_id(&t.key_identifier),
                hx(&t.payload),
                hx(&t.signature)
            )
        });
        self.line(&["token", &hx(data), &rendered]);
    }

    fn signing_input(&mut self, algorithm: Algorithm, key_id: &KeyIdentifier, payload: &[u8]) {
        let input = serialize_signing_input(Version::V0, algorithm, key_id, payload);
        self.line(&[
            "signinput",
            &(algorithm as u8).to_string(),
            &(key_id.key_id_type() as u8).to_string(),
            &hx(key_id.as_bytes()),
            &hx(payload),
            &hx(&input),
        ]);
    }

    fn signing_key(&mut self, data: &[u8]) {
        let fields = walk(data);
        let derived = key_algorithm(&fields)
            .zip(first_len(&fields, 2))
            .and_then(|(algorithm, (_, secret))| raw_public_key(algorithm, secret));
        let result = SigningKey::from_bytes(data);
        let rendered = render(&result, |k| {
            format!(
                "{}:{}:{}",
                k.algorithm() as u8,
                hx(k.secret_key()),
                hx(k.public_key())
            )
        });
        let derived = derived.map_or("!".into(), |pk| hx(&pk));
        self.line(&["sk", &hx(data), &derived, &rendered]);
    }

    fn verifying_key(&mut self, data: &[u8]) {
        let fields = walk(data);
        let valid = key_algorithm(&fields)
            .zip(first_len(&fields, 2))
            .is_some_and(|(algorithm, (_, pk))| raw_public_key_valid(algorithm, pk));
        let result = VerifyingKey::from_bytes(data);
        let rendered = render(&result, |k| {
            format!("{}:{}", k.algorithm() as u8, hx(k.public_key()))
        });
        self.line(&["vk", &hx(data), bit(valid), &rendered]);
    }

    /// Builds the verifier's key from `material`, then verifies.
    fn verify(&mut self, algorithm: Algorithm, material: &[u8], token: &[u8], now: u64) {
        let signature_ok = first_len(&walk(token), 6)
            .is_some_and(|(start, sig)| raw_verify(algorithm, material, &token[..start], sig));
        let result = if algorithm.is_symmetric() {
            SigningKey::from_secret_key(algorithm, Zeroizing::new(material.to_vec()))
                .and_then(|key| key.verify(token, now))
        } else {
            VerifyingKey::new(algorithm, material.to_vec()).and_then(|key| key.verify(token, now))
        };
        self.line(&[
            "verify",
            &(algorithm as u8).to_string(),
            &hx(material),
            &hx(token),
            &now.to_string(),
            bit(raw_public_key_valid(algorithm, material)),
            bit(signature_ok),
            &render(&result, render_verified),
        ]);
    }

    fn sign(&mut self, key: &SigningKey, id_type: KeyIdType, claims: &Claims) {
        let result = key.sign_with_key_id(claims, id_type);
        let signature = match &result {
            Ok(token) => deserialize_signed_token(token).unwrap().signature,
            Err(_) => Vec::new(),
        };
        self.line(&[
            "sign",
            &(key.algorithm() as u8).to_string(),
            &hx(key.secret_key()),
            &hx(key.public_key()),
            &(id_type as u8).to_string(),
            &render_claims(claims),
            &hx(&signature),
            &render(&result, |token| hx(token)),
        ]);
    }
}

/// Times at and around the edges of the claims' validity window.
fn boundary_times(rng: &mut Rng, claims: &Claims) -> u64 {
    let base = if rng.chance(50) {
        claims.expires_at
    } else {
        claims.not_before
    };
    match rng.below(6) {
        0 => base,
        1 => base.wrapping_add(1),
        2 => base.wrapping_sub(1),
        3 => 0,
        4 => u64::MAX,
        _ => claims.not_before / 2 + claims.expires_at / 2,
    }
}

/// The key material a verifier holds for `key`.
fn verifier_material(key: &SigningKey) -> &[u8] {
    if key.algorithm().is_symmetric() {
        key.secret_key()
    } else {
        key.public_key()
    }
}

fn is_slow(algorithm: Algorithm) -> bool {
    algorithm.name().starts_with("slh-dsa")
}

/// A random key. SLH-DSA signing takes about a second, so those keys are rare.
fn pick_signer<'a>(rng: &mut Rng, keys: &'a [SigningKey]) -> &'a SigningKey {
    loop {
        let key = &keys[rng.below(keys.len())];
        if !is_slow(key.algorithm()) || rng.chance(2) {
            return key;
        }
    }
}

fn main() {
    let seed = std::env::args()
        .nth(1)
        .map_or(1, |s| s.parse().expect("seed must be a u64"));
    let rng = &mut Rng(seed);
    let mut e = Emitter {
        out: BufWriter::new(std::io::stdout().lock()),
    };

    // Varints.
    for &v in INTERESTING_U64 {
        e.encode_varint(v);
    }
    for shift in 0..64 {
        for delta in [-1i64, 0, 1] {
            e.encode_varint((1u64 << shift).wrapping_add_signed(delta));
        }
    }
    for _ in 0..3000 {
        let mut data = Vec::new();
        match rng.below(4) {
            0 => data = rng.bytes_below(12),
            1 => put_varint(random_u64(rng), &mut data),
            2 => put_padded_varint(random_u64(rng), 1 + rng.below(9), &mut data),
            _ => {
                let n = 8 + rng.below(4);
                data = vec![0x80 | rng.next() as u8; n];
                data.push(rng.pick(&[0u8, 1, 2, 3, 0x7F, 0x80]));
            }
        }
        if rng.chance(30) {
            data.extend(rng.bytes(3));
        }
        e.varint(&data);
    }

    // UTF-8: every 1- and 2-byte string, and range boundaries for longer forms.
    e.utf8(&[]);
    for a in 0..=255u8 {
        e.utf8(&[a]);
        for b in 0..=255u8 {
            e.utf8(&[a, b]);
        }
    }
    const EDGES: &[u8] = &[
        0x00, 0x7F, 0x80, 0x8F, 0x90, 0x9F, 0xA0, 0xBF, 0xC0, 0xC2, 0xFF,
    ];
    for a in 0xE0..=0xF5u8 {
        for &b in EDGES {
            for &c in EDGES {
                e.utf8(&[a, b, c]);
                for &d in EDGES {
                    e.utf8(&[a, b, c, d]);
                }
            }
        }
    }
    for _ in 0..2000 {
        let len = rng.below(24);
        let mut s = random_string(rng, len).into_bytes();
        if rng.chance(60) {
            s = mutate(rng, &s);
        }
        e.utf8(&s);
    }

    // The runner's own hashes and HMAC.
    for len in (0..300).chain([1000, 1312, 4096]) {
        e.sha256(&rng.bytes(len));
        e.sha384(&rng.bytes(len));
    }
    for key_len in [0, 1, 47, 48, 49, 127, 128, 129, 200] {
        for msg_len in [0, 1, 111, 112, 128, 300] {
            e.hmac(&rng.bytes(key_len), &rng.bytes(msg_len));
        }
    }

    // Claims: encode, validate, decode.
    let mut claims_pool = Vec::new();
    for _ in 0..2500 {
        let claims = random_claims(rng);
        e.validate(&claims);
        e.serialize_claims(&claims);
        let bytes = serialize_claims(&claims);
        e.claims(&bytes);
        claims_pool.push(bytes);
    }
    for _ in 0..6000 {
        let base = &claims_pool[rng.below(claims_pool.len())];
        e.claims(&mutate(rng, base));
    }
    for _ in 0..4000 {
        e.claims(&random_message(rng, 3, 6));
    }
    for len in [4095, 4096, 4097] {
        e.claims(&vec![0u8; len]);
    }
    // Well-formed claims on each side of every limit, so that the limit is
    // the only thing that can reject them.
    let mut limit_claims = Vec::new();
    for count in [31, 32, 33, 34] {
        limit_claims.push(Claims {
            expires_at: 1,
            scopes: (0..count).map(|i| format!("s{i:02}")).collect(),
            ..Default::default()
        });
    }
    for size in [4095, 4096, 4097, 4098] {
        limit_claims.push(claims_of_size(size));
    }
    for len in [254, 255, 256] {
        for field in 0..3 {
            let value = "x".repeat(len);
            let mut claims = Claims {
                expires_at: 1,
                ..Default::default()
            };
            match field {
                0 => claims.subject = value,
                1 => claims.audience = value,
                _ => claims.scopes = vec![value],
            }
            limit_claims.push(claims);
        }
    }
    for claims in &limit_claims {
        e.validate(claims);
        e.serialize_claims(claims);
        e.claims(&serialize_claims(claims));
    }

    // Keys: the stored reference keys, plus two per fast algorithm.
    let json = include_str!("../testdata/reference_vectors.json");
    let reference: VectorFile = serde_json::from_str(json).expect("reference vectors parse");
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut keys = Vec::new();
    for algorithm in Algorithm::ALL.into_iter().filter(|&a| !is_slow(a)) {
        for _ in 0..2 {
            let secret = if is_fn_dsa(algorithm) {
                fn_dsa_fixed::secret_key(algorithm, &rng.bytes(32))
            } else {
                rng.bytes(algorithm.secret_key_len())
            };
            keys.push(SigningKey::from_secret_key(algorithm, Zeroizing::new(secret)).unwrap());
        }
    }
    let mut token_pool: Vec<Vec<u8>> = Vec::new();
    for v in &reference.vectors {
        let key = SigningKey::from_bytes(&b64.decode(&v.signing_key_base64).unwrap()).unwrap();
        let token = b64.decode(&v.token_base64).unwrap();
        e.verify(
            key.algorithm(),
            verifier_material(&key),
            &token,
            2_000_000_000,
        );
        if let Some(vk) = &v.verifying_key_base64 {
            e.verifying_key(&b64.decode(vk).unwrap());
        }
        token_pool.push(token);
        keys.push(key);
    }

    let mut signing_key_pool: Vec<Vec<u8>> = keys.iter().map(|k| k.to_bytes().to_vec()).collect();
    let mut verifying_key_pool: Vec<Vec<u8>> = keys
        .iter()
        .filter_map(|k| k.verifying_key().ok())
        .map(|k| k.to_bytes())
        .collect();
    // Every combination of algorithm byte, secret, and public key from small
    // pools, with lengths on each side of every key size and field limit.
    let around = |lengths: &[usize]| -> Vec<Vec<u8>> {
        let sizes = lengths.iter().flat_map(|&n| [n - 1, n, n + 1]);
        sizes.map(|n| vec![7; n]).collect()
    };
    let mut secret_pool = around(&[1, 32, 48, 64, 96, 128, 1345, 2369]);
    secret_pool.extend(keys.iter().map(|k| k.secret_key().to_vec()));
    let mut public_pool = around(&[1, 32, 48, 64, 897, 1312, 1793, 1952, 2592]);
    public_pool.extend([1312, 1952, 2592].map(|n| vec![0; n]));
    public_pool.extend(keys.iter().map(|k| k.public_key().to_vec()));
    for algorithm_byte in 0..=11 {
        for secret in &secret_pool {
            // Deriving an SLH-DSA public key is slow, so sample the pairs.
            for public in public_pool
                .iter()
                .filter(|p| p.is_empty() || rng.chance(15))
            {
                let mut sk = Vec::new();
                proto3::encode_uint32(1, algorithm_byte, &mut sk);
                proto3::encode_bytes(2, secret, &mut sk);
                proto3::encode_bytes(3, public, &mut sk);
                signing_key_pool.push(sk);
            }
        }
        for public in &public_pool {
            let mut vk = Vec::new();
            proto3::encode_uint32(1, algorithm_byte, &mut vk);
            proto3::encode_bytes(2, public, &mut vk);
            verifying_key_pool.push(vk);
        }
    }
    // An FN-DSA key whose stored hash of the public key is wrong.
    for key in keys.iter().filter(|k| is_fn_dsa(k.algorithm())) {
        let mut bytes = key.to_bytes().to_vec();
        let secret_end = bytes.len() - key.public_key().len() - 3;
        bytes[secret_end - 1] ^= 1;
        signing_key_pool.push(bytes);
    }
    // An SLH-DSA key whose stored root is wrong in both places.
    for key in keys.iter().filter(|k| is_slow(k.algorithm())) {
        let mut bytes = key.to_bytes().to_vec();
        let secret_end = bytes.len() - key.public_key().len() - 2;
        bytes[secret_end - 1] ^= 1;
        *bytes.last_mut().unwrap() ^= 1;
        signing_key_pool.push(bytes);
    }
    for bytes in signing_key_pool.iter().chain(&verifying_key_pool) {
        e.signing_key(bytes);
        e.verifying_key(bytes);
    }
    for _ in 0..2500 {
        let base = &signing_key_pool[rng.below(signing_key_pool.len())];
        e.signing_key(&mutate(rng, base));
        let base = &verifying_key_pool[rng.below(verifying_key_pool.len())];
        e.verifying_key(&mutate(rng, base));
    }
    for _ in 0..1500 {
        let message = random_message(rng, 1, 3);
        e.signing_key(&message);
        e.verifying_key(&message);
    }

    // Signing through the key API, including unusable claims.
    for _ in 0..900 {
        let key = pick_signer(rng, &keys);
        let id_type = rng.pick(&[KeyIdType::KeyHash, KeyIdType::PublicKey]);
        let claims = if rng.chance(70) {
            signable_claims(rng)
        } else {
            random_claims(rng)
        };
        e.sign(key, id_type, &claims);
    }

    // The same limits through signing, and through verification of an
    // envelope that carries a correct signature over the payload.
    for key in keys.iter().filter(|k| !is_slow(k.algorithm())) {
        let material = verifier_material(key);
        let key_id = KeyIdentifier::KeyHash(compute_key_hash(material));
        for claims in &limit_claims {
            e.sign(key, KeyIdType::KeyHash, claims);
            let payload = serialize_claims(claims);
            let input = serialize_signing_input(Version::V0, key.algorithm(), &key_id, &payload);
            let signature = raw_sign(key.algorithm(), key.secret_key(), &input);
            let token = append_signature(input, &signature);
            e.token(&token);
            e.verify(key.algorithm(), material, &token, 1);
        }
    }

    // Tokens: honest ones at boundary times, under the right and wrong keys.
    for _ in 0..1500 {
        let key = pick_signer(rng, &keys);
        let claims = signable_claims(rng);
        let id_type = if key.algorithm().is_symmetric() || rng.chance(70) {
            KeyIdType::KeyHash
        } else {
            KeyIdType::PublicKey
        };
        let token = key.sign_with_key_id(&claims, id_type).unwrap();
        e.token(&token);
        e.verify(
            key.algorithm(),
            verifier_material(key),
            &token,
            boundary_times(rng, &claims),
        );
        if rng.chance(30) {
            let other = &keys[rng.below(keys.len())];
            let algorithm = if rng.chance(50) {
                other.algorithm()
            } else {
                key.algorithm()
            };
            e.verify(
                algorithm,
                verifier_material(other),
                &token,
                claims.expires_at,
            );
        }
        if rng.chance(10) {
            let len = rng.pick(&[0usize, 32, 47, 48, 128, 129, 1311, 1312, 1313, 2592, 2593]);
            e.verify(key.algorithm(), &rng.bytes(len), &token, claims.expires_at);
        }
        if token.len() < 600 || rng.chance(15) {
            // Re-signed so that later mutations do not depend on FN-DSA's randomness.
            let (signed_len, _) = first_len(&walk(&token), 6).unwrap();
            let input = token[..signed_len].to_vec();
            let signature = raw_sign(key.algorithm(), key.secret_key(), &input);
            token_pool.push(append_signature(input, &signature));
        }
    }

    // Correctly signed envelopes around payloads and identifiers that signing
    // would refuse. Only the checks after the signature can reject these.
    for _ in 0..1500 {
        let key = pick_signer(rng, &keys);
        let material = verifier_material(key);
        let payload = match rng.below(4) {
            0 => serialize_claims(&random_claims(rng)),
            1 => {
                let base = rng.below(claims_pool.len());
                mutate(rng, &claims_pool[base])
            }
            2 => random_message(rng, 3, 6),
            _ => rng.bytes_below(20),
        };
        let key_id = match rng.below(8) {
            0 => KeyIdentifier::PublicKey(material.to_vec()),
            1 => KeyIdentifier::KeyHash(rng.bytes(8).try_into().unwrap()),
            2 => {
                let len = rng.pick(&[0usize, 8, 32, 33, 1312]);
                KeyIdentifier::PublicKey(rng.bytes(len))
            }
            _ => KeyIdentifier::KeyHash(compute_key_hash(material)),
        };
        e.signing_input(key.algorithm(), &key_id, &payload);
        let input = serialize_signing_input(Version::V0, key.algorithm(), &key_id, &payload);
        let mut signature = raw_sign(key.algorithm(), key.secret_key(), &input);
        match rng.below(20) {
            0 => signature.truncate(signature.len() - 1),
            1 => signature.push(0),
            2 => signature[0] ^= 1,
            _ => {}
        }
        let token = append_signature(input, &signature);
        e.token(&token);
        let now = deserialize_claims(&payload).map_or(0, |c| boundary_times(rng, &c));
        e.verify(key.algorithm(), material, &token, now);
    }

    // Damaged tokens.
    for _ in 0..7000 {
        let base = &token_pool[rng.below(token_pool.len())];
        let token = mutate(rng, base);
        e.token(&token);
        if rng.chance(40) {
            // Verify under the key that signed the undamaged token, if it is one of ours.
            let original = deserialize_signed_token(base).unwrap();
            let signer = keys.iter().find(|k| {
                let material = verifier_material(k);
                k.algorithm() == original.algorithm
                    && (original.key_identifier.as_bytes() == compute_key_hash(material)
                        || original.key_identifier.as_bytes() == material)
            });
            if let Some(key) = signer {
                let now = deserialize_claims(&original.payload).unwrap().expires_at;
                e.verify(key.algorithm(), verifier_material(key), &token, now);
            }
        }
    }
    for _ in 0..4000 {
        e.token(&random_message(rng, 3, 6));
    }
    for len in [36511, 36512, 36513] {
        e.token(&vec![0u8; len]);
        // The first field has its own error, so the size check must come first.
        for prefix in [[0x08, 0x05], [0x10, 0x0A], [0x18, 0x09]] {
            let mut data = prefix.to_vec();
            data.resize(len, 0);
            e.token(&data);
        }
    }

    // Key identifier and signature lengths on each side of every algorithm's
    // size and of the field limits, under a key that the token names correctly.
    for algorithm in Algorithm::ALL {
        let key_len = algorithm.public_key_len().unwrap_or(48);
        let sig_len = algorithm.signature_len();
        for key_len in [key_len - 1, key_len, key_len + 1, 128, 129, 2592, 2593] {
            // The first byte is the header of an FN-DSA public key.
            let mut material = vec![7; key_len];
            material[0] = if algorithm == Algorithm::FnDsa512 {
                9
            } else {
                10
            };
            for key_id in [
                KeyIdentifier::KeyHash(compute_key_hash(&material)),
                KeyIdentifier::PublicKey(material.clone()),
            ] {
                let input = serialize_signing_input(Version::V0, algorithm, &key_id, &[0x08, 0x01]);
                for sig_len in [1, sig_len - 1, sig_len, sig_len + 1, 29792, 29793] {
                    let token = append_signature(input.clone(), &vec![9; sig_len]);
                    e.token(&token);
                    e.verify(algorithm, &material, &token, 0);
                }
            }
        }
    }

    // One honest SLH-DSA token per parameter set and key identifier type.
    for key in keys.iter().filter(|k| is_slow(k.algorithm())) {
        for id_type in [KeyIdType::KeyHash, KeyIdType::PublicKey] {
            let claims = claims_of_size(4096);
            e.sign(key, id_type, &claims);
            let token = key.sign_with_key_id(&claims, id_type).unwrap();
            e.verify(key.algorithm(), key.public_key(), &token, 1);
        }
    }

    e.out.flush().expect("flush cases");
}
