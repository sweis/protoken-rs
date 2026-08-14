# protoken for Python

Python bindings for [protoken](../../README.md): compact signed tokens
(HMAC-SHA256, Ed25519, ML-DSA-44) using canonical proto3 encoding. The
bindings are a thin [PyO3](https://pyo3.rs) layer over the Rust library, so
all parsing, validation, and cryptography is the same code the CLI uses.

**Warning**: experimental, like the rest of this repository.

## Build

Requires Rust and [maturin](https://www.maturin.rs) (`pip install maturin`).

```sh
cd bindings/python
python -m venv .venv && . .venv/bin/activate
maturin develop          # build and install into the venv
pip install pytest && pytest
```

`maturin build --release` produces a wheel in `target/wheels/`. Wheels use the
stable ABI (`abi3`) and work on Python 3.10 and later.

## Usage

```python
from protoken import Claims, SigningKey, VerifyingKey, TokenExpired

key = SigningKey.generate("ed25519")          # or "hmac-sha256", "ml-dsa-44"
token = key.sign(Claims(
    expires_at=1_800_000_000,
    subject="user:alice",
    scopes=["read", "write"],
))

verifier = VerifyingKey.from_bytes(key.verifying_key().to_bytes())
verified = verifier.verify(token)             # now defaults to the current time
verified.claims.subject                       # 'user:alice'
verified.claims.scopes                        # ('read', 'write')

try:
    verifier.verify(token, now=1_900_000_000)
except TokenExpired:
    ...
```

HMAC keys verify with the `SigningKey` itself. Keys and tokens are `bytes` in
the same wire format as the CLI. The CLI writes them as URL-safe base64
without padding and reads either alphabet with or without padding, so keys
and tokens move between the two freely. Python's decoder does insist on
padding:

```python
import base64

def from_cli(text: str) -> bytes:
    text = text.strip()
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))

key = SigningKey.from_bytes(from_cli(open("my.key").read()))
token_for_cli = base64.urlsafe_b64encode(key.sign(claims)).decode()   # padded is fine
```

`inspect_token(token)` decodes a token without verifying it, for example to
look up which key to use by `key_id`. Nothing it returns can be trusted.

## Errors

All errors are `ProtokenError` (a `ValueError`). `TokenExpired`,
`TokenNotYetValid`, and `VerificationFailed` are subclasses; the last covers
malformed tokens and tokens signed by another key. Passing the wrong Python
type raises `TypeError` as usual.

## Notes

- `SigningKey.to_bytes()` returns the secret. Python cannot zero `bytes`
  objects, so it stays in memory until garbage collected.
- Keys are not picklable; serialize them with `to_bytes()` deliberately.
- Type stubs are included (`py.typed`).
