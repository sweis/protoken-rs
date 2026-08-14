"""Compact signed tokens using canonical proto3 encoding.

    >>> from protoken import Claims, SigningKey
    >>> key = SigningKey.generate("ed25519")
    >>> token = key.sign(Claims(expires_at=1_800_000_000, subject="user:alice"))
    >>> key.verifying_key().verify(token, now=1_799_999_000).claims.subject
    'user:alice'

Keys and tokens are ``bytes``; base64-encode them yourself for transport.
The CLI in this repository uses unpadded URL-safe base64.
"""

from protoken._protoken import (
    ALGORITHMS,
    Claims,
    ProtokenError,
    SigningKey,
    TokenExpired,
    TokenNotYetValid,
    UnverifiedToken,
    VerificationFailed,
    VerifiedToken,
    VerifyingKey,
    inspect_token,
)

__all__ = [
    "ALGORITHMS",
    "Claims",
    "ProtokenError",
    "SigningKey",
    "TokenExpired",
    "TokenNotYetValid",
    "UnverifiedToken",
    "VerificationFailed",
    "VerifiedToken",
    "VerifyingKey",
    "inspect_token",
]
