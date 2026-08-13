import base64
import json
import pickle
from pathlib import Path

import pytest

import protoken
from protoken import (
    ALGORITHMS,
    Claims,
    ProtokenError,
    SigningKey,
    TokenExpired,
    TokenNotYetValid,
    VerificationFailed,
    VerifyingKey,
    inspect_token,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
EXPIRES = 2_000_000_000
NOW = 1_900_000_000
ASYMMETRIC = [a for a in ALGORITHMS if a != "hmac-sha256"]


def b64decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def full_claims() -> Claims:
    return Claims(
        expires_at=EXPIRES,
        not_before=NOW,
        issued_at=NOW,
        subject="user:alice",
        audience="api",
        scopes=["write", "read"],
    )


def test_algorithms_constant():
    assert ALGORITHMS == ("hmac-sha256", "ed25519", "ml-dsa-44")


class TestClaims:
    def test_fields_and_sorted_scopes(self):
        claims = full_claims()
        assert claims.expires_at == EXPIRES
        assert claims.not_before == NOW
        assert claims.subject == "user:alice"
        assert claims.audience == "api"
        assert claims.scopes == ("read", "write")

    def test_defaults(self):
        claims = Claims(EXPIRES)
        assert claims.to_dict() == {"expires_at": EXPIRES}
        assert claims.scopes == ()
        assert claims.subject == ""

    def test_to_dict_full(self):
        assert full_claims().to_dict() == {
            "expires_at": EXPIRES,
            "not_before": NOW,
            "issued_at": NOW,
            "subject": "user:alice",
            "audience": "api",
            "scopes": ("read", "write"),
        }

    def test_equality(self):
        assert full_claims() == full_claims()
        assert full_claims() != Claims(EXPIRES)

    def test_is_immutable(self):
        with pytest.raises(AttributeError):
            full_claims().subject = "mallory"  # type: ignore[misc]

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"expires_at": 0},
            {"expires_at": 10, "not_before": 11},
            {"expires_at": EXPIRES, "subject": "x" * 256},
            {"expires_at": EXPIRES, "scopes": ["a", "a"]},
            {"expires_at": EXPIRES, "scopes": [""]},
            {"expires_at": EXPIRES, "scopes": [f"s{i}" for i in range(33)]},
        ],
    )
    def test_invalid_claims_rejected_at_construction(self, kwargs):
        with pytest.raises(ProtokenError):
            Claims(**kwargs)

    def test_type_errors_are_python_type_errors(self):
        with pytest.raises(TypeError):
            Claims("soon")  # type: ignore[arg-type]
        with pytest.raises((TypeError, OverflowError)):
            Claims(-1)

    def test_repr_uses_sorted_scopes(self):
        assert repr(Claims(5, subject="s", scopes=["b", "a"])) == (
            'Claims(expires_at=5, not_before=0, issued_at=0, subject="s", audience="", scopes=["a", "b"])'
        )


class TestKeys:
    @pytest.mark.parametrize("algorithm", ALGORITHMS)
    def test_generate_and_serialize_roundtrip(self, algorithm):
        key = SigningKey.generate(algorithm)
        assert key.algorithm == algorithm
        assert SigningKey.from_bytes(key.to_bytes()) == key
        assert len(key.key_hash()) == 8

    def test_generate_defaults_to_ed25519(self):
        assert SigningKey.generate().algorithm == "ed25519"

    def test_generate_accepts_aliases(self):
        assert SigningKey.generate("hmac").algorithm == "hmac-sha256"
        assert SigningKey.generate("ML-DSA-44").algorithm == "ml-dsa-44"

    def test_generate_rejects_unknown_algorithm(self):
        with pytest.raises(ProtokenError, match="unknown algorithm"):
            SigningKey.generate("rsa")

    def test_generated_keys_differ(self):
        assert SigningKey.generate() != SigningKey.generate()

    @pytest.mark.parametrize("algorithm", ASYMMETRIC)
    def test_verifying_key(self, algorithm):
        key = SigningKey.generate(algorithm)
        vk = key.verifying_key()
        assert vk.algorithm == algorithm
        assert vk.public_key == key.public_key
        assert vk.key_hash() == key.key_hash()
        assert VerifyingKey.from_bytes(vk.to_bytes()) == vk

    def test_hmac_has_no_verifying_key(self):
        key = SigningKey.generate("hmac-sha256")
        assert key.public_key == b""
        with pytest.raises(ProtokenError):
            key.verifying_key()

    def test_public_key_sizes(self):
        assert len(SigningKey.generate("ed25519").public_key) == 32
        assert len(SigningKey.generate("ml-dsa-44").public_key) == 1312

    @pytest.mark.parametrize("data", [b"", b"\x00", b"\x08\x02\x12\x03abc", bytes(100)])
    def test_malformed_keys_rejected(self, data):
        # Key problems are plain ProtokenError, not VerificationFailed, which
        # is reserved for problems with a token.
        with pytest.raises(ProtokenError) as excinfo:
            SigningKey.from_bytes(data)
        assert type(excinfo.value) is ProtokenError
        with pytest.raises(ProtokenError) as excinfo:
            VerifyingKey.from_bytes(data)
        assert type(excinfo.value) is ProtokenError

    def test_verifying_key_bytes_are_not_a_signing_key(self):
        vk_bytes = SigningKey.generate().verifying_key().to_bytes()
        with pytest.raises(ProtokenError):
            SigningKey.from_bytes(vk_bytes)

    def test_repr_hides_secret(self):
        key = SigningKey.generate("hmac-sha256")
        assert repr(key) == 'SigningKey(algorithm="hmac-sha256")'
        assert repr(SigningKey.generate().verifying_key()) == 'VerifyingKey(algorithm="ed25519")'

    def test_keys_are_not_picklable(self):
        with pytest.raises(TypeError):
            pickle.dumps(SigningKey.generate())


class TestSignVerify:
    @pytest.mark.parametrize("algorithm", ALGORITHMS)
    def test_roundtrip(self, algorithm):
        key = SigningKey.generate(algorithm)
        claims = full_claims()
        token = key.sign(claims)
        assert isinstance(token, bytes)

        verified = key.verify(token, now=NOW)
        assert verified.algorithm == algorithm
        assert verified.key_id_type == "key_hash"
        assert verified.key_id == key.key_hash()
        assert verified.claims == claims

    @pytest.mark.parametrize("algorithm", ASYMMETRIC)
    def test_verify_with_verifying_key(self, algorithm):
        key = SigningKey.generate(algorithm)
        token = key.sign(Claims(EXPIRES))
        vk = VerifyingKey.from_bytes(key.verifying_key().to_bytes())
        assert vk.verify(token, now=NOW).claims == Claims(EXPIRES)

    @pytest.mark.parametrize("algorithm", ASYMMETRIC)
    def test_embed_public_key(self, algorithm):
        key = SigningKey.generate(algorithm)
        token = key.sign(Claims(EXPIRES), embed_public_key=True)
        verified = key.verifying_key().verify(token, now=NOW)
        assert verified.key_id_type == "public_key"
        assert verified.key_id == key.public_key
        assert len(token) > len(key.sign(Claims(EXPIRES)))

    def test_hmac_cannot_embed_public_key(self):
        with pytest.raises(ProtokenError):
            SigningKey.generate("hmac-sha256").sign(Claims(EXPIRES), embed_public_key=True)

    def test_signing_is_deterministic(self):
        key = SigningKey.generate("ml-dsa-44")
        assert key.sign(full_claims()) == key.sign(full_claims())

    def test_now_defaults_to_current_time(self):
        key = SigningKey.generate()
        assert key.verify(key.sign(Claims(EXPIRES))).claims.expires_at == EXPIRES
        with pytest.raises(TokenExpired):
            key.verify(key.sign(Claims(1)))

    def test_expiry_boundaries(self):
        key = SigningKey.generate()
        token = key.sign(Claims(EXPIRES, not_before=NOW))
        assert key.verify(token, now=EXPIRES)
        assert key.verify(token, now=NOW)
        with pytest.raises(TokenExpired):
            key.verify(token, now=EXPIRES + 1)
        with pytest.raises(TokenNotYetValid):
            key.verify(token, now=NOW - 1)

    def test_error_hierarchy(self):
        assert issubclass(TokenExpired, ProtokenError)
        assert issubclass(TokenNotYetValid, ProtokenError)
        assert issubclass(VerificationFailed, ProtokenError)
        assert issubclass(ProtokenError, ValueError)
        assert TokenExpired.__module__ == "protoken"

    @pytest.mark.parametrize("algorithm", ALGORITHMS)
    def test_wrong_key_rejected(self, algorithm):
        token = SigningKey.generate(algorithm).sign(Claims(EXPIRES))
        with pytest.raises(VerificationFailed):
            SigningKey.generate(algorithm).verify(token, now=NOW)

    def test_wrong_algorithm_rejected(self):
        token = SigningKey.generate("hmac-sha256").sign(Claims(EXPIRES))
        with pytest.raises(VerificationFailed, match="expected ed25519"):
            SigningKey.generate("ed25519").verify(token, now=NOW)

    def test_every_single_bit_flip_is_rejected(self):
        key = SigningKey.generate("ed25519")
        token = bytearray(key.sign(full_claims()))
        for i in range(len(token)):
            corrupted = bytearray(token)
            corrupted[i] ^= 0x01
            with pytest.raises(ProtokenError):
                key.verify(bytes(corrupted), now=NOW)

    def test_truncated_and_garbage_tokens_rejected(self):
        key = SigningKey.generate()
        token = key.sign(Claims(EXPIRES))
        for length in range(len(token)):
            with pytest.raises(VerificationFailed):
                key.verify(token[:length], now=NOW)
        with pytest.raises(VerificationFailed):
            key.verify(b"not a token", now=NOW)

    def test_token_argument_must_be_bytes(self):
        with pytest.raises(TypeError):
            SigningKey.generate().verify("dG9rZW4", now=NOW)  # type: ignore[arg-type]

    def test_verified_token_repr(self):
        key = SigningKey.generate("hmac-sha256")
        verified = key.verify(key.sign(Claims(EXPIRES)), now=NOW)
        assert repr(verified).startswith('VerifiedToken(algorithm="hmac-sha256", key_id_type="key_hash"')


class TestInspect:
    def test_inspect_does_not_need_a_key(self):
        key = SigningKey.generate("ed25519")
        claims = full_claims()
        token = key.sign(claims)

        unverified = inspect_token(token)
        assert unverified.algorithm == "ed25519"
        assert unverified.key_id_type == "key_hash"
        assert unverified.key_id == key.key_hash()
        assert unverified.claims == claims
        assert len(unverified.signature) == 64
        assert repr(unverified).startswith("UnverifiedToken(")

    def test_inspect_shows_embedded_public_key(self):
        key = SigningKey.generate("ed25519")
        unverified = inspect_token(key.sign(Claims(EXPIRES), embed_public_key=True))
        assert unverified.key_id_type == "public_key"
        assert unverified.key_id == key.public_key

    def test_inspect_rejects_garbage(self):
        with pytest.raises(VerificationFailed):
            inspect_token(b"\xff\xff")

    def test_inspect_still_parses_expired_tokens(self):
        token = SigningKey.generate().sign(Claims(1))
        assert inspect_token(token).claims.expires_at == 1


class TestReferenceVectors:
    """Interoperability with the tokens and keys produced by the Rust CLI."""

    @pytest.fixture(scope="class")
    def vectors(self):
        path = REPO_ROOT / "testdata" / "reference_vectors.json"
        return json.loads(path.read_text())["vectors"]

    def test_covers_every_algorithm(self, vectors):
        assert sorted(v["algorithm"] for v in vectors) == sorted(ALGORITHMS)

    def test_stored_tokens_verify(self, vectors):
        for v in vectors:
            token = b64decode(v["token_base64"])
            if "verifying_key_base64" in v:
                verifier = VerifyingKey.from_bytes(b64decode(v["verifying_key_base64"]))
            else:
                verifier = SigningKey.from_bytes(b64decode(v["signing_key_base64"]))
            verified = verifier.verify(token, now=NOW)
            assert verified.algorithm == v["algorithm"], v["name"]
            assert verified.claims.to_dict() == {
                **v["claims"],
                "scopes": tuple(v["claims"]["scopes"]),
            }, v["name"]
            assert verified.key_id == b64decode(v["key_hash_base64"]), v["name"]

    def test_resigning_reproduces_stored_tokens(self, vectors):
        for v in vectors:
            key = SigningKey.from_bytes(b64decode(v["signing_key_base64"]))
            token = key.sign(Claims(**v["claims"]))
            assert token == b64decode(v["token_base64"]), v["name"]

    def test_inspect_matches_stored_metadata(self, vectors):
        for v in vectors:
            unverified = inspect_token(b64decode(v["token_base64"]))
            assert unverified.algorithm == v["algorithm"], v["name"]
            assert unverified.key_id == b64decode(v["key_hash_base64"]), v["name"]


def test_public_api_is_exported():
    for name in protoken.__all__:
        assert hasattr(protoken, name), name
