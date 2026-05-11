"""Tests for getpact_verifier."""
from __future__ import annotations

import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from getpact_verifier import (
    StaticVerifierOptions,
    create_static_verifier,
)


def _issue_token(private_pem: bytes, kid: str, claims: dict, alg: str = "EdDSA") -> str:
    return jwt.encode(
        claims,
        private_pem,
        algorithm=alg,
        headers={"kid": kid},
    )


def _make_keypair() -> tuple[bytes, dict]:
    private = Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    raw_public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    import base64

    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64.urlsafe_b64encode(raw_public).rstrip(b"=").decode("ascii"),
        "kid": "k1",
    }
    return private_pem, jwk


def test_static_verifier_accepts_valid_token() -> None:
    private_pem, jwk = _make_keypair()
    now = int(time.time())
    token = _issue_token(
        private_pem,
        kid="k1",
        claims={
            "iss": "https://issuer.test",
            "sub": "user-1",
            "aud": "pact-mcp",
            "exp": now + 60,
            "iat": now,
            "jti": "test-jti",
            "org": "00000000-0000-0000-0000-000000000001",
            "mode": "A",
        },
    )
    verifier = create_static_verifier(
        StaticVerifierOptions(
            public_key_jwk=jwk,
            issuer="https://issuer.test",
            audience="pact-mcp",
        )
    )
    claims = verifier.verify(token)
    assert claims["sub"] == "user-1"
    assert claims["org"] == "00000000-0000-0000-0000-000000000001"
    assert claims["mode"] == "A"


def test_static_verifier_rejects_wrong_audience() -> None:
    private_pem, jwk = _make_keypair()
    now = int(time.time())
    token = _issue_token(
        private_pem,
        kid="k1",
        claims={
            "iss": "https://issuer.test",
            "sub": "user-1",
            "aud": "pact-gateway",
            "exp": now + 60,
            "iat": now,
        },
    )
    verifier = create_static_verifier(
        StaticVerifierOptions(
            public_key_jwk=jwk,
            issuer="https://issuer.test",
            audience="pact-mcp",
        )
    )
    with pytest.raises(jwt.InvalidAudienceError):
        verifier.verify(token)


def test_static_verifier_rejects_wrong_issuer() -> None:
    private_pem, jwk = _make_keypair()
    now = int(time.time())
    token = _issue_token(
        private_pem,
        kid="k1",
        claims={
            "iss": "https://attacker.test",
            "sub": "user-1",
            "aud": "pact-mcp",
            "exp": now + 60,
            "iat": now,
        },
    )
    verifier = create_static_verifier(
        StaticVerifierOptions(
            public_key_jwk=jwk,
            issuer="https://issuer.test",
            audience="pact-mcp",
        )
    )
    with pytest.raises(jwt.InvalidIssuerError):
        verifier.verify(token)


def test_static_verifier_rejects_expired_token() -> None:
    private_pem, jwk = _make_keypair()
    now = int(time.time())
    token = _issue_token(
        private_pem,
        kid="k1",
        claims={
            "iss": "https://issuer.test",
            "sub": "user-1",
            "aud": "pact-mcp",
            "exp": now - 60,
            "iat": now - 120,
        },
    )
    verifier = create_static_verifier(
        StaticVerifierOptions(
            public_key_jwk=jwk,
            issuer="https://issuer.test",
            audience="pact-mcp",
        )
    )
    with pytest.raises(jwt.ExpiredSignatureError):
        verifier.verify(token)


def test_static_verifier_rejects_token_without_kid_header() -> None:
    private_pem, jwk = _make_keypair()
    now = int(time.time())
    token = jwt.encode(
        {
            "iss": "https://issuer.test",
            "sub": "user-1",
            "aud": "pact-mcp",
            "exp": now + 60,
            "iat": now,
        },
        private_pem,
        algorithm="EdDSA",
    )
    verifier = create_static_verifier(
        StaticVerifierOptions(
            public_key_jwk=jwk,
            issuer="https://issuer.test",
            audience="pact-mcp",
        )
    )
    with pytest.raises(jwt.InvalidTokenError):
        verifier.verify(token)


def test_static_verifier_rejects_non_eddsa_alg() -> None:
    """Algorithm confusion: HS256 with public key bytes as secret must fail."""
    _, jwk = _make_keypair()
    now = int(time.time())
    fake_token = jwt.encode(
        {
            "iss": "https://issuer.test",
            "sub": "user-1",
            "aud": "pact-mcp",
            "exp": now + 60,
            "iat": now,
        },
        "secret",
        algorithm="HS256",
        headers={"kid": "k1"},
    )
    verifier = create_static_verifier(
        StaticVerifierOptions(
            public_key_jwk=jwk,
            issuer="https://issuer.test",
            audience="pact-mcp",
        )
    )
    with pytest.raises(jwt.InvalidAlgorithmError):
        verifier.verify(fake_token)
