"""Tests for verify_pact_token: happy path plus the security failure matrix."""

from __future__ import annotations

import base64
import json
import time
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from getpact_verifier import (
    JwksCache,
    ReplayCache,
    VerifyDenied,
    VerifyOpts,
    VerifyResult,
    verify_pact_token,
)

ISSUER = "https://issuer.test/acme"
JWKS_URL = "https://issuer.test/acme/.well-known/jwks.json"
AUDIENCE = "pact-mcp"
WORKSPACE_ID = "11111111-2222-4333-8444-555555555555"
KID = "ws-jwt-1"


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _encode_json(value: Any) -> str:
    return _b64url(json.dumps(value, separators=(",", ":")).encode("utf-8"))


def _sign_compact(
    header: dict[str, Any],
    payload: dict[str, Any],
    private_key: Ed25519PrivateKey,
) -> str:
    h = _encode_json(header)
    b = _encode_json(payload)
    signing_input = f"{h}.{b}".encode("ascii")
    sig = private_key.sign(signing_input)
    return f"{h}.{b}.{_b64url(sig)}"


def _hash_disclosure(token: str) -> str:
    import hashlib

    return _b64url(hashlib.sha256(token.encode("ascii")).digest())


def _build_disclosure(name: str, value: Any, salt: str = "salt-fixed") -> str:
    arr = [salt, name, value]
    return _b64url(json.dumps(arr, separators=(",", ":")).encode("utf-8"))


def _public_jwk(private_key: Ed25519PrivateKey, kid: str | None = None) -> dict[str, Any]:
    from cryptography.hazmat.primitives import serialization

    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    jwk: dict[str, Any] = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64url(raw),
    }
    if kid is not None:
        jwk["kid"] = kid
        jwk["alg"] = "EdDSA"
    return jwk


def _mint_sd_jwt(
    *,
    issuer_private_key: Ed25519PrivateKey,
    kid: str,
    cnf_jwk: dict[str, Any],
    jti: str,
    audience: str = AUDIENCE,
    tool_name: str = "search.documents",
    scope: dict[str, Any] | None = None,
    ttl_seconds: int = 60,
    agent_id: str = "agent-uuid-123",
) -> str:
    if scope is None:
        scope = {"resource": "drive:doc-1"}
    now = int(time.time())
    exp = now + ttl_seconds

    disclosure_tokens = [
        _build_disclosure("scope", {"tool_name": tool_name, **scope}, "salt-scope"),
        _build_disclosure("agent_id", agent_id, "salt-agent"),
    ]
    sd_hashes = [_hash_disclosure(t) for t in disclosure_tokens]

    issuer_payload: dict[str, Any] = {
        "iss": ISSUER,
        "org": WORKSPACE_ID,
        "sub": f"agent_{agent_id}",
        "jti": jti,
        "aud": audience,
        "iat": now,
        "exp": exp,
        "tool_name": tool_name,
        "cnf": {"jwk": cnf_jwk},
        "_sd": sd_hashes,
        "_sd_alg": "sha-256",
    }
    header = {"alg": "EdDSA", "typ": "sd+jwt", "kid": kid}
    jws = _sign_compact(header, issuer_payload, issuer_private_key)
    return "~".join([jws, *disclosure_tokens]) + "~"


def _sign_kb_jwt(
    *,
    holder_private_key: Ed25519PrivateKey,
    sd_jwt: str,
    audience: str = AUDIENCE,
    iat: int | None = None,
    nonce: str = "nonce-fixed",
) -> str:
    import hashlib

    if not sd_jwt.endswith("~"):
        raise ValueError("sd_jwt must end with ~")
    sd_hash = _b64url(hashlib.sha256(sd_jwt.encode("ascii")).digest())
    if iat is None:
        iat = int(time.time())
    payload = {"iat": iat, "aud": audience, "nonce": nonce, "sd_hash": sd_hash}
    header = {"alg": "EdDSA", "typ": "kb+jwt"}
    kb = _sign_compact(header, payload, holder_private_key)
    return f"{sd_jwt}{kb}"


class _MemoryReplayCache:
    def __init__(self) -> None:
        self._seen: set[str] = set()

    def has(self, key: str) -> bool:
        return key in self._seen

    def add(self, key: str) -> None:
        self._seen.add(key)


def _static_jwks_cache(public_jwk: dict[str, Any]) -> JwksCache:
    body = {"keys": [public_jwk]}

    def fetcher(_url: str) -> dict[str, Any]:
        return body

    return JwksCache(fetcher=fetcher)


@pytest.fixture
def issuer_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def holder_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def jwks_cache(issuer_key: Ed25519PrivateKey) -> JwksCache:
    return _static_jwks_cache(_public_jwk(issuer_key, kid=KID))


def test_verifies_well_formed_capability_token(
    issuer_key: Ed25519PrivateKey,
    holder_key: Ed25519PrivateKey,
    jwks_cache: JwksCache,
) -> None:
    sd = _mint_sd_jwt(
        issuer_private_key=issuer_key,
        kid=KID,
        cnf_jwk=_public_jwk(holder_key),
        jti="jti-happy",
    )
    token = _sign_kb_jwt(holder_private_key=holder_key, sd_jwt=sd)
    result = verify_pact_token(
        token,
        VerifyOpts(
            jwks_url=JWKS_URL,
            audience=AUDIENCE,
            tool_name="search.documents",
            resource={"resource": "drive:doc-1"},
            jwks_cache=jwks_cache,
        ),
    )
    assert isinstance(result, VerifyResult)
    assert result.ok is True
    assert result.jti == "jti-happy"
    assert result.workspace_id == WORKSPACE_ID
    assert result.audience == AUDIENCE
    assert result.scope_claim["resource"] == "drive:doc-1"
    assert result.agent_id == "agent-uuid-123"


def test_rejects_tampered_issuer_signature(
    issuer_key: Ed25519PrivateKey,
    holder_key: Ed25519PrivateKey,
    jwks_cache: JwksCache,
) -> None:
    sd = _mint_sd_jwt(
        issuer_private_key=issuer_key,
        kid=KID,
        cnf_jwk=_public_jwk(holder_key),
        jti="jti-tamper",
    )
    parts = sd.split("~")
    jws_parts = parts[0].split(".")
    sig = jws_parts[2]
    flipped = ("B" + sig[1:]) if sig.startswith("A") else ("A" + sig[1:])
    jws_parts[2] = flipped
    parts[0] = ".".join(jws_parts)
    tampered_sd = "~".join(parts)
    token = _sign_kb_jwt(holder_private_key=holder_key, sd_jwt=tampered_sd)

    result = verify_pact_token(
        token,
        VerifyOpts(jwks_url=JWKS_URL, audience=AUDIENCE, jwks_cache=jwks_cache),
    )
    assert isinstance(result, VerifyDenied)
    assert result.reason == "signature_invalid"


def test_rejects_audience_mismatch(
    issuer_key: Ed25519PrivateKey,
    holder_key: Ed25519PrivateKey,
    jwks_cache: JwksCache,
) -> None:
    sd = _mint_sd_jwt(
        issuer_private_key=issuer_key,
        kid=KID,
        cnf_jwk=_public_jwk(holder_key),
        jti="jti-aud",
    )
    token = _sign_kb_jwt(holder_private_key=holder_key, sd_jwt=sd)
    result = verify_pact_token(
        token,
        VerifyOpts(jwks_url=JWKS_URL, audience="pact-admin", jwks_cache=jwks_cache),
    )
    assert isinstance(result, VerifyDenied)
    assert result.reason == "aud_mismatch"


def test_rejects_expired_issuer_token(
    issuer_key: Ed25519PrivateKey,
    holder_key: Ed25519PrivateKey,
    jwks_cache: JwksCache,
) -> None:
    sd = _mint_sd_jwt(
        issuer_private_key=issuer_key,
        kid=KID,
        cnf_jwk=_public_jwk(holder_key),
        jti="jti-exp",
        ttl_seconds=-10,
    )
    token = _sign_kb_jwt(
        holder_private_key=holder_key,
        sd_jwt=sd,
        iat=int(time.time()) - 20,
    )
    result = verify_pact_token(
        token,
        VerifyOpts(jwks_url=JWKS_URL, audience=AUDIENCE, jwks_cache=jwks_cache),
    )
    assert isinstance(result, VerifyDenied)
    assert result.reason == "expired"


def test_rejects_replayed_kb_jwt(
    issuer_key: Ed25519PrivateKey,
    holder_key: Ed25519PrivateKey,
    jwks_cache: JwksCache,
) -> None:
    sd = _mint_sd_jwt(
        issuer_private_key=issuer_key,
        kid=KID,
        cnf_jwk=_public_jwk(holder_key),
        jti="jti-replay",
    )
    token = _sign_kb_jwt(holder_private_key=holder_key, sd_jwt=sd)
    replay_cache: ReplayCache = _MemoryReplayCache()
    opts = VerifyOpts(
        jwks_url=JWKS_URL,
        audience=AUDIENCE,
        tool_name="search.documents",
        resource={"resource": "drive:doc-1"},
        replay_cache=replay_cache,
        jwks_cache=jwks_cache,
    )
    first = verify_pact_token(token, opts)
    assert isinstance(first, VerifyResult)
    second = verify_pact_token(token, opts)
    assert isinstance(second, VerifyDenied)
    assert second.reason == "kb_replay_detected"


def test_rejects_tool_name_mismatch(
    issuer_key: Ed25519PrivateKey,
    holder_key: Ed25519PrivateKey,
    jwks_cache: JwksCache,
) -> None:
    sd = _mint_sd_jwt(
        issuer_private_key=issuer_key,
        kid=KID,
        cnf_jwk=_public_jwk(holder_key),
        jti="jti-tool",
        tool_name="search.documents",
    )
    token = _sign_kb_jwt(holder_private_key=holder_key, sd_jwt=sd)
    result = verify_pact_token(
        token,
        VerifyOpts(
            jwks_url=JWKS_URL,
            audience=AUDIENCE,
            tool_name="write.documents",
            resource={"resource": "drive:doc-1"},
            jwks_cache=jwks_cache,
        ),
    )
    assert isinstance(result, VerifyDenied)
    assert result.reason == "tool_mismatch"


def test_denies_resource_required_when_token_scope_demands_resource(
    issuer_key: Ed25519PrivateKey,
    holder_key: Ed25519PrivateKey,
    jwks_cache: JwksCache,
) -> None:
    sd = _mint_sd_jwt(
        issuer_private_key=issuer_key,
        kid=KID,
        cnf_jwk=_public_jwk(holder_key),
        jti="jti-res",
    )
    token = _sign_kb_jwt(holder_private_key=holder_key, sd_jwt=sd)
    result = verify_pact_token(
        token,
        VerifyOpts(
            jwks_url=JWKS_URL,
            audience=AUDIENCE,
            tool_name="search.documents",
            jwks_cache=jwks_cache,
        ),
    )
    assert isinstance(result, VerifyDenied)
    assert result.reason == "resource_required"


def test_denies_scope_mismatch_when_resource_does_not_satisfy_scope(
    issuer_key: Ed25519PrivateKey,
    holder_key: Ed25519PrivateKey,
    jwks_cache: JwksCache,
) -> None:
    sd = _mint_sd_jwt(
        issuer_private_key=issuer_key,
        kid=KID,
        cnf_jwk=_public_jwk(holder_key),
        jti="jti-scope",
        scope={"resource": "drive:doc-1"},
    )
    token = _sign_kb_jwt(holder_private_key=holder_key, sd_jwt=sd)
    result = verify_pact_token(
        token,
        VerifyOpts(
            jwks_url=JWKS_URL,
            audience=AUDIENCE,
            tool_name="search.documents",
            resource={"resource": "drive:doc-99"},
            jwks_cache=jwks_cache,
        ),
    )
    assert isinstance(result, VerifyDenied)
    assert result.reason == "scope_mismatch"


def test_denies_kb_binding_when_wrong_holder_key(
    issuer_key: Ed25519PrivateKey,
    holder_key: Ed25519PrivateKey,
    jwks_cache: JwksCache,
) -> None:
    other_holder = Ed25519PrivateKey.generate()
    sd = _mint_sd_jwt(
        issuer_private_key=issuer_key,
        kid=KID,
        cnf_jwk=_public_jwk(holder_key),
        jti="jti-binding",
    )
    token = _sign_kb_jwt(holder_private_key=other_holder, sd_jwt=sd)
    result = verify_pact_token(
        token,
        VerifyOpts(
            jwks_url=JWKS_URL,
            audience=AUDIENCE,
            tool_name="search.documents",
            resource={"resource": "drive:doc-1"},
            jwks_cache=jwks_cache,
        ),
    )
    assert isinstance(result, VerifyDenied)
    assert result.reason == "kb_signature_invalid"


def test_returns_jwks_fetch_failed_when_endpoint_unreachable(
    issuer_key: Ed25519PrivateKey,
    holder_key: Ed25519PrivateKey,
) -> None:
    sd = _mint_sd_jwt(
        issuer_private_key=issuer_key,
        kid=KID,
        cnf_jwk=_public_jwk(holder_key),
        jti="jti-jwks",
    )
    token = _sign_kb_jwt(holder_private_key=holder_key, sd_jwt=sd)

    def failing(_url: str) -> dict[str, Any]:
        raise RuntimeError("network down")

    failing_cache = JwksCache(fetcher=failing)
    result = verify_pact_token(
        token,
        VerifyOpts(jwks_url=JWKS_URL, audience=AUDIENCE, jwks_cache=failing_cache),
    )
    assert isinstance(result, VerifyDenied)
    assert result.reason == "jwks_fetch_failed"


def test_denies_kb_iat_invalid_when_iat_too_old(
    issuer_key: Ed25519PrivateKey,
    holder_key: Ed25519PrivateKey,
    jwks_cache: JwksCache,
) -> None:
    sd = _mint_sd_jwt(
        issuer_private_key=issuer_key,
        kid=KID,
        cnf_jwk=_public_jwk(holder_key),
        jti="jti-iat",
    )
    stale_iat = int(time.time()) - 3600
    token = _sign_kb_jwt(holder_private_key=holder_key, sd_jwt=sd, iat=stale_iat)
    result = verify_pact_token(
        token,
        VerifyOpts(
            jwks_url=JWKS_URL,
            audience=AUDIENCE,
            tool_name="search.documents",
            resource={"resource": "drive:doc-1"},
            kb_iat_max_age_seconds=60,
            jwks_cache=jwks_cache,
        ),
    )
    assert isinstance(result, VerifyDenied)
    assert result.reason == "kb_iat_invalid"
