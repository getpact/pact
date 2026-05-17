"""Pact JWT verifier for Python services.

Mirrors the Node SDK (`@getpact/verifier-sdk`). Use `create_verifier` when you
want to fetch JWKS from a Pact issuer over HTTPS, or `create_static_verifier`
when you already pin the workspace's signing public key out-of-band.

Audit-chain verification is a separate concern handled by the `pact` CLI (see
`pact audit verify`). This SDK only validates a Pact-issued JWT against an
expected issuer and audience.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

import httpx
import jwt
from jwt import PyJWKClient
from jwt.algorithms import OKPAlgorithm

from .pact_token import (
    DEFAULT_KB_IAT_MAX_AGE_SECONDS,
    DEFAULT_KB_IAT_SKEW_SECONDS,
    DenyReason,
    JwksCache,
    JwksFetchError,
    ReplayCache,
    VerifyDenied,
    VerifyOpts,
    VerifyResult,
    shared_jwks_cache,
    verify_pact_token,
)

__version__ = "0.2.0"

_ALGORITHMS: list[str] = ["EdDSA"]


@dataclass(frozen=True)
class VerifierOptions:
    jwks_url: str
    issuer: str
    audience: str
    cache_ttl_seconds: int = 300
    request_timeout_seconds: float = 5.0


@dataclass(frozen=True)
class StaticVerifierOptions:
    public_key_jwk: dict[str, Any]
    issuer: str
    audience: str


class Verifier:
    """Verifier returned by `create_verifier` / `create_static_verifier`.

    `verify(token)` returns the decoded claims dict if the signature, issuer,
    audience, and expiry all check out. Raises `jwt.InvalidTokenError` (or a
    subclass) otherwise.

    `decode_claims(token)` returns the claims dict after the same checks. Use
    when you want the claims object directly rather than a verification result.
    """

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        key_resolver: Callable[[str], Any],
    ) -> None:
        self._issuer = issuer
        self._audience = audience
        self._key_resolver = key_resolver

    def verify(self, token: str) -> dict[str, Any]:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if not isinstance(kid, str) or len(kid) == 0:
            raise jwt.InvalidTokenError("missing kid in token header")
        key = self._key_resolver(kid)
        return jwt.decode(
            token,
            key=key,
            algorithms=_ALGORITHMS,
            issuer=self._issuer,
            audience=self._audience,
        )

    def decode_claims(self, token: str) -> dict[str, Any]:
        return self.verify(token)


def create_verifier(options: VerifierOptions) -> Verifier:
    """Build a Verifier that fetches JWKS over HTTPS and caches it."""
    client = PyJWKClient(
        options.jwks_url,
        cache_keys=True,
        lifespan=options.cache_ttl_seconds,
        timeout=int(options.request_timeout_seconds),
    )

    def resolve(kid: str) -> Any:
        return client.get_signing_key(kid).key

    return Verifier(
        issuer=options.issuer,
        audience=options.audience,
        key_resolver=resolve,
    )


def create_static_verifier(options: StaticVerifierOptions) -> Verifier:
    """Build a Verifier with a single pinned JWK (no network fetches)."""
    public_key = OKPAlgorithm.from_jwk(options.public_key_jwk)

    def resolve(_: str) -> Any:
        return public_key

    return Verifier(
        issuer=options.issuer,
        audience=options.audience,
        key_resolver=resolve,
    )


_default_clock_lock = threading.Lock()
_default_clock_offset_seconds = 0


def set_clock_skew_tolerance(seconds: int) -> None:
    """Allow callers to widen JWT exp/iat checks if their clocks drift."""
    global _default_clock_offset_seconds
    with _default_clock_lock:
        _default_clock_offset_seconds = max(0, int(seconds))


def _now() -> int:
    """Return current epoch time including any configured skew tolerance."""
    return int(time.time()) + _default_clock_offset_seconds


__all__ = [
    "DEFAULT_KB_IAT_MAX_AGE_SECONDS",
    "DEFAULT_KB_IAT_SKEW_SECONDS",
    "DenyReason",
    "JwksCache",
    "JwksFetchError",
    "ReplayCache",
    "StaticVerifierOptions",
    "Verifier",
    "VerifierOptions",
    "VerifyDenied",
    "VerifyOpts",
    "VerifyResult",
    "__version__",
    "create_static_verifier",
    "create_verifier",
    "set_clock_skew_tolerance",
    "shared_jwks_cache",
    "verify_pact_token",
]
