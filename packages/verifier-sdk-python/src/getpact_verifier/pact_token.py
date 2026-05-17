"""Verify Pact capability tokens (SD-JWT + KB-JWT).

Mirrors the Node `@getpact/verifier-sdk` `verifyPactToken` shape:

- Parse SD-JWT compact form
- Resolve issuer key from JWKS endpoint (cached)
- Verify issuer JWS (EdDSA only)
- Check aud, exp, jti, org
- Verify KB-JWT under cnf.jwk, bind to sd_hash, enforce iat bounds
- Optional replay cache lookup keyed on (jti, kb_iat, sd_hash)
- Match tool_name and resource scope claims
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Literal, Protocol

import httpx
import jwt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jwt.algorithms import OKPAlgorithm

from ._sd_jwt import (
    b64url_decode,
    collect_disclosed,
    decode_jws_header,
    decode_jws_payload,
    parse_compact,
    sha256_b64url,
)

KB_JWT_TYP = "kb+jwt"
DEFAULT_KB_IAT_SKEW_SECONDS = 300
DEFAULT_KB_IAT_MAX_AGE_SECONDS = 300
DEFAULT_JWKS_TTL_SECONDS = 300

DenyReason = Literal[
    "invalid_format",
    "signature_invalid",
    "jwks_fetch_failed",
    "aud_mismatch",
    "expired",
    "kb_iat_invalid",
    "kb_signature_invalid",
    "kb_binding_invalid",
    "kb_missing",
    "tool_mismatch",
    "resource_required",
    "scope_mismatch",
    "kb_replay_detected",
    "unknown",
]


class ReplayCache(Protocol):
    def has(self, key: str) -> bool: ...
    def add(self, key: str) -> None: ...


class JwksFetchError(Exception):
    pass


@dataclass
class _JwksEntry:
    expires_at: float
    keys: dict[str, Any]


class JwksCache:
    def __init__(
        self,
        *,
        ttl_seconds: int = DEFAULT_JWKS_TTL_SECONDS,
        fetcher: Callable[[str], dict[str, Any]] | None = None,
        request_timeout_seconds: float = 5.0,
    ) -> None:
        self._ttl = ttl_seconds
        self._fetcher = fetcher or self._default_fetcher
        self._timeout = request_timeout_seconds
        self._lock = threading.Lock()
        self._cache: dict[str, _JwksEntry] = {}

    def _default_fetcher(self, url: str) -> dict[str, Any]:
        try:
            resp = httpx.get(
                url,
                headers={"accept": "application/json"},
                timeout=self._timeout,
            )
        except httpx.HTTPError as exc:
            raise JwksFetchError(f"jwks endpoint request failed: {exc}") from exc
        if resp.status_code != 200:
            raise JwksFetchError(f"jwks endpoint returned {resp.status_code}")
        body = resp.json()
        if not isinstance(body, dict) or not isinstance(body.get("keys"), list):
            raise JwksFetchError("jwks response missing keys array")
        return body

    def _load(self, url: str) -> _JwksEntry:
        body = self._fetcher(url)
        keys: dict[str, Any] = {}
        for jwk in body.get("keys", []):
            if not isinstance(jwk, dict):
                continue
            kid = jwk.get("kid")
            if not isinstance(kid, str):
                continue
            try:
                keys[kid] = OKPAlgorithm.from_jwk(jwk)
            except Exception:
                continue
        entry = _JwksEntry(expires_at=time.time() + self._ttl, keys=keys)
        self._cache[url] = entry
        return entry

    def resolve(self, url: str, kid: str) -> Any:
        with self._lock:
            entry = self._cache.get(url)
            if entry is not None and entry.expires_at > time.time():
                key = entry.keys.get(kid)
                if key is not None:
                    return key
            entry = self._load(url)
            key = entry.keys.get(kid)
            if key is None:
                raise JwksFetchError(f"jwks at {url} has no key with kid {kid}")
            return key

    def invalidate(self, url: str | None = None) -> None:
        with self._lock:
            if url is None:
                self._cache.clear()
            else:
                self._cache.pop(url, None)


_shared_jwks_cache = JwksCache()


def shared_jwks_cache() -> JwksCache:
    return _shared_jwks_cache


@dataclass
class VerifyOpts:
    jwks_url: str
    audience: str
    tool_name: str | None = None
    resource: dict[str, Any] | None = None
    kb_iat_skew_seconds: int = DEFAULT_KB_IAT_SKEW_SECONDS
    kb_iat_max_age_seconds: int = DEFAULT_KB_IAT_MAX_AGE_SECONDS
    replay_cache: ReplayCache | None = None
    jwks_cache: JwksCache | None = None
    now: Callable[[], float] | None = None
    issuer: str | None = None


@dataclass
class VerifyResult:
    jti: str
    workspace_id: str
    scope_claim: dict[str, Any]
    audience: str
    expires_at: datetime
    agent_id: str | None = None
    ok: Literal[True] = field(default=True, init=False)


@dataclass
class VerifyDenied:
    reason: DenyReason
    detail: str | None = None
    ok: Literal[False] = field(default=False, init=False)


def _deny(reason: DenyReason, detail: str | None = None) -> VerifyDenied:
    return VerifyDenied(reason=reason, detail=detail)


def _is_plain_object(v: Any) -> bool:
    return isinstance(v, dict)


def _match_pattern(scope_value: Any, requested: Any) -> bool:
    if isinstance(scope_value, str) and isinstance(requested, str):
        if scope_value == requested:
            return True
        if scope_value.endswith("*"):
            prefix = scope_value[:-1]
            return requested.startswith(prefix)
        if scope_value == "*":
            return True
        return False
    if isinstance(scope_value, list):
        return any(_match_pattern(v, requested) for v in scope_value)
    if _is_plain_object(scope_value) and _is_plain_object(requested):
        return _match_scope(scope_value, requested)
    return scope_value == requested


def _match_scope(scope: dict[str, Any], resource: dict[str, Any]) -> bool:
    for k, v in scope.items():
        if k == "tool_name":
            continue
        if k not in resource:
            return False
        if not _match_pattern(v, resource[k]):
            return False
    return True


def _extract_scope_claim(
    issuer_payload: dict[str, Any],
    disclosed: dict[str, Any],
) -> dict[str, Any]:
    direct = disclosed.get("scope")
    if _is_plain_object(direct):
        return direct
    policy = disclosed.get("policy")
    if _is_plain_object(policy) and _is_plain_object(policy.get("scope")):
        return policy["scope"]
    claim = issuer_payload.get("scope_claim")
    if _is_plain_object(claim):
        return claim
    return {}


def _extract_agent_id(
    issuer_payload: dict[str, Any],
    disclosed: dict[str, Any],
) -> str | None:
    direct = disclosed.get("agent_id")
    if isinstance(direct, str):
        return direct
    payload = disclosed.get("payload")
    if _is_plain_object(payload) and isinstance(payload.get("agent_id"), str):
        return payload["agent_id"]
    sub = issuer_payload.get("sub")
    if isinstance(sub, str) and sub.startswith("agent_"):
        return sub[len("agent_") :]
    return None


def _verify_ed25519_jws(jws: str, key: Any) -> dict[str, Any] | None:
    """Verify Ed25519 JWS using pyjwt's decode path. Returns payload or None."""
    try:
        return jwt.decode(
            jws,
            key=key,
            algorithms=["EdDSA"],
            options={
                "verify_signature": True,
                "verify_exp": False,
                "verify_nbf": False,
                "verify_iat": False,
                "verify_aud": False,
                "verify_iss": False,
            },
        )
    except jwt.PyJWTError:
        return None


def _holder_key_from_cnf_jwk(jwk: dict[str, Any]) -> Ed25519PublicKey | None:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        return None
    x = jwk.get("x")
    if not isinstance(x, str):
        return None
    try:
        raw = b64url_decode(x)
    except Exception:
        return None
    if len(raw) != 32:
        return None
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except Exception:
        return None


def _verify_kb_signature(kb_jwt: str, holder_key: Ed25519PublicKey) -> bool:
    parts = kb_jwt.split(".")
    if len(parts) != 3:
        return False
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    try:
        sig = b64url_decode(parts[2])
    except Exception:
        return False
    try:
        holder_key.verify(sig, signing_input)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def verify_pact_token(
    sd_jwt: str,
    opts: VerifyOpts,
) -> VerifyResult | VerifyDenied:
    parsed = parse_compact(sd_jwt)
    if parsed is None:
        return _deny("invalid_format", "could not split sd-jwt compact form")

    header = decode_jws_header(parsed.issuer_jws)
    if header is None:
        return _deny("invalid_format", "issuer jwt header could not be decoded")
    kid = header.get("kid")
    if not isinstance(kid, str) or len(kid) == 0:
        return _deny("invalid_format", "issuer jwt header missing kid")

    cache = opts.jwks_cache or _shared_jwks_cache
    try:
        issuer_key = cache.resolve(opts.jwks_url, kid)
    except JwksFetchError as exc:
        return _deny("jwks_fetch_failed", str(exc))
    except Exception as exc:
        return _deny("jwks_fetch_failed", str(exc))

    issuer_payload = _verify_ed25519_jws(parsed.issuer_jws, issuer_key)
    if issuer_payload is None:
        return _deny("signature_invalid", "issuer jws signature did not verify")

    now_seconds = (opts.now() if opts.now is not None else time.time())
    exp = issuer_payload.get("exp")
    if not isinstance(exp, (int, float)):
        return _deny("invalid_format", "issuer payload missing exp")
    if now_seconds > float(exp):
        return _deny("expired")

    token_aud = issuer_payload.get("aud")
    if not isinstance(token_aud, str) or token_aud != opts.audience:
        return _deny("aud_mismatch", f"expected {opts.audience}, got {token_aud!r}")

    if opts.issuer is not None:
        token_iss = issuer_payload.get("iss")
        if token_iss != opts.issuer:
            return _deny("invalid_format", f"expected iss {opts.issuer}, got {token_iss!r}")

    jti = issuer_payload.get("jti")
    if not isinstance(jti, str) or len(jti) == 0:
        return _deny("invalid_format", "issuer payload missing jti")
    workspace_id = issuer_payload.get("org")
    if not isinstance(workspace_id, str) or len(workspace_id) == 0:
        return _deny("invalid_format", "issuer payload missing org")

    disclosed = collect_disclosed(parsed.disclosures)

    if parsed.kb_jwt is None:
        return _deny("kb_missing", "kb-jwt required but not present")

    kb_header = decode_jws_header(parsed.kb_jwt)
    if kb_header is None:
        return _deny("kb_binding_invalid", "kb-jwt header could not be decoded")
    if kb_header.get("typ") != KB_JWT_TYP:
        return _deny("kb_binding_invalid", f"kb-jwt typ must be {KB_JWT_TYP}")

    cnf = issuer_payload.get("cnf")
    if not _is_plain_object(cnf) or not _is_plain_object(cnf.get("jwk")):
        return _deny("kb_binding_invalid", "issuer payload missing cnf.jwk")
    holder_key = _holder_key_from_cnf_jwk(cnf["jwk"])
    if holder_key is None:
        return _deny("kb_binding_invalid", "cnf.jwk is not a valid Ed25519 public key")

    if not _verify_kb_signature(parsed.kb_jwt, holder_key):
        return _deny("kb_signature_invalid", "kb-jwt signature did not verify")

    kb_payload = decode_jws_payload(parsed.kb_jwt)
    if kb_payload is None:
        return _deny("kb_binding_invalid", "kb-jwt payload could not be decoded")

    expected_sd_hash = sha256_b64url(parsed.sd_hash_input.encode("ascii"))
    if kb_payload.get("sd_hash") != expected_sd_hash:
        return _deny("kb_binding_invalid", "kb-jwt sd_hash does not bind this sd-jwt")

    kb_iat = kb_payload.get("iat")
    skew = opts.kb_iat_skew_seconds
    max_age = opts.kb_iat_max_age_seconds
    if (
        not isinstance(kb_iat, int)
        or isinstance(kb_iat, bool)
        or kb_iat <= 0
        or kb_iat > now_seconds + skew
        or kb_iat < now_seconds - max_age
    ):
        return _deny("kb_iat_invalid")

    if opts.replay_cache is not None:
        replay_key = f"{jti}:{kb_iat}:{expected_sd_hash}"
        try:
            already = opts.replay_cache.has(replay_key)
        except Exception as exc:
            return _deny("unknown", f"replay cache lookup failed: {exc}")
        if already:
            return _deny("kb_replay_detected")
        try:
            opts.replay_cache.add(replay_key)
        except Exception as exc:
            return _deny("unknown", f"replay cache add failed: {exc}")

    scope_claim = _extract_scope_claim(issuer_payload, disclosed)

    if opts.tool_name is not None:
        issuer_tool_name = issuer_payload.get("tool_name")
        scope_tool_name = scope_claim.get("tool_name") if isinstance(scope_claim, dict) else None
        observed: str | None
        if isinstance(issuer_tool_name, str):
            observed = issuer_tool_name
        elif isinstance(scope_tool_name, str):
            observed = scope_tool_name
        else:
            observed = None
        if observed != opts.tool_name:
            return _deny("tool_mismatch", f"expected {opts.tool_name}, got {observed!r}")

    if opts.resource is not None:
        if not _is_plain_object(opts.resource):
            return _deny("resource_required", "resource option must be an object")
        if not _match_scope(scope_claim, opts.resource):
            return _deny("scope_mismatch")
    else:
        has_resource_constraint = any(k != "tool_name" for k in scope_claim.keys())
        if has_resource_constraint:
            return _deny("resource_required", "token scope requires resource match")

    expires_at = datetime.fromtimestamp(float(exp), tz=timezone.utc)
    agent_id = _extract_agent_id(issuer_payload, disclosed)
    return VerifyResult(
        jti=jti,
        workspace_id=workspace_id,
        scope_claim=scope_claim,
        audience=token_aud,
        expires_at=expires_at,
        agent_id=agent_id,
    )


__all__ = [
    "DEFAULT_KB_IAT_MAX_AGE_SECONDS",
    "DEFAULT_KB_IAT_SKEW_SECONDS",
    "DenyReason",
    "JwksCache",
    "JwksFetchError",
    "ReplayCache",
    "VerifyDenied",
    "VerifyOpts",
    "VerifyResult",
    "shared_jwks_cache",
    "verify_pact_token",
]
