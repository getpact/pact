"""Tests for the default JWKS fetcher, which talks real HTTP.

Every other suite injects a fetcher, so the httpx path in JwksCache had no
coverage: the request itself, its failure branches, and the TTL behaviour.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from getpact_verifier import JwksCache, JwksFetchError, VerifyOpts, verify_pact_token

CORPUS: dict[str, Any] = json.loads(
    (Path(__file__).resolve().parents[3] / "conformance" / "verifier-cases.json").read_text(
        encoding="utf-8"
    )
)
JWKS_URL = CORPUS["jwksUri"]
JWKS_BODY = CORPUS["jwks"]
KID = JWKS_BODY["keys"][0]["kid"]


@respx.mock
def test_default_fetcher_loads_jwks_over_http() -> None:
    route = respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=JWKS_BODY))

    key = JwksCache().resolve(JWKS_URL, KID)

    assert key is not None
    assert route.call_count == 1
    assert route.calls[0].request.headers["accept"] == "application/json"


@respx.mock
def test_default_fetcher_serves_second_lookup_from_cache() -> None:
    route = respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=JWKS_BODY))
    cache = JwksCache()

    cache.resolve(JWKS_URL, KID)
    cache.resolve(JWKS_URL, KID)

    assert route.call_count == 1


@respx.mock
def test_default_fetcher_refetches_once_ttl_has_lapsed() -> None:
    route = respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=JWKS_BODY))
    cache = JwksCache(ttl_seconds=0)

    cache.resolve(JWKS_URL, KID)
    cache.resolve(JWKS_URL, KID)

    assert route.call_count == 2


@respx.mock
def test_default_fetcher_rejects_non_200() -> None:
    respx.get(JWKS_URL).mock(return_value=httpx.Response(404))

    with pytest.raises(JwksFetchError, match="returned 404"):
        JwksCache().resolve(JWKS_URL, KID)


@respx.mock
def test_default_fetcher_rejects_body_without_keys_array() -> None:
    respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json={"not_keys": []}))

    with pytest.raises(JwksFetchError, match="missing keys array"):
        JwksCache().resolve(JWKS_URL, KID)


@respx.mock
def test_default_fetcher_wraps_transport_errors() -> None:
    respx.get(JWKS_URL).mock(side_effect=httpx.ConnectError("connection refused"))

    with pytest.raises(JwksFetchError, match="request failed"):
        JwksCache().resolve(JWKS_URL, KID)


@respx.mock
def test_default_fetcher_reports_unknown_kid() -> None:
    respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=JWKS_BODY))

    with pytest.raises(JwksFetchError, match="no key with kid"):
        JwksCache().resolve(JWKS_URL, "kid-that-does-not-exist")


@respx.mock
def test_verifies_a_conformance_token_over_real_http() -> None:
    route = respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=JWKS_BODY))
    case = next(c for c in CORPUS["cases"] if c["expect"].get("ok"))

    result = verify_pact_token(
        case["sdJwt"],
        VerifyOpts(
            jwks_url=JWKS_URL,
            audience=case["options"]["audience"],
            now=lambda: float(CORPUS["nowSeconds"]),
            jwks_cache=JwksCache(),
            **(
                {"tool_name": case["options"]["toolName"]}
                if "toolName" in case["options"]
                else {}
            ),
            **({"resource": case["options"]["resource"]} if "resource" in case["options"] else {}),
        ),
    )

    assert result.ok, getattr(result, "reason", None)
    assert result.jti == case["expect"]["jti"]
    assert route.call_count == 1
