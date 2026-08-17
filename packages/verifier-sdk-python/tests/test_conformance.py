"""Cross-language conformance.

The same corpus is replayed by
packages/verifier-sdk-node/src/__tests__/conformance.test.ts; both suites must
reach the same verdict for every case. See conformance/README.md.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from getpact_verifier import JwksCache, VerifyOpts, verify_pact_token

CORPUS_PATH = Path(__file__).resolve().parents[3] / "conformance" / "verifier-cases.json"
CORPUS: dict[str, Any] = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))


class SeededReplayCache:
    def __init__(self, seed: list[str]) -> None:
        self._seen = set(seed)

    def has(self, key: str) -> bool:
        return key in self._seen

    def add(self, key: str) -> None:
        self._seen.add(key)


def _opts_for(case: dict[str, Any]) -> VerifyOpts:
    options = case["options"]
    kwargs: dict[str, Any] = {
        "jwks_url": CORPUS["jwksUri"],
        "audience": options["audience"],
        # The corpus clock is in seconds, which is what this SDK reads.
        "now": lambda: float(CORPUS["nowSeconds"]),
        "jwks_cache": JwksCache(fetcher=lambda _url: CORPUS["jwks"]),
    }
    if "toolName" in options:
        kwargs["tool_name"] = options["toolName"]
    if "resource" in options:
        kwargs["resource"] = options["resource"]
    if "kbIatSkewSeconds" in options:
        kwargs["kb_iat_skew_seconds"] = options["kbIatSkewSeconds"]
    if "kbIatMaxAgeSeconds" in options:
        kwargs["kb_iat_max_age_seconds"] = options["kbIatMaxAgeSeconds"]
    if case.get("replaySeed"):
        kwargs["replay_cache"] = SeededReplayCache(case["replaySeed"])
    return VerifyOpts(**kwargs)


def test_corpus_version_is_supported() -> None:
    assert CORPUS["version"] == 1
    assert len(CORPUS["cases"]) > 0


@pytest.mark.parametrize("case", CORPUS["cases"], ids=lambda c: c["name"])
def test_conformance_case(case: dict[str, Any]) -> None:
    result = verify_pact_token(case["sdJwt"], _opts_for(case))
    expected = case["expect"]

    if expected.get("ok"):
        assert result.ok, f"expected allow, denied with {getattr(result, 'reason', None)}"
        assert result.jti == expected["jti"]
        assert result.workspace_id == expected["workspaceId"]
        assert result.audience == expected["audience"]
        if "agentId" in expected:
            assert result.agent_id == expected["agentId"]
        return

    assert not result.ok, f"expected deny {expected['reason']}, got allow"
    assert result.reason == expected["reason"]
