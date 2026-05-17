# getpact-verifier

Verify Pact-issued JWTs in Python services. Mirrors the Node `@getpact/verifier-sdk` shape so a FastAPI service can drop Pact authorization in without rolling its own JWKS fetcher.

Audit-chain verification is a separate concern handled by the `pact` CLI (`pact audit verify`).

## Install

```
pip install getpact-verifier
```

## Usage

```python
from getpact_verifier import VerifierOptions, create_verifier

verifier = create_verifier(VerifierOptions(
    jwks_url="https://issuer.getpact.dev/v1/workspaces/<workspace-id>/.well-known/jwks.json",
    issuer="https://issuer.getpact.dev",
    audience="pact-mcp",
))

claims = verifier.verify(token)
print(claims["sub"], claims["org"], claims["mode"])
```

For a pinned public key without network fetches:

```python
from getpact_verifier import StaticVerifierOptions, create_static_verifier

verifier = create_static_verifier(StaticVerifierOptions(
    public_key_jwk={"kty": "OKP", "crv": "Ed25519", "x": "<base64url>"},
    issuer="https://issuer.getpact.dev",
    audience="pact-mcp",
))
```

## Capability tokens (SD-JWT + KB-JWT)

For Pact capability tokens (selective-disclosure JWT bound to a holder key) use `verify_pact_token`. It parses the SD-JWT compact form (RFC 9901), verifies the issuer JWS, validates the KB-JWT against `cnf.jwk` (RFC 7800), checks `sd_hash` binding, enforces `kb_iat` bounds, and optionally consults a replay cache.

```python
from getpact_verifier import (
    JwksCache,
    ReplayCache,
    VerifyDenied,
    VerifyOpts,
    VerifyResult,
    verify_pact_token,
)


class InMemoryReplayCache:
    def __init__(self) -> None:
        self._seen: set[str] = set()

    def has(self, key: str) -> bool:
        return key in self._seen

    def add(self, key: str) -> None:
        self._seen.add(key)


result = verify_pact_token(
    sd_jwt_compact,
    VerifyOpts(
        jwks_url="https://issuer.getpact.dev/v1/workspaces/<id>/.well-known/jwks.json",
        audience="pact-mcp",
        tool_name="search.documents",
        resource={"resource": "drive:doc-1"},
        replay_cache=InMemoryReplayCache(),
    ),
)
if isinstance(result, VerifyResult):
    print(result.jti, result.workspace_id, result.scope_claim, result.agent_id)
else:
    assert isinstance(result, VerifyDenied)
    print("deny", result.reason, result.detail)
```

`VerifyOpts` fields:

- `jwks_url` - issuer JWKS endpoint (Ed25519 public keys only).
- `audience` - required `aud` claim.
- `tool_name` - optional; when set, the token must carry a matching `tool_name`.
- `resource` - optional; matched against the token's scope claim using exact, `*` suffix, and `*` wildcard rules.
- `kb_iat_skew_seconds` - allowed clock skew on the future side (default 300).
- `kb_iat_max_age_seconds` - allowed age on the past side (default 300).
- `replay_cache` - optional. Caller-supplied object with `has(key)` and `add(key)`.
- `jwks_cache` - optional `JwksCache`. Defaults to a shared cache with 5 minute TTL.
- `issuer` - optional; if set, the issuer JWT must carry a matching `iss`.
- `now` - optional clock override for tests.

`VerifyResult` exposes `jti`, `workspace_id`, `scope_claim`, `audience`, `expires_at`, and `agent_id`. `VerifyDenied.reason` is one of: `invalid_format`, `signature_invalid`, `jwks_fetch_failed`, `aud_mismatch`, `expired`, `kb_iat_invalid`, `kb_signature_invalid`, `kb_binding_invalid`, `kb_missing`, `tool_mismatch`, `resource_required`, `scope_mismatch`, `kb_replay_detected`, `unknown`.

The replay cache key is `f"{jti}:{kb_iat}:{sd_hash}"`. Supplying a cache turns single-use semantics into hard rejects on the second presentation within the iat window.

## Algorithm

Pact issues EdDSA (Ed25519) tokens. The SDK rejects all other `alg` values to defend against algorithm-confusion attacks.

## Claims

Every Pact JWT carries the standard claims (`iss`, `sub`, `aud`, `exp`, `iat`, `jti`) plus:

- `org` - workspace id (uuid)
- `email` - canonicalized user email
- `groups` - string array
- `roles` - string array
- `mode` - `"A"` (admin/audit/mcp audience) or `"B"` (gateway audience)

## Status

Beta. Public API may change before v1.0.
