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
