# @getpact/verifier

Stateless authorization oracle. Takes (token, action, resource, audience), returns allow/deny + reasons. Emits audit events for every decision.

## Endpoints

- `POST /v1/verify` - verify and authorize

## Env

- `DATABASE_URL` - Postgres URL
- `MEK` - workspace key-wrap master key
- `ISSUER_BASE_URL` - expected `iss` claim
- `VERIFIER_AUDIENCES` - comma-separated allowlist of accepted audiences (default `pact-mcp`)
- `VERIFIER_SERVICE_TOKEN` - bearer secret required from callers. **Mandatory in production**; verifier 503s if unset and `ENVIRONMENT=production`.
- `REVOCATION_CACHE` - KV namespace for jti revocation cache (TTL 60s)
- `ENVIRONMENT` - `production` enforces service-token gate
