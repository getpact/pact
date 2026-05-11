# @getpact/gateway

Mode B forwarding gateway. Caller presents a Pact JWT (`aud=pact-gateway`); gateway verifies, looks up brain config + credential, forwards to the upstream brain API with bearer credential injected.

## Endpoints

- `ALL /:workspace/gateway/:brain/*` - authorize + forward to brain upstream
- `GET /health`

## Flow

1. Bearer parsed, JWT decoded (signature checked by verifier).
2. Workspace param vs JWT `org` claim.
3. Verifier RPC with service-token auth.
4. Brain lookup (active status only).
5. Rate-limit per (workspace, brain, client-ip).
6. Bearer credential loaded from vault if `authScheme=bearer`.
7. Upstream URL built (SSRF + path-traversal guards).
8. Pre-forward `gateway.attempt` audit.
9. Forward; audit outcome.

## Env

- `DATABASE_URL`, `MEK`, `VERIFIER_URL` (required)
- `VERIFIER_SERVICE_TOKEN` - matches verifier's expected token
- `GATEWAY_AUDIENCE` (default `pact-gateway`)
- `GATEWAY_UPSTREAM_TIMEOUT_MS` (default 5000, max 30000)
- `GATEWAY_RATE_LIMIT` / `GATEWAY_RATE_WINDOW_SECONDS` (defaults 60/60)
- `GATEWAY_AUDIT_MODE` - `required` | `best_effort` (default `required` in prod)
- `GATEWAY_FORWARD_HEADER_ALLOWLIST` - csv allowlist for headers forwarded to upstream
- `GATEWAY_RESPONSE_HEADER_ALLOWLIST` - csv allowlist for headers returned from upstream to client
- `UPSTREAM_HOST_ALLOWLIST` - csv pattern list (`*.example.com`); required in prod

## Audit outcomes

`attempt`, `forwarded`, `denied`, `brain_not_found`, `rate_limited`, `mek_not_configured`, `brain_credential_missing`, `brain_credential_invalid`, `unsupported_auth_scheme`, `invalid_upstream`, `timeout`, `upstream_failed`, `redirect`
