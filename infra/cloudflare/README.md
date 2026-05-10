# Cloudflare infra

Per-Worker `wrangler.toml` lives under `apps/<name>/wrangler.toml`.

## Resources expected to exist before deploy

- Cloudflare account with `getpact.dev` zone active
- Workers Paid plan
- Hyperdrive binding pointing to a Neon Postgres connection string
- KV namespaces: `pact-revocation`, `pact-jwks-cache`
- Durable Object class: `WorkspaceChainLock` (registered in `apps/audit-api/wrangler.toml`)
- R2 buckets: `pact-audit-prod`, `pact-audit-staging`
- Queues: `pact-audit-archive`, `pact-oauth-refresh`
- Vars on admin API and gateway: `UPSTREAM_HOST_ALLOWLIST` with comma-separated
  exact hosts or wildcard suffixes, for example `httpbin.org,*.slack.com`
- Platform SSRF control for the gateway: outbound Worker traffic must be pinned
  behind Cloudflare egress controls, Zero Trust Gateway, or equivalent network
  policy that blocks private, link-local, metadata, and RFC1918 destinations
  after DNS resolution. `UPSTREAM_HOST_ALLOWLIST` is required but is not enough
  by itself because DNS rebinding can change where an allowed hostname resolves.
- Gateway audit is required in production by default. Set
  `GATEWAY_AUDIT_MODE=best_effort` only for controlled non-critical smoke
  environments.
- Secrets per environment: `MEK`, `RESEND_API_KEY`, `SENTRY_DSN`, `BETTERSTACK_TOKEN`, `GOOGLE_OAUTH_CLIENT_SECRET`

## Deploy

Run `pnpm deploy:cloudflare` from the repository root after bootstrap. The script
validates Worker manifests, runs `pnpm typecheck`, runs `pnpm build`, then deploys
issuer, verifier, MCP server, admin API, and audit API in order.

The gateway Worker is opt-in while Mode B is being hardened. Deploy it with
`PACT_DEPLOY_GATEWAY=true pnpm deploy:cloudflare`.

After deploy, run a health smoke test:

```sh
PACT_ISSUER_URL=https://pact-issuer.<subdomain>.workers.dev \
PACT_VERIFIER_URL=https://pact-verifier.<subdomain>.workers.dev \
PACT_MCP_URL=https://pact-mcp-server.<subdomain>.workers.dev \
pnpm smoke:cloudflare
```

Set `PACT_SMOKE_DEV_FLOW=true` plus `PACT_SMOKE_WORKSPACE_ID` and
`PACT_SMOKE_WORKSPACE_SLUG` to exercise dev issue, verifier, and MCP initialize
against a non-production environment. Deployed non-production issuers must set
`DEV_ISSUE_SECRET`; pass the same value to smoke tests as
`PACT_DEV_ISSUE_SECRET`.

Set `PACT_SMOKE_GATEWAY_FLOW=true` to also exercise Mode B gateway traffic. The
workspace must already have an active policy that allows `gateway.get` on the
configured gateway resource. To seed the brain during smoke, also set
`PACT_ADMIN_API_URL` and `PACT_SMOKE_GATEWAY_BASE_URL`; the smoke upstream host
must be present in `UPSTREAM_HOST_ALLOWLIST` for both admin API and gateway. For
example:

```sh
PACT_SMOKE_DEV_FLOW=true \
PACT_SMOKE_GATEWAY_FLOW=true \
PACT_SMOKE_WORKSPACE_ID=<workspace-id> \
PACT_SMOKE_WORKSPACE_SLUG=<workspace-slug> \
PACT_GATEWAY_URL=https://pact-gateway.<subdomain>.workers.dev \
PACT_ADMIN_API_URL=https://pact-admin-api.<subdomain>.workers.dev \
PACT_AUDIT_API_URL=https://pact-audit-api.<subdomain>.workers.dev \
PACT_SMOKE_GATEWAY_BRAIN=smoke-http \
PACT_SMOKE_GATEWAY_PATH=get \
PACT_SMOKE_GATEWAY_BASE_URL=https://httpbin.org \
pnpm smoke:cloudflare
```

## Bootstrap

The bootstrap is manual until we move to Terraform. Steps:

1. `wrangler login`
2. Create KV namespaces and copy ids into per-app `wrangler.toml`
3. Create R2 buckets
4. Create queues
5. Create Hyperdrive binding (needs Neon connection string)
6. Set secrets via `wrangler secret put <NAME>` per Worker that needs it

The MEK is a 256-bit AES-GCM key. Generate locally with `openssl rand -base64 32` and upload via `wrangler secret put MEK`.
