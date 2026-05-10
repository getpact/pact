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
- Secrets per environment: `MEK`, `RESEND_API_KEY`, `SENTRY_DSN`, `BETTERSTACK_TOKEN`, `GOOGLE_OAUTH_CLIENT_SECRET`

## Bootstrap

The bootstrap is manual until we move to Terraform. Steps:

1. `wrangler login`
2. Create KV namespaces and copy ids into per-app `wrangler.toml`
3. Create R2 buckets
4. Create queues
5. Create Hyperdrive binding (needs Neon connection string)
6. Set secrets via `wrangler secret put <NAME>` per Worker that needs it

The MEK is a 256-bit AES-GCM key. Generate locally with `openssl rand -base64 32` and upload via `wrangler secret put MEK`.
