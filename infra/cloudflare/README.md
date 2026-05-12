# Cloudflare infra

Per-Worker `wrangler.toml` lives under `apps/<name>/wrangler.toml`.

## Resources expected to exist before deploy

- Cloudflare account with `getpact.dev` zone active
- Workers Paid plan
- `DATABASE_URL` secret pointing to Neon/Postgres. Hyperdrive is not wired into
  the current Workers yet; do not claim Hyperdrive production support until the
  Worker envs accept `HYPERDRIVE.connectionString`.
- KV namespace: `pact-revocation`
- Custom domains configured by each Worker manifest:
  `app.getpact.dev`, `issuer.getpact.dev`, `verifier.getpact.dev`,
  `mcp.getpact.dev`, `admin.getpact.dev`, `audit.getpact.dev`, and optionally
  `gateway.getpact.dev`
- Vars on admin API and gateway: `UPSTREAM_HOST_ALLOWLIST` with comma-separated
  exact hosts or wildcard suffixes, for example `httpbin.org,*.slack.com`
- Platform SSRF control for the gateway: outbound Worker traffic must be pinned
  behind Cloudflare egress controls, Zero Trust Gateway, or equivalent network
  policy that blocks private, link-local, metadata, and RFC1918 destinations
  after DNS resolution. `UPSTREAM_HOST_ALLOWLIST` is required but is not enough
  by itself because DNS rebinding can change where an allowed hostname resolves.
- Verifier service auth: set the same `VERIFIER_SERVICE_TOKEN` secret on the
  verifier and every internal caller that invokes it, including MCP server and
  gateway. Production verifier requests fail closed if this secret is missing.
  Non-production verifiers without this secret remain publicly callable and are
  only acceptable for disposable smoke environments.
- Google OAuth for login and Drive: set `GOOGLE_OAUTH_CLIENT_ID` and
  `GOOGLE_OAUTH_CLIENT_SECRET` on the issuer and admin API. Set the same
  `GOOGLE_OAUTH_CLIENT_ID` on the web dashboard. Set both Google OAuth secrets
  on MCP server as well; MCP uses them to refresh stored Google Drive access
  tokens before executing Drive tools.
- Gateway audit is required in production by default. Set
  `GATEWAY_AUDIT_MODE=best_effort` only for controlled non-critical smoke
  environments.
- Secrets per environment are checked during deploy with `wrangler secret list`.
  Required secrets include `DATABASE_URL`, `MEK`, `VERIFIER_SERVICE_TOKEN`,
  `WEB_ISSUER_SERVICE_TOKEN`, and Google OAuth secrets for the issuer,
  admin API, MCP server, and web dashboard.

## Deploy

Run `pnpm deploy:cloudflare` from the repository root after bootstrap. The script
validates Worker manifests, validates required Cloudflare secrets, runs
`pnpm typecheck`, runs `pnpm build`, then deploys issuer, verifier, MCP server,
admin API, audit API, and web dashboard in order.

Keep that order for dashboard MCP rollouts: the issuer must accept the
`pact-mcp` dashboard audience before the web dashboard starts requesting MCP
tokens during Google sign-in.

The gateway Worker is opt-in while Mode B is being hardened. Deploy it only
after configuring both the runtime host allowlist and platform egress controls.
The deploy validator requires a concrete Cloudflare Zero Trust Gateway rule id
and checks through the Cloudflare API that the rule is enabled, uses `block`,
and names private, link-local, metadata, and local address ranges:

```sh
PACT_DEPLOY_GATEWAY=true \
PACT_GATEWAY_EGRESS_POLICY_ID=<cloudflare-gateway-rule-id> \
CLOUDFLARE_ACCOUNT_ID=<account-id> \
CLOUDFLARE_API_TOKEN=<api-token> \
pnpm deploy:cloudflare
```

This is still a deployment control, not a Worker-code resolver hook. Keep the
rule managed in infrastructure and review every change to its blocked ranges.

After deploy, run a health smoke test:

```sh
PACT_ISSUER_URL=https://issuer.getpact.dev \
PACT_VERIFIER_URL=https://verifier.getpact.dev \
PACT_MCP_URL=https://mcp.getpact.dev \
PACT_VERIFIER_SERVICE_TOKEN=<shared-secret> \
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
PACT_GATEWAY_URL=https://gateway.getpact.dev \
PACT_ADMIN_API_URL=https://admin.getpact.dev \
PACT_AUDIT_API_URL=https://audit.getpact.dev \
PACT_SMOKE_GATEWAY_BRAIN=smoke-http \
PACT_SMOKE_GATEWAY_PATH=get \
PACT_SMOKE_GATEWAY_BASE_URL=https://httpbin.org \
pnpm smoke:cloudflare
```

## Bootstrap

The bootstrap is manual until we move to Terraform. Steps:

1. `wrangler login`
2. Create KV namespaces and copy ids into per-app `wrangler.toml`
3. Configure the custom domains listed in each per-app `wrangler.toml`
4. Upload `DATABASE_URL` as a secret for every Worker that uses Postgres
5. Set secrets via `wrangler secret put <NAME>` per Worker that needs it
6. Configure Google OAuth redirect URIs:
   `https://app.getpact.dev/v1/auth/google/callback` for dashboard sign-in and
   `https://app.getpact.dev/v1/connections/google-drive/callback` for Drive
   connection
7. Set `GOOGLE_DRIVE_OAUTH_REDIRECT_URI` on admin API to the Drive callback URI

The MEK is a 256-bit AES-GCM key. Generate locally with `openssl rand -base64 32` and upload via `wrangler secret put MEK`.
