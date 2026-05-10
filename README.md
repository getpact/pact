# pact

Auth for AI agents reading and writing data.

## Status

Pre-v1.0.

## Layout

- `apps/` - Cloudflare Workers (issuer, verifier, mcp-server, gateway, admin-api, audit-api)
- `packages/` - shared libraries and OSS packages
- `infra/cloudflare/` - Wrangler config and Cloudflare resource definitions
- `infra/compose/` - local Postgres + Miniflare

## Local development

Requirements: Node 22, pnpm 9, Docker.

```
pnpm install
docker compose -f infra/compose/docker-compose.yml up -d
pnpm --filter @getpact/db db:migrate
pnpm dev
```

## Packages

OSS (MIT):

- `@getpact/cli`
- `@getpact/verifier-sdk-node`
- `@getpact/adapter-sdk`
- `@getpact/adapter-slack`
- `getpact-verifier` (Python)

Internal: `@getpact/core`, `@getpact/db`, `@getpact/crypto`, `@getpact/policy`, `@getpact/audit`, `@getpact/vault`, `@getpact/keystore`, `@getpact/logger`, `@getpact/ratelimit`, `@getpact/test-helpers`.
