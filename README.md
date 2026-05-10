# pact

Auth for AI agents reading and writing data.

## Status

Pre-v1.0.

## Layout

- `apps/` - Cloudflare Workers (issuer, verifier, mcp-server, proxy, admin-api, audit-api)
- `packages/` - shared libraries and OSS packages
- `infra/cloudflare/` - Wrangler config and Cloudflare resource definitions
- `infra/compose/` - local Postgres + Miniflare

## Local development

Requirements: Node 22, pnpm 10, Docker.

```
pnpm install
docker compose -f infra/compose/docker-compose.yml up -d
pnpm dev
```

## Packages

OSS (MIT):

- `@getpact/cli`
- `@getpact/verifier-sdk`
- `@getpact/adapter-sdk`
- `@getpact/adapter-slack`
- `@getpact/adapter-drive`
- `@getpact/audit-verifier`
- `getpact-verifier` (Python)

Internal: `@getpact/core`, `@getpact/db`, `@getpact/crypto`, `@getpact/policy`, `@getpact/audit`, `@getpact/vault`.
