# @getpact/mcp-server

Model Context Protocol server. Exposes brain adapters (Slack, Drive, etc.) as MCP tools. Each tool call is authorized via the verifier before execution.

## Endpoints

- `POST /:workspace/mcp` - MCP JSON-RPC handler

## Auth

Bearer JWT with `aud=pact-mcp` (Mode A). Workspace slug or id in path must match token `org` claim.

## Env

- `DATABASE_URL`, `MEK`, `ISSUER_BASE_URL` (required)
- `VERIFIER_SERVICE` - Cloudflare service binding to verifier in production
- `VERIFIER_URL` - local-dev fallback only
- `VERIFIER_SERVICE_TOKEN`
- `MCP_AUDIENCE` (default `pact-mcp`)
- Per-adapter secrets (e.g. `SLACK_*` via vault, not env)
- `ENVIRONMENT`

## Adapters

Wired adapters live in `@getpact/adapter-slack` and consume `@getpact/adapter-sdk`. New adapters register tools via `buildToolRegistry`.
