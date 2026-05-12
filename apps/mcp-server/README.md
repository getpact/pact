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
- `GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET` - required for refreshing Google Drive access tokens when Drive MCP tools are enabled
- `GOOGLE_OAUTH_TOKEN_ENDPOINT` - optional local-test override for Google's token endpoint
- Per-adapter secrets (e.g. `SLACK_*` via vault, not env)
- `ENVIRONMENT`

## Adapters

Wired adapters live in `@getpact/adapter-slack` and `@getpact/adapter-drive`; both consume `@getpact/adapter-sdk`. New adapters register tools via `buildToolRegistry`.
