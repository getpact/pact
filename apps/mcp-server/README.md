# @getpact/mcp-server

Model Context Protocol server. Exposes brain adapters (Drive, etc.) as MCP tools. Each tool call is authorized via the verifier before execution.

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
- Per-adapter secrets via vault, not env
- `ENVIRONMENT`

## Adapters

Wired adapters live in `@getpact/adapter-drive` and consume `@getpact/adapter-sdk`. New adapters register tools via `buildToolRegistry`.

## Drive Retrieval

Drive MCP tools require the signed-in user to connect Google Drive in the web dashboard first.

- `pact.drive.files.list` lists files visible to the connected Google account.
- `pact.drive.file.get` exports one Drive file as text.
- `pact.drive.file.index` exports a Drive file, chunks text, and stores workspace/user-scoped chunks in Postgres.
- `pact.drive.search` runs lexical full-text search over indexed chunks and returns snippets for agent context.

This is a minimal retrieval layer, not embedding-based RAG yet. Indexed chunks are scoped by `workspaceId` and `userId`; one user's Drive chunks are not shared with other users in the same workspace.
