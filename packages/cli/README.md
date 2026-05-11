# @getpact/cli

Workspace onboarding and operations CLI for pact.

## Status

Pre-v1.0. Private internal operations tool. ESM-only, Node 22+.

The package is marked `"private": true` and is not published to npm. It depends on `@getpact/audit` which transitively pulls `@getpact/db` (private workspace package). Two paths to a public CLI are tracked as follow-ups:

1. Split `@getpact/audit/writer` into a separate `@getpact/audit-server` package so the verifier path used by the CLI no longer carries a database dependency.
2. Or bundle the CLI with esbuild/tsup into a standalone artifact with no runtime dependency graph.

Until one of those lands, the CLI is built and consumed from the workspace only. ESM-only is intentional; no CJS build is shipped.

## Commands

- `pact init` creates a workspace through the dev path and stores local credentials.
- `pact login` completes Google OAuth with a loopback callback.
- `pact refresh` rotates the stored access token.
- `pact mcp install --client claude-code` registers the MCP stdio proxy.
- `pact audit verify` verifies signatures and hash links for the workspace audit chain.
- `pact audit checkpoint` exports a signed audit head checkpoint.
- `pact mek rewrap [--apply] [--new-key-id <id>]` rewraps stored secrets with a new MEK.

## Environment

- `PACT_ENDPOINT` - issuer URL, default `http://localhost:8787`
- `PACT_AUDIT_ENDPOINT` - audit API URL, default `PACT_ENDPOINT`
- `PACT_AUDIENCE` - token audience, default `pact-mcp`
- `PACT_AUDIT_EXPECTED_HEAD` - optional external checkpoint hash for audit verification
- `PACT_AUDIT_CHECKPOINT_FILE` - signed checkpoint JSON path for export or verify
- `PACT_AUDIT_CHECKPOINT_SECRET` - HMAC key required for signed checkpoints
- `DATABASE_URL` - postgres dsn for `mek rewrap`
- `PACT_MEK_OLD` - base64 current MEK for `mek rewrap`
- `PACT_MEK_NEW` - base64 new MEK for `mek rewrap`
