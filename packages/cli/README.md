# @getpact/cli

Workspace onboarding and operations CLI for pact.

## Status

Pre-v1.0. Private package until its audit verification dependencies are split into publishable packages.

## Commands

- `pact init` creates a workspace through the dev path and stores local credentials.
- `pact login` completes Google OAuth with a loopback callback.
- `pact refresh` rotates the stored access token.
- `pact mcp install --client claude-code` registers the MCP stdio proxy.
- `pact audit verify` verifies signatures and hash links for the workspace audit chain.

## Environment

- `PACT_ENDPOINT` - issuer URL, default `http://localhost:8787`
- `PACT_AUDIT_ENDPOINT` - audit API URL, default `PACT_ENDPOINT`
- `PACT_AUDIENCE` - token audience, default `pact-mcp`
- `PACT_AUDIT_EXPECTED_HEAD` - optional external checkpoint hash for audit verification
