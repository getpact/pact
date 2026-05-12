# @getpact/adapter-drive

Google Drive adapter for Pact MCP tools.

## Tools

- `pact.drive.files.list` lists Drive files visible to the connected user.
- `pact.drive.file.get` exports a Google Workspace file as text for agent context.

## Requirements

The adapter expects an OAuth connection in Vault under `kind=google_drive_oauth` and `target=user:<userId>`. Tokens must be created by the dashboard/admin OAuth flow; browser clients never receive Drive tokens. The MCP server refreshes expired Google access tokens before invoking the adapter.

## Commands

- `pnpm --filter @getpact/adapter-drive build`
- `pnpm --filter @getpact/adapter-drive test`
