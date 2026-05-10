# @getpact/adapter-slack

Slack adapter primitives for Pact.

## Usage

```ts
import { createSlackClient } from "@getpact/adapter-slack";

const slack = createSlackClient({ token: process.env.SLACK_BOT_TOKEN ?? "" });
const result = await slack.authTest();
```

The first implemented call is `auth.test`, used by the MCP tool
`pact.slack.auth.test` to verify the workspace bot token stored in Pact Vault.

## Development

Run `pnpm --filter @getpact/adapter-slack test` before changing adapter behavior.
