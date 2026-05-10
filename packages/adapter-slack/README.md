# @getpact/adapter-slack

Slack adapter primitives for Pact.

## Usage

```ts
import { createSlackClient } from "@getpact/adapter-slack";

const slack = createSlackClient({ token: process.env.SLACK_BOT_TOKEN ?? "" });
const result = await slack.authTest();
```

Implemented calls include `auth.test` and `conversations.list`, exposed through
the `pact.slack.auth.test` and `pact.slack.channels.list` MCP tools.

## Development

Run `pnpm --filter @getpact/adapter-slack test` before changing adapter behavior.
