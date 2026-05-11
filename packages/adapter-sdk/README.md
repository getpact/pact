# @getpact/adapter-sdk

Plug a data source or company brain into pact.

## Status

Pre-v1.0. Not yet published.

## Adapter Shape

Export an `Adapter` with one or more tools. Each tool provides a descriptor, an optional authorization mapping, and a handler.

```ts
import { type Adapter, json } from "@getpact/adapter-sdk";

export const adapter: Adapter = {
  name: "example",
  tools: [
    {
      descriptor: {
        name: "example.ping",
        description: "Return a health marker.",
        inputSchema: { type: "object" },
      },
      authorize: (_args, ctx) => ({
        action: "tool:example.ping",
        resource: `workspace:${ctx.workspaceId}:example:ping`,
      }),
      handler: async () => json({ ok: true }),
    },
  ],
};
```

Authorization resources should include the workspace id unless the tool is intentionally global.
