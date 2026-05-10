# @getpact/logger

Structured JSON logger plus a Hono request middleware that attaches a request id, logs request completion with status and duration, and exposes a child logger via `c.get("logger")`. Errors are serialized to `{ name, message, stack }` and circular references are replaced with `[circular]`.

```ts
import { createLogger, requestLogger } from "@getpact/logger";

const log = createLogger({ base: { app: "issuer" } });
app.use("*", requestLogger(log, "issuer"));
log.info("ready", { port: 8787 });
```

In Cloudflare Workers, `process.stdout.write` is mapped to the platform's log sink. Pass a custom `sink` for testing.
