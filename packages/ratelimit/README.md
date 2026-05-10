# @getpact/ratelimit

Hono middleware for fixed-window rate limiting. The package currently exports an in-memory backend for tests and local development. For distributed Cloudflare deployments, use a database-backed limiter for atomicity across edge nodes.

```ts
import { memoryRateLimiter, rateLimit } from "@getpact/ratelimit";

const limiter = memoryRateLimiter();
app.use("/v1/refresh", rateLimit({
  limiter,
  limit: 30,
  windowSeconds: 60,
  keyFn: (c) => `refresh:${c.req.header("cf-connecting-ip") ?? "anon"}`,
}));
```

The `rateLimit` middleware sets `x-ratelimit-limit`, `x-ratelimit-remaining`, `x-ratelimit-reset`, and `retry-after` headers and returns 429 with `{ error: "rate_limited" }` when over the limit.
