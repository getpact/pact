# @getpact/test-helpers

Test setup helpers: build an env object with a fresh MEK, create a workspace via the issuer app, and issue dev tokens. Used by app integration tests to remove ~40 lines of boilerplate per test file.

```ts
import { buildTestEnv, createTestWorkspace, issueTestToken, uniqueSlug } from "@getpact/test-helpers";

const env = await buildTestEnv(process.env.DATABASE_URL);
const created = await createTestWorkspace(issuer, env, {
  slug: uniqueSlug("test"),
  adminEmail: "alice@example.com",
});
const issued = await issueTestToken(issuer, env, {
  workspaceId: created.workspaceId,
  email: "alice@example.com",
  audience: env.ADMIN_AUDIENCE,
});
```

The package exposes types at `./src/index.ts` so test consumers do not need a build step.
