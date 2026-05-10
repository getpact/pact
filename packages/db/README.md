# @getpact/db

Drizzle ORM schema and Postgres client for Pact. Tenant-scoped tables enforce row-level security via the `app.current_workspace_id` session variable, set automatically by the `withWorkspace` transaction wrapper.

```ts
import { createClient, withWorkspace, schema } from "@getpact/db";

const db = createClient(process.env.DATABASE_URL);
await withWorkspace(db, workspaceId, async (tx) => {
  return tx.select().from(schema.users);
});
```

Migrations live in `migrations/`. Apply with `drizzle-kit` against the `pact` migration role; the application connects as `pact_app` (NOLOGIN-derived role with NOBYPASSRLS) so RLS policies are enforced.
