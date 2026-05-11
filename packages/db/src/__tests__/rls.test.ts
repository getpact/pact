import { eq, sql } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createClient, type DbClient, withWorkspace } from "../client.js";
import { users, workspaces } from "../schema.js";

const url = process.env.RLS_TEST_DB;
const run = url ? describe : describe.skip;

run("rls tenant isolation", () => {
  let db: DbClient;
  let wsA: string;
  let wsB: string;

  beforeAll(async () => {
    db = createClient(url as string);
    const a = await db
      .insert(workspaces)
      .values({ slug: `rls-a-${Date.now()}`, name: "A" })
      .returning();
    const b = await db
      .insert(workspaces)
      .values({ slug: `rls-b-${Date.now()}`, name: "B" })
      .returning();
    if (!a[0] || !b[0]) throw new Error("workspace insert failed");
    wsA = a[0].id;
    wsB = b[0].id;
    await withWorkspace(db, wsA, (tx) =>
      tx.insert(users).values({ workspaceId: wsA, email: "a@example.com" }),
    );
    await withWorkspace(db, wsB, (tx) =>
      tx.insert(users).values({ workspaceId: wsB, email: "b@example.com" }),
    );
  });

  afterAll(async () => {
    await db.delete(workspaces).where(eq(workspaces.id, wsA));
    await db.delete(workspaces).where(eq(workspaces.id, wsB));
  });

  it("returns zero rows without workspace context", async () => {
    const rows = await db.execute(
      sql`SELECT id FROM users WHERE email IN ('a@example.com', 'b@example.com')`,
    );
    expect(rows.length).toBe(0);
  });

  it("returns only workspace A rows when scoped to A", async () => {
    const rows = await withWorkspace(db, wsA, (tx) =>
      tx.execute(sql`SELECT email FROM users WHERE email IN ('a@example.com', 'b@example.com')`),
    );
    expect(rows.length).toBe(1);
    expect((rows[0] as { email: string }).email).toBe("a@example.com");
  });

  it("returns only workspace B rows when scoped to B", async () => {
    const rows = await withWorkspace(db, wsB, (tx) =>
      tx.execute(sql`SELECT email FROM users WHERE email IN ('a@example.com', 'b@example.com')`),
    );
    expect(rows.length).toBe(1);
    expect((rows[0] as { email: string }).email).toBe("b@example.com");
  });

  it("has google subject migration artifacts", async () => {
    const columns = await db.execute(
      sql`SELECT column_name
          FROM information_schema.columns
          WHERE table_schema = 'public'
            AND table_name = 'users'
            AND column_name = 'google_sub'`,
    );
    expect(columns.length).toBe(1);

    const indexes = await db.execute(
      sql`SELECT indexname
          FROM pg_indexes
          WHERE schemaname = 'public'
            AND tablename = 'users'
            AND indexname = 'users_workspace_google_sub_idx'
            AND indexdef ILIKE '%WHERE (google_sub IS NOT NULL)%'`,
    );
    expect(indexes.length).toBe(1);
  });

  it("enforces partial google subject uniqueness per workspace", async () => {
    await withWorkspace(db, wsA, (tx) =>
      tx.insert(users).values([
        { workspaceId: wsA, email: "null-google-1@example.com" },
        { workspaceId: wsA, email: "null-google-2@example.com" },
      ]),
    );
    await expect(
      withWorkspace(db, wsA, (tx) =>
        tx.insert(users).values([
          { workspaceId: wsA, email: "google-one@example.com", googleSub: "google-sub-unique" },
          { workspaceId: wsA, email: "google-two@example.com", googleSub: "google-sub-unique" },
        ]),
      ),
    ).rejects.toThrow();
    await withWorkspace(db, wsB, (tx) =>
      tx.insert(users).values({
        workspaceId: wsB,
        email: "google-other-workspace@example.com",
        googleSub: "google-sub-unique",
      }),
    );
  });
});
