import { eq, sql } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createClient, type DbClient, withWorkspace } from "../client.js";
import { users, workspaceOauthConnections, workspaces } from "../schema.js";

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
    const [userA] = await withWorkspace(db, wsA, (tx) =>
      tx
        .insert(users)
        .values({ workspaceId: wsA, email: "a@example.com" })
        .returning({ id: users.id }),
    );
    const [userB] = await withWorkspace(db, wsB, (tx) =>
      tx
        .insert(users)
        .values({ workspaceId: wsB, email: "b@example.com" })
        .returning({ id: users.id }),
    );
    if (!userA || !userB) throw new Error("user insert failed");
    await withWorkspace(db, wsA, (tx) =>
      tx.insert(workspaceOauthConnections).values({
        workspaceId: wsA,
        provider: "google_drive",
        userId: userA.id,
        providerSubject: "google-sub-a",
        email: "a@example.com",
        scopes: ["https://www.googleapis.com/auth/drive.readonly"],
        vaultTarget: `user:${userA.id}`,
      }),
    );
    await withWorkspace(db, wsB, (tx) =>
      tx.insert(workspaceOauthConnections).values({
        workspaceId: wsB,
        provider: "google_drive",
        userId: userB.id,
        providerSubject: "google-sub-b",
        email: "b@example.com",
        scopes: ["https://www.googleapis.com/auth/drive.readonly"],
        vaultTarget: `user:${userB.id}`,
      }),
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

  it("isolates workspace OAuth connection metadata", async () => {
    const rowsA = await withWorkspace(db, wsA, (tx) =>
      tx
        .select({ email: workspaceOauthConnections.email })
        .from(workspaceOauthConnections)
        .where(eq(workspaceOauthConnections.provider, "google_drive")),
    );
    const rowsB = await withWorkspace(db, wsB, (tx) =>
      tx
        .select({ email: workspaceOauthConnections.email })
        .from(workspaceOauthConnections)
        .where(eq(workspaceOauthConnections.provider, "google_drive")),
    );
    expect(rowsA).toEqual([{ email: "a@example.com" }]);
    expect(rowsB).toEqual([{ email: "b@example.com" }]);
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
