import { eq, sql } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createClient, type DbClient, withWorkspace } from "../client.js";
import { agents, users, workspaces } from "../schema.js";

const url = process.env.RLS_TEST_DB;
const run = url ? describe : describe.skip;

const sampleJwk = {
  kty: "OKP",
  crv: "Ed25519",
  x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
};

run("agents tenant isolation", () => {
  let db: DbClient;
  let wsA: string;
  let wsB: string;
  let ownerA: string;
  let ownerB: string;
  let agentAId: string;

  beforeAll(async () => {
    db = createClient(url as string);
    const stamp = Date.now();
    const a = await db
      .insert(workspaces)
      .values({ slug: `agents-a-${stamp}`, name: "A" })
      .returning();
    const b = await db
      .insert(workspaces)
      .values({ slug: `agents-b-${stamp}`, name: "B" })
      .returning();
    if (!a[0] || !b[0]) throw new Error("workspace insert failed");
    wsA = a[0].id;
    wsB = b[0].id;

    const [uA] = await withWorkspace(db, wsA, (tx) =>
      tx
        .insert(users)
        .values({ workspaceId: wsA, email: `owner-a-${stamp}@example.com` })
        .returning({ id: users.id }),
    );
    const [uB] = await withWorkspace(db, wsB, (tx) =>
      tx
        .insert(users)
        .values({ workspaceId: wsB, email: `owner-b-${stamp}@example.com` })
        .returning({ id: users.id }),
    );
    if (!uA || !uB) throw new Error("user insert failed");
    ownerA = uA.id;
    ownerB = uB.id;

    const [createdA] = await withWorkspace(db, wsA, (tx) =>
      tx
        .insert(agents)
        .values({
          workspaceId: wsA,
          slug: "billing-bot",
          displayName: "Billing Bot",
          kind: "service",
          ownerUserId: ownerA,
          pubkeyJwk: sampleJwk,
          pubkeyThumbprint: `thumb-a-${stamp}`,
        })
        .returning({ id: agents.id }),
    );
    if (!createdA) throw new Error("agent A insert failed");
    agentAId = createdA.id;

    await withWorkspace(db, wsB, (tx) =>
      tx.insert(agents).values({
        workspaceId: wsB,
        slug: "billing-bot",
        displayName: "Billing Bot B",
        kind: "service",
        ownerUserId: ownerB,
        pubkeyJwk: sampleJwk,
        pubkeyThumbprint: `thumb-b-${stamp}`,
      }),
    );
  });

  afterAll(async () => {
    if (wsA) await db.delete(workspaces).where(eq(workspaces.id, wsA));
    if (wsB) await db.delete(workspaces).where(eq(workspaces.id, wsB));
  });

  it("denies cross-workspace SELECT", async () => {
    const rows = await withWorkspace(db, wsB, (tx) =>
      tx.select({ id: agents.id }).from(agents).where(eq(agents.id, agentAId)),
    );
    expect(rows.length).toBe(0);
  });

  it("rejects cross-workspace INSERT via WITH CHECK", async () => {
    await expect(
      withWorkspace(db, wsA, (tx) =>
        tx.insert(agents).values({
          workspaceId: wsB,
          slug: "smuggled",
          displayName: "Smuggled",
          kind: "service",
          ownerUserId: ownerA,
          pubkeyJwk: sampleJwk,
          pubkeyThumbprint: `smuggled-${Date.now()}`,
        }),
      ),
    ).rejects.toThrow();
  });

  it("allows same-workspace SELECT", async () => {
    const rows = await withWorkspace(db, wsA, (tx) =>
      tx.select({ id: agents.id, slug: agents.slug }).from(agents).where(eq(agents.id, agentAId)),
    );
    expect(rows.length).toBe(1);
    expect(rows[0]?.slug).toBe("billing-bot");
  });

  it("enforces unique slug per workspace", async () => {
    await expect(
      withWorkspace(db, wsA, (tx) =>
        tx.insert(agents).values({
          workspaceId: wsA,
          slug: "billing-bot",
          displayName: "Duplicate",
          kind: "service",
          ownerUserId: ownerA,
          pubkeyJwk: sampleJwk,
          pubkeyThumbprint: `dup-slug-${Date.now()}`,
        }),
      ),
    ).rejects.toThrow();
  });

  it("permits thumbprint reuse after revocation", async () => {
    const stamp = Date.now();
    const thumb = `reused-thumb-${stamp}`;
    const [first] = await withWorkspace(db, wsA, (tx) =>
      tx
        .insert(agents)
        .values({
          workspaceId: wsA,
          slug: `agent-revoke-${stamp}`,
          displayName: "Revoke Me",
          kind: "service",
          ownerUserId: ownerA,
          pubkeyJwk: sampleJwk,
          pubkeyThumbprint: thumb,
        })
        .returning({ id: agents.id }),
    );
    if (!first) throw new Error("first agent insert failed");

    await expect(
      withWorkspace(db, wsA, (tx) =>
        tx.insert(agents).values({
          workspaceId: wsA,
          slug: `agent-revoke-dup-${stamp}`,
          displayName: "Active Dup",
          kind: "service",
          ownerUserId: ownerA,
          pubkeyJwk: sampleJwk,
          pubkeyThumbprint: thumb,
        }),
      ),
    ).rejects.toThrow();

    await withWorkspace(db, wsA, (tx) =>
      tx
        .update(agents)
        .set({ status: "revoked", revokedAt: new Date() })
        .where(eq(agents.id, first.id)),
    );

    await withWorkspace(db, wsA, (tx) =>
      tx.insert(agents).values({
        workspaceId: wsA,
        slug: `agent-revoke-reuse-${stamp}`,
        displayName: "Reused Thumb",
        kind: "service",
        ownerUserId: ownerA,
        pubkeyJwk: sampleJwk,
        pubkeyThumbprint: thumb,
      }),
    );
  });

  it("rejects invalid kind via CHECK constraint", async () => {
    await expect(
      withWorkspace(db, wsA, (tx) =>
        tx.execute(sql`
          INSERT INTO agents (workspace_id, slug, display_name, kind, owner_user_id, pubkey_jwk, pubkey_thumbprint)
          VALUES (${wsA}::uuid, ${`bad-kind-${Date.now()}`}, 'Bad Kind', 'not_a_kind', ${ownerA}::uuid, ${sql.raw("'{}'::jsonb")}, ${`thumb-bad-kind-${Date.now()}`})
        `),
      ),
    ).rejects.toThrow();
  });

  it("rejects invalid status via CHECK constraint", async () => {
    await expect(
      withWorkspace(db, wsA, (tx) =>
        tx.execute(sql`
          INSERT INTO agents (workspace_id, slug, display_name, kind, owner_user_id, pubkey_jwk, pubkey_thumbprint, status)
          VALUES (${wsA}::uuid, ${`bad-status-${Date.now()}`}, 'Bad Status', 'service', ${ownerA}::uuid, ${sql.raw("'{}'::jsonb")}, ${`thumb-bad-status-${Date.now()}`}, 'paused')
        `),
      ),
    ).rejects.toThrow();
  });

  it("prevents owner deletion via RESTRICT", async () => {
    await expect(
      withWorkspace(db, wsA, (tx) => tx.delete(users).where(eq(users.id, ownerA))),
    ).rejects.toThrow();
  });
});
