import { eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createClient, type DbClient, withWorkspace } from "../client.js";
import {
  agentCapabilityGrants,
  agentInvocations,
  agents,
  delegationChains,
  users,
  workspaces,
} from "../schema.js";

const url = process.env.RLS_TEST_DB;
const run = url ? describe : describe.skip;

const sampleJwk = {
  kty: "OKP",
  crv: "Ed25519",
  x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
};

run("agent grants tenant isolation", () => {
  let db: DbClient;
  let wsA: string;
  let wsB: string;
  let ownerA: string;
  let ownerB: string;
  let agentAId: string;
  let agentBId: string;
  let grantAId: string;
  let invocationAJti: string;

  beforeAll(async () => {
    db = createClient(url as string);
    const stamp = Date.now();

    const a = await db
      .insert(workspaces)
      .values({ slug: `grants-a-${stamp}`, name: "A" })
      .returning();
    const b = await db
      .insert(workspaces)
      .values({ slug: `grants-b-${stamp}`, name: "B" })
      .returning();
    if (!a[0] || !b[0]) throw new Error("workspace insert failed");
    wsA = a[0].id;
    wsB = b[0].id;

    const [uA] = await withWorkspace(db, wsA, (tx) =>
      tx
        .insert(users)
        .values({ workspaceId: wsA, email: `grants-owner-a-${stamp}@example.com` })
        .returning({ id: users.id }),
    );
    const [uB] = await withWorkspace(db, wsB, (tx) =>
      tx
        .insert(users)
        .values({ workspaceId: wsB, email: `grants-owner-b-${stamp}@example.com` })
        .returning({ id: users.id }),
    );
    if (!uA || !uB) throw new Error("user insert failed");
    ownerA = uA.id;
    ownerB = uB.id;

    const [agA] = await withWorkspace(db, wsA, (tx) =>
      tx
        .insert(agents)
        .values({
          workspaceId: wsA,
          slug: `grants-agent-a-${stamp}`,
          displayName: "Grants Agent A",
          kind: "service",
          ownerUserId: ownerA,
          pubkeyJwk: sampleJwk,
          pubkeyThumbprint: `grants-thumb-a-${stamp}`,
        })
        .returning({ id: agents.id }),
    );
    const [agB] = await withWorkspace(db, wsB, (tx) =>
      tx
        .insert(agents)
        .values({
          workspaceId: wsB,
          slug: `grants-agent-b-${stamp}`,
          displayName: "Grants Agent B",
          kind: "service",
          ownerUserId: ownerB,
          pubkeyJwk: sampleJwk,
          pubkeyThumbprint: `grants-thumb-b-${stamp}`,
        })
        .returning({ id: agents.id }),
    );
    if (!agA || !agB) throw new Error("agent insert failed");
    agentAId = agA.id;
    agentBId = agB.id;

    const [grA] = await withWorkspace(db, wsA, (tx) =>
      tx
        .insert(agentCapabilityGrants)
        .values({
          workspaceId: wsA,
          agentId: agentAId,
          onBehalfOfUserId: ownerA,
          toolName: "search.documents",
          scope: { resource: "drive:*" },
          createdByUserId: ownerA,
        })
        .returning({ id: agentCapabilityGrants.id }),
    );
    if (!grA) throw new Error("grant A insert failed");
    grantAId = grA.id;

    invocationAJti = crypto.randomUUID();
    await withWorkspace(db, wsA, (tx) =>
      tx.insert(agentInvocations).values({
        workspaceId: wsA,
        jti: invocationAJti,
        agentId: agentAId,
        grantId: grantAId,
        onBehalfOfUserId: ownerA,
        toolName: "search.documents",
        scopeClaim: { resource: "drive:doc-1" },
        audience: "pact-mcp",
        cnfThumbprint: `cnf-a-${stamp}`,
        redeemStatus: "issued",
        expiresAt: new Date(Date.now() + 60_000),
      }),
    );

    await withWorkspace(db, wsA, (tx) =>
      tx.insert(delegationChains).values({
        workspaceId: wsA,
        parentJti: invocationAJti,
        childJti: crypto.randomUUID(),
        parentAgentId: agentAId,
        childAgentId: agentAId,
        scopeReduction: { resource: "drive:doc-1#section-2" },
        depth: 1,
      }),
    );
  });

  afterAll(async () => {
    if (wsA) await db.delete(workspaces).where(eq(workspaces.id, wsA));
    if (wsB) await db.delete(workspaces).where(eq(workspaces.id, wsB));
  });

  it("denies cross-workspace SELECT on grants", async () => {
    const rows = await withWorkspace(db, wsB, (tx) =>
      tx
        .select({ id: agentCapabilityGrants.id })
        .from(agentCapabilityGrants)
        .where(eq(agentCapabilityGrants.id, grantAId)),
    );
    expect(rows.length).toBe(0);
  });

  it("rejects cross-workspace INSERT on grants via WITH CHECK", async () => {
    await expect(
      withWorkspace(db, wsA, (tx) =>
        tx.insert(agentCapabilityGrants).values({
          workspaceId: wsB,
          agentId: agentBId,
          onBehalfOfUserId: ownerB,
          toolName: "smuggled",
          scope: {},
          createdByUserId: ownerB,
        }),
      ),
    ).rejects.toThrow();
  });

  it("denies cross-workspace SELECT on invocations", async () => {
    const rows = await withWorkspace(db, wsB, (tx) =>
      tx
        .select({ id: agentInvocations.id })
        .from(agentInvocations)
        .where(eq(agentInvocations.workspaceId, wsA)),
    );
    expect(rows.length).toBe(0);
  });

  it("rejects cross-workspace INSERT on invocations via WITH CHECK", async () => {
    await expect(
      withWorkspace(db, wsA, (tx) =>
        tx.insert(agentInvocations).values({
          workspaceId: wsB,
          jti: crypto.randomUUID(),
          agentId: agentBId,
          toolName: "search.documents",
          scopeClaim: {},
          audience: "pact-mcp",
          cnfThumbprint: "smuggled-cnf",
          redeemStatus: "issued",
          expiresAt: new Date(Date.now() + 60_000),
        }),
      ),
    ).rejects.toThrow();
  });

  it("denies cross-workspace SELECT on delegation chains", async () => {
    const rows = await withWorkspace(db, wsB, (tx) =>
      tx
        .select({ id: delegationChains.id })
        .from(delegationChains)
        .where(eq(delegationChains.workspaceId, wsA)),
    );
    expect(rows.length).toBe(0);
  });

  it("rejects cross-workspace INSERT on delegation chains via WITH CHECK", async () => {
    await expect(
      withWorkspace(db, wsA, (tx) =>
        tx.insert(delegationChains).values({
          workspaceId: wsB,
          parentJti: crypto.randomUUID(),
          childJti: crypto.randomUUID(),
          parentAgentId: agentBId,
          childAgentId: agentBId,
          scopeReduction: {},
          depth: 1,
        }),
      ),
    ).rejects.toThrow();
  });
});
