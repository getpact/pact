import { createClient, withWorkspace } from "@getpact/db";
import {
  agentCapabilityGrants,
  agentInvocations,
  agents,
  users,
  workspaces,
} from "@getpact/db/schema";
import { buildTestEnv, createTestWorkspace, uniqueSlug } from "@getpact/test-helpers";
import { and, eq } from "drizzle-orm";
import { afterEach, describe, expect, it } from "vitest";
import app from "../index.js";

const url = process.env.RLS_TEST_DB;
const adminUrl = process.env.DATABASE_URL ?? url;
const run = url && adminUrl ? describe : describe.skip;

const sampleAgentJwk = {
  kty: "OKP",
  crv: "Ed25519",
  x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
};

const seedAgent = async (
  adminDb: ReturnType<typeof createClient>,
  workspaceId: string,
  ownerUserId: string,
  suffix: string,
): Promise<string> =>
  withWorkspace(adminDb, workspaceId, async (tx) => {
    const [agent] = await tx
      .insert(agents)
      .values({
        workspaceId,
        slug: `cascade-${suffix}`,
        displayName: `Cascade ${suffix}`,
        kind: "service",
        ownerUserId,
        pubkeyJwk: sampleAgentJwk,
        pubkeyThumbprint: `thumb-${suffix}`,
      })
      .returning({ id: agents.id });
    if (!agent) throw new Error("agent insert failed");
    return agent.id;
  });

const seedGrant = async (
  adminDb: ReturnType<typeof createClient>,
  workspaceId: string,
  input: { agentId: string; ownerUserId: string; onBehalfOfUserId: string },
): Promise<string> =>
  withWorkspace(adminDb, workspaceId, async (tx) => {
    const [grant] = await tx
      .insert(agentCapabilityGrants)
      .values({
        workspaceId,
        agentId: input.agentId,
        onBehalfOfUserId: input.onBehalfOfUserId,
        toolName: "pact.drive.search",
        scope: { folder: "shared" },
        audience: ["pact-mcp"],
        createdByUserId: input.ownerUserId,
      })
      .returning({ id: agentCapabilityGrants.id });
    if (!grant) throw new Error("grant insert failed");
    return grant.id;
  });

const seedInvocation = async (
  adminDb: ReturnType<typeof createClient>,
  workspaceId: string,
  input: { agentId: string; grantId: string; onBehalfOfUserId: string; jti: string },
): Promise<void> => {
  await withWorkspace(adminDb, workspaceId, async (tx) => {
    await tx.insert(agentInvocations).values({
      workspaceId,
      jti: input.jti,
      agentId: input.agentId,
      agentIdSnapshot: input.agentId,
      grantId: input.grantId,
      onBehalfOfUserId: input.onBehalfOfUserId,
      onBehalfOfUserIdSnapshot: input.onBehalfOfUserId,
      toolName: "pact.drive.search",
      scopeClaim: { folder: "shared" },
      audience: "pact-mcp",
      cnfThumbprint: "filler",
      redeemStatus: "issued",
      issuedAt: new Date(),
      expiresAt: new Date(Date.now() + 300_000),
    });
  });
};

const seedUser = async (
  adminDb: ReturnType<typeof createClient>,
  workspaceId: string,
  email: string,
): Promise<string> =>
  withWorkspace(adminDb, workspaceId, async (tx) => {
    const [u] = await tx.insert(users).values({ workspaceId, email }).returning({ id: users.id });
    if (!u) throw new Error("user insert failed");
    return u.id;
  });

run("agent_invocations snapshot survives parent delete", () => {
  const adminDb = createClient(adminUrl as string);
  const cleanup: string[] = [];

  afterEach(async () => {
    while (cleanup.length > 0) {
      const id = cleanup.pop();
      if (!id) continue;
      try {
        await adminDb.delete(workspaces).where(eq(workspaces.id, id));
      } catch {
        // ignore
      }
    }
  });

  it("preserves agent_id_snapshot when the agent is hard-deleted", async () => {
    const env = await buildTestEnv(adminUrl as string);
    const created = await createTestWorkspace(app, env, {
      slug: uniqueSlug("cascade-agent"),
      adminEmail: "alice@example.com",
    });
    cleanup.push(created.workspaceId);

    const suffix = `a-${Date.now()}`;
    const agentId = await seedAgent(adminDb, created.workspaceId, created.adminUserId, suffix);
    const grantId = await seedGrant(adminDb, created.workspaceId, {
      agentId,
      ownerUserId: created.adminUserId,
      onBehalfOfUserId: created.adminUserId,
    });
    const jti = crypto.randomUUID();
    await seedInvocation(adminDb, created.workspaceId, {
      agentId,
      grantId,
      onBehalfOfUserId: created.adminUserId,
      jti,
    });

    await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx.delete(agents).where(eq(agents.id, agentId)),
    );

    const rows = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx
        .select({
          jti: agentInvocations.jti,
          agentId: agentInvocations.agentId,
          agentIdSnapshot: agentInvocations.agentIdSnapshot,
          grantId: agentInvocations.grantId,
        })
        .from(agentInvocations)
        .where(
          and(eq(agentInvocations.workspaceId, created.workspaceId), eq(agentInvocations.jti, jti)),
        ),
    );

    expect(rows).toHaveLength(1);
    const row = rows[0];
    if (!row) throw new Error("missing invocation");
    expect(row.agentId).toBeNull();
    expect(row.agentIdSnapshot).toBe(agentId);
    expect(row.grantId).toBeNull();
  });

  it("preserves on_behalf_of_user_id_snapshot when the user is hard-deleted", async () => {
    const env = await buildTestEnv(adminUrl as string);
    const created = await createTestWorkspace(app, env, {
      slug: uniqueSlug("cascade-user"),
      adminEmail: "alice@example.com",
    });
    cleanup.push(created.workspaceId);

    const subjectId = await seedUser(adminDb, created.workspaceId, `bob-${Date.now()}@example.com`);
    const suffix = `u-${Date.now()}`;
    const agentId = await seedAgent(adminDb, created.workspaceId, created.adminUserId, suffix);
    const grantId = await seedGrant(adminDb, created.workspaceId, {
      agentId,
      ownerUserId: created.adminUserId,
      onBehalfOfUserId: subjectId,
    });
    const jti = crypto.randomUUID();
    await seedInvocation(adminDb, created.workspaceId, {
      agentId,
      grantId,
      onBehalfOfUserId: subjectId,
      jti,
    });

    await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx.delete(users).where(eq(users.id, subjectId)),
    );

    const rows = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx
        .select({
          onBehalfOfUserId: agentInvocations.onBehalfOfUserId,
          onBehalfOfUserIdSnapshot: agentInvocations.onBehalfOfUserIdSnapshot,
        })
        .from(agentInvocations)
        .where(
          and(eq(agentInvocations.workspaceId, created.workspaceId), eq(agentInvocations.jti, jti)),
        ),
    );

    expect(rows).toHaveLength(1);
    const row = rows[0];
    if (!row) throw new Error("missing invocation");
    expect(row.onBehalfOfUserId).toBeNull();
    expect(row.onBehalfOfUserIdSnapshot).toBe(subjectId);
  });

  it("backfills snapshot columns via trigger when omitted", async () => {
    const env = await buildTestEnv(adminUrl as string);
    const created = await createTestWorkspace(app, env, {
      slug: uniqueSlug("cascade-trg"),
      adminEmail: "alice@example.com",
    });
    cleanup.push(created.workspaceId);

    const suffix = `t-${Date.now()}`;
    const agentId = await seedAgent(adminDb, created.workspaceId, created.adminUserId, suffix);
    const grantId = await seedGrant(adminDb, created.workspaceId, {
      agentId,
      ownerUserId: created.adminUserId,
      onBehalfOfUserId: created.adminUserId,
    });
    const jti = crypto.randomUUID();

    await withWorkspace(adminDb, created.workspaceId, async (tx) => {
      await tx.insert(agentInvocations).values({
        workspaceId: created.workspaceId,
        jti,
        agentId,
        grantId,
        onBehalfOfUserId: created.adminUserId,
        toolName: "pact.drive.search",
        scopeClaim: { folder: "shared" },
        audience: "pact-mcp",
        cnfThumbprint: "filler",
        redeemStatus: "issued",
        issuedAt: new Date(),
        expiresAt: new Date(Date.now() + 300_000),
      });
    });

    const rows = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx
        .select({
          agentIdSnapshot: agentInvocations.agentIdSnapshot,
          onBehalfOfUserIdSnapshot: agentInvocations.onBehalfOfUserIdSnapshot,
        })
        .from(agentInvocations)
        .where(
          and(eq(agentInvocations.workspaceId, created.workspaceId), eq(agentInvocations.jti, jti)),
        ),
    );

    expect(rows[0]?.agentIdSnapshot).toBe(agentId);
    expect(rows[0]?.onBehalfOfUserIdSnapshot).toBe(created.adminUserId);
  });
});
