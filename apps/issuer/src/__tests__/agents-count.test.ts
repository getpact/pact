import { createClient, withWorkspace } from "@getpact/db";
import { agentCapabilityGrants, agentInvocations, agents, workspaces } from "@getpact/db/schema";
import { buildTestEnv, createTestWorkspace, uniqueSlug } from "@getpact/test-helpers";
import { eq } from "drizzle-orm";
import { afterEach, describe, expect, it } from "vitest";
import app from "../index.js";
import { countRecentInvocations } from "../routes/agents.js";

const url = process.env.RLS_TEST_DB;
const adminUrl = process.env.DATABASE_URL ?? url;
const run = url && adminUrl ? describe : describe.skip;

const sampleAgentJwk = {
  kty: "OKP",
  crv: "Ed25519",
  x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
};

run("countRecentInvocations", () => {
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

  it("counts invocations from the last 24h without FOR UPDATE", async () => {
    const env = await buildTestEnv(adminUrl as string);
    const created = await createTestWorkspace(app, env, {
      slug: uniqueSlug("count"),
      adminEmail: "alice@example.com",
    });
    cleanup.push(created.workspaceId);

    const { agentId, grantId } = await withWorkspace(adminDb, created.workspaceId, async (tx) => {
      const stamp = `${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
      const [agent] = await tx
        .insert(agents)
        .values({
          workspaceId: created.workspaceId,
          slug: `count-${stamp}`,
          displayName: "Count",
          kind: "service",
          ownerUserId: created.adminUserId,
          pubkeyJwk: sampleAgentJwk,
          pubkeyThumbprint: `thumb-${stamp}`,
        })
        .returning({ id: agents.id });
      if (!agent) throw new Error("agent insert failed");
      const [grant] = await tx
        .insert(agentCapabilityGrants)
        .values({
          workspaceId: created.workspaceId,
          agentId: agent.id,
          onBehalfOfUserId: created.adminUserId,
          toolName: "pact.x",
          scope: { folder: "shared" },
          audience: ["pact-x"],
          createdByUserId: created.adminUserId,
        })
        .returning({ id: agentCapabilityGrants.id });
      if (!grant) throw new Error("grant insert failed");
      return { agentId: agent.id, grantId: grant.id };
    });

    await withWorkspace(adminDb, created.workspaceId, async (tx) => {
      const now = new Date();
      const exp = new Date(now.getTime() + 300_000);
      for (let i = 0; i < 3; i += 1) {
        await tx.insert(agentInvocations).values({
          workspaceId: created.workspaceId,
          jti: crypto.randomUUID(),
          agentId,
          grantId,
          onBehalfOfUserId: created.adminUserId,
          toolName: "pact.x",
          scopeClaim: { folder: "shared" },
          audience: "pact-x",
          cnfThumbprint: "filler",
          redeemStatus: "issued",
          issuedAt: now,
          expiresAt: exp,
        });
      }
    });

    const recent = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      countRecentInvocations(tx, created.workspaceId, grantId),
    );
    expect(recent).toBe(3);
  });
});
