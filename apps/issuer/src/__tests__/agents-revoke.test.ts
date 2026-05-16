import { createClient, withWorkspace } from "@getpact/db";
import {
  agentCapabilityGrants,
  agentInvocations,
  agents,
  auditEvents,
  delegationChains,
  revokedJtis,
  workspaces,
} from "@getpact/db/schema";
import {
  buildTestEnv,
  createTestWorkspace,
  issueTestToken,
  uniqueSlug,
} from "@getpact/test-helpers";
import { eq, inArray } from "drizzle-orm";
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
        slug: `agent-${suffix}`,
        displayName: `Agent ${suffix}`,
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
  input: {
    agentId: string;
    grantId?: string;
    onBehalfOfUserId: string;
    jti: string;
    parentJti?: string | null;
  },
): Promise<void> => {
  await withWorkspace(adminDb, workspaceId, async (tx) => {
    await tx.insert(agentInvocations).values({
      workspaceId,
      jti: input.jti,
      parentJti: input.parentJti ?? null,
      agentId: input.agentId,
      grantId: input.grantId ?? null,
      onBehalfOfUserId: input.onBehalfOfUserId,
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

const seedChain = async (
  adminDb: ReturnType<typeof createClient>,
  workspaceId: string,
  input: {
    parentJti: string;
    childJti: string;
    parentAgentId: string;
    childAgentId: string;
    depth: number;
  },
): Promise<void> => {
  await withWorkspace(adminDb, workspaceId, async (tx) => {
    await tx.insert(delegationChains).values({
      workspaceId,
      parentJti: input.parentJti,
      childJti: input.childJti,
      parentAgentId: input.parentAgentId,
      childAgentId: input.childAgentId,
      scopeReduction: { reduce: "noop" },
      depth: input.depth,
    });
  });
};

const callRevoke = (
  jti: string,
  token: string,
  body: Record<string, unknown> | undefined,
  env: Record<string, unknown>,
) => {
  const init: RequestInit = {
    method: "DELETE",
    headers: {
      "content-type": "application/json",
      Authorization: `Bearer ${token}`,
    },
  };
  if (body) init.body = JSON.stringify(body);
  return app.request(`/v1/capabilities/${jti}`, init, env);
};

run("agents capability revoke", () => {
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

  const setup = async () => {
    const env = await buildTestEnv(adminUrl as string);
    const created = await createTestWorkspace(app, env, {
      slug: uniqueSlug("rev"),
      adminEmail: "alice@example.com",
    });
    cleanup.push(created.workspaceId);
    const issued = await issueTestToken(app, env, {
      workspaceId: created.workspaceId,
      email: "alice@example.com",
      audience: env.ADMIN_AUDIENCE,
    });
    return { env, created, token: issued.token };
  };

  it("revokes a single capability and writes the revoked_jtis row", async () => {
    const { env, created, token } = await setup();
    const agentId = await seedAgent(adminDb, created.workspaceId, created.adminUserId, "solo");
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

    const res = await callRevoke(jti, token, { cascade: false, reason: "manual" }, env);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { revoked: string[]; count: number };
    expect(body.count).toBe(1);
    expect(body.revoked).toEqual([jti]);

    const inv = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx.select().from(agentInvocations).where(eq(agentInvocations.jti, jti)),
    );
    expect(inv[0]?.redeemStatus).toBe("revoked");

    const revRows = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx.select().from(revokedJtis).where(eq(revokedJtis.workspaceId, created.workspaceId)),
    );
    expect(revRows.find((r) => r.jti === jti)).toBeDefined();
    expect(revRows.find((r) => r.jti === jti)?.reason).toBe("manual");

    const events = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx
        .select({ action: auditEvents.action })
        .from(auditEvents)
        .where(eq(auditEvents.workspaceId, created.workspaceId)),
    );
    expect(events.find((e) => e.action === "agent.capability.revoked")).toBeDefined();
  });

  it("cascades revocation across a 4-deep delegation chain", async () => {
    const { env, created, token } = await setup();
    const a0 = await seedAgent(adminDb, created.workspaceId, created.adminUserId, "d0");
    const a1 = await seedAgent(adminDb, created.workspaceId, created.adminUserId, "d1");
    const a2 = await seedAgent(adminDb, created.workspaceId, created.adminUserId, "d2");
    const a3 = await seedAgent(adminDb, created.workspaceId, created.adminUserId, "d3");

    const root = crypto.randomUUID();
    const c1 = crypto.randomUUID();
    const c2 = crypto.randomUUID();
    const c3 = crypto.randomUUID();

    await seedInvocation(adminDb, created.workspaceId, {
      agentId: a0,
      onBehalfOfUserId: created.adminUserId,
      jti: root,
    });
    await seedInvocation(adminDb, created.workspaceId, {
      agentId: a1,
      onBehalfOfUserId: created.adminUserId,
      jti: c1,
      parentJti: root,
    });
    await seedInvocation(adminDb, created.workspaceId, {
      agentId: a2,
      onBehalfOfUserId: created.adminUserId,
      jti: c2,
      parentJti: c1,
    });
    await seedInvocation(adminDb, created.workspaceId, {
      agentId: a3,
      onBehalfOfUserId: created.adminUserId,
      jti: c3,
      parentJti: c2,
    });

    await seedChain(adminDb, created.workspaceId, {
      parentJti: root,
      childJti: c1,
      parentAgentId: a0,
      childAgentId: a1,
      depth: 1,
    });
    await seedChain(adminDb, created.workspaceId, {
      parentJti: c1,
      childJti: c2,
      parentAgentId: a1,
      childAgentId: a2,
      depth: 2,
    });
    await seedChain(adminDb, created.workspaceId, {
      parentJti: c2,
      childJti: c3,
      parentAgentId: a2,
      childAgentId: a3,
      depth: 3,
    });

    const res = await callRevoke(root, token, { cascade: true, reason: "owner_request" }, env);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { revoked: string[]; count: number };
    expect(body.count).toBe(4);
    expect(new Set(body.revoked)).toEqual(new Set([root, c1, c2, c3]));

    const invs = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx
        .select()
        .from(agentInvocations)
        .where(inArray(agentInvocations.jti, [root, c1, c2, c3])),
    );
    expect(invs.length).toBe(4);
    for (const row of invs) {
      expect(row.redeemStatus).toBe("revoked");
    }

    const rev = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx
        .select({ jti: revokedJtis.jti })
        .from(revokedJtis)
        .where(eq(revokedJtis.workspaceId, created.workspaceId)),
    );
    expect(new Set(rev.map((r) => r.jti))).toEqual(new Set([root, c1, c2, c3]));

    const events = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx
        .select({ action: auditEvents.action, supporting: auditEvents.supporting })
        .from(auditEvents)
        .where(eq(auditEvents.workspaceId, created.workspaceId)),
    );
    const revokedEvents = events.filter((e) => e.action === "agent.capability.revoked");
    expect(revokedEvents.length).toBe(4);
  });
});
