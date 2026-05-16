import { createClient, withWorkspace } from "@getpact/db";
import {
  agentCapabilityGrants,
  agentInvocations,
  agents,
  auditEvents,
  workspaces,
} from "@getpact/db/schema";
import {
  buildTestEnv,
  createTestWorkspace,
  issueTestToken,
  uniqueSlug,
} from "@getpact/test-helpers";
import { eq } from "drizzle-orm";
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

const recipientJwk = {
  kty: "OKP" as const,
  crv: "Ed25519" as const,
  x: "VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ",
};

const seedAgentAndGrant = async (
  adminDb: ReturnType<typeof createClient>,
  workspaceId: string,
  input: {
    ownerUserId: string;
    onBehalfOfUserId: string;
    toolName: string;
    scope: Record<string, unknown>;
    audience: string[];
    maxUsesPerDay?: number;
    createdByUserId?: string;
    slug?: string;
    thumbprint?: string;
  },
): Promise<{ agentId: string; grantId: string }> =>
  withWorkspace(adminDb, workspaceId, async (tx) => {
    const stamp = `${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const [agent] = await tx
      .insert(agents)
      .values({
        workspaceId,
        slug: input.slug ?? `bot-${stamp}`,
        displayName: "Mint Bot",
        kind: "service",
        ownerUserId: input.ownerUserId,
        pubkeyJwk: sampleAgentJwk,
        pubkeyThumbprint: input.thumbprint ?? `thumb-${stamp}`,
      })
      .returning({ id: agents.id });
    if (!agent) throw new Error("agent insert failed");
    const [grant] = await tx
      .insert(agentCapabilityGrants)
      .values({
        workspaceId,
        agentId: agent.id,
        onBehalfOfUserId: input.onBehalfOfUserId,
        toolName: input.toolName,
        scope: input.scope,
        maxUsesPerDay: input.maxUsesPerDay ?? 1000,
        audience: input.audience,
        createdByUserId: input.createdByUserId ?? input.ownerUserId,
      })
      .returning({ id: agentCapabilityGrants.id });
    if (!grant) throw new Error("grant insert failed");
    return { agentId: agent.id, grantId: grant.id };
  });

const callMint = (
  agentId: string,
  token: string,
  body: Record<string, unknown>,
  env: Record<string, unknown>,
) =>
  app.request(
    `/v1/agents/${agentId}/capabilities`,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(body),
    },
    env,
  );

run("agents capability mint", () => {
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
      slug: uniqueSlug("mint"),
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

  it("mints a capability sd-jwt and records an invocation", async () => {
    const { env, created, token } = await setup();
    const { agentId, grantId } = await seedAgentAndGrant(adminDb, created.workspaceId, {
      ownerUserId: created.adminUserId,
      onBehalfOfUserId: created.adminUserId,
      toolName: "pact.drive.search",
      scope: { folder: "shared" },
      audience: ["pact-drive"],
    });

    const res = await callMint(
      agentId,
      token,
      {
        on_behalf_of: "alice@example.com",
        tool_name: "pact.drive.search",
        scope: { folder: "shared" },
        audience: "pact-drive",
        ttl_seconds: 300,
        max_redeems: 1,
        cnf_jwk: recipientJwk,
      },
      env,
    );

    expect(res.status).toBe(201);
    const body = (await res.json()) as {
      jti: string;
      sd_jwt: string;
      exp: number;
      cnf_thumbprint: string;
    };
    expect(body.sd_jwt.startsWith("ey")).toBe(true);
    expect(body.sd_jwt.endsWith("~")).toBe(true);
    expect(body.cnf_thumbprint.length).toBeGreaterThan(10);

    const invocations = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx
        .select()
        .from(agentInvocations)
        .where(eq(agentInvocations.workspaceId, created.workspaceId)),
    );
    expect(invocations.length).toBe(1);
    const row = invocations[0];
    if (!row) throw new Error("missing invocation");
    expect(row.jti).toBe(body.jti);
    expect(row.grantId).toBe(grantId);
    expect(row.redeemStatus).toBe("issued");
    expect(row.toolName).toBe("pact.drive.search");
    expect(row.cnfThumbprint).toBe(body.cnf_thumbprint);

    const events = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx
        .select({ action: auditEvents.action, decision: auditEvents.decision })
        .from(auditEvents)
        .where(eq(auditEvents.workspaceId, created.workspaceId)),
    );
    const mintEvent = events.find((e) => e.action === "agent.capability.minted");
    expect(mintEvent).toBeDefined();
    expect(mintEvent?.decision).toBe("allow");
  });

  it("returns 409 when the daily grant quota is exhausted", async () => {
    const { env, created, token } = await setup();
    const { agentId, grantId } = await seedAgentAndGrant(adminDb, created.workspaceId, {
      ownerUserId: created.adminUserId,
      onBehalfOfUserId: created.adminUserId,
      toolName: "pact.drive.search",
      scope: { folder: "private" },
      audience: ["pact-drive"],
      maxUsesPerDay: 2,
    });

    await withWorkspace(adminDb, created.workspaceId, async (tx) => {
      const now = new Date();
      const exp = new Date(now.getTime() + 300_000);
      for (let i = 0; i < 2; i += 1) {
        await tx.insert(agentInvocations).values({
          workspaceId: created.workspaceId,
          jti: crypto.randomUUID(),
          agentId,
          grantId,
          onBehalfOfUserId: created.adminUserId,
          toolName: "pact.drive.search",
          scopeClaim: { folder: "private" },
          audience: "pact-drive",
          cnfThumbprint: "filler",
          redeemStatus: "issued",
          issuedAt: now,
          expiresAt: exp,
        });
      }
    });

    const res = await callMint(
      agentId,
      token,
      {
        on_behalf_of: "alice@example.com",
        tool_name: "pact.drive.search",
        scope: { folder: "private" },
        audience: "pact-drive",
        cnf_jwk: recipientJwk,
      },
      env,
    );
    expect(res.status).toBe(409);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("quota_exceeded");
  });

  it("returns 403 when no grant matches the request", async () => {
    const { env, created, token } = await setup();
    const { agentId } = await seedAgentAndGrant(adminDb, created.workspaceId, {
      ownerUserId: created.adminUserId,
      onBehalfOfUserId: created.adminUserId,
      toolName: "pact.drive.search",
      scope: { folder: "shared" },
      audience: ["pact-drive"],
    });
    const res = await callMint(
      agentId,
      token,
      {
        on_behalf_of: "alice@example.com",
        tool_name: "pact.drive.write",
        scope: { folder: "shared" },
        audience: "pact-drive",
        cnf_jwk: recipientJwk,
      },
      env,
    );
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("no_matching_grant");
  });

  it("rate limits per workspace and agent at 100 per minute", async () => {
    const { env, created, token } = await setup();
    const { agentId } = await seedAgentAndGrant(adminDb, created.workspaceId, {
      ownerUserId: created.adminUserId,
      onBehalfOfUserId: created.adminUserId,
      toolName: "pact.drive.search",
      scope: { folder: "shared" },
      audience: ["pact-drive"],
    });

    const localEnv = { ...env, ENVIRONMENT: "development" };
    let limitedStatus = 0;
    for (let i = 0; i < 105; i += 1) {
      const res = await callMint(
        agentId,
        token,
        {
          on_behalf_of: "alice@example.com",
          tool_name: "pact.drive.search",
          scope: { folder: "shared" },
          audience: "pact-drive",
          cnf_jwk: recipientJwk,
        },
        localEnv,
      );
      if (res.status === 429) {
        limitedStatus = 429;
        break;
      }
    }
    expect(limitedStatus).toBe(429);
  });

  it("returns 400 when cnf_jwk is missing", async () => {
    const { env, created, token } = await setup();
    const { agentId } = await seedAgentAndGrant(adminDb, created.workspaceId, {
      ownerUserId: created.adminUserId,
      onBehalfOfUserId: created.adminUserId,
      toolName: "pact.drive.search",
      scope: { folder: "shared" },
      audience: ["pact-drive"],
    });

    const res = await callMint(
      agentId,
      token,
      {
        on_behalf_of: "alice@example.com",
        tool_name: "pact.drive.search",
        scope: { folder: "shared" },
        audience: "pact-drive",
      },
      env,
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string; message: string };
    expect(body.error).toBe("invalid_body");
    expect(body.message).toContain("cnf_jwk");
  });
});
