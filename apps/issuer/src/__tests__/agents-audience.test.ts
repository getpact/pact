import { createClient, withWorkspace } from "@getpact/db";
import { agentCapabilityGrants, agents, workspaceAudiences, workspaces } from "@getpact/db/schema";
import {
  buildTestEnv,
  createTestWorkspace,
  issueTestToken,
  uniqueSlug,
} from "@getpact/test-helpers";
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
  },
): Promise<{ agentId: string; grantId: string }> =>
  withWorkspace(adminDb, workspaceId, async (tx) => {
    const stamp = `${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const [agent] = await tx
      .insert(agents)
      .values({
        workspaceId,
        slug: `bot-${stamp}`,
        displayName: "Audience Bot",
        kind: "service",
        ownerUserId: input.ownerUserId,
        pubkeyJwk: sampleAgentJwk,
        pubkeyThumbprint: `thumb-${stamp}`,
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
        audience: input.audience,
        createdByUserId: input.ownerUserId,
      })
      .returning({ id: agentCapabilityGrants.id });
    if (!grant) throw new Error("grant insert failed");
    return { agentId: agent.id, grantId: grant.id };
  });

const registerAudience = async (
  adminDb: ReturnType<typeof createClient>,
  workspaceId: string,
  input: { name: string; patterns?: string[] },
): Promise<void> => {
  await withWorkspace(adminDb, workspaceId, async (tx) => {
    await tx.insert(workspaceAudiences).values({
      workspaceId,
      name: input.name,
      allowedSubjectPatterns: input.patterns ?? [],
    });
  });
};

const revokeAudience = async (
  adminDb: ReturnType<typeof createClient>,
  workspaceId: string,
  name: string,
): Promise<void> => {
  await withWorkspace(adminDb, workspaceId, async (tx) => {
    await tx
      .update(workspaceAudiences)
      .set({ revokedAt: new Date() })
      .where(
        and(eq(workspaceAudiences.workspaceId, workspaceId), eq(workspaceAudiences.name, name)),
      );
  });
};

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

run("agents capability mint - audience allowlist", () => {
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
      slug: uniqueSlug("aud"),
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

  it("mints when the audience is registered for the workspace", async () => {
    const { env, created, token } = await setup();
    await registerAudience(adminDb, created.workspaceId, { name: "pact-drive" });
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
        cnf_jwk: recipientJwk,
      },
      env,
    );
    expect(res.status).toBe(201);
  });

  it("returns 400 unknown_audience when the audience is not registered", async () => {
    const { env, created, token } = await setup();
    await revokeAudience(adminDb, created.workspaceId, "pact-mcp");
    const { agentId } = await seedAgentAndGrant(adminDb, created.workspaceId, {
      ownerUserId: created.adminUserId,
      onBehalfOfUserId: created.adminUserId,
      toolName: "pact.mcp.invoke",
      scope: { tool: "echo" },
      audience: ["pact-mcp"],
    });

    const res = await callMint(
      agentId,
      token,
      {
        on_behalf_of: "alice@example.com",
        tool_name: "pact.mcp.invoke",
        scope: { tool: "echo" },
        audience: "pact-mcp",
        cnf_jwk: recipientJwk,
      },
      env,
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("unknown_audience");
  });

  it("mints when the subject matches one of the audience patterns", async () => {
    const { env, created, token } = await setup();
    await registerAudience(adminDb, created.workspaceId, {
      name: "pact-internal",
      patterns: ["@example.com"],
    });
    const { agentId } = await seedAgentAndGrant(adminDb, created.workspaceId, {
      ownerUserId: created.adminUserId,
      onBehalfOfUserId: created.adminUserId,
      toolName: "pact.internal.ping",
      scope: { area: "ops" },
      audience: ["pact-internal"],
    });

    const res = await callMint(
      agentId,
      token,
      {
        on_behalf_of: "alice@example.com",
        tool_name: "pact.internal.ping",
        scope: { area: "ops" },
        audience: "pact-internal",
        cnf_jwk: recipientJwk,
      },
      env,
    );
    expect(res.status).toBe(201);
  });

  it("returns 400 subject_not_allowed when the subject fails the pattern check", async () => {
    const { env, created, token } = await setup();
    await registerAudience(adminDb, created.workspaceId, {
      name: "pact-partner",
      patterns: ["@partner.io"],
    });
    const { agentId } = await seedAgentAndGrant(adminDb, created.workspaceId, {
      ownerUserId: created.adminUserId,
      onBehalfOfUserId: created.adminUserId,
      toolName: "pact.partner.fetch",
      scope: { partner: "acme" },
      audience: ["pact-partner"],
    });

    const res = await callMint(
      agentId,
      token,
      {
        on_behalf_of: "alice@example.com",
        tool_name: "pact.partner.fetch",
        scope: { partner: "acme" },
        audience: "pact-partner",
        cnf_jwk: recipientJwk,
      },
      env,
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("subject_not_allowed");
  });
});
