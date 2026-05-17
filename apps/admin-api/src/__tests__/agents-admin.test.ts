import { type Ed25519PublicJwk, generateEd25519Keypair } from "@getpact/crypto";
import { createClient, withWorkspace } from "@getpact/db";
import { agentCapabilityGrants, users, workspaces } from "@getpact/db/schema";
import {
  buildTestEnv,
  createTestWorkspace,
  issueTestToken,
  uniqueSlug,
} from "@getpact/test-helpers";
import { and, eq, sql } from "drizzle-orm";
import { afterEach, describe, expect, it } from "vitest";
import issuer from "../../../../apps/issuer/src/index.js";
import app from "../index.js";

const url = process.env.DATABASE_URL;
const run = url ? describe : describe.skip;

const exportEd25519Jwk = async (key: CryptoKey): Promise<Ed25519PublicJwk> => {
  const jwk = (await crypto.subtle.exportKey("jwk", key)) as JsonWebKey;
  return { kty: "OKP", crv: "Ed25519", x: jwk.x as string };
};

run("admin api agents", () => {
  const adminDb = createClient(url as string);
  const cleanup: string[] = [];

  afterEach(async () => {
    while (cleanup.length > 0) {
      const id = cleanup.pop();
      if (!id) continue;
      try {
        await adminDb.delete(workspaces).where(eq(workspaces.id, id));
      } catch {}
    }
  });

  const setup = async () => {
    const env = await buildTestEnv(url as string);
    const created = await createTestWorkspace(issuer, env, {
      slug: uniqueSlug("agt"),
      adminEmail: "alice@example.com",
    });
    cleanup.push(created.workspaceId);
    const issued = await issueTestToken(issuer, env, {
      workspaceId: created.workspaceId,
      email: "alice@example.com",
      audience: env.ADMIN_AUDIENCE,
    });
    const subjectRows = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx
        .insert(users)
        .values({ workspaceId: created.workspaceId, email: "bob@example.com" })
        .returning({ id: users.id }),
    );
    const subjectId = subjectRows[0]?.id as string;
    const kp = await generateEd25519Keypair();
    const pubkeyJwk = await exportEd25519Jwk(kp.publicKey);
    return { env, created, token: issued.token, subjectId, pubkeyJwk };
  };

  const callApi = async (
    suffix: string,
    token: string | null,
    method: "DELETE" | "GET" | "POST",
    body: unknown,
    workspaceId: string,
    env: { DATABASE_URL: string; MEK: string; ADMIN_AUDIENCE: string },
  ): Promise<Response> => {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (token) headers.authorization = `Bearer ${token}`;
    const init: RequestInit = { method, headers };
    if (body !== undefined) init.body = JSON.stringify(body);
    const path = `/v1/workspaces/${workspaceId}${suffix}`;
    return app.request(path, init, { ISSUER_BASE_URL: "https://issuer.test/acme", ...env });
  };

  it("mints an agent and a grant, then revokes the grant idempotently", async () => {
    const { env, created, token, subjectId, pubkeyJwk } = await setup();
    const runtime = {
      DATABASE_URL: env.DATABASE_URL,
      MEK: env.MEK,
      ADMIN_AUDIENCE: env.ADMIN_AUDIENCE,
    };

    const agentRes = await callApi(
      "/agents",
      token,
      "POST",
      {
        name: "ci-bot",
        owner_user_id: created.adminUserId,
        description: "for ci runs",
        pubkey_jwk: pubkeyJwk,
      },
      created.workspaceId,
      runtime,
    );
    expect(agentRes.status).toBe(201);
    const agent = ((await agentRes.json()) as { agent: { id: string; name: string } }).agent;
    expect(agent.name).toBe("ci-bot");

    const listRes = await callApi("/agents", token, "GET", undefined, created.workspaceId, runtime);
    expect(listRes.status).toBe(200);
    const listed = (await listRes.json()) as { agents: Array<{ id: string }> };
    expect(listed.agents.map((a) => a.id)).toContain(agent.id);

    const grantRes = await callApi(
      `/agents/${agent.id}/grants`,
      token,
      "POST",
      {
        tool_name: "pact.brain.search",
        audience: "pact-mcp",
        scope: { group_in: ["eng"] },
        max_per_day: 100,
        on_behalf_of_user_id: subjectId,
      },
      created.workspaceId,
      runtime,
    );
    expect(grantRes.status).toBe(201);
    const grant = ((await grantRes.json()) as { grant: { id: string; tool_name: string } }).grant;
    expect(grant.tool_name).toBe("pact.brain.search");

    const revokeRes = await callApi(
      `/agents/${agent.id}/grants/${grant.id}`,
      token,
      "DELETE",
      undefined,
      created.workspaceId,
      runtime,
    );
    expect(revokeRes.status).toBe(200);

    const rows = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx
        .select()
        .from(agentCapabilityGrants)
        .where(
          and(
            eq(agentCapabilityGrants.workspaceId, created.workspaceId),
            eq(agentCapabilityGrants.id, grant.id),
          ),
        ),
    );
    expect(rows[0]?.revokedAt).not.toBeNull();

    const revokeAgain = await callApi(
      `/agents/${agent.id}/grants/${grant.id}`,
      token,
      "DELETE",
      undefined,
      created.workspaceId,
      runtime,
    );
    expect(revokeAgain.status).toBe(200);
  });

  it("rejects a grant with an unknown audience", async () => {
    const { env, created, token, subjectId, pubkeyJwk } = await setup();
    const runtime = {
      DATABASE_URL: env.DATABASE_URL,
      MEK: env.MEK,
      ADMIN_AUDIENCE: env.ADMIN_AUDIENCE,
    };
    const agentRes = await callApi(
      "/agents",
      token,
      "POST",
      { name: "ghost", owner_user_id: created.adminUserId, pubkey_jwk: pubkeyJwk },
      created.workspaceId,
      runtime,
    );
    expect(agentRes.status).toBe(201);
    const agent = ((await agentRes.json()) as { agent: { id: string } }).agent;

    const res = await callApi(
      `/agents/${agent.id}/grants`,
      token,
      "POST",
      {
        tool_name: "pact.brain.search",
        audience: "not-registered",
        scope: {},
        on_behalf_of_user_id: subjectId,
      },
      created.workspaceId,
      runtime,
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("unknown_audience");
  });

  it("returns 404 when creating a grant for an unknown agent", async () => {
    const { env, created, token, subjectId } = await setup();
    const runtime = {
      DATABASE_URL: env.DATABASE_URL,
      MEK: env.MEK,
      ADMIN_AUDIENCE: env.ADMIN_AUDIENCE,
    };
    const fakeAgentId = "11111111-1111-4111-8111-111111111111";
    const res = await callApi(
      `/agents/${fakeAgentId}/grants`,
      token,
      "POST",
      {
        tool_name: "pact.brain.search",
        audience: "pact-mcp",
        scope: {},
        on_behalf_of_user_id: subjectId,
      },
      created.workspaceId,
      runtime,
    );
    expect(res.status).toBe(404);
  });

  it("rejects requests with no admin token as 401", async () => {
    const res = await app.request(
      "/v1/workspaces/11111111-1111-4111-8111-111111111111/agents",
      { method: "GET" },
      {
        DATABASE_URL: url as string,
        MEK: "unused",
        ISSUER_BASE_URL: "https://issuer.test/acme",
        ADMIN_AUDIENCE: "pact-admin",
      },
    );
    expect(res.status).toBe(401);
  });

  it("rejects non-admin role with 403", async () => {
    const { env, created, pubkeyJwk } = await setup();
    const runtime = {
      DATABASE_URL: env.DATABASE_URL,
      MEK: env.MEK,
      ADMIN_AUDIENCE: env.ADMIN_AUDIENCE,
    };
    const nonAdminToken = await issueTestToken(issuer, env, {
      workspaceId: created.workspaceId,
      email: "bob@example.com",
      audience: env.ADMIN_AUDIENCE,
    });
    const res = await callApi(
      "/agents",
      nonAdminToken.token,
      "POST",
      { name: "noop", owner_user_id: created.adminUserId, pubkey_jwk: pubkeyJwk },
      created.workspaceId,
      runtime,
    );
    expect(res.status).toBe(403);
  });

  it("persists grant expires_at and rejects mint after it lapses", async () => {
    const { env, created, token, subjectId, pubkeyJwk } = await setup();
    const runtime = {
      DATABASE_URL: env.DATABASE_URL,
      MEK: env.MEK,
      ADMIN_AUDIENCE: env.ADMIN_AUDIENCE,
    };

    const agentRes = await callApi(
      "/agents",
      token,
      "POST",
      { name: "ttl-bot", owner_user_id: created.adminUserId, pubkey_jwk: pubkeyJwk },
      created.workspaceId,
      runtime,
    );
    expect(agentRes.status).toBe(201);
    const agent = ((await agentRes.json()) as { agent: { id: string } }).agent;

    const future = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    const grantRes = await callApi(
      `/agents/${agent.id}/grants`,
      token,
      "POST",
      {
        tool_name: "pact.brain.search",
        audience: "pact-mcp",
        scope: { group_in: ["eng"] },
        on_behalf_of_user_id: subjectId,
        expires_at: future,
      },
      created.workspaceId,
      runtime,
    );
    expect(grantRes.status).toBe(201);
    const grant = ((await grantRes.json()) as { grant: { id: string; expires_at: string } }).grant;
    expect(grant.expires_at).toBe(future);

    const stored = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx
        .select({ expiresAt: agentCapabilityGrants.expiresAt })
        .from(agentCapabilityGrants)
        .where(
          and(
            eq(agentCapabilityGrants.workspaceId, created.workspaceId),
            eq(agentCapabilityGrants.id, grant.id),
          ),
        ),
    );
    expect(stored[0]?.expiresAt).not.toBeNull();
    expect(stored[0]?.expiresAt?.toISOString()).toBe(future);

    await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx.execute(
        sql`UPDATE agent_capability_grants
            SET expires_at = NOW() - INTERVAL '1 minute'
            WHERE workspace_id = ${created.workspaceId}::uuid
              AND id = ${grant.id}::uuid`,
      ),
    );

    const subjectRow = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx.select({ email: users.email }).from(users).where(eq(users.id, subjectId)),
    );
    const subjectEmail = subjectRow[0]?.email as string;

    const recipient = await generateEd25519Keypair();
    const cnfJwk = await exportEd25519Jwk(recipient.publicKey);

    const mintRes = await issuer.request(
      `/v1/agents/${agent.id}/capabilities`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          on_behalf_of: subjectEmail,
          tool_name: "pact.brain.search",
          scope: { group_in: ["eng"] },
          audience: "pact-mcp",
          cnf_jwk: cnfJwk,
        }),
      },
      { ...runtime, ISSUER_BASE_URL: "https://issuer.test/acme", ENVIRONMENT: "test" },
    );
    expect(mintRes.status).toBe(403);
    const mintBody = (await mintRes.json()) as { error: string };
    expect(mintBody.error).toBe("grant_expired");
  });

  it("isolates agents across tenants via RLS", async () => {
    const a = await setup();
    const b = await setup();
    const runtimeA = {
      DATABASE_URL: a.env.DATABASE_URL,
      MEK: a.env.MEK,
      ADMIN_AUDIENCE: a.env.ADMIN_AUDIENCE,
    };
    const runtimeB = {
      DATABASE_URL: b.env.DATABASE_URL,
      MEK: b.env.MEK,
      ADMIN_AUDIENCE: b.env.ADMIN_AUDIENCE,
    };
    const mintA = await callApi(
      "/agents",
      a.token,
      "POST",
      { name: "alpha", owner_user_id: a.created.adminUserId, pubkey_jwk: a.pubkeyJwk },
      a.created.workspaceId,
      runtimeA,
    );
    expect(mintA.status).toBe(201);

    const listB = await callApi(
      "/agents",
      b.token,
      "GET",
      undefined,
      b.created.workspaceId,
      runtimeB,
    );
    const listedB = (await listB.json()) as { agents: Array<{ id: string }> };
    expect(listedB.agents).toHaveLength(0);
  });
});
