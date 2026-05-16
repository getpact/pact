import { createClient, withWorkspace } from "@getpact/db";
import { agents, auditEvents, workspaces } from "@getpact/db/schema";
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

const seedAgent = async (
  adminDb: ReturnType<typeof createClient>,
  workspaceId: string,
  ownerUserId: string,
  input: { slug: string; status?: string; thumb: string },
): Promise<string> =>
  withWorkspace(adminDb, workspaceId, async (tx) => {
    const [row] = await tx
      .insert(agents)
      .values({
        workspaceId,
        slug: input.slug,
        displayName: `Agent ${input.slug}`,
        kind: "service",
        ownerUserId,
        pubkeyJwk: sampleAgentJwk,
        pubkeyThumbprint: input.thumb,
        status: input.status ?? "active",
      })
      .returning({ id: agents.id });
    if (!row) throw new Error("agent insert failed");
    return row.id;
  });

const callList = (query: string, token: string, env: Record<string, unknown>) =>
  app.request(
    `/v1/agents${query}`,
    {
      method: "GET",
      headers: { Authorization: `Bearer ${token}` },
    },
    env,
  );

run("agents list", () => {
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
      slug: uniqueSlug("list"),
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

  it("returns an empty list when the workspace has no agents", async () => {
    const { env, created, token } = await setup();
    const res = await callList(`?workspace_id=${created.workspaceId}`, token, env);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { agents: unknown[] };
    expect(body.agents).toEqual([]);

    const events = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx
        .select({ action: auditEvents.action })
        .from(auditEvents)
        .where(eq(auditEvents.workspaceId, created.workspaceId)),
    );
    expect(events.some((e) => e.action === "agent.list")).toBe(true);
  });

  it("filters by status", async () => {
    const { env, created, token } = await setup();
    const stamp = `${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const activeId = await seedAgent(adminDb, created.workspaceId, created.adminUserId, {
      slug: `active-${stamp}`,
      thumb: `t-active-${stamp}`,
    });
    await seedAgent(adminDb, created.workspaceId, created.adminUserId, {
      slug: `suspended-${stamp}`,
      thumb: `t-susp-${stamp}`,
      status: "suspended",
    });

    const res = await callList(`?workspace_id=${created.workspaceId}&status=active`, token, env);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      agents: Array<{ id: string; status: string; slug: string }>;
    };
    expect(body.agents.length).toBe(1);
    expect(body.agents[0]?.id).toBe(activeId);
    expect(body.agents[0]?.status).toBe("active");
  });

  it("denies cross-tenant access", async () => {
    const { env, created, token } = await setup();
    const other = await createTestWorkspace(app, env, {
      slug: uniqueSlug("other"),
      adminEmail: "bob@example.com",
    });
    cleanup.push(other.workspaceId);
    await seedAgent(adminDb, other.workspaceId, other.adminUserId, {
      slug: "other-agent",
      thumb: `t-other-${Date.now()}`,
    });

    const res = await callList(`?workspace_id=${other.workspaceId}`, token, env);
    // The token is for `created.workspaceId`; pointing it at `other.workspaceId`
    // must be rejected by the admin auth layer before any rows are returned.
    expect([401, 403]).toContain(res.status);
  });
});
