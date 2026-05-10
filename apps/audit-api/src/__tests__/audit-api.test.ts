import { exportAesKey, generateAesKey, toBase64 } from "@getpact/crypto";
import { createClient } from "@getpact/db";
import { workspaces } from "@getpact/db/schema";
import { eq } from "drizzle-orm";
import { afterEach, describe, expect, it } from "vitest";
import adminApp from "../../../../apps/admin-api/src/index.js";
import issuer from "../../../../apps/issuer/src/index.js";
import app from "../index.js";

const url = process.env.DATABASE_URL;
const run = url ? describe : describe.skip;

const tokenWithBadHeader = (claims: Record<string, unknown>) =>
  [
    Buffer.from("not json").toString("base64url"),
    Buffer.from(JSON.stringify(claims)).toString("base64url"),
    "sig",
  ].join(".");

describe("audit api auth hardening", () => {
  it("rejects malformed token headers as unauthorized", async () => {
    const workspaceId = "00000000-0000-0000-0000-000000000000";
    const token = tokenWithBadHeader({
      org: workspaceId,
      sub: "user-1",
      scopes: ["auditor"],
    });
    const res = await app.request(
      `/v1/workspaces/${workspaceId}/audit/events`,
      { method: "GET", headers: { Authorization: `Bearer ${token}` } },
      {
        DATABASE_URL: "postgres://unused",
        ISSUER_BASE_URL: "https://issuer.test/acme",
        AUDIT_AUDIENCE: "pact-audit",
      },
    );
    expect(res.status).toBe(401);
  });
});

const buildEnv = async () => {
  const mek = await generateAesKey();
  return {
    DATABASE_URL: url as string,
    MEK: toBase64(await exportAesKey(mek)),
    GOOGLE_OAUTH_CLIENT_ID: "test",
    GOOGLE_OAUTH_CLIENT_SECRET: "test",
    ISSUER_BASE_URL: "https://issuer.test/acme",
    ENVIRONMENT: "test",
    ENABLE_DEV_ISSUE: "true",
    ADMIN_AUDIENCE: "pact-admin",
    AUDIT_AUDIENCE: "pact-audit",
  };
};

run("audit api", () => {
  const adminDb = createClient(url as string);
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
    const env = await buildEnv();
    const slug = `aud-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const createRes = await issuer.request(
      "/v1/workspaces",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ slug, name: "Aud", adminEmail: "alice@example.com" }),
      },
      env,
    );
    const created = (await createRes.json()) as { workspaceId: string };
    cleanup.push(created.workspaceId);

    const adminTokenRes = await issuer.request(
      "/v1/dev/issue",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          workspaceId: created.workspaceId,
          email: "alice@example.com",
          audience: "pact-admin",
        }),
      },
      env,
    );
    const auditTokenRes = await issuer.request(
      "/v1/dev/issue",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          workspaceId: created.workspaceId,
          email: "alice@example.com",
          audience: "pact-audit",
        }),
      },
      env,
    );
    const adminToken = ((await adminTokenRes.json()) as { token: string }).token;
    const auditToken = ((await auditTokenRes.json()) as { token: string }).token;

    // Generate a few audit events via admin user.created.
    for (const email of ["a@example.com", "b@example.com", "c@example.com"]) {
      await adminApp.request(
        `/v1/workspaces/${created.workspaceId}/users`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            Authorization: `Bearer ${adminToken}`,
          },
          body: JSON.stringify({ email }),
        },
        {
          DATABASE_URL: env.DATABASE_URL,
          MEK: env.MEK,
          ISSUER_BASE_URL: env.ISSUER_BASE_URL,
          ADMIN_AUDIENCE: env.ADMIN_AUDIENCE,
        },
      );
    }

    return { env, created, auditToken };
  };

  const auditEnv = (env: Record<string, unknown>) => ({
    DATABASE_URL: env.DATABASE_URL,
    ISSUER_BASE_URL: env.ISSUER_BASE_URL,
    AUDIT_AUDIENCE: env.AUDIT_AUDIENCE,
  });

  it("rejects without bearer token", async () => {
    const { created, env } = await setup();
    const res = await app.request(
      `/v1/workspaces/${created.workspaceId}/audit/events`,
      { method: "GET" },
      auditEnv(env),
    );
    expect(res.status).toBe(401);
  });

  it("lists audit events for a workspace", async () => {
    const { created, env, auditToken } = await setup();
    const res = await app.request(
      `/v1/workspaces/${created.workspaceId}/audit/events`,
      { method: "GET", headers: { Authorization: `Bearer ${auditToken}` } },
      auditEnv(env),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { events: Array<{ action: string }>; nextCursor: null };
    const actions = body.events.map((e) => e.action);
    expect(actions.filter((a) => a === "admin.user.created").length).toBeGreaterThanOrEqual(3);
  });

  it("filters events by action", async () => {
    const { created, env, auditToken } = await setup();
    const res = await app.request(
      `/v1/workspaces/${created.workspaceId}/audit/events?action=admin.user.created`,
      { method: "GET", headers: { Authorization: `Bearer ${auditToken}` } },
      auditEnv(env),
    );
    const body = (await res.json()) as { events: Array<{ action: string }> };
    expect(body.events.length).toBeGreaterThanOrEqual(3);
    expect(body.events.every((e) => e.action === "admin.user.created")).toBe(true);
  });

  it("paginates with cursor", async () => {
    const { created, env, auditToken } = await setup();
    const first = await app.request(
      `/v1/workspaces/${created.workspaceId}/audit/events?limit=2`,
      { method: "GET", headers: { Authorization: `Bearer ${auditToken}` } },
      auditEnv(env),
    );
    const firstBody = (await first.json()) as {
      events: Array<{ thisHash: string }>;
      nextCursor: string | null;
    };
    expect(firstBody.events.length).toBe(2);
    expect(firstBody.nextCursor).not.toBeNull();

    const second = await app.request(
      `/v1/workspaces/${created.workspaceId}/audit/events?limit=10&cursor=${encodeURIComponent(firstBody.nextCursor as string)}`,
      { method: "GET", headers: { Authorization: `Bearer ${auditToken}` } },
      auditEnv(env),
    );
    const secondBody = (await second.json()) as { events: Array<{ thisHash: string }> };
    const firstHashes = new Set(firstBody.events.map((e) => e.thisHash));
    expect(secondBody.events.every((e) => !firstHashes.has(e.thisHash))).toBe(true);
  });

  it("returns chain head", async () => {
    const { created, env, auditToken } = await setup();
    const res = await app.request(
      `/v1/workspaces/${created.workspaceId}/audit/chain`,
      { method: "GET", headers: { Authorization: `Bearer ${auditToken}` } },
      auditEnv(env),
    );
    const body = (await res.json()) as {
      head: { lastHash: string; lastEventId: string | null } | null;
    };
    expect(body.head).not.toBeNull();
    expect(body.head?.lastHash.length).toBeGreaterThan(0);
  });
});
