import { exportAesKey, generateAesKey, toBase64 } from "@getpact/crypto";
import { createClient, withWorkspace } from "@getpact/db";
import { auditEvents, workspaces } from "@getpact/db/schema";
import { and, eq } from "drizzle-orm";
import { afterEach, describe, expect, it, vi } from "vitest";
import issuer from "../../../../apps/issuer/src/index.js";
import type { KVNamespace } from "../cache.js";
import app from "../index.js";

const url = process.env.DATABASE_URL;
const run = url ? describe : describe.skip;

const tokenWithBadHeader = (claims: Record<string, unknown>) =>
  [
    Buffer.from("not json").toString("base64url"),
    Buffer.from(JSON.stringify(claims)).toString("base64url"),
    "sig",
  ].join(".");

describe("admin api auth hardening", () => {
  it("rejects malformed token headers as unauthorized", async () => {
    const workspaceId = "00000000-0000-0000-0000-000000000000";
    const token = tokenWithBadHeader({
      org: workspaceId,
      sub: "user-1",
      scopes: ["admin"],
    });
    const res = await app.request(
      `/v1/workspaces/${workspaceId}/users`,
      { method: "GET", headers: { Authorization: `Bearer ${token}` } },
      {
        DATABASE_URL: "postgres://unused",
        MEK: "unused",
        ISSUER_BASE_URL: "https://issuer.test/acme",
        ADMIN_AUDIENCE: "pact-admin",
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
  };
};

run("admin api", () => {
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
    const slug = `adm-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const createRes = await issuer.request(
      "/v1/workspaces",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ slug, name: "Adm", adminEmail: "alice@example.com" }),
      },
      env,
    );
    const created = (await createRes.json()) as { workspaceId: string };
    cleanup.push(created.workspaceId);

    const issueRes = await issuer.request(
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
    const issued = (await issueRes.json()) as { token: string };
    return { env, created, token: issued.token };
  };

  const callAdmin = async (
    path: string,
    token: string,
    method: "GET" | "POST",
    body: unknown,
    env: Record<string, unknown>,
  ) => {
    const init: RequestInit = {
      method,
      headers: { "content-type": "application/json", Authorization: `Bearer ${token}` },
    };
    if (method === "POST") init.body = JSON.stringify(body);
    return app.request(path, init, {
      ISSUER_BASE_URL: "https://issuer.test/acme",
      ...env,
    });
  };

  it("rejects without admin role", async () => {
    const { env } = await setup();
    const res = await app.request(
      `/v1/workspaces/${"00000000-0000-0000-0000-000000000000"}/users`,
      { method: "GET" },
      { DATABASE_URL: env.DATABASE_URL, MEK: env.MEK, ADMIN_AUDIENCE: env.ADMIN_AUDIENCE },
    );
    expect(res.status).toBe(401);
  });

  it("creates a user and lists it", async () => {
    const { env, created, token } = await setup();
    const create = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/users`,
      token,
      "POST",
      { email: "BOB@example.com", name: "Bob" },
      { DATABASE_URL: env.DATABASE_URL, MEK: env.MEK, ADMIN_AUDIENCE: env.ADMIN_AUDIENCE },
    );
    expect(create.status).toBe(201);
    const createdUser = (await create.json()) as { user: { id: string; email: string } };
    expect(createdUser.user.email).toBe("bob@example.com");

    const list = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/users`,
      token,
      "GET",
      undefined,
      { DATABASE_URL: env.DATABASE_URL, MEK: env.MEK, ADMIN_AUDIENCE: env.ADMIN_AUDIENCE },
    );
    const body = (await list.json()) as { users: Array<{ email: string }> };
    const emails = body.users.map((u) => u.email);
    expect(emails).toContain("alice@example.com");
    expect(emails).toContain("bob@example.com");
  });

  it("creates a group and adds a member", async () => {
    const { env, created, token } = await setup();
    const userRes = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/users`,
      token,
      "POST",
      { email: "carol@example.com" },
      { DATABASE_URL: env.DATABASE_URL, MEK: env.MEK, ADMIN_AUDIENCE: env.ADMIN_AUDIENCE },
    );
    const user = ((await userRes.json()) as { user: { id: string } }).user;

    const groupRes = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/groups`,
      token,
      "POST",
      { name: "eng" },
      { DATABASE_URL: env.DATABASE_URL, MEK: env.MEK, ADMIN_AUDIENCE: env.ADMIN_AUDIENCE },
    );
    const group = ((await groupRes.json()) as { group: { id: string } }).group;

    const memberRes = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/groups/${group.id}/members`,
      token,
      "POST",
      { userId: user.id },
      { DATABASE_URL: env.DATABASE_URL, MEK: env.MEK, ADMIN_AUDIENCE: env.ADMIN_AUDIENCE },
    );
    expect(memberRes.status).toBe(201);
  });

  it("creates a policy version and supersedes the previous", async () => {
    const { env, created, token } = await setup();

    const v1 = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/policies`,
      token,
      "POST",
      {
        body: { rules: [{ subject: { kind: "role", value: "admin" }, effect: "allow" }] },
      },
      { DATABASE_URL: env.DATABASE_URL, MEK: env.MEK, ADMIN_AUDIENCE: env.ADMIN_AUDIENCE },
    );
    expect(v1.status).toBe(201);
    const a = (await v1.json()) as { policy: { version: number } };
    expect(a.policy.version).toBe(1);

    const v2 = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/policies`,
      token,
      "POST",
      {
        body: {
          rules: [{ subject: { kind: "role", value: "admin" }, effect: "allow", action: "read" }],
        },
      },
      { DATABASE_URL: env.DATABASE_URL, MEK: env.MEK, ADMIN_AUDIENCE: env.ADMIN_AUDIENCE },
    );
    const b = (await v2.json()) as { policy: { version: number } };
    expect(b.policy.version).toBe(2);

    const list = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/policies`,
      token,
      "GET",
      undefined,
      { DATABASE_URL: env.DATABASE_URL, MEK: env.MEK, ADMIN_AUDIENCE: env.ADMIN_AUDIENCE },
    );
    const listed = (await list.json()) as {
      policies: Array<{ version: number; replacedAt: string | null }>;
    };
    expect(listed.policies.length).toBe(2);
    const v1Row = listed.policies.find((p) => p.version === 1);
    expect(v1Row?.replacedAt).not.toBeNull();
  });

  it("serializes concurrent policy creation", async () => {
    const { env, created, token } = await setup();
    const request = (action: string) =>
      callAdmin(
        `/v1/workspaces/${created.workspaceId}/policies`,
        token,
        "POST",
        {
          body: {
            rules: [{ subject: { kind: "role", value: "admin" }, effect: "allow", action }],
          },
        },
        { DATABASE_URL: env.DATABASE_URL, MEK: env.MEK, ADMIN_AUDIENCE: env.ADMIN_AUDIENCE },
      );

    const [a, b] = await Promise.all([request("read"), request("write")]);
    expect([a.status, b.status].sort()).toEqual([201, 201]);

    const list = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/policies`,
      token,
      "GET",
      undefined,
      { DATABASE_URL: env.DATABASE_URL, MEK: env.MEK, ADMIN_AUDIENCE: env.ADMIN_AUDIENCE },
    );
    const listed = (await list.json()) as {
      policies: Array<{ version: number; replacedAt: string | null }>;
    };
    expect(listed.policies.map((p) => p.version).sort()).toEqual([1, 2]);
    expect(listed.policies.filter((p) => p.replacedAt === null)).toHaveLength(1);
  });

  it("revokes a jti", async () => {
    const { env, created, token } = await setup();
    const res = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/revocations`,
      token,
      "POST",
      { jti: "test-jti-123", reason: "incident" },
      { DATABASE_URL: env.DATABASE_URL, MEK: env.MEK, ADMIN_AUDIENCE: env.ADMIN_AUDIENCE },
    );
    expect(res.status).toBe(201);
  });

  it("emits an audit event when a user is created", async () => {
    const { env, created, token } = await setup();
    await callAdmin(
      `/v1/workspaces/${created.workspaceId}/users`,
      token,
      "POST",
      { email: "audit-target@example.com" },
      { DATABASE_URL: env.DATABASE_URL, MEK: env.MEK, ADMIN_AUDIENCE: env.ADMIN_AUDIENCE },
    );
    const events = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx
        .select()
        .from(auditEvents)
        .where(
          and(
            eq(auditEvents.workspaceId, created.workspaceId),
            eq(auditEvents.action, "admin.user.created"),
          ),
        ),
    );
    expect(events.length).toBeGreaterThan(0);
    expect(events[0]?.actorKind).toBe("admin");
    expect(events[0]?.decision).toBe("allow");
  });

  it("busts the kv revocation cache when a jti is revoked", async () => {
    const { env, created, token } = await setup();
    const putMock = vi.fn(async () => {});
    const kv: KVNamespace = { put: putMock };

    const res = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/revocations`,
      token,
      "POST",
      { jti: "kv-bust-jti-1", reason: "key leak" },
      {
        ISSUER_BASE_URL: env.ISSUER_BASE_URL,
        DATABASE_URL: env.DATABASE_URL,
        MEK: env.MEK,
        ADMIN_AUDIENCE: env.ADMIN_AUDIENCE,
        REVOCATION_CACHE: kv,
      },
    );
    expect(res.status).toBe(201);
    expect(putMock).toHaveBeenCalledWith(`rev:${created.workspaceId}:kv-bust-jti-1`, "revoked", {
      expirationTtl: 60,
    });
  });

  it("rejects invalid policy bodies", async () => {
    const { env, created, token } = await setup();
    const res = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/policies`,
      token,
      "POST",
      { body: { rules: "not-an-array" } },
      {
        DATABASE_URL: env.DATABASE_URL,
        MEK: env.MEK,
        ISSUER_BASE_URL: env.ISSUER_BASE_URL,
        ADMIN_AUDIENCE: env.ADMIN_AUDIENCE,
      },
    );
    expect(res.status).toBe(400);
  });
});
