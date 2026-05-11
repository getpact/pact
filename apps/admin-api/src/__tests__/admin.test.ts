import { createClient, withWorkspace } from "@getpact/db";
import {
  auditEvents,
  brains,
  invites,
  policies,
  revokedJtis,
  users,
  vaultSecrets,
  workspaces,
} from "@getpact/db/schema";
import {
  buildTestEnv,
  createTestWorkspace,
  issueTestToken,
  uniqueSlug,
} from "@getpact/test-helpers";
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
      roles: ["admin"],
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
    const env = await buildTestEnv(url as string);
    const created = await createTestWorkspace(issuer, env, {
      slug: uniqueSlug("adm"),
      adminEmail: "alice@example.com",
    });
    cleanup.push(created.workspaceId);
    const issued = await issueTestToken(issuer, env, {
      workspaceId: created.workspaceId,
      email: "alice@example.com",
      audience: env.ADMIN_AUDIENCE,
    });
    return { env, created, token: issued.token };
  };

  const callAdmin = async (
    path: string,
    token: string,
    method: "DELETE" | "GET" | "POST" | "PUT",
    body: unknown,
    env: Record<string, unknown>,
  ) => {
    const init: RequestInit = {
      method,
      headers: { "content-type": "application/json", Authorization: `Bearer ${token}` },
    };
    if (body !== undefined) init.body = JSON.stringify(body);
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

  it("creates, lists, and deletes a gateway brain", async () => {
    const { env, created, token } = await setup();
    const runtime = {
      DATABASE_URL: env.DATABASE_URL,
      MEK: env.MEK,
      ADMIN_AUDIENCE: env.ADMIN_AUDIENCE,
    };
    const create = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/brains`,
      token,
      "POST",
      { kind: "notion", baseUrl: "https://api.example.com/base", authScheme: "bearer" },
      runtime,
    );
    expect(create.status).toBe(201);
    const createdBrain = (await create.json()) as { brain: { id: string; kind: string } };
    expect(createdBrain.brain.kind).toBe("notion");

    const duplicate = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/brains`,
      token,
      "POST",
      { kind: "notion", baseUrl: "https://api.example.com/other" },
      runtime,
    );
    expect(duplicate.status).toBe(409);

    const list = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/brains`,
      token,
      "GET",
      undefined,
      runtime,
    );
    const listed = (await list.json()) as { brains: Array<{ id: string; kind: string }> };
    expect(listed.brains.map((brain) => brain.kind)).toContain("notion");

    const credential = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/brains/${createdBrain.brain.id}/credential`,
      token,
      "PUT",
      { token: "xoxb-test" },
      runtime,
    );
    expect(credential.status).toBe(200);
    const stored = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx.select().from(vaultSecrets).where(eq(vaultSecrets.workspaceId, created.workspaceId)),
    );
    expect(stored).toHaveLength(1);
    expect(stored[0]?.target).toBe(createdBrain.brain.id);
    expect(stored[0]?.ciphertext).not.toContain("xoxb-test");

    const del = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/brains/${createdBrain.brain.id}`,
      token,
      "DELETE",
      undefined,
      runtime,
    );
    expect(del.status).toBe(200);

    const rows = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx.select().from(brains).where(eq(brains.workspaceId, created.workspaceId)),
    );
    expect(rows).toHaveLength(0);
    const secrets = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx.select().from(vaultSecrets).where(eq(vaultSecrets.workspaceId, created.workspaceId)),
    );
    expect(secrets).toHaveLength(0);
  });

  it("rejects unsafe gateway brain configuration", async () => {
    const { env, created, token } = await setup();
    const runtime = {
      DATABASE_URL: env.DATABASE_URL,
      MEK: env.MEK,
      ADMIN_AUDIENCE: env.ADMIN_AUDIENCE,
    };
    const unsafeHost = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/brains`,
      token,
      "POST",
      { kind: "local", baseUrl: "https://127.0.0.1:8443" },
      runtime,
    );
    expect(unsafeHost.status).toBe(400);

    const unsafeJson = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/brains`,
      token,
      "POST",
      {
        kind: "unsafe",
        baseUrl: "https://api.example.com",
        scopeInjectionTemplate: { constructor: { polluted: true } },
      },
      runtime,
    );
    expect(unsafeJson.status).toBe(400);

    const inertFilter = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/brains`,
      token,
      "POST",
      {
        kind: "filtered",
        baseUrl: "https://api.example.com",
        responseFilter: { allow: ["id"] },
      },
      runtime,
    );
    expect(inertFilter.status).toBe(400);
  });

  it("rejects http brain baseUrl", async () => {
    const { env, created, token } = await setup();
    const res = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/brains`,
      token,
      "POST",
      { kind: "insecure", baseUrl: "http://api.example.com" },
      { DATABASE_URL: env.DATABASE_URL, MEK: env.MEK, ADMIN_AUDIENCE: env.ADMIN_AUDIENCE },
    );
    expect(res.status).toBe(400);
  });

  it("rejects brain delete from a different workspace", async () => {
    const a = await setup();
    const b = await setup();
    const create = await callAdmin(
      `/v1/workspaces/${a.created.workspaceId}/brains`,
      a.token,
      "POST",
      { kind: "victim", baseUrl: "https://api.example.com" },
      { DATABASE_URL: a.env.DATABASE_URL, MEK: a.env.MEK, ADMIN_AUDIENCE: a.env.ADMIN_AUDIENCE },
    );
    const brain = (await create.json()) as { brain: { id: string } };
    const del = await callAdmin(
      `/v1/workspaces/${b.created.workspaceId}/brains/${brain.brain.id}`,
      b.token,
      "DELETE",
      undefined,
      { DATABASE_URL: b.env.DATABASE_URL, MEK: b.env.MEK, ADMIN_AUDIENCE: b.env.ADMIN_AUDIENCE },
    );
    expect(del.status).toBe(404);
  });

  it("rejects malformed gateway brain request bodies", async () => {
    const { env, created, token } = await setup();
    const runtime = {
      DATABASE_URL: env.DATABASE_URL,
      MEK: env.MEK,
      ADMIN_AUDIENCE: env.ADMIN_AUDIENCE,
    };
    const nullBody = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/brains`,
      token,
      "POST",
      null,
      runtime,
    );
    expect(nullBody.status).toBe(400);

    const invalidJson = await app.request(
      `/v1/workspaces/${created.workspaceId}/brains`,
      {
        method: "POST",
        headers: { "content-type": "application/json", Authorization: `Bearer ${token}` },
        body: "{",
      },
      {
        ISSUER_BASE_URL: "https://issuer.test/acme",
        DATABASE_URL: env.DATABASE_URL,
        MEK: env.MEK,
        ADMIN_AUDIENCE: env.ADMIN_AUDIENCE,
      },
    );
    expect(invalidJson.status).toBe(400);
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

  it("rolls back user creation when required audit cannot decrypt keys", async () => {
    const { env, created, token } = await setup();
    const res = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/users`,
      token,
      "POST",
      { email: "rollback-user@example.com" },
      {
        DATABASE_URL: env.DATABASE_URL,
        MEK: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ADMIN_AUDIENCE: env.ADMIN_AUDIENCE,
      },
    );
    expect(res.status).toBe(500);
    const rows = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx.select({ id: users.id }).from(users).where(eq(users.email, "rollback-user@example.com")),
    );
    expect(rows).toHaveLength(0);
  });

  it("rolls back revocation and skips cache bust when audit fails", async () => {
    const { env, created, token } = await setup();
    const putMock = vi.fn(async () => {});
    const kv: KVNamespace = { put: putMock };
    const res = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/revocations`,
      token,
      "POST",
      { jti: "rollback-jti-1", reason: "test" },
      {
        DATABASE_URL: env.DATABASE_URL,
        MEK: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ADMIN_AUDIENCE: env.ADMIN_AUDIENCE,
        REVOCATION_CACHE: kv,
      },
    );
    expect(res.status).toBe(500);
    expect(putMock).not.toHaveBeenCalled();
    const rows = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx
        .select({ jti: revokedJtis.jti })
        .from(revokedJtis)
        .where(eq(revokedJtis.jti, "rollback-jti-1")),
    );
    expect(rows).toHaveLength(0);
  });

  it("rolls back policy replacement when audit fails", async () => {
    const { env, created, token } = await setup();
    const runtime = {
      DATABASE_URL: env.DATABASE_URL,
      MEK: env.MEK,
      ADMIN_AUDIENCE: env.ADMIN_AUDIENCE,
    };
    const v1 = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/policies`,
      token,
      "POST",
      {
        body: { rules: [{ subject: { kind: "role", value: "admin" }, effect: "allow" }] },
      },
      runtime,
    );
    expect(v1.status).toBe(201);

    const failed = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/policies`,
      token,
      "POST",
      {
        body: {
          rules: [{ subject: { kind: "role", value: "admin" }, effect: "allow", action: "read" }],
        },
      },
      {
        ...runtime,
        MEK: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      },
    );
    expect(failed.status).toBe(500);

    const rows = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx
        .select({ version: policies.version, replacedAt: policies.replacedAt })
        .from(policies)
        .where(eq(policies.workspaceId, created.workspaceId)),
    );
    expect(rows).toEqual([{ version: 1, replacedAt: null }]);
    const events = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx
        .select({ action: auditEvents.action })
        .from(auditEvents)
        .where(
          and(
            eq(auditEvents.workspaceId, created.workspaceId),
            eq(auditEvents.action, "admin.policy.created"),
          ),
        ),
    );
    expect(events).toHaveLength(1);
  });

  it("rolls back invite creation when required audit fails", async () => {
    const { env, created, token } = await setup();
    const res = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/invites`,
      token,
      "POST",
      { email: "rollback-invite@example.com", scope: {}, ttl: "1d" },
      {
        DATABASE_URL: env.DATABASE_URL,
        MEK: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ADMIN_AUDIENCE: env.ADMIN_AUDIENCE,
      },
    );
    expect(res.status).toBe(500);
    const rows = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx
        .select({ id: invites.id })
        .from(invites)
        .where(eq(invites.email, "rollback-invite@example.com")),
    );
    expect(rows).toHaveLength(0);
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

  it("fails closed on invalid policy when audit cannot decrypt keys", async () => {
    const { env, created, token } = await setup();
    const res = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/policies`,
      token,
      "POST",
      { body: { rules: "not-an-array" } },
      {
        DATABASE_URL: env.DATABASE_URL,
        MEK: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ADMIN_AUDIENCE: env.ADMIN_AUDIENCE,
      },
    );

    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: "audit_unavailable" });
  });
});
