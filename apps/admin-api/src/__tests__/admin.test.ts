import { exportAesKey, generateAesKey, toBase64 } from "@getpact/crypto";
import { createClient } from "@getpact/db";
import { workspaces } from "@getpact/db/schema";
import { eq } from "drizzle-orm";
import { afterEach, describe, expect, it } from "vitest";
import issuer from "../../../../apps/issuer/src/index.js";
import app from "../index.js";

const url = process.env.DATABASE_URL;
const run = url ? describe : describe.skip;

const buildEnv = async () => {
  const mek = await generateAesKey();
  return {
    DATABASE_URL: url as string,
    MEK: toBase64(await exportAesKey(mek)),
    GOOGLE_OAUTH_CLIENT_ID: "test",
    GOOGLE_OAUTH_CLIENT_SECRET: "test",
    ISSUER_BASE_URL: "https://issuer.test/acme",
    ENVIRONMENT: "test",
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
    env: { DATABASE_URL: string },
  ) => {
    const init: RequestInit = {
      method,
      headers: { "content-type": "application/json", Authorization: `Bearer ${token}` },
    };
    if (method === "POST") init.body = JSON.stringify(body);
    return app.request(path, init, env);
  };

  it("rejects without admin role", async () => {
    const { env } = await setup();
    const res = await app.request(
      `/v1/workspaces/${"00000000-0000-0000-0000-000000000000"}/users`,
      { method: "GET" },
      { DATABASE_URL: env.DATABASE_URL, ADMIN_AUDIENCE: env.ADMIN_AUDIENCE },
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
      { DATABASE_URL: env.DATABASE_URL, ADMIN_AUDIENCE: env.ADMIN_AUDIENCE },
    );
    expect(create.status).toBe(201);
    const createdUser = (await create.json()) as { user: { id: string; email: string } };
    expect(createdUser.user.email).toBe("bob@example.com");

    const list = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/users`,
      token,
      "GET",
      undefined,
      { DATABASE_URL: env.DATABASE_URL, ADMIN_AUDIENCE: env.ADMIN_AUDIENCE },
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
      { DATABASE_URL: env.DATABASE_URL, ADMIN_AUDIENCE: env.ADMIN_AUDIENCE },
    );
    const user = ((await userRes.json()) as { user: { id: string } }).user;

    const groupRes = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/groups`,
      token,
      "POST",
      { name: "eng" },
      { DATABASE_URL: env.DATABASE_URL, ADMIN_AUDIENCE: env.ADMIN_AUDIENCE },
    );
    const group = ((await groupRes.json()) as { group: { id: string } }).group;

    const memberRes = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/groups/${group.id}/members`,
      token,
      "POST",
      { userId: user.id },
      { DATABASE_URL: env.DATABASE_URL, ADMIN_AUDIENCE: env.ADMIN_AUDIENCE },
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
      { DATABASE_URL: env.DATABASE_URL, ADMIN_AUDIENCE: env.ADMIN_AUDIENCE },
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
      { DATABASE_URL: env.DATABASE_URL, ADMIN_AUDIENCE: env.ADMIN_AUDIENCE },
    );
    const b = (await v2.json()) as { policy: { version: number } };
    expect(b.policy.version).toBe(2);

    const list = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/policies`,
      token,
      "GET",
      undefined,
      { DATABASE_URL: env.DATABASE_URL, ADMIN_AUDIENCE: env.ADMIN_AUDIENCE },
    );
    const listed = (await list.json()) as {
      policies: Array<{ version: number; replacedAt: string | null }>;
    };
    expect(listed.policies.length).toBe(2);
    const v1Row = listed.policies.find((p) => p.version === 1);
    expect(v1Row?.replacedAt).not.toBeNull();
  });

  it("revokes a jti", async () => {
    const { env, created, token } = await setup();
    const res = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/revocations`,
      token,
      "POST",
      { jti: "test-jti-123", reason: "incident" },
      { DATABASE_URL: env.DATABASE_URL, ADMIN_AUDIENCE: env.ADMIN_AUDIENCE },
    );
    expect(res.status).toBe(201);
  });

  it("rejects invalid policy bodies", async () => {
    const { env, created, token } = await setup();
    const res = await callAdmin(
      `/v1/workspaces/${created.workspaceId}/policies`,
      token,
      "POST",
      { body: { rules: "not-an-array" } },
      { DATABASE_URL: env.DATABASE_URL, ADMIN_AUDIENCE: env.ADMIN_AUDIENCE },
    );
    expect(res.status).toBe(400);
  });
});
