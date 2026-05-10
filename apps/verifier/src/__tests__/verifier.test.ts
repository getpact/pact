import { exportAesKey, generateAesKey, toBase64 } from "@getpact/crypto";
import { createClient, type DbClient, withWorkspace } from "@getpact/db";
import { auditEvents, policies, revokedJtis, workspaces } from "@getpact/db/schema";
import { and, eq } from "drizzle-orm";
import { afterEach, describe, expect, it, vi } from "vitest";
import issuer from "../../../../apps/issuer/src/index.js";
import { type KVNamespace } from "../cache.js";
import app from "../index.js";

type KvSpy = {
  binding: KVNamespace;
  store: Map<string, string>;
  getMock: ReturnType<typeof vi.fn>;
  putMock: ReturnType<typeof vi.fn>;
};

const buildKvMock = (): KvSpy => {
  const store = new Map<string, string>();
  const getMock = vi.fn(async (key: string) => store.get(key) ?? null);
  const putMock = vi.fn(async (key: string, value: string) => {
    store.set(key, value);
  });
  return {
    binding: { get: getMock, put: putMock } as unknown as KVNamespace,
    store,
    getMock,
    putMock,
  };
};

const url = process.env.DATABASE_URL;
const run = url ? describe : describe.skip;

const buildEnv = async () => {
  const mek = await generateAesKey();
  const rawMek = await exportAesKey(mek);
  return {
    DATABASE_URL: url as string,
    MEK: toBase64(rawMek),
    GOOGLE_OAUTH_CLIENT_ID: "test",
    GOOGLE_OAUTH_CLIENT_SECRET: "test",
    ISSUER_BASE_URL: "https://issuer.test/acme",
    ENVIRONMENT: "test",
  };
};

run("verifier", () => {
  const cleanup: string[] = [];
  let db: DbClient;

  if (url) {
    db = createClient(url);
  }

  afterEach(async () => {
    while (cleanup.length > 0) {
      const id = cleanup.pop();
      if (!id) continue;
      try {
        await db.delete(workspaces).where(eq(workspaces.id, id));
      } catch {
        // ignore
      }
    }
  });

  const setupWorkspace = async () => {
    const env = await buildEnv();
    const slug = `vrf-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const createRes = await issuer.request(
      "/v1/workspaces",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ slug, name: "Vrf", adminEmail: "alice@example.com" }),
      },
      env,
    );
    const created = (await createRes.json()) as {
      workspaceId: string;
      adminUserId: string;
    };
    cleanup.push(created.workspaceId);

    const issueRes = await issuer.request(
      "/v1/dev/issue",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          workspaceId: created.workspaceId,
          email: "alice@example.com",
          audience: "pact-mcp",
        }),
      },
      env,
    );
    const issued = (await issueRes.json()) as { token: string; jti: string };
    return { env, created, issued };
  };

  const insertPolicy = async (workspaceId: string, adminUserId: string, body: unknown) => {
    await withWorkspace(db, workspaceId, (tx) =>
      tx.insert(policies).values({ workspaceId, version: 1, body, createdBy: adminUserId }),
    );
  };

  it("denies when no policy exists", async () => {
    const { env, issued } = await setupWorkspace();
    const res = await app.request(
      "/v1/verify",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          token: issued.token,
          action: "read",
          resource: "doc:any",
          audience: "pact-mcp",
        }),
      },
      { DATABASE_URL: env.DATABASE_URL, MEK: env.MEK },
    );
    expect(res.status).toBe(403);
    const body = (await res.json()) as { allow: boolean; reasons: string[] };
    expect(body.allow).toBe(false);
    expect(body.reasons).toContain("no active policy");
  });

  it("allows when policy grants admin access", async () => {
    const { env, created, issued } = await setupWorkspace();
    await insertPolicy(created.workspaceId, created.adminUserId, {
      rules: [{ subject: { kind: "role", value: "admin" }, effect: "allow" }],
    });

    const res = await app.request(
      "/v1/verify",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          token: issued.token,
          action: "read",
          resource: "doc:any",
          audience: "pact-mcp",
        }),
      },
      { DATABASE_URL: env.DATABASE_URL, MEK: env.MEK },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { allow: boolean };
    expect(body.allow).toBe(true);
  });

  it("denies revoked tokens", async () => {
    const { env, created, issued } = await setupWorkspace();
    await insertPolicy(created.workspaceId, created.adminUserId, {
      rules: [{ subject: { kind: "role", value: "admin" }, effect: "allow" }],
    });

    await withWorkspace(db, created.workspaceId, (tx) =>
      tx.insert(revokedJtis).values({
        workspaceId: created.workspaceId,
        jti: issued.jti,
        reason: "test",
      }),
    );

    const res = await app.request(
      "/v1/verify",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          token: issued.token,
          action: "read",
          resource: "doc:any",
          audience: "pact-mcp",
        }),
      },
      { DATABASE_URL: env.DATABASE_URL, MEK: env.MEK },
    );
    expect(res.status).toBe(403);
    const body = (await res.json()) as { allow: boolean; reasons: string[] };
    expect(body.reasons).toContain("token revoked");
  });

  it("emits an audit event for an allowed decision", async () => {
    const { env, created, issued } = await setupWorkspace();
    await insertPolicy(created.workspaceId, created.adminUserId, {
      rules: [{ subject: { kind: "role", value: "admin" }, effect: "allow" }],
    });

    await app.request(
      "/v1/verify",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          token: issued.token,
          action: "read",
          resource: "doc:abc",
          audience: "pact-mcp",
        }),
      },
      { DATABASE_URL: env.DATABASE_URL, MEK: env.MEK },
    );

    const events = await withWorkspace(db, created.workspaceId, (tx) =>
      tx
        .select()
        .from(auditEvents)
        .where(
          and(
            eq(auditEvents.workspaceId, created.workspaceId),
            eq(auditEvents.action, "verify.read"),
          ),
        ),
    );
    expect(events.length).toBeGreaterThan(0);
    expect(events[0]?.decision).toBe("allow");
  });

  it("emits audit event on revoked token deny", async () => {
    const { env, created, issued } = await setupWorkspace();
    await insertPolicy(created.workspaceId, created.adminUserId, {
      rules: [{ subject: { kind: "role", value: "admin" }, effect: "allow" }],
    });
    await withWorkspace(db, created.workspaceId, (tx) =>
      tx.insert(revokedJtis).values({
        workspaceId: created.workspaceId,
        jti: issued.jti,
        reason: "test",
      }),
    );

    await app.request(
      "/v1/verify",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          token: issued.token,
          action: "delete",
          resource: "doc:critical",
          audience: "pact-mcp",
        }),
      },
      { DATABASE_URL: env.DATABASE_URL, MEK: env.MEK },
    );

    const events = await withWorkspace(db, created.workspaceId, (tx) =>
      tx
        .select()
        .from(auditEvents)
        .where(
          and(
            eq(auditEvents.workspaceId, created.workspaceId),
            eq(auditEvents.action, "verify.delete"),
          ),
        ),
    );
    expect(events.length).toBeGreaterThan(0);
    expect(events[0]?.decision).toBe("deny");
    const supporting = events[0]?.supporting as { reasons: string[] };
    expect(supporting.reasons).toContain("token revoked");
  });

  it("emits audit event on no-policy deny", async () => {
    const { env, created, issued } = await setupWorkspace();

    await app.request(
      "/v1/verify",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          token: issued.token,
          action: "list",
          resource: "doc:any",
          audience: "pact-mcp",
        }),
      },
      { DATABASE_URL: env.DATABASE_URL, MEK: env.MEK },
    );

    const events = await withWorkspace(db, created.workspaceId, (tx) =>
      tx
        .select()
        .from(auditEvents)
        .where(
          and(
            eq(auditEvents.workspaceId, created.workspaceId),
            eq(auditEvents.action, "verify.list"),
          ),
        ),
    );
    expect(events.length).toBeGreaterThan(0);
    expect(events[0]?.decision).toBe("deny");
    const supporting = events[0]?.supporting as { reasons: string[] };
    expect(supporting.reasons).toContain("no active policy");
  });

  it("uses revocation cache for second verify of same jti", async () => {
    const { env, created, issued } = await setupWorkspace();
    await insertPolicy(created.workspaceId, created.adminUserId, {
      rules: [{ subject: { kind: "role", value: "admin" }, effect: "allow" }],
    });
    const kv = buildKvMock();
    const envWithKv = {
      DATABASE_URL: env.DATABASE_URL,
      MEK: env.MEK,
      REVOCATION_CACHE: kv.binding,
    };

    const callBody = JSON.stringify({
      token: issued.token,
      action: "read",
      resource: "doc:any",
      audience: "pact-mcp",
    });

    const a = await app.request(
      "/v1/verify",
      { method: "POST", headers: { "content-type": "application/json" }, body: callBody },
      envWithKv,
    );
    expect(a.status).toBe(200);
    expect(kv.putMock).toHaveBeenCalled();

    const putCallsAfterFirst = kv.putMock.mock.calls.length;

    const b = await app.request(
      "/v1/verify",
      { method: "POST", headers: { "content-type": "application/json" }, body: callBody },
      envWithKv,
    );
    expect(b.status).toBe(200);
    expect(kv.getMock).toHaveBeenCalledTimes(2);
    expect(kv.putMock.mock.calls.length).toBe(putCallsAfterFirst);
  });

  it("rejects malformed token", async () => {
    const env = { DATABASE_URL: url as string, MEK: "" };
    const res = await app.request(
      "/v1/verify",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          token: "not.a.jwt",
          action: "read",
          resource: "doc:any",
          audience: "pact-mcp",
        }),
      },
      env,
    );
    expect(res.status).toBe(403);
  });
});
