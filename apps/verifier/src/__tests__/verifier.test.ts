import { fromBase64, issueJwt } from "@getpact/crypto";
import { createClient, type DbClient, withWorkspace } from "@getpact/db";
import { auditEvents, policies, revokedJtis, workspaces } from "@getpact/db/schema";
import { loadActiveSigningKey } from "@getpact/keystore";
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
import app, { allowedAudiences } from "../index.js";

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

describe("verifier audience config", () => {
  it("defaults to the MCP audience only", () => {
    expect(allowedAudiences({})).toEqual(["pact-mcp"]);
  });

  it("parses the allowed audience list", () => {
    expect(allowedAudiences({ VERIFIER_AUDIENCES: "pact-mcp, pact-gateway" })).toEqual([
      "pact-mcp",
      "pact-gateway",
    ]);
  });

  it("rejects disallowed requested audiences before verification work", async () => {
    const res = await app.request(
      "/v1/verify",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          token: "unused",
          action: "gateway.get",
          resource: "gateway:notion:/v1/pages",
          audience: "pact-gateway",
        }),
      },
      {
        DATABASE_URL: "postgres://unused",
        MEK: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ISSUER_BASE_URL: "https://issuer.test",
        VERIFIER_AUDIENCES: "pact-mcp",
      },
    );

    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: "invalid_audience",
      message: "audience is not allowed",
    });
  });

  it("requires service auth when configured", async () => {
    const request = {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        token: "unused",
        action: "read",
        resource: "doc:any",
        audience: "pact-mcp",
      }),
    };
    const env = {
      DATABASE_URL: "postgres://unused",
      MEK: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      ISSUER_BASE_URL: "https://issuer.test",
      VERIFIER_SERVICE_TOKEN: "service-secret",
    };

    const missing = await app.request("/v1/verify", request, env);
    expect(missing.status).toBe(401);
    expect(await missing.json()).toEqual({
      error: "unauthorized",
      message: "invalid service token",
    });

    const allowed = await app.request(
      "/v1/verify",
      {
        ...request,
        headers: {
          "content-type": "application/json",
          authorization: "Bearer service-secret",
        },
      },
      { ...env, VERIFIER_AUDIENCES: "pact-other" },
    );
    expect(allowed.status).toBe(400);
    expect(await allowed.json()).toEqual({
      error: "invalid_audience",
      message: "audience is not allowed",
    });
  });

  it("fails closed in production when service auth is not configured", async () => {
    const res = await app.request(
      "/v1/verify",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          token: "unused",
          action: "read",
          resource: "doc:any",
          audience: "pact-mcp",
        }),
      },
      {
        DATABASE_URL: "postgres://unused",
        MEK: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ISSUER_BASE_URL: "https://issuer.test",
        ENVIRONMENT: "production",
      },
    );

    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({
      error: "misconfigured",
      message: "verifier service token is required",
    });
  });
});

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
    const env = await buildTestEnv(url as string);
    const created = await createTestWorkspace(issuer, env, {
      slug: uniqueSlug("vrf"),
      adminEmail: "alice@example.com",
    });
    cleanup.push(created.workspaceId);
    const issued = await issueTestToken(issuer, env, {
      workspaceId: created.workspaceId,
      email: "alice@example.com",
      audience: env.MCP_AUDIENCE,
    });
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
      { DATABASE_URL: env.DATABASE_URL, MEK: env.MEK, ISSUER_BASE_URL: env.ISSUER_BASE_URL },
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
      { DATABASE_URL: env.DATABASE_URL, MEK: env.MEK, ISSUER_BASE_URL: env.ISSUER_BASE_URL },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { allow: boolean };
    expect(body.allow).toBe(true);
  });

  it("allows Mode B gateway tokens on the gateway audience", async () => {
    const { env, created } = await setupWorkspace();
    await insertPolicy(created.workspaceId, created.adminUserId, {
      rules: [{ subject: { kind: "role", value: "admin" }, effect: "allow" }],
    });
    const issued = await issueTestToken(issuer, env, {
      workspaceId: created.workspaceId,
      email: "alice@example.com",
      audience: "pact-gateway",
    });

    const res = await app.request(
      "/v1/verify",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          token: issued.token,
          action: "gateway.get",
          resource: "gateway:notion:/v1/pages",
          audience: "pact-gateway",
        }),
      },
      {
        DATABASE_URL: env.DATABASE_URL,
        MEK: env.MEK,
        ISSUER_BASE_URL: env.ISSUER_BASE_URL,
        VERIFIER_AUDIENCES: "pact-mcp,pact-gateway",
      },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { allow: boolean };
    expect(body.allow).toBe(true);
  });

  it("rejects a gateway-audience token with the wrong mode", async () => {
    const { env, created } = await setupWorkspace();
    await insertPolicy(created.workspaceId, created.adminUserId, {
      rules: [{ subject: { kind: "role", value: "admin" }, effect: "allow" }],
    });
    const rawMek = fromBase64(env.MEK);
    const key = await withWorkspace(db, created.workspaceId, (tx) =>
      loadActiveSigningKey(tx, created.workspaceId, "jwt", rawMek),
    );
    const token = await issueJwt(
      {
        sub: created.adminUserId,
        email: "alice@example.com",
        org: created.workspaceId,
        roles: ["admin"],
        groups: [],
        mode: "A",
      },
      {
        privateKey: key.privateKey,
        kid: key.id,
        issuer: env.ISSUER_BASE_URL,
        audience: "pact-gateway",
        ttlSeconds: 900,
        jti: crypto.randomUUID(),
      },
    );

    const res = await app.request(
      "/v1/verify",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          token,
          action: "gateway.get",
          resource: "gateway:notion:/v1/pages",
          audience: "pact-gateway",
        }),
      },
      {
        DATABASE_URL: env.DATABASE_URL,
        MEK: env.MEK,
        ISSUER_BASE_URL: env.ISSUER_BASE_URL,
        VERIFIER_AUDIENCES: "pact-mcp,pact-gateway",
      },
    );
    expect(res.status).toBe(403);
    const body = (await res.json()) as { allow: boolean; reasons: string[] };
    expect(body.allow).toBe(false);
    expect(body.reasons).toContain("token mode mismatch");
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
      { DATABASE_URL: env.DATABASE_URL, MEK: env.MEK, ISSUER_BASE_URL: env.ISSUER_BASE_URL },
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
      { DATABASE_URL: env.DATABASE_URL, MEK: env.MEK, ISSUER_BASE_URL: env.ISSUER_BASE_URL },
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
      { DATABASE_URL: env.DATABASE_URL, MEK: env.MEK, ISSUER_BASE_URL: env.ISSUER_BASE_URL },
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
      { DATABASE_URL: env.DATABASE_URL, MEK: env.MEK, ISSUER_BASE_URL: env.ISSUER_BASE_URL },
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
      ISSUER_BASE_URL: env.ISSUER_BASE_URL,
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
    const env = {
      DATABASE_URL: url as string,
      MEK: "",
      ISSUER_BASE_URL: "https://issuer.test/acme",
    };
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
