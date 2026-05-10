import { createClient, schema, withWorkspace } from "@getpact/db";
import { auditEvents, workspaces } from "@getpact/db/schema";
import {
  buildTestEnv,
  createTestWorkspace,
  issueTestToken,
  uniqueSlug,
} from "@getpact/test-helpers";
import { eq } from "drizzle-orm";
import { afterEach, describe, expect, it, vi } from "vitest";
import issuer from "../../../../apps/issuer/src/index.js";
import app, {
  buildGatewayTarget,
  forwardedRequestHeaders,
  gatewayAuthorization,
} from "../index.js";

const env = { ENVIRONMENT: "test" };
const url = process.env.DATABASE_URL;
const run = url ? describe : describe.skip;

describe("gateway", () => {
  it("returns health", async () => {
    const res = await app.request("/health", undefined, env);
    expect(res.status).toBe(200);
  });

  it("rejects gateway requests without bearer auth", async () => {
    const res = await app.request("/acme/gateway/notion/v1/pages", undefined, env);
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "unauthorized", message: "missing bearer token" });
  });

  it("sets security headers", async () => {
    const res = await app.request("/health", undefined, env);
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get("x-frame-options")).toBe("DENY");
    expect(res.headers.get("content-security-policy")).toContain("default-src 'none'");
  });

  it("builds gateway authorization from method, brain, and path", () => {
    expect(gatewayAuthorization("POST", "notion", "v1/pages")).toEqual({
      action: "gateway.post",
      resource: "gateway:notion:/v1/pages",
    });
  });

  it("builds safe HTTPS upstream targets", () => {
    expect(
      buildGatewayTarget("https://api.example.com/root", "v1/pages", "?limit=1").toString(),
    ).toBe("https://api.example.com/root/v1/pages?limit=1");
  });

  it("rejects private or non-HTTPS upstream targets", () => {
    expect(() => buildGatewayTarget("http://api.example.com", "v1/pages", "")).toThrow(
      "upstream must use https",
    );
    expect(() => buildGatewayTarget("https://127.0.0.1:8080", "v1/pages", "")).toThrow(
      "upstream host not allowed",
    );
    expect(() => buildGatewayTarget("https://8.8.8.8", "v1/pages", "")).toThrow(
      "upstream host not allowed",
    );
    expect(() => buildGatewayTarget("https://service.local", "v1/pages", "")).toThrow(
      "upstream host not allowed",
    );
    expect(() =>
      buildGatewayTarget("https://api.example.com", "v1/pages", "", "other.example.com"),
    ).toThrow("upstream host not allowed by allowlist");
    expect(() => buildGatewayTarget("https://api.example.com", "v1/pages", "", "", true)).toThrow(
      "upstream host allowlist required",
    );
  });

  it("rejects paths that escape the upstream base", () => {
    expect(() => buildGatewayTarget("https://api.example.com/root", "../admin", "")).toThrow(
      "gateway path escapes upstream base",
    );
    expect(() => buildGatewayTarget("https://api.example.com/root", "%2e%2e/admin", "")).toThrow(
      "gateway path escapes upstream base",
    );
    expect(() => buildGatewayTarget("https://api.example.com/root", "%2f..%2fadmin", "")).toThrow(
      "gateway path escapes upstream base",
    );
    expect(() =>
      buildGatewayTarget("https://api.example.com/root", "safe%5c..%5cadmin", ""),
    ).toThrow("gateway path escapes upstream base");
  });

  it("strips method override and credential forwarding headers", () => {
    const headers = forwardedRequestHeaders(
      new Headers({
        authorization: "Bearer secret",
        cookie: "session=secret",
        "x-api-key": "secret",
        "x-client": "test",
        "x-forwarded-for": "10.0.0.1",
        "x-http-method": "DELETE",
        "x-http-method-override": "DELETE",
        "x-method-override": "PATCH",
      }),
    );
    expect(headers.get("x-client")).toBe("test");
    expect(headers.get("authorization")).toBeNull();
    expect(headers.get("cookie")).toBeNull();
    expect(headers.get("x-api-key")).toBeNull();
    expect(headers.get("x-forwarded-for")).toBeNull();
    expect(headers.get("x-http-method")).toBeNull();
    expect(headers.get("x-http-method-override")).toBeNull();
    expect(headers.get("x-method-override")).toBeNull();
  });

  it("fails closed when verifier is unavailable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("offline");
      }),
    );
    const res = await app.request(
      "/acme/gateway/notion/v1/pages",
      { headers: { authorization: "Bearer not-a-jwt" } },
      { ENVIRONMENT: "test", VERIFIER_URL: "https://verifier.test" },
    );
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "denied", reasons: ["verifier unavailable"] });
    vi.unstubAllGlobals();
  });
});

run("gateway integration", () => {
  const db = createClient(url as string);
  const cleanup: string[] = [];

  afterEach(async () => {
    vi.unstubAllGlobals();
    while (cleanup.length > 0) {
      const id = cleanup.pop();
      if (!id) continue;
      try {
        await db.delete(workspaces).where(eq(workspaces.id, id));
      } catch {
        // ignore cleanup races
      }
    }
  });

  const setup = async () => {
    const testEnv = await buildTestEnv(url as string);
    const created = await createTestWorkspace(issuer, testEnv, {
      slug: uniqueSlug("gtw"),
      adminEmail: "alice@example.com",
    });
    cleanup.push(created.workspaceId);
    const issued = await issueTestToken(issuer, testEnv, {
      workspaceId: created.workspaceId,
      email: "alice@example.com",
      audience: "pact-gateway",
    });
    await withWorkspace(db, created.workspaceId, (tx) =>
      tx.insert(schema.brains).values({
        workspaceId: created.workspaceId,
        kind: "notion",
        baseUrl: "https://api.example.com/base",
        authScheme: "none",
        scopeInjectionTemplate: {},
      }),
    );
    return { testEnv, created, issued };
  };

  it("verifies policy, loads the brain, and forwards to upstream", async () => {
    const { testEnv, created, issued } = await setup();
    const requested: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL, init?: RequestInit) => {
        const target = input.toString();
        requested.push(target);
        if (target === "https://verifier.test/v1/verify") {
          const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
          expect(body).toMatchObject({
            action: "gateway.get",
            resource: "gateway:notion:/v1/pages",
            audience: "pact-gateway",
          });
          return Response.json({ allow: true, reasons: ["ok"] });
        }
        expect(target).toBe("https://api.example.com/base/v1/pages?limit=1");
        expect((init?.headers as Headers).get("authorization")).toBeNull();
        expect((init?.headers as Headers).get("cookie")).toBeNull();
        expect((init?.headers as Headers).get("x-api-key")).toBeNull();
        expect((init?.headers as Headers).get("x-forwarded-for")).toBeNull();
        expect((init?.headers as Headers).get("x-client")).toBe("test");
        return Response.json(
          { ok: true },
          { headers: { "set-cookie": "secret=value", "x-upstream": "ok" } },
        );
      }),
    );

    const res = await app.request(
      `/${created.workspaceId}/gateway/notion/v1/pages?limit=1`,
      {
        headers: {
          authorization: `Bearer ${issued.token}`,
          cookie: "session=secret",
          "x-client": "test",
          "x-api-key": "secret",
          "x-forwarded-for": "10.0.0.1",
        },
      },
      {
        DATABASE_URL: testEnv.DATABASE_URL,
        VERIFIER_URL: "https://verifier.test",
        GATEWAY_AUDIENCE: "pact-gateway",
        MEK: testEnv.MEK,
      },
    );

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
    expect(res.headers.get("set-cookie")).toBeNull();
    expect(res.headers.get("x-upstream")).toBe("ok");
    expect(requested).toEqual([
      "https://verifier.test/v1/verify",
      "https://api.example.com/base/v1/pages?limit=1",
    ]);
    const rows = await withWorkspace(db, created.workspaceId, (tx) =>
      tx
        .select({
          action: auditEvents.action,
          decision: auditEvents.decision,
          target: auditEvents.target,
          supporting: auditEvents.supporting,
        })
        .from(auditEvents)
        .where(eq(auditEvents.workspaceId, created.workspaceId)),
    );
    expect(rows).toContainEqual(
      expect.objectContaining({
        action: "gateway.get",
        decision: "allow",
        target: expect.objectContaining({
          brain: "notion",
          resource: "gateway:notion:/v1/pages",
        }),
        supporting: expect.objectContaining({
          outcome: "forwarded",
          upstreamStatus: 200,
        }),
      }),
    );
  });

  it("does not forward when verifier denies", async () => {
    const { testEnv, created, issued } = await setup();
    const fetchMock = vi.fn(async () => Response.json({ allow: false, reasons: ["deny"] }));
    vi.stubGlobal("fetch", fetchMock);

    const res = await app.request(
      `/${created.workspaceId}/gateway/notion/v1/pages`,
      { headers: { authorization: `Bearer ${issued.token}` } },
      {
        DATABASE_URL: testEnv.DATABASE_URL,
        VERIFIER_URL: "https://verifier.test",
        GATEWAY_AUDIENCE: "pact-gateway",
      },
    );

    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "denied", reasons: ["deny"] });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("rate limits gateway calls before forwarding upstream", async () => {
    const { testEnv, created, issued } = await setup();
    const fetchMock = vi.fn(async (input: string | URL) => {
      const target = input.toString();
      if (target === "https://verifier.test/v1/verify") {
        return Response.json({ allow: true, reasons: ["ok"] });
      }
      return Response.json({ ok: true });
    });
    vi.stubGlobal("fetch", fetchMock);

    const call = () =>
      app.request(
        `/${created.workspaceId}/gateway/notion/v1/pages`,
        { headers: { authorization: `Bearer ${issued.token}` } },
        {
          DATABASE_URL: testEnv.DATABASE_URL,
          VERIFIER_URL: "https://verifier.test",
          GATEWAY_AUDIENCE: "pact-gateway",
          GATEWAY_RATE_LIMIT: "1",
          GATEWAY_RATE_WINDOW_SECONDS: "60",
          MEK: testEnv.MEK,
        },
      );

    const first = await call();
    expect(first.status).toBe(200);
    const second = await call();
    expect(second.status).toBe(429);
    expect(second.headers.get("retry-after")).toBeTruthy();
    expect(await second.json()).toEqual({
      error: "rate_limited",
      message: "too many requests",
    });
    const upstreamCalls = fetchMock.mock.calls.filter(
      ([input]) => input.toString() === "https://api.example.com/base/v1/pages",
    );
    expect(upstreamCalls).toHaveLength(1);
  });

  it("rejects a token routed through another workspace", async () => {
    const first = await setup();
    const second = await createTestWorkspace(issuer, first.testEnv, {
      slug: uniqueSlug("gtw-other"),
      adminEmail: "bob@example.com",
    });
    cleanup.push(second.workspaceId);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json({ allow: true, reasons: ["ok"] })),
    );

    const res = await app.request(
      `/${second.workspaceId}/gateway/notion/v1/pages`,
      { headers: { authorization: `Bearer ${first.issued.token}` } },
      {
        DATABASE_URL: first.testEnv.DATABASE_URL,
        VERIFIER_URL: "https://verifier.test",
        GATEWAY_AUDIENCE: "pact-gateway",
      },
    );

    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({
      error: "unauthorized",
      message: "workspace mismatch",
    });
  });
});
