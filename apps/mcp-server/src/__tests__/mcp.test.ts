import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { fromBase64 } from "@getpact/crypto";
import { createClient, withWorkspace } from "@getpact/db";
import { policies, workspaceOauthConnections, workspaces } from "@getpact/db/schema";
import {
  buildTestEnv,
  createTestWorkspace,
  issueTestToken,
  uniqueSlug,
} from "@getpact/test-helpers";
import { loadSecretString, storeSecret } from "@getpact/vault";
import { eq } from "drizzle-orm";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import issuer from "../../../../apps/issuer/src/index.js";
import verifier from "../../../../apps/verifier/src/index.js";
import { handleMcp } from "../handler.js";
import app from "../index.js";
import { httpVerifyClient } from "../verify-client.js";

const url = process.env.DATABASE_URL;
const run = url ? describe : describe.skip;

const tokenWithBadHeader = (claims: Record<string, unknown>) =>
  [
    Buffer.from("not json").toString("base64url"),
    Buffer.from(JSON.stringify(claims)).toString("base64url"),
    "sig",
  ].join(".");

describe("mcp server auth hardening", () => {
  it("rejects malformed token headers as unauthorized", async () => {
    const token = tokenWithBadHeader({
      org: "00000000-0000-0000-0000-000000000000",
      sub: "user-1",
      jti: "jti-1",
    });
    const res = await app.request(
      "/acme/mcp",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }),
      },
      {
        DATABASE_URL: "postgres://unused",
        ISSUER_BASE_URL: "https://issuer.test/acme",
        MCP_AUDIENCE: "pact-mcp",
      },
    );
    expect(res.status).toBe(401);
  });

  it("treats non-2xx verifier allow bodies as denial", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json({ allow: true, reasons: ["ok"] }, { status: 500 })),
    );
    const verify = httpVerifyClient("https://verifier.test");
    await expect(
      verify({
        token: "token",
        action: "pact.whoami",
        resource: "pact:whoami",
        audience: "pact-mcp",
      }),
    ).resolves.toEqual({ allow: false, reasons: ["verifier returned 500"] });
    vi.unstubAllGlobals();
  });

  it("preserves verifier deny reasons returned with 403", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json({ allow: false, reasons: ["policy denied"] }, { status: 403 }),
      ),
    );
    const verify = httpVerifyClient("https://verifier.test");
    await expect(
      verify({
        token: "token",
        action: "pact.whoami",
        resource: "pact:whoami",
        audience: "pact-mcp",
      }),
    ).resolves.toEqual({ allow: false, reasons: ["policy denied"] });
    vi.unstubAllGlobals();
  });
});

describe("mcp handler registry injection", () => {
  const ctx = {
    workspaceId: "00000000-0000-0000-0000-000000000001",
    userId: "user-1",
    email: "alice@example.com",
    groups: [],
    roles: ["admin"],
    jti: "jti-1",
    token: "token-1",
  };

  it("lists and calls tools from an injected registry", async () => {
    const verify = vi.fn(async () => ({ allow: true, reasons: [] }));
    const registry = new Map([
      [
        "test.echo",
        {
          descriptor: {
            name: "test.echo",
            description: "Echo test input.",
            inputSchema: { type: "object" as const },
          },
          authorize: () => ({
            action: "test.echo",
            resource: "test:echo",
          }),
          handler: async (args: Record<string, unknown>) => ({
            content: [{ type: "text" as const, text: JSON.stringify(args) }],
          }),
        },
      ],
    ]);

    const listed = await handleMcp({ jsonrpc: "2.0", id: 1, method: "tools/list" }, ctx, {
      audience: "pact-mcp",
      deps: { databaseUrl: "postgres://unused" },
      registry,
    });
    expect(listed.result).toEqual({
      tools: [
        {
          name: "test.echo",
          description: "Echo test input.",
          inputSchema: { type: "object" },
        },
      ],
    });

    const called = await handleMcp(
      {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: "test.echo", arguments: { ok: true } },
      },
      ctx,
      {
        audience: "pact-mcp",
        verify,
        deps: { databaseUrl: "postgres://unused" },
        registry,
      },
    );
    expect(called.error).toBeUndefined();
    expect(called.result).toEqual({
      content: [{ type: "text", text: '{"ok":true}' }],
    });
    expect(verify).toHaveBeenCalledWith({
      token: "token-1",
      action: "test.echo",
      resource: "test:echo",
      audience: "pact-mcp",
    });
  });
});

describe("mcp builtin tool guards", () => {
  const baseCtx = {
    workspaceId: "00000000-0000-0000-0000-000000000001",
    userId: "user-1",
    email: "alice@example.com",
    groups: [],
    roles: [] as string[],
    jti: "jti-1",
    token: "token-1",
  };

  const callBuiltin = (name: string, roles: string[] = []) =>
    handleMcp(
      {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name, arguments: {} },
      },
      { ...baseCtx, roles },
      {
        audience: "pact-mcp",
        verify: vi.fn(async () => ({ allow: true, reasons: [] })),
        deps: { databaseUrl: "postgres://unused" },
      },
    );

  it("requires admin for policy.active even when policy allows", async () => {
    const body = await callBuiltin("pact.policy.active");
    expect(body.error).toBeUndefined();
    expect(body.result).toEqual({
      content: [{ type: "text", text: "admin role required" }],
      isError: true,
    });
  });

  it("requires admin or auditor for audit.recent even when policy allows", async () => {
    const body = await callBuiltin("pact.audit.recent");
    expect(body.error).toBeUndefined();
    expect(body.result).toEqual({
      content: [{ type: "text", text: "admin or auditor role required" }],
      isError: true,
    });
  });

  it("reports Drive credential store misconfiguration when MEK is missing", async () => {
    const body = await handleMcp(
      {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "pact.drive.files.list", arguments: {} },
      },
      { ...baseCtx, roles: ["admin"] },
      {
        audience: "pact-mcp",
        verify: vi.fn(async () => ({ allow: true, reasons: [] })),
        deps: { databaseUrl: "postgres://unused" },
      },
    );
    expect(body.error).toEqual({
      code: -32000,
      message: "Drive credential store is not configured",
    });
  });
});

run("mcp server", () => {
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
    const slug = uniqueSlug("mcp");
    const created = await createTestWorkspace(issuer, env, {
      slug,
      adminEmail: "alice@example.com",
    });
    cleanup.push(created.workspaceId);
    const issued = await issueTestToken(issuer, env, {
      workspaceId: created.workspaceId,
      email: "alice@example.com",
      audience: env.MCP_AUDIENCE,
    });
    return { env, slug, created, token: issued.token };
  };

  const callMcp = async (
    slug: string,
    token: string,
    body: unknown,
    env: { DATABASE_URL: string },
  ) =>
    app.request(
      `/${slug}/mcp`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(body),
      },
      { ISSUER_BASE_URL: "https://issuer.test/acme", ...env },
    );

  it("rejects requests without an Authorization header", async () => {
    const { env, slug } = await setup();
    const res = await app.request(
      `/${slug}/mcp`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }),
      },
      { DATABASE_URL: env.DATABASE_URL },
    );
    expect(res.status).toBe(401);
  });

  it("returns initialize info for a valid token", async () => {
    const { env, slug, token } = await setup();
    const res = await callMcp(
      slug,
      token,
      { jsonrpc: "2.0", id: 1, method: "initialize" },
      {
        DATABASE_URL: env.DATABASE_URL,
      },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      result: { protocolVersion: string; serverInfo: { name: string } };
    };
    expect(body.result.protocolVersion).toBe("2024-11-05");
    expect(body.result.serverInfo.name).toBe("pact-mcp");
  });

  it("rejects a valid token on another workspace route", async () => {
    const first = await setup();
    const second = await setup();
    const res = await callMcp(
      second.slug,
      first.token,
      { jsonrpc: "2.0", id: 11, method: "initialize" },
      {
        DATABASE_URL: first.env.DATABASE_URL,
      },
    );
    expect(res.status).toBe(401);
  });

  it("lists pact.whoami in tools/list", async () => {
    const { env, slug, token } = await setup();
    const res = await callMcp(
      slug,
      token,
      { jsonrpc: "2.0", id: 2, method: "tools/list" },
      {
        DATABASE_URL: env.DATABASE_URL,
      },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { result: { tools: Array<{ name: string }> } };
    const names = body.result.tools.map((t) => t.name);
    expect(names).toContain("pact.whoami");
    expect(names).toContain("pact.slack.auth.test");
    expect(names).toContain("pact.drive.files.list");
    expect(names).toContain("pact.drive.file.get");
  });

  it("does not expose orphaned Drive vault secrets without active connection metadata", async () => {
    const { env, created } = await setup();
    await withWorkspace(adminDb, created.workspaceId, (tx) =>
      storeSecret(tx, fromBase64(env.MEK), {
        workspaceId: created.workspaceId,
        kind: "google_drive_oauth",
        target: `user:${created.adminUserId}`,
        plaintext: JSON.stringify({ accessToken: "orphaned-drive-token" }),
      }),
    );

    const body = await handleMcp(
      {
        jsonrpc: "2.0",
        id: 12,
        method: "tools/call",
        params: { name: "pact.drive.files.list", arguments: {} },
      },
      {
        workspaceId: created.workspaceId,
        userId: created.adminUserId,
        email: "alice@example.com",
        groups: [],
        roles: ["admin"],
        jti: "jti-1",
        token: "token-1",
      },
      {
        audience: env.MCP_AUDIENCE,
        verify: vi.fn(async () => ({ allow: true, reasons: [] })),
        deps: { databaseUrl: env.DATABASE_URL, rawMek: fromBase64(env.MEK) },
      },
    );
    expect(body.error).toBeUndefined();
    expect(body.result).toEqual({
      content: [{ type: "text", text: "Google Drive is not connected for this user." }],
      isError: true,
    });
  });

  it("loads an active Drive connection and calls Google Drive with the stored access token", async () => {
    const { env, created } = await setup();
    const rawMek = fromBase64(env.MEK);
    await withWorkspace(adminDb, created.workspaceId, async (tx) => {
      await tx.insert(workspaceOauthConnections).values({
        workspaceId: created.workspaceId,
        provider: "google_drive",
        userId: created.adminUserId,
        providerSubject: "google-sub-1",
        email: "alice@example.com",
        scopes: ["https://www.googleapis.com/auth/drive.readonly"],
        vaultTarget: `user:${created.adminUserId}`,
        expiresAt: new Date(Date.now() + 600_000),
      });
      await storeSecret(tx, rawMek, {
        workspaceId: created.workspaceId,
        kind: "google_drive_oauth",
        target: `user:${created.adminUserId}`,
        plaintext: JSON.stringify({
          accessToken: "active-drive-token",
          refreshToken: "refresh-token",
          expiresAt: new Date(Date.now() + 600_000).toISOString(),
          googleSub: "google-sub-1",
          email: "alice@example.com",
        }),
      });
    });

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      expect(request.headers.get("authorization")).toBe("Bearer active-drive-token");
      return Response.json({ files: [{ id: "file_1", name: "Plan" }] });
    });
    vi.stubGlobal("fetch", fetchMock);
    try {
      const body = await handleMcp(
        {
          jsonrpc: "2.0",
          id: 13,
          method: "tools/call",
          params: { name: "pact.drive.files.list", arguments: {} },
        },
        {
          workspaceId: created.workspaceId,
          userId: created.adminUserId,
          email: "alice@example.com",
          groups: [],
          roles: ["admin"],
          jti: "jti-1",
          token: "token-1",
        },
        {
          audience: env.MCP_AUDIENCE,
          verify: vi.fn(async () => ({ allow: true, reasons: [] })),
          deps: { databaseUrl: env.DATABASE_URL, rawMek },
        },
      );
      expect(body.error).toBeUndefined();
      expect(fetchMock).toHaveBeenCalledTimes(1);
      const result = body.result as { content: Array<{ text: string }> };
      expect(JSON.parse(result.content[0]?.text ?? "{}")).toEqual({
        files: [{ id: "file_1", name: "Plan" }],
      });
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("refreshes an expired Drive access token before calling Google Drive", async () => {
    const { env, created } = await setup();
    const rawMek = fromBase64(env.MEK);
    const vaultTarget = `user:${created.adminUserId}`;
    await withWorkspace(adminDb, created.workspaceId, async (tx) => {
      await tx.insert(workspaceOauthConnections).values({
        workspaceId: created.workspaceId,
        provider: "google_drive",
        userId: created.adminUserId,
        providerSubject: "google-sub-1",
        email: "alice@example.com",
        scopes: ["https://www.googleapis.com/auth/drive.readonly"],
        vaultTarget,
        expiresAt: new Date(Date.now() - 60_000),
      });
      await storeSecret(tx, rawMek, {
        workspaceId: created.workspaceId,
        kind: "google_drive_oauth",
        target: vaultTarget,
        plaintext: JSON.stringify({
          accessToken: "expired-drive-token",
          refreshToken: "refresh-token",
          expiresAt: new Date(Date.now() - 60_000).toISOString(),
          googleSub: "google-sub-1",
          email: "alice@example.com",
        }),
      });
    });

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      if (request.url.includes("oauth2.googleapis.com/token")) {
        const body = await request.text();
        expect(body).toContain("grant_type=refresh_token");
        expect(body).toContain("refresh_token=refresh-token");
        return Response.json({
          access_token: "fresh-drive-token",
          expires_in: 3600,
          scope: "https://www.googleapis.com/auth/drive.readonly",
        });
      }
      expect(request.headers.get("authorization")).toBe("Bearer fresh-drive-token");
      return Response.json({ files: [{ id: "file_2", name: "Fresh" }] });
    });
    vi.stubGlobal("fetch", fetchMock);
    try {
      const body = await handleMcp(
        {
          jsonrpc: "2.0",
          id: 14,
          method: "tools/call",
          params: { name: "pact.drive.files.list", arguments: {} },
        },
        {
          workspaceId: created.workspaceId,
          userId: created.adminUserId,
          email: "alice@example.com",
          groups: [],
          roles: ["admin"],
          jti: "jti-1",
          token: "token-1",
        },
        {
          audience: env.MCP_AUDIENCE,
          verify: vi.fn(async () => ({ allow: true, reasons: [] })),
          deps: {
            databaseUrl: env.DATABASE_URL,
            rawMek,
            providerConfig: {
              GOOGLE_OAUTH_CLIENT_ID: "google-client",
              GOOGLE_OAUTH_CLIENT_SECRET: "google-secret",
            },
          },
        },
      );
      expect(body.error).toBeUndefined();
      expect(fetchMock).toHaveBeenCalledTimes(2);
      const result = body.result as { content: Array<{ text: string }> };
      expect(JSON.parse(result.content[0]?.text ?? "{}")).toEqual({
        files: [{ id: "file_2", name: "Fresh" }],
      });

      const stored = await withWorkspace(adminDb, created.workspaceId, (tx) =>
        loadSecretString(tx, rawMek, {
          workspaceId: created.workspaceId,
          kind: "google_drive_oauth",
          target: vaultTarget,
        }),
      );
      expect(stored).toContain("fresh-drive-token");
      const [connection] = await withWorkspace(adminDb, created.workspaceId, (tx) =>
        tx
          .select({
            status: workspaceOauthConnections.status,
            lastRefreshAt: workspaceOauthConnections.lastRefreshAt,
            lastError: workspaceOauthConnections.lastError,
          })
          .from(workspaceOauthConnections)
          .where(eq(workspaceOauthConnections.workspaceId, created.workspaceId))
          .limit(1),
      );
      expect(connection?.status).toBe("connected");
      expect(connection?.lastRefreshAt).toBeTruthy();
      expect(connection?.lastError).toBeNull();
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("marks Drive connection expired when Google refresh fails", async () => {
    const { env, created } = await setup();
    const rawMek = fromBase64(env.MEK);
    const vaultTarget = `user:${created.adminUserId}`;
    await withWorkspace(adminDb, created.workspaceId, async (tx) => {
      await tx.insert(workspaceOauthConnections).values({
        workspaceId: created.workspaceId,
        provider: "google_drive",
        userId: created.adminUserId,
        providerSubject: "google-sub-1",
        email: "alice@example.com",
        scopes: ["https://www.googleapis.com/auth/drive.readonly"],
        vaultTarget,
        expiresAt: new Date(Date.now() - 60_000),
      });
      await storeSecret(tx, rawMek, {
        workspaceId: created.workspaceId,
        kind: "google_drive_oauth",
        target: vaultTarget,
        plaintext: JSON.stringify({
          accessToken: "expired-drive-token",
          refreshToken: "refresh-token",
          expiresAt: new Date(Date.now() - 60_000).toISOString(),
          googleSub: "google-sub-1",
          email: "alice@example.com",
        }),
      });
    });

    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json({ error: "invalid_grant" }, { status: 400 })),
    );
    try {
      const body = await handleMcp(
        {
          jsonrpc: "2.0",
          id: 15,
          method: "tools/call",
          params: { name: "pact.drive.files.list", arguments: {} },
        },
        {
          workspaceId: created.workspaceId,
          userId: created.adminUserId,
          email: "alice@example.com",
          groups: [],
          roles: ["admin"],
          jti: "jti-1",
          token: "token-1",
        },
        {
          audience: env.MCP_AUDIENCE,
          verify: vi.fn(async () => ({ allow: true, reasons: [] })),
          deps: {
            databaseUrl: env.DATABASE_URL,
            rawMek,
            providerConfig: {
              GOOGLE_OAUTH_CLIENT_ID: "google-client",
              GOOGLE_OAUTH_CLIENT_SECRET: "google-secret",
            },
          },
        },
      );
      expect(body.error).toBeUndefined();
      expect(body.result).toEqual({
        content: [{ type: "text", text: "Google Drive is not connected for this user." }],
        isError: true,
      });
      const [connection] = await withWorkspace(adminDb, created.workspaceId, (tx) =>
        tx
          .select({
            status: workspaceOauthConnections.status,
            lastError: workspaceOauthConnections.lastError,
          })
          .from(workspaceOauthConnections)
          .where(eq(workspaceOauthConnections.workspaceId, created.workspaceId))
          .limit(1),
      );
      expect(connection?.status).toBe("expired");
      expect(connection?.lastError).toContain("invalid_grant");
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("does not expire a Drive connection when another request already refreshed it", async () => {
    const { env, created } = await setup();
    const rawMek = fromBase64(env.MEK);
    const vaultTarget = `user:${created.adminUserId}`;
    await withWorkspace(adminDb, created.workspaceId, async (tx) => {
      await tx.insert(workspaceOauthConnections).values({
        workspaceId: created.workspaceId,
        provider: "google_drive",
        userId: created.adminUserId,
        providerSubject: "google-sub-1",
        email: "alice@example.com",
        scopes: ["https://www.googleapis.com/auth/drive.readonly"],
        vaultTarget,
        expiresAt: new Date(Date.now() - 60_000),
      });
      await storeSecret(tx, rawMek, {
        workspaceId: created.workspaceId,
        kind: "google_drive_oauth",
        target: vaultTarget,
        plaintext: JSON.stringify({
          accessToken: "expired-drive-token",
          refreshToken: "refresh-token",
          expiresAt: new Date(Date.now() - 60_000).toISOString(),
          googleSub: "google-sub-1",
          email: "alice@example.com",
        }),
      });
    });

    const freshExpiresAt = new Date(Date.now() + 600_000).toISOString();
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      if (request.url.includes("oauth2.googleapis.com/token")) {
        await withWorkspace(adminDb, created.workspaceId, async (tx) => {
          await storeSecret(tx, rawMek, {
            workspaceId: created.workspaceId,
            kind: "google_drive_oauth",
            target: vaultTarget,
            plaintext: JSON.stringify({
              accessToken: "concurrent-fresh-token",
              refreshToken: "refresh-token",
              expiresAt: freshExpiresAt,
              googleSub: "google-sub-1",
              email: "alice@example.com",
            }),
          });
          await tx
            .update(workspaceOauthConnections)
            .set({ status: "connected", expiresAt: new Date(freshExpiresAt), lastError: null })
            .where(eq(workspaceOauthConnections.workspaceId, created.workspaceId));
        });
        return Response.json({ error: "invalid_grant" }, { status: 400 });
      }
      expect(request.headers.get("authorization")).toBe("Bearer concurrent-fresh-token");
      return Response.json({ files: [{ id: "file_3", name: "Concurrent" }] });
    });
    vi.stubGlobal("fetch", fetchMock);
    try {
      const body = await handleMcp(
        {
          jsonrpc: "2.0",
          id: 17,
          method: "tools/call",
          params: { name: "pact.drive.files.list", arguments: {} },
        },
        {
          workspaceId: created.workspaceId,
          userId: created.adminUserId,
          email: "alice@example.com",
          groups: [],
          roles: ["admin"],
          jti: "jti-1",
          token: "token-1",
        },
        {
          audience: env.MCP_AUDIENCE,
          verify: vi.fn(async () => ({ allow: true, reasons: [] })),
          deps: {
            databaseUrl: env.DATABASE_URL,
            rawMek,
            providerConfig: {
              GOOGLE_OAUTH_CLIENT_ID: "google-client",
              GOOGLE_OAUTH_CLIENT_SECRET: "google-secret",
            },
          },
        },
      );
      expect(body.error).toBeUndefined();
      expect(fetchMock).toHaveBeenCalledTimes(2);
      const [connection] = await withWorkspace(adminDb, created.workspaceId, (tx) =>
        tx
          .select({
            status: workspaceOauthConnections.status,
            lastError: workspaceOauthConnections.lastError,
          })
          .from(workspaceOauthConnections)
          .where(eq(workspaceOauthConnections.workspaceId, created.workspaceId))
          .limit(1),
      );
      expect(connection?.status).toBe("connected");
      expect(connection?.lastError).toBeNull();
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("marks Drive connection expired without calling Drive when refresh token is missing", async () => {
    const { env, created } = await setup();
    const rawMek = fromBase64(env.MEK);
    const vaultTarget = `user:${created.adminUserId}`;
    await withWorkspace(adminDb, created.workspaceId, async (tx) => {
      await tx.insert(workspaceOauthConnections).values({
        workspaceId: created.workspaceId,
        provider: "google_drive",
        userId: created.adminUserId,
        providerSubject: "google-sub-1",
        email: "alice@example.com",
        scopes: ["https://www.googleapis.com/auth/drive.readonly"],
        vaultTarget,
        expiresAt: new Date(Date.now() + 30_000),
      });
      await storeSecret(tx, rawMek, {
        workspaceId: created.workspaceId,
        kind: "google_drive_oauth",
        target: vaultTarget,
        plaintext: JSON.stringify({
          accessToken: "near-expiry-drive-token",
          expiresAt: new Date(Date.now() + 30_000).toISOString(),
          googleSub: "google-sub-1",
          email: "alice@example.com",
        }),
      });
    });

    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    try {
      const body = await handleMcp(
        {
          jsonrpc: "2.0",
          id: 16,
          method: "tools/call",
          params: { name: "pact.drive.files.list", arguments: {} },
        },
        {
          workspaceId: created.workspaceId,
          userId: created.adminUserId,
          email: "alice@example.com",
          groups: [],
          roles: ["admin"],
          jti: "jti-1",
          token: "token-1",
        },
        {
          audience: env.MCP_AUDIENCE,
          verify: vi.fn(async () => ({ allow: true, reasons: [] })),
          deps: { databaseUrl: env.DATABASE_URL, rawMek },
        },
      );
      expect(body.error).toBeUndefined();
      expect(body.result).toEqual({
        content: [{ type: "text", text: "Google Drive is not connected for this user." }],
        isError: true,
      });
      expect(fetchMock).not.toHaveBeenCalled();
      const [connection] = await withWorkspace(adminDb, created.workspaceId, (tx) =>
        tx
          .select({
            status: workspaceOauthConnections.status,
            lastError: workspaceOauthConnections.lastError,
          })
          .from(workspaceOauthConnections)
          .where(eq(workspaceOauthConnections.workspaceId, created.workspaceId))
          .limit(1),
      );
      expect(connection?.status).toBe("expired");
      expect(connection?.lastError).toContain("refresh token is missing");
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("refuses tool calls when verifier is not configured", async () => {
    const { env, slug, token } = await setup();
    const res = await callMcp(
      slug,
      token,
      {
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: { name: "pact.whoami", arguments: {} },
      },
      { DATABASE_URL: env.DATABASE_URL },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      error?: { code: number; message: string };
    };
    expect(body.error?.code).toBe(-32002);
    expect(body.error?.message).toBe("verifier unavailable");
  });

  it("rejects unknown methods with -32601", async () => {
    const { env, slug, token } = await setup();
    const res = await callMcp(
      slug,
      token,
      { jsonrpc: "2.0", id: 4, method: "totally/fake" },
      {
        DATABASE_URL: env.DATABASE_URL,
      },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { error?: { code: number } };
    expect(body.error?.code).toBe(-32601);
  });

  it("rejects unknown tools", async () => {
    const { env, slug, token } = await setup();
    const res = await callMcp(
      slug,
      token,
      {
        jsonrpc: "2.0",
        id: 5,
        method: "tools/call",
        params: { name: "nonexistent.tool", arguments: {} },
      },
      { DATABASE_URL: env.DATABASE_URL },
    );
    const body = (await res.json()) as { error?: { code: number; message: string } };
    expect(body.error?.code).toBe(-32601);
    expect(body.error?.message).toContain("nonexistent.tool");
  });
});

run("mcp server with verifier", () => {
  const adminDb = createClient(url as string);
  const cleanup: string[] = [];
  const verifierServiceToken = "verifier-service-secret";
  let server: ReturnType<typeof createServer>;
  let verifierUrl: string;
  let proxyEnv: Record<string, unknown> = {};

  beforeAll(async () => {
    server = createServer((req: IncomingMessage, res: ServerResponse) => {
      let body = "";
      req.on("data", (c) => {
        body += c;
      });
      req.on("end", async () => {
        try {
          const method = req.method ?? "POST";
          const headers = new Headers({ "content-type": "application/json" });
          if (req.headers.authorization) {
            headers.set("authorization", req.headers.authorization);
          }
          const init: RequestInit = {
            method,
            headers,
          };
          if (method !== "GET" && method !== "HEAD") init.body = body;
          const upstreamRes = await verifier.request(req.url ?? "/", init, proxyEnv);
          const text = await upstreamRes.text();
          res.writeHead(upstreamRes.status, {
            "content-type": upstreamRes.headers.get("content-type") ?? "application/json",
          });
          res.end(text);
        } catch (e) {
          const message = e instanceof Error ? e.message : "proxy error";
          res.writeHead(500, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: message }));
        }
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    const port = (server.address() as AddressInfo).port;
    verifierUrl = `http://127.0.0.1:${port}`;
  });

  afterAll(
    () =>
      new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      ),
  );

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

  const setupWithPolicy = async (policyBody: unknown) => {
    const env = await buildTestEnv(url as string);
    const slug = uniqueSlug("mcpv");
    const created = await createTestWorkspace(issuer, env, {
      slug,
      adminEmail: "alice@example.com",
    });
    cleanup.push(created.workspaceId);

    await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx.insert(policies).values({
        workspaceId: created.workspaceId,
        version: 1,
        body: policyBody,
        createdBy: created.adminUserId,
      }),
    );

    const issued = await issueTestToken(issuer, env, {
      workspaceId: created.workspaceId,
      email: "alice@example.com",
      audience: env.MCP_AUDIENCE,
    });
    return { env, slug, created, token: issued.token };
  };

  const setVerifierEnv = (env: Awaited<ReturnType<typeof buildTestEnv>>) => {
    proxyEnv = {
      DATABASE_URL: env.DATABASE_URL,
      MEK: env.MEK,
      ISSUER_BASE_URL: env.ISSUER_BASE_URL,
      VERIFIER_SERVICE_TOKEN: verifierServiceToken,
    };
  };

  const callTool = async (
    slug: string,
    token: string,
    env: Awaited<ReturnType<typeof buildTestEnv>>,
    name: string,
    args: Record<string, unknown> = {},
  ) =>
    app.request(
      `/${slug}/mcp`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: { name, arguments: args },
        }),
      },
      {
        DATABASE_URL: env.DATABASE_URL,
        ISSUER_BASE_URL: env.ISSUER_BASE_URL,
        VERIFIER_URL: verifierUrl,
        VERIFIER_SERVICE_TOKEN: verifierServiceToken,
        MCP_AUDIENCE: env.MCP_AUDIENCE,
      },
    );

  const parseToolResult = async <T>(res: Response): Promise<T> => {
    const body = (await res.json()) as {
      result?: { content: Array<{ text: string }> };
      error?: unknown;
    };
    expect(body.error).toBeUndefined();
    const text = body.result?.content[0]?.text;
    if (!text) throw new Error("missing tool result text");
    return JSON.parse(text) as T;
  };

  it("calls verifier and runs tool when policy allows", async () => {
    const { env, slug, token } = await setupWithPolicy({
      rules: [{ subject: { kind: "role", value: "admin" }, effect: "allow" }],
    });

    setVerifierEnv(env);
    const res = await callTool(slug, token, env, "pact.whoami");
    const body = (await res.json()) as {
      result?: { content: Array<{ text: string }> };
      error?: unknown;
    };
    expect(body.error).toBeUndefined();
    expect(body.result?.content[0]?.text).toContain("alice@example.com");
  });

  it("returns workspace metadata through pact.workspace.info", async () => {
    const { env, slug, created, token } = await setupWithPolicy({
      rules: [{ subject: { kind: "role", value: "admin" }, effect: "allow" }],
    });

    setVerifierEnv(env);
    const res = await callTool(slug, token, env, "pact.workspace.info");
    const body = await parseToolResult<{ id: string; slug: string }>(res);
    expect(body.id).toBe(created.workspaceId);
    expect(body.slug).toBe(slug);
  });

  it("returns active policy through pact.policy.active", async () => {
    const policy = { rules: [{ subject: { kind: "role", value: "admin" }, effect: "allow" }] };
    const { env, slug, token } = await setupWithPolicy(policy);

    setVerifierEnv(env);
    const res = await callTool(slug, token, env, "pact.policy.active");
    const body = await parseToolResult<{ version: number; body: unknown }>(res);
    expect(body.version).toBe(1);
    expect(body.body).toEqual(policy);
  });

  it("filters recent audit events through pact.audit.recent", async () => {
    const { env, slug, token } = await setupWithPolicy({
      rules: [{ subject: { kind: "role", value: "admin" }, effect: "allow" }],
    });

    setVerifierEnv(env);
    await callTool(slug, token, env, "pact.whoami");
    await callTool(slug, token, env, "pact.whoami");

    const res = await callTool(slug, token, env, "pact.audit.recent", {
      action: "verify.tool:pact.whoami",
      limit: 1,
    });
    const body = await parseToolResult<{ events: Array<{ action: string }> }>(res);
    expect(body.events.length).toBe(1);
    expect(body.events[0]?.action).toBe("verify.tool:pact.whoami");
  });

  it("denies tool when policy denies", async () => {
    const { env, slug, token } = await setupWithPolicy({
      rules: [{ subject: { kind: "role", value: "admin" }, effect: "deny" }],
    });

    setVerifierEnv(env);
    const res = await callTool(slug, token, env, "pact.whoami");
    const body = (await res.json()) as { error?: { code: number; data?: { reasons: string[] } } };
    expect(body.error?.code).toBe(-32001);
    expect(body.error?.data?.reasons).toBeDefined();
  });
});
