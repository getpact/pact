import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { type Ed25519PublicJwk, fromBase64, generateEd25519Keypair, sdjwt } from "@getpact/crypto";
import { createClient, withWorkspace } from "@getpact/db";
import {
  agentCapabilityGrants,
  agents,
  driveDocumentChunks,
  policies,
  workspaceOauthConnections,
  workspaces,
} from "@getpact/db/schema";
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
import { isSdJwtCompact } from "../auth.js";
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

describe("sd-jwt detection", () => {
  it("treats plain JWT as bearer", () => {
    expect(isSdJwtCompact("abc.def.ghi")).toBe(false);
  });

  it("recognises issuer JWS followed by trailing tilde", () => {
    expect(isSdJwtCompact("aaa.bbb.ccc~")).toBe(true);
  });

  it("recognises issuer JWS with disclosures and kb-jwt", () => {
    expect(isSdJwtCompact("aaa.bbb.ccc~disc1~disc2~kb.head.sig")).toBe(true);
  });

  it("rejects empty or junk before tilde", () => {
    expect(isSdJwtCompact("~")).toBe(false);
    expect(isSdJwtCompact("not.a.jws~tail")).toBe(true);
    expect(isSdJwtCompact("only-one-segment~tail")).toBe(false);
  });

  it("rejects when the first segment contains characters outside the JWS alphabet", () => {
    expect(isSdJwtCompact("aaa.bbb.ccc!~tail")).toBe(false);
  });
});

describe("mcp handler sd-jwt redeem path", () => {
  const sdJwtCtx = {
    kind: "sd_jwt" as const,
    workspaceId: "00000000-0000-0000-0000-000000000001",
    userId: "agent_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    email: "alice2@example.com",
    groups: [] as string[],
    roles: [] as string[],
    jti: "11111111-1111-1111-1111-111111111111",
    token: "header.payload.sig~policy_d~payload_d~audience_d~kb.head.sig",
    agentId: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    audience: "pact-mcp",
  };

  const registry = new Map([
    [
      "pact.brain.search",
      {
        descriptor: {
          name: "pact.brain.search",
          description: "Echo redeem path.",
          inputSchema: { type: "object" as const },
        },
        authorize: () => ({
          action: "tool:pact.brain.search",
          resource: "workspace:00000000-0000-0000-0000-000000000001:brain:read",
        }),
        handler: async () => ({ content: [{ type: "text" as const, text: "ran" }] }),
      },
    ],
  ]);

  it("calls redeem (not verify) for sd-jwt context and runs tool on allow", async () => {
    const redeem = vi.fn(async () => ({
      allow: true as const,
      status: 200 as const,
      scope_claim: { group_in: ["eng"] },
      agent_id: sdJwtCtx.agentId,
      on_behalf_of: "user-id",
      audience: "pact-mcp",
      delegation_depth: 0,
    }));
    const verify = vi.fn(async () => ({ allow: true, reasons: [] }));

    const res = await handleMcp(
      {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "pact.brain.search", arguments: { query: "hi" } },
      },
      sdJwtCtx,
      {
        audience: "pact-mcp",
        verify,
        redeem,
        deps: { databaseUrl: "postgres://unused" },
        registry,
      },
    );

    expect(verify).not.toHaveBeenCalled();
    expect(redeem).toHaveBeenCalledTimes(1);
    expect(redeem).toHaveBeenCalledWith({
      sd_jwt: sdJwtCtx.token,
      jti: sdJwtCtx.jti,
      tool_name: "pact.brain.search",
      resource: {
        tool_name: "pact.brain.search",
        resource: "workspace:00000000-0000-0000-0000-000000000001:brain:read",
        action: "tool:pact.brain.search",
      },
    });
    expect(res.error).toBeUndefined();
    expect(res.result).toEqual({ content: [{ type: "text", text: "ran" }] });
  });

  it("surfaces kb_replay_detected as -32001 with status 410", async () => {
    const redeem = vi.fn(async () => ({
      allow: false as const,
      status: 410,
      reasons: ["kb_replay_detected"],
    }));

    const res = await handleMcp(
      {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: "pact.brain.search", arguments: { query: "hi" } },
      },
      sdJwtCtx,
      {
        audience: "pact-mcp",
        redeem,
        deps: { databaseUrl: "postgres://unused" },
        registry,
      },
    );

    expect(res.error?.code).toBe(-32001);
    expect(res.error?.data).toEqual({ reasons: ["kb_replay_detected"], status: 410 });
  });

  it("returns -32002 when redeem client is unavailable for sd-jwt context", async () => {
    const res = await handleMcp(
      {
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: { name: "pact.brain.search", arguments: { query: "hi" } },
      },
      sdJwtCtx,
      {
        audience: "pact-mcp",
        verify: vi.fn(async () => ({ allow: true, reasons: [] })),
        deps: { databaseUrl: "postgres://unused" },
        registry,
      },
    );

    expect(res.error?.code).toBe(-32002);
    expect(res.error?.message).toBe("verifier unavailable");
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
    env: { DATABASE_URL: string; DRIVE_RAG_ENABLED?: string },
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
    expect(names).toContain("pact.drive.files.list");
    expect(names).toContain("pact.drive.file.get");
    expect(names).not.toContain("pact.drive.file.index");
    expect(names).not.toContain("pact.drive.search");

    const enabledRes = await callMcp(
      slug,
      token,
      { jsonrpc: "2.0", id: 3, method: "tools/list" },
      {
        DATABASE_URL: env.DATABASE_URL,
        DRIVE_RAG_ENABLED: "true",
      },
    );
    const enabledBody = (await enabledRes.json()) as {
      result: { tools: Array<{ name: string }> };
    };
    const enabledNames = enabledBody.result.tools.map((t) => t.name);
    expect(enabledNames).toContain("pact.drive.file.index");
    expect(enabledNames).toContain("pact.drive.search");
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

  it("indexes and searches Drive file chunks for retrieval", async () => {
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
        expiresAt: new Date(Date.now() + 600_000),
      });
      await storeSecret(tx, rawMek, {
        workspaceId: created.workspaceId,
        kind: "google_drive_oauth",
        target: vaultTarget,
        plaintext: JSON.stringify({
          accessToken: "active-drive-token",
          refreshToken: "refresh-token",
          expiresAt: new Date(Date.now() + 600_000).toISOString(),
          googleSub: "google-sub-1",
          email: "alice@example.com",
        }),
      });
    });

    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const request = new Request(input, init);
        expect(request.headers.get("authorization")).toBe("Bearer active-drive-token");
        if (request.url.includes("/files/doc_1?")) {
          return Response.json({
            id: "doc_1",
            name: "Customer Notes",
            mimeType: "application/vnd.google-apps.document",
            modifiedTime: "2026-05-12T10:00:00.000Z",
          });
        }
        return new Response(
          [
            "Pact customer notes",
            "",
            "Brandon asked for Google Drive documents to become searchable agent context.".repeat(
              8,
            ),
            "",
            "The retrieval layer should return relevant snippets with file metadata.".repeat(8),
          ].join("\n"),
          { headers: { "content-type": "text/plain" } },
        );
      }),
    );
    try {
      const ctx = {
        workspaceId: created.workspaceId,
        userId: created.adminUserId,
        email: "alice@example.com",
        groups: [],
        roles: ["admin"],
        jti: "jti-1",
        token: "token-1",
      };
      const deps = {
        databaseUrl: env.DATABASE_URL,
        rawMek,
        providerConfig: { DRIVE_RAG_ENABLED: "true" },
      };
      const indexed = await handleMcp(
        {
          jsonrpc: "2.0",
          id: 18,
          method: "tools/call",
          params: {
            name: "pact.drive.file.index",
            arguments: {
              fileId: "doc_1",
              fileName: "Customer Notes",
              chunkChars: 80,
            },
          },
        },
        ctx,
        {
          audience: env.MCP_AUDIENCE,
          verify: vi.fn(async () => ({ allow: true, reasons: [] })),
          deps,
        },
      );
      expect(indexed.error).toBeUndefined();
      const indexResult = JSON.parse(
        (indexed.result as { content: Array<{ text: string }> }).content[0]?.text ?? "{}",
      ) as { chunks: number };
      expect(indexResult.chunks).toBeGreaterThan(1);

      for (let i = 0; i < 9; i += 1) {
        const repeated = await handleMcp(
          {
            jsonrpc: "2.0",
            id: 180 + i,
            method: "tools/call",
            params: {
              name: "pact.drive.file.index",
              arguments: { fileId: "doc_1", chunkChars: 80 },
            },
          },
          ctx,
          {
            audience: env.MCP_AUDIENCE,
            verify: vi.fn(async () => ({ allow: true, reasons: [] })),
            deps,
          },
        );
        expect(repeated.error).toBeUndefined();
      }

      const limited = await handleMcp(
        {
          jsonrpc: "2.0",
          id: 199,
          method: "tools/call",
          params: {
            name: "pact.drive.file.index",
            arguments: { fileId: "doc_1", chunkChars: 80 },
          },
        },
        ctx,
        {
          audience: env.MCP_AUDIENCE,
          verify: vi.fn(async () => ({ allow: true, reasons: [] })),
          deps,
        },
      );
      expect(limited.error).toBeUndefined();
      expect(
        (limited.result as { content: Array<{ text: string }>; isError?: boolean }).content[0]
          ?.text,
      ).toBe("Drive indexing rate limit exceeded. Try again later.");
      expect((limited.result as { isError?: boolean }).isError).toBe(true);

      const stored = await withWorkspace(adminDb, created.workspaceId, (tx) =>
        tx
          .select()
          .from(driveDocumentChunks)
          .where(eq(driveDocumentChunks.workspaceId, created.workspaceId)),
      );
      expect(stored.length).toBe(indexResult.chunks);

      const searched = await handleMcp(
        {
          jsonrpc: "2.0",
          id: 19,
          method: "tools/call",
          params: {
            name: "pact.drive.search",
            arguments: { query: "searchable agent context", limit: 3 },
          },
        },
        ctx,
        {
          audience: env.MCP_AUDIENCE,
          verify: vi.fn(async () => ({ allow: true, reasons: [] })),
          deps,
        },
      );
      expect(searched.error).toBeUndefined();
      const searchResult = JSON.parse(
        (searched.result as { content: Array<{ text: string }> }).content[0]?.text ?? "{}",
      ) as { results: Array<{ fileId: string; snippet: string }> };
      expect(searchResult.results[0]?.fileId).toBe("doc_1");
      expect(searchResult.results[0]?.snippet).toContain("searchable agent context");

      vi.stubGlobal(
        "fetch",
        vi.fn(async () => Response.json({ error: { message: "not found" } }, { status: 404 })),
      );
      const inaccessibleSearch = await handleMcp(
        {
          jsonrpc: "2.0",
          id: 21,
          method: "tools/call",
          params: {
            name: "pact.drive.search",
            arguments: { query: "searchable agent context", limit: 3 },
          },
        },
        ctx,
        {
          audience: env.MCP_AUDIENCE,
          verify: vi.fn(async () => ({ allow: true, reasons: [] })),
          deps,
        },
      );
      expect(inaccessibleSearch.error).toBeUndefined();
      const inaccessibleSearchResult = JSON.parse(
        (inaccessibleSearch.result as { content: Array<{ text: string }> }).content[0]?.text ??
          "{}",
      ) as { results: unknown[] };
      expect(inaccessibleSearchResult.results).toEqual([]);

      const otherUserSearch = await handleMcp(
        {
          jsonrpc: "2.0",
          id: 20,
          method: "tools/call",
          params: {
            name: "pact.drive.search",
            arguments: { query: "searchable agent context", limit: 3 },
          },
        },
        {
          ...ctx,
          userId: "00000000-0000-0000-0000-000000000099",
          email: "bob@example.com",
          token: "token-2",
          jti: "jti-2",
        },
        {
          audience: env.MCP_AUDIENCE,
          verify: vi.fn(async () => ({ allow: true, reasons: [] })),
          deps,
        },
      );
      expect(otherUserSearch.error).toBeUndefined();
      expect(
        (otherUserSearch.result as { content: Array<{ text: string }>; isError?: boolean })
          .content[0]?.text,
      ).toBe("Google Drive is not connected for this user.");
      expect(
        (otherUserSearch.result as { content: Array<{ text: string }>; isError?: boolean }).isError,
      ).toBe(true);
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

  it("routes sd-jwt bearers to verifier redeem and rejects replays", async () => {
    const { env, slug, created } = await setupWithPolicy({
      rules: [{ subject: { kind: "role", value: "admin" }, effect: "allow" }],
    });
    setVerifierEnv(env);

    const adminMintToken = (
      await issueTestToken(issuer, env, {
        workspaceId: created.workspaceId,
        email: "alice@example.com",
        audience: env.ADMIN_AUDIENCE,
      })
    ).token;

    const exportJwk = async (key: CryptoKey): Promise<Ed25519PublicJwk> => {
      const jwk = (await crypto.subtle.exportKey("jwk", key)) as JsonWebKey;
      return { kty: "OKP", crv: "Ed25519", x: jwk.x as string };
    };

    const holder = await generateEd25519Keypair();
    const holderPubJwk = await exportJwk(holder.publicKey);
    const holderThumb = await sdjwt.jwkThumbprint(holderPubJwk);

    const { agentId } = await withWorkspace(adminDb, created.workspaceId, async (tx) => {
      const [agentRow] = await tx
        .insert(agents)
        .values({
          workspaceId: created.workspaceId,
          slug: `mcp-sdjwt-${Date.now().toString(36)}`,
          displayName: "MCP SD-JWT Agent",
          kind: "service",
          ownerUserId: created.adminUserId,
          pubkeyJwk: holderPubJwk,
          pubkeyThumbprint: holderThumb,
        })
        .returning({ id: agents.id });
      if (!agentRow) throw new Error("agent insert failed");
      await tx.insert(agentCapabilityGrants).values({
        workspaceId: created.workspaceId,
        agentId: agentRow.id,
        onBehalfOfUserId: created.adminUserId,
        toolName: "pact.whoami",
        scope: {},
        audience: ["pact-mcp"],
        createdByUserId: created.adminUserId,
      });
      return { agentId: agentRow.id };
    });

    const mintRes = await issuer.request(
      `/v1/agents/${agentId}/capabilities`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          Authorization: `Bearer ${adminMintToken}`,
        },
        body: JSON.stringify({
          on_behalf_of: "alice@example.com",
          tool_name: "pact.whoami",
          scope: {},
          audience: "pact-mcp",
          ttl_seconds: 300,
          max_redeems: 2,
          cnf_jwk: holderPubJwk,
        }),
      },
      env as unknown as Record<string, unknown>,
    );
    expect(mintRes.status).toBe(201);
    const minted = (await mintRes.json()) as { jti: string; sd_jwt: string };

    const sdJwtWithKb = await sdjwt.signKbJwt({
      holderPrivateKey: holder.privateKey,
      sdJwt: minted.sd_jwt,
      audience: "pact-mcp",
      nonce: crypto.randomUUID(),
    });

    const firstCall = await callTool(slug, sdJwtWithKb, env, "pact.whoami");
    const firstBody = (await firstCall.json()) as {
      result?: { content: Array<{ text: string }> };
      error?: { code: number; data?: { reasons: string[]; status?: number } };
    };
    expect(firstBody.error).toBeUndefined();
    expect(firstBody.result?.content[0]?.text).toContain("alice@example.com");

    const replayCall = await callTool(slug, sdJwtWithKb, env, "pact.whoami");
    const replayBody = (await replayCall.json()) as {
      error?: { code: number; data?: { reasons: string[]; status?: number } };
    };
    expect(replayBody.error?.code).toBe(-32001);
    expect(replayBody.error?.data?.reasons).toContain("kb_replay_detected");
    expect(replayBody.error?.data?.status).toBe(410);
  });
});
