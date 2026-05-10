import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { createClient, withWorkspace } from "@getpact/db";
import { policies, workspaces } from "@getpact/db/schema";
import {
  buildTestEnv,
  createTestWorkspace,
  issueTestToken,
  uniqueSlug,
} from "@getpact/test-helpers";
import { eq } from "drizzle-orm";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import issuer from "../../../../apps/issuer/src/index.js";
import verifier from "../../../../apps/verifier/src/index.js";
import app from "../index.js";

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
          const init: RequestInit = {
            method,
            headers: { "content-type": "application/json" },
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

  it("calls verifier and runs tool when policy allows", async () => {
    const { env, slug, token } = await setupWithPolicy({
      rules: [{ subject: { kind: "role", value: "admin" }, effect: "allow" }],
    });

    proxyEnv = {
      DATABASE_URL: env.DATABASE_URL,
      MEK: env.MEK,
      ISSUER_BASE_URL: env.ISSUER_BASE_URL,
    };
    const res = await app.request(
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
          params: { name: "pact.whoami", arguments: {} },
        }),
      },
      {
        DATABASE_URL: env.DATABASE_URL,
        ISSUER_BASE_URL: env.ISSUER_BASE_URL,
        VERIFIER_URL: verifierUrl,
        MCP_AUDIENCE: "pact-mcp",
      },
    );
    const body = (await res.json()) as {
      result?: { content: Array<{ text: string }> };
      error?: unknown;
    };
    expect(body.error).toBeUndefined();
    expect(body.result?.content[0]?.text).toContain("alice@example.com");
  });

  it("denies tool when policy denies", async () => {
    const { env, slug, token } = await setupWithPolicy({
      rules: [{ subject: { kind: "role", value: "admin" }, effect: "deny" }],
    });

    proxyEnv = {
      DATABASE_URL: env.DATABASE_URL,
      MEK: env.MEK,
      ISSUER_BASE_URL: env.ISSUER_BASE_URL,
    };
    const res = await app.request(
      `/${slug}/mcp`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 2,
          method: "tools/call",
          params: { name: "pact.whoami", arguments: {} },
        }),
      },
      {
        DATABASE_URL: env.DATABASE_URL,
        ISSUER_BASE_URL: env.ISSUER_BASE_URL,
        VERIFIER_URL: verifierUrl,
        MCP_AUDIENCE: "pact-mcp",
      },
    );
    const body = (await res.json()) as { error?: { code: number; data?: { reasons: string[] } } };
    expect(body.error?.code).toBe(-32001);
    expect(body.error?.data?.reasons).toBeDefined();
  });
});
