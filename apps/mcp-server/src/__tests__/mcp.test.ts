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
    MCP_AUDIENCE: "pact-mcp",
  };
};

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
    const env = await buildEnv();
    const slug = `mcp-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const createRes = await issuer.request(
      "/v1/workspaces",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ slug, name: "MCP", adminEmail: "alice@example.com" }),
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
          audience: "pact-mcp",
        }),
      },
      env,
    );
    const issued = (await issueRes.json()) as { token: string };
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
      env,
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

  it("calls pact.whoami and returns claims", async () => {
    const { env, slug, token, created } = await setup();
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
      result: { content: Array<{ type: string; text: string }> };
    };
    const text = body.result.content[0]?.text ?? "";
    const parsed = JSON.parse(text) as {
      workspaceId: string;
      email: string;
      roles: string[];
    };
    expect(parsed.workspaceId).toBe(created.workspaceId);
    expect(parsed.email).toBe("alice@example.com");
    expect(parsed.roles).toEqual(["admin"]);
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
