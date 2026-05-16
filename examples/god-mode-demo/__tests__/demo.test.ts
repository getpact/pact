import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import {
  applyScopeFilter,
  buildAuditChain,
  buildMintBody,
  buildOutput,
  fixtureFallbackHits,
  mintCapabilityLive,
  mintCapabilityStub,
  type ScopedCapability,
  searchBrainLive,
} from "../after.js";
import { buildPutCall, contentForFile, seedAll, seedFile } from "../seed.js";

type DriveFixture = {
  generatedAt: string;
  folders: { id: string; name: string }[];
  files: Array<{
    id: string;
    name: string;
    mimeType: string;
    parents: string[];
    modifiedTime: string;
    size: string;
  }>;
};

const here = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(
  readFileSync(join(here, "..", "drive-fixture.json"), "utf8"),
) as DriveFixture;

const folderXFiles = fixture.files.filter((f) => f.parents.includes("folder_X"));

const okResponse = (body: unknown): Response => {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  }) as unknown as Response;
};

const errResponse = (status: number, body: string): Response =>
  new Response(body, { status }) as unknown as Response;

const makeFetch = (
  handler: (url: string, init: RequestInit) => Promise<Response>,
): typeof fetch => {
  return ((input: unknown, init?: RequestInit) => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.toString()
          : ((input as { url?: string }).url ?? String(input));
    return handler(url, init ?? {});
  }) as typeof fetch;
};

describe("fixture sanity", () => {
  it("has 5000 files and 12 in folder_X", () => {
    expect(fixture.files.length).toBe(5000);
    expect(folderXFiles.length).toBe(12);
  });
});

describe("seed", () => {
  it("derives deterministic content per file", () => {
    const file = folderXFiles[0];
    expect(file).toBeDefined();
    const a = contentForFile(file!);
    const b = contentForFile(file!);
    expect(a).toBe(b);
    expect(a).toContain(file!.id);
    expect(a).toContain("folder_X");
  });

  it("buildPutCall maps a file to a connector page with folder audience", () => {
    const file = folderXFiles[0]!;
    const call = buildPutCall(file);
    expect(call.source_uri).toBe(`gdrive://${file.id}`);
    expect(call.source_kind).toBe("connector");
    expect(call.title).toBe(file.name);
    expect(call.audience).toEqual(["folder_X"]);
    expect(call.content).toBe(contentForFile(file));
  });

  it("seedFile sends a jsonrpc tools/call for pact.brain.put with bearer auth", async () => {
    const file = folderXFiles[0]!;
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const fetchImpl = makeFetch(async (url, init) => {
      calls.push({ url, init });
      return okResponse({
        jsonrpc: "2.0",
        id: 1,
        result: {
          content: [{ type: "text", text: JSON.stringify({ page_id: "p-1", idempotent: false }) }],
        },
      });
    });
    const outcome = await seedFile(
      file,
      { mcpUrl: "http://mcp.local/ws/mcp", token: "test-token", fetchImpl },
      1,
    );
    expect(outcome).toBe("inserted");
    expect(calls).toHaveLength(1);
    const call = calls[0]!;
    expect(call.url).toBe("http://mcp.local/ws/mcp");
    expect(call.init.method).toBe("POST");
    const headers = call.init.headers as Record<string, string>;
    expect(headers["authorization"]).toBe("Bearer test-token");
    expect(headers["content-type"]).toBe("application/json");
    const body = JSON.parse(call.init.body as string) as {
      method: string;
      params: { name: string; arguments: Record<string, unknown> };
    };
    expect(body.method).toBe("tools/call");
    expect(body.params.name).toBe("pact.brain.put");
    expect(body.params.arguments.source_uri).toBe(`gdrive://${file.id}`);
  });

  it("seedFile reports idempotent when the server says so", async () => {
    const fetchImpl = makeFetch(async () =>
      okResponse({
        jsonrpc: "2.0",
        id: 1,
        result: {
          content: [{ type: "text", text: JSON.stringify({ page_id: "p-1", idempotent: true }) }],
        },
      }),
    );
    const outcome = await seedFile(
      folderXFiles[0]!,
      { mcpUrl: "http://mcp.local/ws/mcp", token: "t", fetchImpl },
      1,
    );
    expect(outcome).toBe("idempotent");
  });

  it("seedFile marks failures when the server returns an error", async () => {
    const fetchImpl = makeFetch(async () => errResponse(500, "oops"));
    const outcome = await seedFile(
      folderXFiles[0]!,
      { mcpUrl: "http://mcp.local/ws/mcp", token: "t", fetchImpl },
      1,
    );
    expect(outcome).toBe("failed");
  });

  it("seedAll counts inserts, idempotent hits, and failures across a slice", async () => {
    const subset: DriveFixture = {
      generatedAt: fixture.generatedAt,
      folders: fixture.folders,
      files: fixture.files.slice(0, 4),
    };
    let n = 0;
    const fetchImpl = makeFetch(async () => {
      n += 1;
      if (n === 1) {
        return okResponse({
          jsonrpc: "2.0",
          id: n,
          result: {
            content: [{ type: "text", text: JSON.stringify({ page_id: "p", idempotent: false }) }],
          },
        });
      }
      if (n === 2) {
        return okResponse({
          jsonrpc: "2.0",
          id: n,
          result: {
            content: [{ type: "text", text: JSON.stringify({ page_id: "p", idempotent: true }) }],
          },
        });
      }
      if (n === 3) {
        return okResponse({
          jsonrpc: "2.0",
          id: n,
          result: { isError: true, content: [{ type: "text", text: "boom" }] },
        });
      }
      return okResponse({
        jsonrpc: "2.0",
        id: n,
        result: {
          content: [{ type: "text", text: JSON.stringify({ page_id: "p", idempotent: true }) }],
        },
      });
    });
    const result = await seedAll(subset, {
      mcpUrl: "http://mcp.local/ws/mcp",
      token: "t",
      fetchImpl,
    });
    expect(result.total).toBe(4);
    expect(result.inserted).toBe(1);
    expect(result.idempotent).toBe(2);
    expect(result.failed).toBe(1);
  });
});

describe("mintCapability", () => {
  it("buildMintBody maps to the issuer wire shape", () => {
    const body = buildMintBody({
      agentId: "agent-uuid",
      onBehalfOf: "user@example.com",
      tool: "pact.brain.search",
      scope: { folder_id: ["folder_X"] },
      audience: "mcp-server.local",
      ttlSeconds: 300,
      maxRedeems: 5,
    });
    expect(body).toEqual({
      on_behalf_of: "user@example.com",
      tool_name: "pact.brain.search",
      scope: { folder_id: ["folder_X"] },
      audience: "mcp-server.local",
      ttl_seconds: 300,
      max_redeems: 5,
    });
  });

  it("mintCapabilityLive POSTs to /v1/agents/:id/capabilities and adapts the response", async () => {
    const issuedExp = Math.floor(Date.now() / 1000) + 300;
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const fetchImpl = makeFetch(async (url, init) => {
      calls.push({ url, init });
      return okResponse({
        jti: "00000000-0000-0000-0000-00000000aaaa",
        sd_jwt: "head.body.sig~disclosure1~disclosure2~",
        exp: issuedExp,
        cnf_thumbprint: "",
      });
    });
    const cap = await mintCapabilityLive(
      {
        agentId: "agent-uuid",
        onBehalfOf: "user@example.com",
        tool: "pact.brain.search",
        scope: { folder_id: ["folder_X"] },
        audience: "mcp-server.local",
        ttlSeconds: 300,
        maxRedeems: 5,
      },
      { apiBase: "http://issuer.local", adminToken: "admin", fetchImpl },
    );
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe("http://issuer.local/v1/agents/agent-uuid/capabilities");
    const headers = calls[0]!.init.headers as Record<string, string>;
    expect(headers["authorization"]).toBe("Bearer admin");
    expect(cap.jti).toBe("00000000-0000-0000-0000-00000000aaaa");
    expect(cap.token).toBe("head.body.sig~disclosure1~disclosure2~");
    expect(cap.source).toBe("live");
    expect(cap.scope.folder_id).toEqual(["folder_X"]);
  });

  it("mintCapabilityStub returns a structurally sd-jwt-shaped token", async () => {
    const cap = await mintCapabilityStub({
      agentId: "stub-agent",
      onBehalfOf: "demo-user@example.com",
      tool: "pact.brain.search",
      scope: { folder_id: ["folder_X"] },
      audience: "mcp-server.local",
      ttlSeconds: 300,
      maxRedeems: 5,
    });
    expect(cap.source).toBe("stub");
    expect(cap.token).toMatch(/^[^.]+\.[^.]+\.[^~]+~/);
    expect(cap.token.endsWith("~")).toBe(true);
  });
});

describe("brain.search call shape", () => {
  it("sends pact.brain.search with query and k via jsonrpc", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const fetchImpl = makeFetch(async (url, init) => {
      calls.push({ url, init });
      return okResponse({
        jsonrpc: "2.0",
        id: 100,
        result: {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                results: folderXFiles.map((f) => ({
                  source_uri: `gdrive://${f.id}`,
                  snippet: f.name,
                  score: 0.5,
                  page_id: "p",
                  chunk_id: "c",
                })),
                meta: { vector_enabled: true, embed_model: "stub:deterministic" },
              }),
            },
          ],
        },
      });
    });
    const hits = await searchBrainLive("Q3 planning notes", 12, {
      mcpUrl: "http://mcp.local/ws/mcp",
      token: "user-token",
      fetchImpl,
    });
    expect(calls).toHaveLength(1);
    const body = JSON.parse(calls[0]!.init.body as string) as {
      method: string;
      params: { name: string; arguments: { query: string; k: number } };
    };
    expect(body.method).toBe("tools/call");
    expect(body.params.name).toBe("pact.brain.search");
    expect(body.params.arguments).toEqual({ query: "Q3 planning notes", k: 12 });
    expect(hits).toHaveLength(12);
    expect(hits[0]!.source_uri.startsWith("gdrive://")).toBe(true);
  });
});

describe("scope filtering", () => {
  const cap: ScopedCapability = {
    jti: "j",
    token: "t",
    scope: { folder_id: ["folder_X"] },
    issuedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    audience: "mcp-server.local",
    source: "stub",
  };

  it("applyScopeFilter is retained for back-compat but the live path no longer calls it", () => {
    const allHits = fixture.files.slice(0, 200).map((f) => ({
      source_uri: `gdrive://${f.id}`,
      snippet: "",
      score: 0,
      page_id: null,
      chunk_id: null,
    }));
    const filtered = applyScopeFilter(allHits, cap, fixture);
    for (const hit of filtered) {
      const id = hit.source_uri.replace("gdrive://", "");
      const file = fixture.files.find((f) => f.id === id);
      expect(file).toBeDefined();
      expect(file!.parents.some((p) => cap.scope.folder_id.includes(p))).toBe(true);
    }
  });

  it("fixtureFallbackHits yields exactly 12 files for folder_X", () => {
    const hits = fixtureFallbackHits(cap, fixture, 50);
    expect(hits).toHaveLength(12);
  });

  it("buildOutput reports the same count the demo prints (server-side audience filter)", () => {
    const hits = fixtureFallbackHits(cap, fixture, 50);
    const out = buildOutput(cap, hits, "fixture");
    expect(out.totalFiles).toBe(12);
    expect(out.path).toBe("after");
    expect(out.scope).toEqual({ folder_id: ["folder_X"] });
    expect(out.capabilitySource).toBe("stub");
    expect(out.searchSource).toBe("fixture");
  });

  it("live note advertises server-side audience filtering", () => {
    const liveCap: ScopedCapability = { ...cap, source: "live" };
    const out = buildOutput(liveCap, [], "live");
    expect(out.note).toContain("server-side");
    expect(out.note).toContain("audience");
  });

  it("audit chain records mint and redeem events", () => {
    const audit = buildAuditChain(cap);
    expect(audit.map((e) => e.action)).toEqual([
      "agent.capability.minted",
      "agent.capability.redeemed",
    ]);
    expect(audit.every((e) => e.decision === "allow")).toBe(true);
  });
});

describe("diff math", () => {
  it("before=5000 after=12 yields the documented 99.76% reduction", () => {
    const before = fixture.files.length;
    const after = folderXFiles.length;
    expect(before).toBe(5000);
    expect(after).toBe(12);
    const reductionTenths = Math.round(((before - after) / before) * 10000) / 100;
    expect(reductionTenths).toBeCloseTo(99.76, 2);
  });
});

describe("module entrypoint hygiene", () => {
  it("after.ts and seed.ts can be imported without side effects", async () => {
    const spy = vi.spyOn(process.stdout, "write");
    await import("../after.js");
    await import("../seed.js");
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });
});
