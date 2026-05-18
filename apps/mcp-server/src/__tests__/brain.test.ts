import { fromBase64 } from "@getpact/crypto";
import { createClient, withWorkspace } from "@getpact/db";
import {
  brainChunkEmbeddings,
  brainChunks,
  brainPages,
  workspaceSigningKeys,
  workspaces,
} from "@getpact/db/schema";
import { issuerApp as issuer } from "@getpact/test-harness";
import {
  buildTestEnv,
  createTestWorkspace,
  issueTestToken,
  uniqueSlug,
} from "@getpact/test-helpers";
import { and, eq, sql } from "drizzle-orm";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { handleMcp } from "../handler.js";

const url = process.env.DATABASE_URL;
const run = url ? describe : describe.skip;

const NOTES_ONE = [
  "Pact brain ingestion notes.",
  "",
  "Brandon wants brain memory tools so agents can search prior conversations.",
  "The retrieval layer needs to return relevant snippets with provenance pointers.",
].join("\n");

const NOTES_TWO = "Completely unrelated text about cooking pasta and tomato sauce.";

const ctxFor = (workspaceId: string, userId: string) => ({
  workspaceId,
  userId,
  email: "alice@example.com",
  groups: [],
  roles: ["admin"],
  jti: "jti-brain",
  token: "token-brain",
});

const callTool = (
  ctx: ReturnType<typeof ctxFor>,
  deps: {
    databaseUrl: string;
    rawMek?: Uint8Array;
    providerConfig?: Record<string, string | undefined>;
  },
  name: string,
  args: Record<string, unknown>,
  id = 1,
) =>
  handleMcp({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } }, ctx, {
    audience: "pact-mcp",
    verify: vi.fn(async () => ({ allow: true, reasons: [] })),
    deps,
  });

const parseResult = <T>(body: { result?: unknown; error?: unknown }): T => {
  expect(body.error).toBeUndefined();
  const result = body.result as { content?: Array<{ text?: string }> } | undefined;
  const text = result?.content?.[0]?.text;
  if (!text) throw new Error("missing tool result text");
  return JSON.parse(text) as T;
};

let pgvectorAvailable = false;

const checkPgvector = async (databaseUrl: string): Promise<boolean> => {
  const db = createClient(databaseUrl);
  try {
    await db.execute(sql`SELECT '[0,0,0]'::vector(3) AS v`);
    return true;
  } catch {
    return false;
  }
};

run("brain mcp tools", () => {
  beforeAll(async () => {
    pgvectorAvailable = await checkPgvector(url as string);
  });

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
    const slug = uniqueSlug("brain");
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

  it("puts a page and round-trips a hybrid search", async () => {
    if (!pgvectorAvailable) return;
    const { env, created } = await setup();
    const rawMek = fromBase64(env.MEK);
    const ctx = ctxFor(created.workspaceId, created.adminUserId);
    const deps = {
      databaseUrl: env.DATABASE_URL,
      rawMek,
      providerConfig: { BRAIN_EMBED_STUB: "true" },
    };

    const putBody = await callTool(
      ctx,
      deps,
      "pact.brain.put",
      {
        source_uri: "note://round-trip",
        source_kind: "manual",
        content: NOTES_ONE,
      },
      11,
    );
    const putResult = parseResult<{ page_id: string; chunks_created: number; idempotent: boolean }>(
      putBody,
    );
    expect(putResult.idempotent).toBe(false);
    expect(putResult.chunks_created).toBeGreaterThan(0);
    expect(putResult.page_id).toMatch(/^[0-9a-f-]{36}$/);

    const searchBody = await callTool(
      ctx,
      deps,
      "pact.brain.search",
      { query: "agents search prior conversations", k: 5 },
      12,
    );
    const searchResult = parseResult<{
      results: Array<{
        page_id: string | null;
        source_uri: string;
        chunk_id: string | null;
        snippet: string;
        score: number;
        provenance: {
          source_uri: string;
          chunk_index: number;
          chunk_id: string | null;
          kid?: string;
          signature?: string;
        };
      }>;
      meta: { signing_kid: string | null };
    }>(searchBody);
    expect(searchResult.results.length).toBeGreaterThan(0);
    const top = searchResult.results[0];
    expect(top?.source_uri).toBe("note://round-trip");
    expect(top?.chunk_id).toMatch(/^[0-9a-f-]{36}$/);
    expect(top?.page_id).toBe(putResult.page_id);
    expect(top?.provenance.source_uri).toBe("note://round-trip");
    expect(typeof top?.provenance.chunk_index).toBe("number");

    const provenanceRows = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx
        .select({ id: workspaceSigningKeys.id })
        .from(workspaceSigningKeys)
        .where(
          and(
            eq(workspaceSigningKeys.workspaceId, created.workspaceId),
            eq(workspaceSigningKeys.kind, "provenance"),
          ),
        ),
    );
    const auditRows = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx
        .select({ id: workspaceSigningKeys.id })
        .from(workspaceSigningKeys)
        .where(
          and(
            eq(workspaceSigningKeys.workspaceId, created.workspaceId),
            eq(workspaceSigningKeys.kind, "audit"),
          ),
        ),
    );
    expect(provenanceRows.length).toBe(1);
    expect(auditRows.length).toBe(1);
    const provenanceKid = provenanceRows[0]?.id;
    const auditKid = auditRows[0]?.id;
    expect(provenanceKid).toBeDefined();
    expect(auditKid).toBeDefined();
    expect(provenanceKid).not.toBe(auditKid);
    expect(top?.provenance.kid).toBe(provenanceKid);
    expect(searchResult.meta.signing_kid).toBe(provenanceKid);
  });

  it("is idempotent when the same content is put twice", async () => {
    if (!pgvectorAvailable) return;
    const { env, created } = await setup();
    const rawMek = fromBase64(env.MEK);
    const ctx = ctxFor(created.workspaceId, created.adminUserId);
    const deps = {
      databaseUrl: env.DATABASE_URL,
      rawMek,
      providerConfig: { BRAIN_EMBED_STUB: "true" },
    };

    const first = parseResult<{ page_id: string; idempotent: boolean; chunks_created: number }>(
      await callTool(
        ctx,
        deps,
        "pact.brain.put",
        {
          source_uri: "note://idem",
          source_kind: "manual",
          content: NOTES_ONE,
        },
        21,
      ),
    );
    const second = parseResult<{ page_id: string; idempotent: boolean; chunks_created: number }>(
      await callTool(
        ctx,
        deps,
        "pact.brain.put",
        {
          source_uri: "note://idem",
          source_kind: "manual",
          content: NOTES_ONE,
        },
        22,
      ),
    );

    expect(second.idempotent).toBe(true);
    expect(second.page_id).toBe(first.page_id);
    expect(second.chunks_created).toBe(0);

    const pages = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx.select().from(brainPages).where(eq(brainPages.workspaceId, created.workspaceId)),
    );
    expect(pages.length).toBe(1);

    const chunkRows = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx.select().from(brainChunks).where(eq(brainChunks.workspaceId, created.workspaceId)),
    );
    expect(chunkRows.length).toBe(first.chunks_created);

    const embeddingRows = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx
        .select()
        .from(brainChunkEmbeddings)
        .where(eq(brainChunkEmbeddings.workspaceId, created.workspaceId)),
    );
    expect(embeddingRows.length).toBe(first.chunks_created);
  });

  it("isolates pages across tenants", async () => {
    if (!pgvectorAvailable) return;
    const tenantA = await setup();
    const tenantB = await setup();
    const rawMekA = fromBase64(tenantA.env.MEK);
    const rawMekB = fromBase64(tenantB.env.MEK);
    const ctxA = ctxFor(tenantA.created.workspaceId, tenantA.created.adminUserId);
    const ctxB = ctxFor(tenantB.created.workspaceId, tenantB.created.adminUserId);

    const depsA = {
      databaseUrl: tenantA.env.DATABASE_URL,
      rawMek: rawMekA,
      providerConfig: { BRAIN_EMBED_STUB: "true" },
    };
    const depsB = {
      databaseUrl: tenantB.env.DATABASE_URL,
      rawMek: rawMekB,
      providerConfig: { BRAIN_EMBED_STUB: "true" },
    };

    await callTool(
      ctxA,
      depsA,
      "pact.brain.put",
      {
        source_uri: "note://tenant-a",
        source_kind: "manual",
        content: NOTES_ONE,
      },
      31,
    );
    await callTool(
      ctxB,
      depsB,
      "pact.brain.put",
      {
        source_uri: "note://tenant-b",
        source_kind: "manual",
        content: NOTES_TWO,
      },
      32,
    );

    const searchA = parseResult<{ results: Array<{ source_uri: string }> }>(
      await callTool(ctxA, depsA, "pact.brain.search", { query: "agents", k: 5 }, 33),
    );
    expect(searchA.results.every((r) => r.source_uri === "note://tenant-a")).toBe(true);

    const searchB = parseResult<{ results: Array<{ source_uri: string }> }>(
      await callTool(ctxB, depsB, "pact.brain.search", { query: "pasta", k: 5 }, 34),
    );
    expect(searchB.results.every((r) => r.source_uri === "note://tenant-b")).toBe(true);
  });
});

describe("brain tools input validation", () => {
  const ctx = ctxFor("00000000-0000-0000-0000-000000000001", "user-1");
  const deps = { databaseUrl: "postgres://unused" };

  it("rejects missing fields on pact.brain.put", async () => {
    const body = await handleMcp(
      {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "pact.brain.put", arguments: { source_uri: "note://x" } },
      },
      ctx,
      {
        audience: "pact-mcp",
        verify: vi.fn(async () => ({ allow: true, reasons: [] })),
        deps,
      },
    );
    expect(body.result).toEqual({
      content: [{ type: "text", text: "source_uri, source_kind, content are required" }],
      isError: true,
    });
  });

  it("rejects empty query on pact.brain.search", async () => {
    const body = await handleMcp(
      {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: "pact.brain.search", arguments: {} },
      },
      ctx,
      {
        audience: "pact-mcp",
        verify: vi.fn(async () => ({ allow: true, reasons: [] })),
        deps,
      },
    );
    expect(body.result).toEqual({
      content: [{ type: "text", text: "query is required" }],
      isError: true,
    });
  });
});
