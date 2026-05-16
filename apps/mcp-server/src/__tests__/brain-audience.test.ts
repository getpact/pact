import { fromBase64 } from "@getpact/crypto";
import { createClient } from "@getpact/db";
import { workspaces } from "@getpact/db/schema";
import { buildTestEnv, createTestWorkspace, uniqueSlug } from "@getpact/test-helpers";
import { eq, sql } from "drizzle-orm";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import issuer from "../../../../apps/issuer/src/index.js";
import { handleMcp } from "../handler.js";

const url = process.env.DATABASE_URL;
const run = url ? describe : describe.skip;

const PUBLIC_NOTES = [
  "Public Q3 planning brief.",
  "",
  "Anyone in the workspace can read this overview of the planning cycle.",
].join("\n");

const ALICE_NOTES = [
  "Private planning notes for Alice.",
  "",
  "Confidential staffing decisions for the Q3 planning cycle.",
].join("\n");

const BOB_NOTES = [
  "Bob's planning scratch pad.",
  "",
  "Bob's confidential reading list for the Q3 planning cycle.",
].join("\n");

const QUERY = "planning cycle";

const ctxFor = (
  workspaceId: string,
  userId: string,
  email: string,
  groups: string[] = [],
): {
  workspaceId: string;
  userId: string;
  email: string;
  groups: string[];
  roles: string[];
  jti: string;
  token: string;
} => ({
  workspaceId,
  userId,
  email,
  groups,
  roles: ["admin"],
  jti: "jti-audience",
  token: "token-audience",
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

type SearchHit = { source_uri: string };
type SearchBody = { results: SearchHit[] };

const seedAudienceSet = async (
  ctx: ReturnType<typeof ctxFor>,
  deps: {
    databaseUrl: string;
    rawMek: Uint8Array;
    providerConfig: Record<string, string | undefined>;
  },
  idBase: number,
): Promise<void> => {
  await callTool(
    ctx,
    deps,
    "pact.brain.put",
    {
      source_uri: "note://public",
      source_kind: "manual",
      content: PUBLIC_NOTES,
    },
    idBase + 1,
  );
  await callTool(
    ctx,
    deps,
    "pact.brain.put",
    {
      source_uri: "note://alice",
      source_kind: "manual",
      content: ALICE_NOTES,
      audience: ["alice@example.com"],
    },
    idBase + 2,
  );
  await callTool(
    ctx,
    deps,
    "pact.brain.put",
    {
      source_uri: "note://bob",
      source_kind: "manual",
      content: BOB_NOTES,
      audience: ["bob@example.com"],
    },
    idBase + 3,
  );
};

run("brain search audience filter", () => {
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
    const slug = uniqueSlug("audience");
    const created = await createTestWorkspace(issuer, env, {
      slug,
      adminEmail: "alice@example.com",
    });
    cleanup.push(created.workspaceId);
    return { env, created };
  };

  it("alice sees her own chunks plus public, never bob's", async () => {
    if (!pgvectorAvailable) return;
    const { env, created } = await setup();
    const rawMek = fromBase64(env.MEK);
    const deps = {
      databaseUrl: env.DATABASE_URL,
      rawMek,
      providerConfig: { BRAIN_EMBED_STUB: "true" },
    };
    const seedCtx = ctxFor(created.workspaceId, created.adminUserId, "alice@example.com");
    await seedAudienceSet(seedCtx, deps, 100);

    const aliceCtx = ctxFor(created.workspaceId, created.adminUserId, "alice@example.com");
    const body = await callTool(aliceCtx, deps, "pact.brain.search", { query: QUERY, k: 10 }, 110);
    const result = parseResult<SearchBody>(body);
    const uris = new Set(result.results.map((r) => r.source_uri));
    expect(uris.has("note://alice")).toBe(true);
    expect(uris.has("note://public")).toBe(true);
    expect(uris.has("note://bob")).toBe(false);
  });

  it("bob sees his own chunks plus public, never alice's", async () => {
    if (!pgvectorAvailable) return;
    const { env, created } = await setup();
    const rawMek = fromBase64(env.MEK);
    const deps = {
      databaseUrl: env.DATABASE_URL,
      rawMek,
      providerConfig: { BRAIN_EMBED_STUB: "true" },
    };
    const seedCtx = ctxFor(created.workspaceId, created.adminUserId, "alice@example.com");
    await seedAudienceSet(seedCtx, deps, 200);

    const bobCtx = ctxFor(created.workspaceId, created.adminUserId, "bob@example.com");
    const body = await callTool(bobCtx, deps, "pact.brain.search", { query: QUERY, k: 10 }, 210);
    const result = parseResult<SearchBody>(body);
    const uris = new Set(result.results.map((r) => r.source_uri));
    expect(uris.has("note://bob")).toBe(true);
    expect(uris.has("note://public")).toBe(true);
    expect(uris.has("note://alice")).toBe(false);
  });

  it("group membership grants audience visibility", async () => {
    if (!pgvectorAvailable) return;
    const { env, created } = await setup();
    const rawMek = fromBase64(env.MEK);
    const deps = {
      databaseUrl: env.DATABASE_URL,
      rawMek,
      providerConfig: { BRAIN_EMBED_STUB: "true" },
    };
    const seedCtx = ctxFor(created.workspaceId, created.adminUserId, "alice@example.com");
    await callTool(
      seedCtx,
      deps,
      "pact.brain.put",
      {
        source_uri: "note://eng",
        source_kind: "manual",
        content: "Engineering planning cycle review notes for the leadership group.",
        audience: ["group:engineering"],
      },
      301,
    );

    const carolCtx = ctxFor(created.workspaceId, created.adminUserId, "carol@example.com", [
      "group:engineering",
    ]);
    const body = await callTool(
      carolCtx,
      deps,
      "pact.brain.search",
      { query: "engineering planning cycle", k: 10 },
      310,
    );
    const result = parseResult<SearchBody>(body);
    expect(result.results.some((r) => r.source_uri === "note://eng")).toBe(true);
  });

  it("cross-tenant isolation holds even when audience matches", async () => {
    if (!pgvectorAvailable) return;
    const tenantA = await setup();
    const tenantB = await setup();
    const rawMekA = fromBase64(tenantA.env.MEK);
    const rawMekB = fromBase64(tenantB.env.MEK);
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
    const ctxA = ctxFor(
      tenantA.created.workspaceId,
      tenantA.created.adminUserId,
      "alice@example.com",
    );
    const ctxB = ctxFor(
      tenantB.created.workspaceId,
      tenantB.created.adminUserId,
      "alice@example.com",
    );

    await callTool(
      ctxA,
      depsA,
      "pact.brain.put",
      {
        source_uri: "note://tenant-a-alice",
        source_kind: "manual",
        content: ALICE_NOTES,
        audience: ["alice@example.com"],
      },
      401,
    );

    const body = await callTool(ctxB, depsB, "pact.brain.search", { query: QUERY, k: 10 }, 402);
    const result = parseResult<SearchBody>(body);
    const uris = new Set(result.results.map((r) => r.source_uri));
    expect(uris.has("note://tenant-a-alice")).toBe(false);
  });
});
