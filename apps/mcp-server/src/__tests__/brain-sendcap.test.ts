import { fromBase64 } from "@getpact/crypto";
import { createClient, withWorkspace } from "@getpact/db";
import { sendCaps, users, workspaces } from "@getpact/db/schema";
import { issuerApp as issuer } from "@getpact/test-harness";
import { buildTestEnv, createTestWorkspace, uniqueSlug } from "@getpact/test-helpers";
import { and, eq, sql } from "drizzle-orm";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { handleMcp } from "../handler.js";

const url = process.env.DATABASE_URL;
const run = url ? describe : describe.skip;

const NOTES = ["Notes for shared brain.", "These mention SendCap consent enforcement."].join("\n");

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

const parseResultText = (body: { result?: unknown; error?: unknown }): string => {
  expect(body.error).toBeUndefined();
  const result = body.result as { content?: Array<{ text?: string }>; isError?: boolean };
  return result?.content?.[0]?.text ?? "";
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

run("brain.put send-cap enforcement", () => {
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
    const created = await createTestWorkspace(issuer, env, {
      slug: uniqueSlug("scbrain"),
      adminEmail: "alice@example.com",
    });
    cleanup.push(created.workspaceId);
    const otherRows = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx
        .insert(users)
        .values({ workspaceId: created.workspaceId, email: "carol@example.com" })
        .returning({ id: users.id }),
    );
    const otherUserId = otherRows[0]?.id as string;
    return { env, created, otherUserId };
  };

  const writeBody = (uri: string, audience: string[]) => ({
    source_uri: uri,
    source_kind: "manual",
    content: NOTES,
    audience,
  });

  it("denies put when audience contains another user without a cap", async () => {
    if (!pgvectorAvailable) return;
    const { env, created, otherUserId } = await setup();
    const deps = {
      databaseUrl: env.DATABASE_URL,
      rawMek: fromBase64(env.MEK),
      providerConfig: { BRAIN_EMBED_STUB: "true" },
    };
    const ctx = ctxFor(created.workspaceId, created.adminUserId);

    const body = await callTool(
      ctx,
      deps,
      "pact.brain.put",
      writeBody("note://needs-cap", [otherUserId]),
      101,
    );
    const text = parseResultText(body);
    expect(text).toContain("send_cap_required");
  });

  it("allows put once a SendCap is issued and consumes a use", async () => {
    if (!pgvectorAvailable) return;
    const { env, created, otherUserId } = await setup();
    const deps = {
      databaseUrl: env.DATABASE_URL,
      rawMek: fromBase64(env.MEK),
      providerConfig: { BRAIN_EMBED_STUB: "true" },
    };
    const ctx = ctxFor(created.workspaceId, created.adminUserId);

    const capRow = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx
        .insert(sendCaps)
        .values({
          workspaceId: created.workspaceId,
          issuerUserId: otherUserId,
          granteeUserId: created.adminUserId,
          maxUses: 2,
        })
        .returning({ id: sendCaps.id }),
    );
    const capId = capRow[0]?.id as string;

    const ok = await callTool(
      ctx,
      deps,
      "pact.brain.put",
      writeBody("note://with-cap", [otherUserId]),
      102,
    );
    const text = parseResultText(ok);
    expect(text).toContain("page_id");

    const afterOne = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx.select().from(sendCaps).where(eq(sendCaps.id, capId)),
    );
    expect(afterOne[0]?.usedCount).toBe(1);

    const ok2 = await callTool(
      ctx,
      deps,
      "pact.brain.put",
      writeBody("note://with-cap-2", [otherUserId]),
      103,
    );
    expect(parseResultText(ok2)).toContain("page_id");

    const exhausted = await callTool(
      ctx,
      deps,
      "pact.brain.put",
      writeBody("note://exhausted", [otherUserId]),
      104,
    );
    expect(parseResultText(exhausted)).toContain("send_cap_required");
  });

  it("denies after the SendCap is revoked", async () => {
    if (!pgvectorAvailable) return;
    const { env, created, otherUserId } = await setup();
    const deps = {
      databaseUrl: env.DATABASE_URL,
      rawMek: fromBase64(env.MEK),
      providerConfig: { BRAIN_EMBED_STUB: "true" },
    };
    const ctx = ctxFor(created.workspaceId, created.adminUserId);

    const capRow = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx
        .insert(sendCaps)
        .values({
          workspaceId: created.workspaceId,
          issuerUserId: otherUserId,
          granteeUserId: created.adminUserId,
        })
        .returning({ id: sendCaps.id }),
    );
    const capId = capRow[0]?.id as string;

    await withWorkspace(adminDb, created.workspaceId, (tx) =>
      tx
        .update(sendCaps)
        .set({ revokedAt: new Date(), revokedReason: "test" })
        .where(and(eq(sendCaps.workspaceId, created.workspaceId), eq(sendCaps.id, capId))),
    );

    const body = await callTool(
      ctx,
      deps,
      "pact.brain.put",
      writeBody("note://revoked", [otherUserId]),
      105,
    );
    expect(parseResultText(body)).toContain("send_cap_required");
  });

  it("bypasses the check when actor writes to self or to group/tier", async () => {
    if (!pgvectorAvailable) return;
    const { env, created } = await setup();
    const deps = {
      databaseUrl: env.DATABASE_URL,
      rawMek: fromBase64(env.MEK),
      providerConfig: { BRAIN_EMBED_STUB: "true" },
    };
    const ctx = ctxFor(created.workspaceId, created.adminUserId);

    const self = await callTool(
      ctx,
      deps,
      "pact.brain.put",
      writeBody("note://self", [created.adminUserId]),
      111,
    );
    expect(parseResultText(self)).toContain("page_id");

    const group = await callTool(
      ctx,
      deps,
      "pact.brain.put",
      writeBody("note://group", ["tier:work", "group:eng"]),
      112,
    );
    expect(parseResultText(group)).toContain("page_id");
  });
});
