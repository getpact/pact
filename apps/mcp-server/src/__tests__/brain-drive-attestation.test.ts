import {
  computeDriveContentHash,
  type DriveAttestation,
  serializeDriveAttestationPayload,
  signDriveAttestation,
} from "@getpact/adapter-drive/attestation";
import { fromBase64 } from "@getpact/crypto";
import { createClient, withWorkspace } from "@getpact/db";
import { workspaces } from "@getpact/db/schema";
import { loadActiveHmacKey } from "@getpact/keystore";
import { issuerApp as issuer } from "@getpact/test-harness";
import { buildTestEnv, createTestWorkspace, uniqueSlug } from "@getpact/test-helpers";
import { eq, sql } from "drizzle-orm";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { handleMcp } from "../handler.js";

const url = process.env.DATABASE_URL;
const run = url ? describe : describe.skip;

const NOTES = [
  "Drive ingest payload for HMAC fencing.",
  "This page is supposed to come from a real connector.",
].join("\n");

const ctxFor = (workspaceId: string, userId: string) => ({
  workspaceId,
  userId,
  email: "alice@example.com",
  groups: [],
  roles: ["admin"],
  jti: "jti-drive-att",
  token: "token-drive-att",
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

run("brain.put drive attestation fence", () => {
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
      slug: uniqueSlug("drv"),
      adminEmail: "alice@example.com",
    });
    cleanup.push(created.workspaceId);
    const rawMek = fromBase64(env.MEK);
    const keyRow = await withWorkspace(adminDb, created.workspaceId, (tx) =>
      loadActiveHmacKey(tx, created.workspaceId, "adapter-drive", rawMek),
    );
    return { env, created, rawMek, keyBytes: keyRow.keyBytes };
  };

  const baseBody = (
    sourceUri: string,
    audience: string[],
    attestation: DriveAttestation | undefined,
  ): Record<string, unknown> => {
    const body: Record<string, unknown> = {
      source_uri: sourceUri,
      source_kind: "connector",
      content: NOTES,
      audience,
    };
    if (attestation) body.drive_attestation = attestation;
    return body;
  };

  it("accepts a drive page with a valid attestation", async () => {
    if (!pgvectorAvailable) return;
    const { env, created, rawMek, keyBytes } = await setup();
    const deps = {
      databaseUrl: env.DATABASE_URL,
      rawMek,
      providerConfig: { BRAIN_EMBED_STUB: "true" },
    };
    const ctx = ctxFor(created.workspaceId, created.adminUserId);
    const sourceUri = "gdrive://file_ok_1";
    const audience = ["gdrive_owner:alice@example.com"];
    const attestation = await signDriveAttestation({
      keyBytes,
      sourceUri,
      content: NOTES,
      audience,
    });
    const body = await callTool(
      ctx,
      deps,
      "pact.brain.put",
      baseBody(sourceUri, audience, attestation),
      201,
    );
    expect(parseResultText(body)).toContain("page_id");
  });

  it("rejects a drive page when the attestation is missing", async () => {
    if (!pgvectorAvailable) return;
    const { env, created, rawMek } = await setup();
    const deps = {
      databaseUrl: env.DATABASE_URL,
      rawMek,
      providerConfig: { BRAIN_EMBED_STUB: "true" },
    };
    const ctx = ctxFor(created.workspaceId, created.adminUserId);
    const body = await callTool(
      ctx,
      deps,
      "pact.brain.put",
      baseBody("gdrive://file_missing", ["gdrive_owner:alice@example.com"], undefined),
      202,
    );
    expect(parseResultText(body)).toContain("drive_attestation_invalid");
    expect(parseResultText(body)).toContain("missing");
  });

  it("rejects when the mac does not verify under the workspace key", async () => {
    if (!pgvectorAvailable) return;
    const { env, created, rawMek } = await setup();
    const deps = {
      databaseUrl: env.DATABASE_URL,
      rawMek,
      providerConfig: { BRAIN_EMBED_STUB: "true" },
    };
    const ctx = ctxFor(created.workspaceId, created.adminUserId);
    const sourceUri = "gdrive://file_badmac";
    const audience = ["gdrive_owner:alice@example.com"];
    const wrongKey = new Uint8Array(32);
    for (let i = 0; i < wrongKey.length; i += 1) wrongKey[i] = i + 1;
    const attestation = await signDriveAttestation({
      keyBytes: wrongKey,
      sourceUri,
      content: NOTES,
      audience,
    });
    const body = await callTool(
      ctx,
      deps,
      "pact.brain.put",
      baseBody(sourceUri, audience, attestation),
      203,
    );
    expect(parseResultText(body)).toContain("mac_mismatch");
  });

  it("rejects when the payload source_uri does not match the request", async () => {
    if (!pgvectorAvailable) return;
    const { env, created, rawMek, keyBytes } = await setup();
    const deps = {
      databaseUrl: env.DATABASE_URL,
      rawMek,
      providerConfig: { BRAIN_EMBED_STUB: "true" },
    };
    const ctx = ctxFor(created.workspaceId, created.adminUserId);
    const audience = ["gdrive_owner:alice@example.com"];
    const attestation = await signDriveAttestation({
      keyBytes,
      sourceUri: "gdrive://file_other",
      content: NOTES,
      audience,
    });
    const body = await callTool(
      ctx,
      deps,
      "pact.brain.put",
      baseBody("gdrive://file_request", audience, attestation),
      204,
    );
    expect(parseResultText(body)).toContain("source_uri_mismatch");
  });

  it("rejects when the request audience differs from the signed audience", async () => {
    if (!pgvectorAvailable) return;
    const { env, created, rawMek, keyBytes } = await setup();
    const deps = {
      databaseUrl: env.DATABASE_URL,
      rawMek,
      providerConfig: { BRAIN_EMBED_STUB: "true" },
    };
    const ctx = ctxFor(created.workspaceId, created.adminUserId);
    const sourceUri = "gdrive://file_aud";
    const signedAudience = ["gdrive_owner:alice@example.com"];
    const requestAudience = ["gdrive_owner:bob@example.com"];
    const attestation = await signDriveAttestation({
      keyBytes,
      sourceUri,
      content: NOTES,
      audience: signedAudience,
    });
    const body = await callTool(
      ctx,
      deps,
      "pact.brain.put",
      baseBody(sourceUri, requestAudience, attestation),
      205,
    );
    expect(parseResultText(body)).toContain("audience_mismatch");
  });

  it("rejects when issued_at is outside the allowed skew window", async () => {
    if (!pgvectorAvailable) return;
    const { env, created, rawMek, keyBytes } = await setup();
    const deps = {
      databaseUrl: env.DATABASE_URL,
      rawMek,
      providerConfig: { BRAIN_EMBED_STUB: "true" },
    };
    const ctx = ctxFor(created.workspaceId, created.adminUserId);
    const sourceUri = "gdrive://file_stale";
    const audience = ["gdrive_owner:alice@example.com"];
    const stale = Math.floor(Date.now() / 1000) - 60 * 60;
    const attestation = await signDriveAttestation({
      keyBytes,
      sourceUri,
      content: NOTES,
      audience,
      issuedAt: stale,
    });
    const body = await callTool(
      ctx,
      deps,
      "pact.brain.put",
      baseBody(sourceUri, audience, attestation),
      206,
    );
    expect(parseResultText(body)).toContain("issued_at_out_of_window");
  });

  it("rejects when the content does not match the attested hash", async () => {
    if (!pgvectorAvailable) return;
    const { env, created, rawMek, keyBytes } = await setup();
    const deps = {
      databaseUrl: env.DATABASE_URL,
      rawMek,
      providerConfig: { BRAIN_EMBED_STUB: "true" },
    };
    const ctx = ctxFor(created.workspaceId, created.adminUserId);
    const sourceUri = "gdrive://file_tampered";
    const audience = ["gdrive_owner:alice@example.com"];
    const attestation = await signDriveAttestation({
      keyBytes,
      sourceUri,
      content: "ORIGINAL CONTENT THE ADAPTER OBSERVED",
      audience,
    });
    const body = await callTool(
      ctx,
      deps,
      "pact.brain.put",
      {
        source_uri: sourceUri,
        source_kind: "connector",
        content: NOTES,
        audience,
        drive_attestation: attestation,
      },
      207,
    );
    expect(parseResultText(body)).toContain("content_hash_mismatch");
  });

  it("does not require an attestation for non-drive source uris", async () => {
    if (!pgvectorAvailable) return;
    const { env, created, rawMek } = await setup();
    const deps = {
      databaseUrl: env.DATABASE_URL,
      rawMek,
      providerConfig: { BRAIN_EMBED_STUB: "true" },
    };
    const ctx = ctxFor(created.workspaceId, created.adminUserId);
    const body = await callTool(
      ctx,
      deps,
      "pact.brain.put",
      {
        source_uri: "note://manual-write",
        source_kind: "manual",
        content: NOTES,
      },
      208,
    );
    expect(parseResultText(body)).toContain("page_id");
  });

  it("matches the expected payload serialization shape", async () => {
    const sorted = serializeDriveAttestationPayload({
      source_uri: "gdrive://x",
      content_hash: await computeDriveContentHash("hello"),
      audience: ["b", "a"],
      issued_at: 1700000000,
    });
    const parsed = JSON.parse(sorted) as {
      audience: string[];
      issued_at: number;
      source_uri: string;
      content_hash: string;
    };
    expect(parsed.audience).toEqual(["a", "b"]);
    expect(parsed.source_uri).toBe("gdrive://x");
    expect(parsed.issued_at).toBe(1700000000);
    expect(parsed.content_hash).toMatch(/^[a-f0-9]{64}$/);
  });
});
