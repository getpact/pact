import { type Adapter, type AdapterTool, json, type ToolDeps } from "@getpact/adapter-sdk";
import { writeEvent } from "@getpact/audit";
import { chunkText } from "@getpact/brain-core/chunkers";
import { hybridSearch } from "@getpact/brain-core/search";
import { isUuid } from "@getpact/core";
import { createClient, type DbClient, type Tx, withWorkspace } from "@getpact/db";
import {
  brainChunkEmbeddings,
  brainChunks,
  brainPages,
  sendCaps,
  workspaces,
} from "@getpact/db/schema";
import { loadActiveSigningKey } from "@getpact/keystore";
import { and, eq, gt, isNull, or, sql } from "drizzle-orm";
import { BrainAdapter } from "../brain-adapter.js";

const EMBED_DIMS = 1536;
const OPENAI_EMBED_URL = "https://api.openai.com/v1/embeddings";
const MAX_CONTENT_BYTES = 1_000_000;
const MAX_CHUNKS_PER_PAGE = 500;
const SEARCH_MAX_K = 50;
const SEARCH_DEFAULT_K = 10;
const SEARCH_QUERY_MAX_CHARS = 500;
const EMBED_BATCH_SIZE = 32;

type EmbedProvider = (texts: string[]) => Promise<Float32Array[]>;

const sha256Bytes = async (value: string): Promise<Buffer> => {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Buffer.from(new Uint8Array(digest));
};

const stringInput = (input: unknown, key: string): string | undefined => {
  if (!input || typeof input !== "object") return undefined;
  const value = (input as Record<string, unknown>)[key];
  return typeof value === "string" && value.length > 0 ? value : undefined;
};

const stringArrayInput = (input: unknown, key: string): string[] | undefined => {
  if (!input || typeof input !== "object") return undefined;
  const value = (input as Record<string, unknown>)[key];
  if (!Array.isArray(value)) return undefined;
  return value.filter((v): v is string => typeof v === "string" && v.length > 0);
};

const numberInput = (input: unknown, key: string): number | undefined => {
  if (!input || typeof input !== "object") return undefined;
  const value = (input as Record<string, unknown>)[key];
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
};

const isValidSourceKind = (value: string | undefined): value is "manual" | "connector" =>
  value === "manual" || value === "connector";

type CallerLike = { email?: string; groups?: string[] };

const callerAudience = (ctx: CallerLike): string[] => {
  const out: string[] = [];
  const seen = new Set<string>();
  const push = (raw: string | undefined) => {
    if (typeof raw !== "string") return;
    const value = raw.trim();
    if (value.length === 0 || seen.has(value)) return;
    seen.add(value);
    out.push(value);
  };
  push(ctx.email);
  if (Array.isArray(ctx.groups)) {
    for (const g of ctx.groups) push(g);
  }
  return out;
};

const openAiEmbedder = (
  apiKey: string,
  model: string,
  providerConfig?: Record<string, string | undefined>,
): EmbedProvider => {
  const baseUrl = providerConfig?.OPENAI_EMBED_URL ?? OPENAI_EMBED_URL;
  return async (texts) => {
    if (texts.length === 0) return [];
    const results: Float32Array[] = [];
    for (let i = 0; i < texts.length; i += EMBED_BATCH_SIZE) {
      const batch = texts.slice(i, i + EMBED_BATCH_SIZE);
      const response = await fetch(baseUrl, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({ model, input: batch, dimensions: EMBED_DIMS }),
        signal: AbortSignal.timeout(30_000),
      });
      if (!response.ok) {
        const text = await response.text().catch(() => "");
        throw new Error(`embedding provider returned ${response.status}: ${text.slice(0, 200)}`);
      }
      const body = (await response.json()) as { data?: Array<{ embedding?: number[] }> };
      if (!body.data || body.data.length !== batch.length) {
        throw new Error("embedding provider returned mismatched batch size");
      }
      for (const item of body.data) {
        const arr = item.embedding ?? [];
        if (arr.length !== EMBED_DIMS) {
          throw new Error(`embedding provider returned ${arr.length} dims, expected ${EMBED_DIMS}`);
        }
        results.push(Float32Array.from(arr));
      }
    }
    return results;
  };
};

const resolveEmbedder = (deps: ToolDeps): { embedder: EmbedProvider; model: string } | null => {
  const provider = deps.providerConfig ?? {};
  const apiKey = provider.OPENAI_API_KEY ?? process.env.OPENAI_API_KEY;
  if (!apiKey) return null;
  const model = provider.BRAIN_EMBED_MODEL ?? "text-embedding-3-small";
  return { embedder: openAiEmbedder(apiKey, model, provider), model: `openai:${model}` };
};

const stubEmbedderFromDeps = (
  deps: ToolDeps,
): { embedder: EmbedProvider; model: string } | null => {
  const provider = deps.providerConfig ?? {};
  if (provider.BRAIN_EMBED_STUB !== "true") return null;
  const dims = EMBED_DIMS;
  const embedder: EmbedProvider = async (texts) => {
    return texts.map((text) => deterministicEmbedding(text, dims));
  };
  return { embedder, model: "stub:deterministic" };
};

const deterministicEmbedding = (text: string, dims: number): Float32Array => {
  const out = new Float32Array(dims);
  let h = 2166136261;
  for (let i = 0; i < text.length; i += 1) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  for (let i = 0; i < dims; i += 1) {
    h = Math.imul(h ^ (i + 1), 16777619);
    out[i] = ((h & 0xffff) / 0xffff) * 2 - 1;
  }
  let mag = 0;
  for (let i = 0; i < dims; i += 1) mag += (out[i] ?? 0) * (out[i] ?? 0);
  mag = Math.sqrt(mag) || 1;
  for (let i = 0; i < dims; i += 1) out[i] = (out[i] ?? 0) / mag;
  return out;
};

const pickEmbedder = (deps: ToolDeps): { embedder: EmbedProvider; model: string } | null => {
  return stubEmbedderFromDeps(deps) ?? resolveEmbedder(deps);
};

const tryAuditBrainWrite = async (
  db: DbClient,
  workspaceId: string,
  rawMek: Uint8Array | undefined,
  payload: {
    pageId: string;
    sourceUri: string;
    chunksCreated: number;
    idempotent: boolean;
    actorUserId: string;
  },
): Promise<void> => {
  if (!rawMek) return;
  try {
    await withWorkspace(db, workspaceId, async (tx) => {
      const [ws] = await tx
        .select({ createdAt: workspaces.createdAt })
        .from(workspaces)
        .where(eq(workspaces.id, workspaceId))
        .limit(1);
      if (!ws) return;
      const auditKey = await loadActiveSigningKey(tx, workspaceId, "audit", rawMek);
      await writeEvent(tx, {
        workspaceId,
        workspaceCreatedAt: ws.createdAt,
        signingKeyId: auditKey.id,
        signingKey: auditKey.privateKey,
        event: {
          actorKind: "user",
          actorId: payload.actorUserId,
          action: "brain.page.write",
          target: { pageId: payload.pageId, sourceUri: payload.sourceUri },
          decision: "allow",
          supporting: {
            chunksCreated: payload.chunksCreated,
            idempotent: payload.idempotent,
          },
        },
      });
    });
  } catch {
    // best-effort
  }
};

type SendCapCheckResult =
  | { kind: "allow" }
  | { kind: "deny"; audienceUserId: string; reason: string };

const isUserAudienceEntry = (entry: string): boolean => {
  if (entry.startsWith("tier:") || entry.startsWith("group:") || entry.startsWith("role:")) {
    return false;
  }
  return isUuid(entry);
};

const consumeSendCapsForAudience = async (
  tx: Tx,
  workspaceId: string,
  actorUserId: string,
  audience: string[],
): Promise<{ result: SendCapCheckResult; consumedCapIds: string[] }> => {
  const consumed: string[] = [];
  const seen = new Set<string>();
  for (const entry of audience) {
    if (!isUserAudienceEntry(entry)) continue;
    if (entry === actorUserId) continue;
    if (seen.has(entry)) continue;
    seen.add(entry);

    const nowSql = sql`NOW()`;
    const [cap] = await tx
      .select({
        id: sendCaps.id,
        maxUses: sendCaps.maxUses,
        usedCount: sendCaps.usedCount,
        expiresAt: sendCaps.expiresAt,
        revokedAt: sendCaps.revokedAt,
      })
      .from(sendCaps)
      .where(
        and(
          eq(sendCaps.workspaceId, workspaceId),
          eq(sendCaps.issuerUserId, entry),
          eq(sendCaps.granteeUserId, actorUserId),
          isNull(sendCaps.revokedAt),
          or(isNull(sendCaps.expiresAt), gt(sendCaps.expiresAt, nowSql)),
          or(isNull(sendCaps.maxUses), gt(sendCaps.maxUses, sendCaps.usedCount)),
        ),
      )
      .orderBy(sendCaps.createdAt)
      .limit(1)
      .for("update", { skipLocked: true });
    if (!cap) {
      return {
        result: { kind: "deny", audienceUserId: entry, reason: "send_cap_required" },
        consumedCapIds: consumed,
      };
    }
    const updated = await tx
      .update(sendCaps)
      .set({ usedCount: sql`${sendCaps.usedCount} + 1` })
      .where(
        and(
          eq(sendCaps.workspaceId, workspaceId),
          eq(sendCaps.id, cap.id),
          isNull(sendCaps.revokedAt),
          or(isNull(sendCaps.maxUses), gt(sendCaps.maxUses, sendCaps.usedCount)),
        ),
      )
      .returning({ id: sendCaps.id });
    if (updated.length === 0) {
      return {
        result: { kind: "deny", audienceUserId: entry, reason: "send_cap_exhausted" },
        consumedCapIds: consumed,
      };
    }
    consumed.push(cap.id);
  }
  return { result: { kind: "allow" }, consumedCapIds: consumed };
};

const trySendCapAudit = async (
  db: DbClient,
  workspaceId: string,
  rawMek: Uint8Array | undefined,
  payload: {
    action: string;
    actorUserId: string;
    target: unknown;
    decision: "allow" | "deny";
    supporting?: unknown;
  },
): Promise<void> => {
  if (!rawMek) return;
  try {
    await withWorkspace(db, workspaceId, async (tx) => {
      const [ws] = await tx
        .select({ createdAt: workspaces.createdAt })
        .from(workspaces)
        .where(eq(workspaces.id, workspaceId))
        .limit(1);
      if (!ws) return;
      const auditKey = await loadActiveSigningKey(tx, workspaceId, "audit", rawMek);
      await writeEvent(tx, {
        workspaceId,
        workspaceCreatedAt: ws.createdAt,
        signingKeyId: auditKey.id,
        signingKey: auditKey.privateKey,
        event: {
          actorKind: "user",
          actorId: payload.actorUserId,
          action: payload.action,
          target: payload.target,
          decision: payload.decision,
          supporting: payload.supporting ?? null,
        },
      });
    });
  } catch {
    // best-effort
  }
};

const findExistingPage = async (
  tx: Tx,
  workspaceId: string,
  sourceUri: string,
  contentHash: Buffer,
): Promise<{ id: string } | null> => {
  const rows = await tx
    .select({ id: brainPages.id })
    .from(brainPages)
    .where(
      and(
        eq(brainPages.workspaceId, workspaceId),
        eq(brainPages.sourceUri, sourceUri),
        eq(brainPages.contentHash, contentHash),
        isNull(brainPages.deletedAt),
      ),
    )
    .limit(1);
  return rows[0] ?? null;
};

const brainPut: AdapterTool = {
  descriptor: {
    name: "pact.brain.put",
    description: "Ingest a document into the brain: chunk, embed, and store for retrieval.",
    inputSchema: {
      type: "object",
      required: ["source_uri", "source_kind", "content"],
      properties: {
        source_uri: { type: "string" },
        source_kind: { type: "string", enum: ["manual", "connector"] },
        content: { type: "string" },
        title: { type: "string" },
        author: { type: "string" },
        audience: { type: "array", items: { type: "string" } },
      },
    },
  },
  authorize: (_input, ctx) => ({
    action: "tool:pact.brain.put",
    resource: `workspace:${ctx.workspaceId}:brain:write`,
  }),
  async handler(input, ctx, deps) {
    const sourceUri = stringInput(input, "source_uri");
    const sourceKind = stringInput(input, "source_kind");
    const content = stringInput(input, "content");
    if (!sourceUri || !sourceKind || !content) {
      return {
        content: [{ type: "text", text: "source_uri, source_kind, content are required" }],
        isError: true,
      };
    }
    if (!isValidSourceKind(sourceKind)) {
      return {
        content: [{ type: "text", text: "source_kind must be manual or connector" }],
        isError: true,
      };
    }
    if (Buffer.byteLength(content, "utf8") > MAX_CONTENT_BYTES) {
      return {
        content: [{ type: "text", text: "content exceeds maximum size" }],
        isError: true,
      };
    }

    const title = stringInput(input, "title") ?? null;
    const audience = stringArrayInput(input, "audience") ?? [];
    const contentHash = await sha256Bytes(content);
    const db = createClient(deps.databaseUrl);

    const existing = await withWorkspace(db, ctx.workspaceId, (tx) =>
      findExistingPage(tx, ctx.workspaceId, sourceUri, contentHash),
    );
    if (existing) {
      await tryAuditBrainWrite(db, ctx.workspaceId, deps.rawMek, {
        pageId: existing.id,
        sourceUri,
        chunksCreated: 0,
        idempotent: true,
        actorUserId: ctx.userId,
      });
      return json({
        page_id: existing.id,
        chunks_created: 0,
        idempotent: true,
      });
    }

    const sendCapCheck = await withWorkspace(db, ctx.workspaceId, (tx) =>
      consumeSendCapsForAudience(tx, ctx.workspaceId, ctx.userId, audience),
    );
    if (sendCapCheck.result.kind === "deny") {
      const denial = sendCapCheck.result;
      await trySendCapAudit(db, ctx.workspaceId, deps.rawMek, {
        action: "brain.put.send_cap_required",
        actorUserId: ctx.userId,
        target: { sourceUri, audience_user_id: denial.audienceUserId },
        decision: "deny",
        supporting: { reason: denial.reason },
      });
      return {
        content: [
          {
            type: "text",
            text: `send_cap_required: no active SendCap from ${denial.audienceUserId} to actor`,
          },
        ],
        isError: true,
      };
    }
    for (const capId of sendCapCheck.consumedCapIds) {
      await trySendCapAudit(db, ctx.workspaceId, deps.rawMek, {
        action: "send_cap.used",
        actorUserId: ctx.userId,
        target: { send_cap_id: capId, sourceUri },
        decision: "allow",
      });
    }

    const embedderConfig = pickEmbedder(deps);
    if (!embedderConfig) {
      return {
        content: [
          {
            type: "text",
            text: "embedding provider not configured (set OPENAI_API_KEY)",
          },
        ],
        isError: true,
      };
    }

    const chunks = chunkText(content).slice(0, MAX_CHUNKS_PER_PAGE);
    if (chunks.length === 0) {
      return {
        content: [{ type: "text", text: "content produced no chunks" }],
        isError: true,
      };
    }

    const embeddings = await embedderConfig.embedder(chunks.map((c) => c.text));
    if (embeddings.length !== chunks.length) {
      return {
        content: [{ type: "text", text: "embedding count mismatch" }],
        isError: true,
      };
    }

    const chunkHashes = await Promise.all(chunks.map((c) => sha256Bytes(c.text)));

    const pageId = await withWorkspace(db, ctx.workspaceId, async (tx) => {
      const inserted = await tx
        .insert(brainPages)
        .values({
          workspaceId: ctx.workspaceId,
          sourceUri,
          sourceKind,
          contentHash,
          title,
          authorUserId: ctx.userId,
          audience,
        })
        .returning({ id: brainPages.id });
      const newPageId = inserted[0]?.id;
      if (!newPageId) throw new Error("brain page insert returned no id");

      const insertedChunks = await tx
        .insert(brainChunks)
        .values(
          chunks.map((c, idx) => ({
            workspaceId: ctx.workspaceId,
            pageId: newPageId,
            chunkIndex: c.index,
            content: c.text,
            contentSha256: chunkHashes[idx] as Buffer,
            tokenCount: estimateTokens(c.text),
          })),
        )
        .returning({ id: brainChunks.id, chunkIndex: brainChunks.chunkIndex });

      const byIndex = new Map(insertedChunks.map((row) => [row.chunkIndex, row.id]));
      const embeddingRows = chunks
        .map((c, idx) => {
          const chunkId = byIndex.get(c.index);
          const embedding = embeddings[idx];
          if (!chunkId || !embedding) return null;
          return {
            chunkId,
            workspaceId: ctx.workspaceId,
            model: embedderConfig.model,
            embedding: Array.from(embedding),
          };
        })
        .filter((v): v is NonNullable<typeof v> => v !== null);

      if (embeddingRows.length > 0) {
        await tx.insert(brainChunkEmbeddings).values(embeddingRows);
      }

      return newPageId;
    });

    await tryAuditBrainWrite(db, ctx.workspaceId, deps.rawMek, {
      pageId,
      sourceUri,
      chunksCreated: chunks.length,
      idempotent: false,
      actorUserId: ctx.userId,
    });

    return json({
      page_id: pageId,
      chunks_created: chunks.length,
      idempotent: false,
    });
  },
};

const brainSearch: AdapterTool = {
  descriptor: {
    name: "pact.brain.search",
    description: "Search the brain for chunks relevant to a natural-language query.",
    inputSchema: {
      type: "object",
      required: ["query"],
      properties: {
        query: { type: "string" },
        k: { type: "number", minimum: 1, maximum: SEARCH_MAX_K },
      },
    },
  },
  authorize: (_input, ctx) => ({
    action: "tool:pact.brain.search",
    resource: `workspace:${ctx.workspaceId}:brain:read`,
  }),
  async handler(input, ctx, deps) {
    const queryRaw = stringInput(input, "query");
    if (!queryRaw) {
      return { content: [{ type: "text", text: "query is required" }], isError: true };
    }
    const query = queryRaw.slice(0, SEARCH_QUERY_MAX_CHARS);
    const k = Math.max(
      1,
      Math.min(SEARCH_MAX_K, Math.floor(numberInput(input, "k") ?? SEARCH_DEFAULT_K)),
    );

    const db = createClient(deps.databaseUrl);
    const adapter = new BrainAdapter({ db, workspaceId: ctx.workspaceId });
    const embedderConfig = pickEmbedder(deps);
    const audienceFilter = callerAudience(ctx);

    const results = await hybridSearch(adapter, query, {
      limit: k,
      ...(audienceFilter.length > 0 ? { audienceFilter } : {}),
      ...(embedderConfig
        ? {
            embed: async (text: string) =>
              (await embedderConfig.embedder([text]))[0] ?? new Float32Array(EMBED_DIMS),
          }
        : {}),
    });

    return json({
      results: results.map((r) => {
        const chunkUuid = adapter.resolveUuid(r.chunk_id) ?? null;
        const pageUuid = adapter.resolvePageUuid(r.chunk_id) ?? null;
        return {
          page_id: pageUuid,
          source_uri: r.slug,
          chunk_id: chunkUuid,
          snippet: snippetFor(r.chunk_text, query),
          score: r.score,
          provenance: {
            source_uri: r.slug,
            chunk_index: r.chunk_index,
            chunk_id: chunkUuid,
            page_id: pageUuid,
          },
        };
      }),
      meta: {
        vector_enabled: Boolean(embedderConfig),
        embed_model: embedderConfig?.model ?? null,
      },
    });
  },
};

const estimateTokens = (text: string): number => {
  return Math.max(1, Math.ceil(text.length / 4));
};

const snippetFor = (content: string, query: string): string => {
  const terms = query
    .toLowerCase()
    .split(/\s+/)
    .map((term) => term.replace(/[^a-z0-9_-]/g, ""))
    .filter(Boolean);
  const lower = content.toLowerCase();
  const hits = terms.map((term) => lower.indexOf(term)).filter((idx) => idx >= 0);
  const anchor =
    hits.length > 1 ? Math.floor((Math.min(...hits) + Math.max(...hits)) / 2) : (hits[0] ?? 0);
  const start = Math.max(0, anchor - 240);
  const end = Math.min(content.length, anchor + 360);
  return content.slice(start, end).trim();
};

export const brainAdapter: Adapter = {
  name: "brain",
  tools: [brainPut, brainSearch],
};
