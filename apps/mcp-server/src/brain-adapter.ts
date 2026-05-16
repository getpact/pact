import type { PageRef, SearchAdapter } from "@getpact/brain-core/search";
import type { Edge, SearchOpts, SearchResult } from "@getpact/brain-core/types";
import type { DbClient, Tx } from "@getpact/db";
import { withWorkspace } from "@getpact/db";
import { sql } from "drizzle-orm";

export type BrainAdapterDeps = {
  db: DbClient;
  workspaceId: string;
};

type KeywordRow = {
  chunk_id: string;
  page_id: string;
  source_uri: string;
  chunk_index: number;
  content: string;
  score: number;
};

type VectorRow = {
  chunk_id: string;
  page_id: string;
  source_uri: string;
  chunk_index: number;
  content: string;
  distance: number;
};

type EmbeddingRow = {
  chunk_id: string;
  embedding: string;
};

type HydrateRow = {
  chunk_id: string;
  page_id: string;
  source_uri: string;
  chunk_index: number;
  content: string;
};

const MAX_CHUNK_ID_MAP = 5000;

const fnv1a64 = (input: string): bigint => {
  let hash = 0xcbf29ce484222325n;
  const prime = 0x100000001b3n;
  const mask = 0xffffffffffffffffn;
  for (let i = 0; i < input.length; i += 1) {
    hash ^= BigInt(input.charCodeAt(i));
    hash = (hash * prime) & mask;
  }
  return hash;
};

const uuidToIntKey = (uuid: string): number => {
  const hex = uuid.replace(/-/g, "");
  const high = BigInt(`0x${hex.slice(0, 8)}`);
  const low = BigInt(`0x${hex.slice(8, 13)}`);
  const combined = (high << 20n) | low;
  return Number(combined & 0x1fffffffffffffn);
};

const parseEmbedding = (raw: string): Float32Array => {
  if (!raw) return new Float32Array(0);
  const trimmed = raw.replace(/^\[/, "").replace(/\]$/, "");
  if (trimmed.length === 0) return new Float32Array(0);
  const parts = trimmed.split(",");
  const out = new Float32Array(parts.length);
  for (let i = 0; i < parts.length; i += 1) {
    const v = Number(parts[i]);
    out[i] = Number.isFinite(v) ? v : 0;
  }
  return out;
};

const formatVector = (embedding: Float32Array | number[]): string => {
  const arr = Array.from(embedding);
  return `[${arr.join(",")}]`;
};

const clampLimit = (limit: number | undefined, fallback: number, max: number): number => {
  if (typeof limit !== "number" || !Number.isFinite(limit)) return fallback;
  return Math.max(1, Math.min(max, Math.floor(limit)));
};

export class BrainAdapter implements SearchAdapter {
  private readonly idMap = new Map<number, string>();
  private readonly pageMap = new Map<number, string>();

  constructor(private readonly deps: BrainAdapterDeps) {}

  resolveUuid(intId: number): string | undefined {
    return this.idMap.get(intId);
  }

  resolvePageUuid(intId: number): string | undefined {
    return this.pageMap.get(intId);
  }

  private remember(chunkUuid: string, pageUuid: string): number {
    const intId = uuidToIntKey(chunkUuid);
    const existing = this.idMap.get(intId);
    if (existing && existing !== chunkUuid) {
      const fallback = Number(fnv1a64(chunkUuid) & 0x1fffffffffffffn);
      if (!this.idMap.has(fallback)) {
        this.idMap.set(fallback, chunkUuid);
        this.pageMap.set(fallback, pageUuid);
        return fallback;
      }
    }
    if (this.idMap.size > MAX_CHUNK_ID_MAP) {
      this.idMap.clear();
      this.pageMap.clear();
    }
    this.idMap.set(intId, chunkUuid);
    this.pageMap.set(intId, pageUuid);
    return intId;
  }

  private withTx<T>(fn: (tx: Tx) => Promise<T>): Promise<T> {
    return withWorkspace(this.deps.db, this.deps.workspaceId, fn);
  }

  async searchKeyword(query: string, opts: SearchOpts): Promise<SearchResult[]> {
    const limit = clampLimit(opts.limit, 20, 200);
    const text = query.trim();
    if (text.length === 0) return [];
    const rows = (await this.withTx((tx) =>
      tx.execute(sql`
        SELECT
          c.id::text AS chunk_id,
          c.page_id::text AS page_id,
          p.source_uri AS source_uri,
          c.chunk_index AS chunk_index,
          c.content AS content,
          ts_rank_cd(to_tsvector('english', c.content), websearch_to_tsquery('english', ${text})) AS score
        FROM brain_chunks c
        JOIN brain_pages p ON p.id = c.page_id AND p.deleted_at IS NULL
        WHERE c.workspace_id = ${this.deps.workspaceId}
          AND c.deleted_at IS NULL
          AND to_tsvector('english', c.content) @@ websearch_to_tsquery('english', ${text})
        ORDER BY score DESC, c.created_at DESC
        LIMIT ${limit}
      `),
    )) as KeywordRow[];

    return rows.map((row) => this.rowToResult(row, Number(row.score)));
  }

  async searchVector(embedding: Float32Array, opts: SearchOpts): Promise<SearchResult[]> {
    if (embedding.length === 0) return [];
    const limit = clampLimit(opts.limit, 20, 200);
    const vector = formatVector(embedding);
    const rows = (await this.withTx((tx) =>
      tx.execute(sql`
        SELECT
          c.id::text AS chunk_id,
          c.page_id::text AS page_id,
          p.source_uri AS source_uri,
          c.chunk_index AS chunk_index,
          c.content AS content,
          (e.embedding <=> ${vector}::vector) AS distance
        FROM brain_chunk_embeddings e
        JOIN brain_chunks c ON c.id = e.chunk_id AND c.deleted_at IS NULL
        JOIN brain_pages p ON p.id = c.page_id AND p.deleted_at IS NULL
        WHERE e.workspace_id = ${this.deps.workspaceId}
        ORDER BY e.embedding <=> ${vector}::vector
        LIMIT ${limit}
      `),
    )) as VectorRow[];

    return rows.map((row) => {
      const distance = Number(row.distance);
      const score = Number.isFinite(distance) ? Math.max(0, 1 - distance) : 0;
      return this.rowToResult(row, score);
    });
  }

  async getEmbeddingsByChunkIds(chunkIds: number[]): Promise<Map<number, Float32Array>> {
    const result = new Map<number, Float32Array>();
    if (chunkIds.length === 0) return result;
    const uuids: string[] = [];
    const idForUuid = new Map<string, number>();
    for (const id of chunkIds) {
      const uuid = this.idMap.get(id);
      if (uuid) {
        uuids.push(uuid);
        idForUuid.set(uuid, id);
      }
    }
    if (uuids.length === 0) return result;

    const rows = (await this.withTx((tx) =>
      tx.execute(sql`
        SELECT chunk_id::text AS chunk_id, embedding::text AS embedding
        FROM brain_chunk_embeddings
        WHERE workspace_id = ${this.deps.workspaceId}
          AND chunk_id = ANY(${sql.raw(`ARRAY[${uuids.map((u) => `'${u}'`).join(",")}]::uuid[]`)})
      `),
    )) as EmbeddingRow[];

    for (const row of rows) {
      const intId = idForUuid.get(row.chunk_id);
      if (intId == null) continue;
      result.set(intId, parseEmbedding(row.embedding));
    }
    return result;
  }

  async getBacklinkCounts(_slugs: string[]): Promise<Map<string, number>> {
    return new Map();
  }

  async getSalienceScores(_refs: PageRef[]): Promise<Map<string, number>> {
    return new Map();
  }

  async getEffectiveDates(_refs: PageRef[]): Promise<Map<string, Date>> {
    return new Map();
  }

  async getEdgesByChunk(
    _chunkId: number,
    _opts: { direction: "in" | "out" | "both"; limit: number },
  ): Promise<Edge[]> {
    return [];
  }

  async getChunksByIds(chunkIds: number[]): Promise<SearchResult[]> {
    if (chunkIds.length === 0) return [];
    const uuids: string[] = [];
    for (const id of chunkIds) {
      const uuid = this.idMap.get(id);
      if (uuid) uuids.push(uuid);
    }
    if (uuids.length === 0) return [];

    const rows = (await this.withTx((tx) =>
      tx.execute(sql`
        SELECT
          c.id::text AS chunk_id,
          c.page_id::text AS page_id,
          p.source_uri AS source_uri,
          c.chunk_index AS chunk_index,
          c.content AS content
        FROM brain_chunks c
        JOIN brain_pages p ON p.id = c.page_id AND p.deleted_at IS NULL
        WHERE c.workspace_id = ${this.deps.workspaceId}
          AND c.deleted_at IS NULL
          AND c.id = ANY(${sql.raw(`ARRAY[${uuids.map((u) => `'${u}'`).join(",")}]::uuid[]`)})
      `),
    )) as HydrateRow[];

    return rows.map((row) => this.rowToResult(row, 0));
  }

  async getChunkIdsBySymbol(): Promise<number[]> {
    return [];
  }

  private rowToResult(
    row: {
      chunk_id: string;
      page_id: string;
      source_uri: string;
      chunk_index: number;
      content: string;
    },
    score: number,
  ): SearchResult {
    const chunkIntId = this.remember(row.chunk_id, row.page_id);
    const pageIntId = uuidToIntKey(row.page_id);
    return {
      slug: row.source_uri,
      page_id: pageIntId,
      title: row.source_uri,
      type: "note",
      chunk_text: row.content,
      chunk_source: "compiled_truth",
      chunk_id: chunkIntId,
      chunk_index: Number(row.chunk_index),
      score,
      stale: false,
      source_id: "brain",
    };
  }
}

export const lookupPageUuid = (uuid: string): number => uuidToIntKey(uuid);
