/**
 * SearchAdapter: the only storage contract this package depends on.
 *
 * In gbrain this surface was the `BrainEngine` interface implemented by
 * pglite-engine.ts and postgres-engine.ts (1300+ LOC each). For Pact we
 * abstract the small slice the search pipeline actually needs so callers
 * can wire their own store (Drizzle on D1, libSQL, Postgres, whatever).
 *
 * Each method should be best-effort safe: throwing is allowed, but the
 * hybrid pipeline catches and degrades (keyword-only fallback, no post-
 * fusion boosts, etc.). The pipeline still works when an adapter only
 * implements `searchKeyword` and leaves vector and boost methods returning
 * empty.
 */

import type { Edge, SearchOpts, SearchResult } from "../types.js";

/**
 * Page ref keyed by composite (source_id, slug). The boost methods accept
 * arrays of these and return Maps keyed by `${source_id}::${slug}`.
 */
export interface PageRef {
  source_id: string;
  slug: string;
}

export interface SearchAdapter {
  /** Lexical search. Always available. */
  searchKeyword(query: string, opts: SearchOpts): Promise<SearchResult[]>;

  /** Vector search. May return empty when no embedding backend is wired. */
  searchVector(embedding: Float32Array, opts: SearchOpts): Promise<SearchResult[]>;

  /** Chunk embeddings keyed by chunk_id, for cosine re-scoring. */
  getEmbeddingsByChunkIds(chunkIds: number[]): Promise<Map<number, Float32Array>>;

  /** Backlink count per slug. Drives the post-fusion link-prestige boost. */
  getBacklinkCounts(slugs: string[]): Promise<Map<string, number>>;

  /** Salience score per (source_id, slug). Returned map keyed `${source_id}::${slug}`. */
  getSalienceScores(refs: PageRef[]): Promise<Map<string, number>>;

  /** Effective date per (source_id, slug). Returned map keyed `${source_id}::${slug}`. */
  getEffectiveDates(refs: PageRef[]): Promise<Map<string, Date>>;

  /** Code edges out of a chunk. Used by two-pass structural expansion. */
  getEdgesByChunk(
    chunkId: number,
    opts: { direction: "in" | "out" | "both"; limit: number },
  ): Promise<Edge[]>;

  /** Hydrate chunk IDs into full SearchResult rows. Two-pass uses this. */
  getChunksByIds(chunkIds: number[]): Promise<SearchResult[]>;

  /** Resolve a fully-qualified symbol name to chunk IDs. Two-pass anchors. */
  getChunkIdsBySymbol(symbol: string, sourceId?: string, limit?: number): Promise<number[]>;
}

/**
 * A no-op adapter that returns empty results. Useful for tests that exercise
 * pure pipeline stages without standing up a store.
 */
export const emptyAdapter: SearchAdapter = {
  async searchKeyword() {
    return [];
  },
  async searchVector() {
    return [];
  },
  async getEmbeddingsByChunkIds() {
    return new Map();
  },
  async getBacklinkCounts() {
    return new Map();
  },
  async getSalienceScores() {
    return new Map();
  },
  async getEffectiveDates() {
    return new Map();
  },
  async getEdgesByChunk() {
    return [];
  },
  async getChunksByIds() {
    return [];
  },
  async getChunkIdsBySymbol() {
    return [];
  },
};
