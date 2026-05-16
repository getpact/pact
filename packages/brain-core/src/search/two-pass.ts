/**
 * v0.20.0 Cathedral II Layer 7 (A2) - two-pass structural retrieval.
 *
 * Given an anchor set of chunks (either from a keyword/vector anchor
 * search OR from a --near-symbol qualified-name lookup), walk
 * code_edges_chunk + code_edges_symbol up to walkDepth hops and collect
 * structural neighbors. Score each neighbor as anchor_score * 1/(1+hop).
 *
 * Default OFF. Activation:
 *  - opts.walkDepth > 0 -> walk N hops from the anchors.
 *  - opts.nearSymbol set -> anchor set includes chunks whose
 *     symbol_name_qualified matches, in addition to the keyword/vector
 *     anchors.
 *
 * Caps:
 *  - depth capped at 2 (neighborhood blast radius)
 *  - neighbor cap 50 per hop (high-fan-out protection)
 *
 * Returns a flat merged list: anchors (score preserved) + neighbors
 * (scored by 1/(1+hop) * anchor_score). Caller feeds this back into
 * the RRF-deduped pipeline.
 */

import type { SearchResult } from "../types.js";
import type { SearchAdapter } from "./adapter.js";

const MAX_WALK_DEPTH = 2;
const NEIGHBOR_CAP_PER_HOP = 50;

export interface TwoPassOpts {
  walkDepth?: number;
  nearSymbol?: string;
  sourceId?: string;
}

interface ChunkWithScore {
  chunk_id: number;
  score: number;
  hop: number;
  source: "anchor" | "neighbor";
}

export async function expandAnchors(
  adapter: SearchAdapter,
  anchors: SearchResult[],
  opts: TwoPassOpts = {},
): Promise<ChunkWithScore[]> {
  const depth = Math.min(Math.max(opts.walkDepth ?? 0, 0), MAX_WALK_DEPTH);
  if (depth === 0 && !opts.nearSymbol) {
    return anchors.map((a) => ({
      chunk_id: a.chunk_id,
      score: a.score,
      hop: 0,
      source: "anchor" as const,
    }));
  }

  const seen = new Map<number, ChunkWithScore>();
  for (const a of anchors) {
    seen.set(a.chunk_id, {
      chunk_id: a.chunk_id,
      score: a.score,
      hop: 0,
      source: "anchor",
    });
  }

  if (opts.nearSymbol) {
    try {
      const ids = await adapter.getChunkIdsBySymbol(
        opts.nearSymbol,
        opts.sourceId,
        NEIGHBOR_CAP_PER_HOP,
      );
      const first = anchors[0];
      const baseScore = first ? first.score : 1.0;
      for (const id of ids) {
        if (!seen.has(id)) {
          seen.set(id, { chunk_id: id, score: baseScore, hop: 0, source: "anchor" });
        }
      }
    } catch {
      // best-effort
    }
  }

  let frontier = Array.from(seen.values())
    .filter((c) => c.hop === 0)
    .map((c) => c.chunk_id);
  for (let hop = 1; hop <= depth; hop++) {
    if (frontier.length === 0) break;
    const nextFrontier = new Set<number>();
    const decay = 1 / (1 + hop);

    for (const chunkId of frontier) {
      const current = seen.get(chunkId);
      if (!current) continue;

      let edges: Awaited<ReturnType<SearchAdapter["getEdgesByChunk"]>> = [];
      try {
        edges = await adapter.getEdgesByChunk(chunkId, {
          direction: "both",
          limit: NEIGHBOR_CAP_PER_HOP,
        });
      } catch {
        continue;
      }

      const directChunkIds: number[] = [];
      const unresolvedTargets: string[] = [];
      for (const e of edges) {
        if (e.to_chunk_id != null) directChunkIds.push(e.to_chunk_id);
        else if (e.to_symbol_qualified) unresolvedTargets.push(e.to_symbol_qualified);
      }

      if (unresolvedTargets.length > 0) {
        for (const sym of unresolvedTargets) {
          try {
            const resolved = await adapter.getChunkIdsBySymbol(
              sym,
              opts.sourceId,
              NEIGHBOR_CAP_PER_HOP,
            );
            for (const id of resolved) directChunkIds.push(id);
          } catch {
            // best-effort
          }
        }
      }

      for (const tid of directChunkIds) {
        if (seen.has(tid)) continue;
        const nbScore = current.score * decay;
        seen.set(tid, { chunk_id: tid, score: nbScore, hop, source: "neighbor" });
        nextFrontier.add(tid);
      }
    }

    frontier = Array.from(nextFrontier);
  }

  return Array.from(seen.values());
}

/**
 * Fetch SearchResult rows for a set of chunk IDs. Used to hydrate
 * two-pass neighbor IDs into full result rows the hybrid pipeline expects.
 * Missing chunk IDs are silently skipped.
 */
export async function hydrateChunks(
  adapter: SearchAdapter,
  chunkIds: number[],
): Promise<SearchResult[]> {
  if (chunkIds.length === 0) return [];
  return adapter.getChunksByIds(chunkIds);
}
