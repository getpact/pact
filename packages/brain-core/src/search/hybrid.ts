/**
 * Hybrid Search with Reciprocal Rank Fusion (RRF)
 * Ported from production Ruby implementation (content_chunk.rb)
 *
 * Pipeline: keyword + vector -> RRF fusion -> normalize -> boost ->
 *           cosine re-score -> post-fusion boosts -> dedup -> token budget
 *
 * RRF score = sum(1 / (k + rank_in_list))
 * Compiled truth boost: 2.0x for compiled_truth chunks after RRF normalization
 * Cosine re-score: blend 0.7 * rrf + 0.3 * cosine for query-specific ranking
 *
 * Simplifications from upstream gbrain:
 *  - Storage abstracted behind SearchAdapter; no direct SQL.
 *  - LLM query expansion and cross-encoder reranker removed; pass an
 *     `expandFn` if you want expansion, otherwise the original query runs.
 *  - Mode bundle, semantic cache, and telemetry removed; behavior is
 *     configured per call via opts.
 *  - Embedding is injected via `EmbedFn` so callers wire whichever
 *     provider they own.
 */

import type { BrainTracer, SpanAttrs } from "../otel.js";
import { mergeAttrs, noopTracer } from "../otel.js";
import type { HybridSearchMeta, Logger, SearchOpts, SearchResult } from "../types.js";
import { consoleLogger } from "../types.js";
import type { SearchAdapter } from "./adapter.js";
import { dedupResults } from "./dedup.js";
import { applyExactMatchBoost, effectiveRrfK, weightsForIntent } from "./intent-weights.js";
import { autoDetectDetail, classifyQuery } from "./query-intent.js";
import type { RecencyDecayConfig, RecencyDecayMap } from "./recency-decay.js";
import { DEFAULT_FALLBACK, DEFAULT_RECENCY_DECAY } from "./recency-decay.js";
import { enforceTokenBudget } from "./token-budget.js";
import { expandAnchors, hydrateChunks } from "./two-pass.js";

const RRF_K = 60;
const COMPILED_TRUTH_BOOST = 2.0;
const BACKLINK_BOOST_COEF = 0.05;
const MAX_SEARCH_LIMIT = 200;

/** Embedding function injected by the caller. */
export type HybridEmbedFn = (text: string) => Promise<Float32Array>;

export interface HybridSearchOpts extends SearchOpts {
  /** Embedding function. When omitted, the pipeline runs keyword-only. */
  embed?: HybridEmbedFn;
  /** Optional async query expander. Default off. */
  expandFn?: (query: string) => Promise<string[]>;
  /** Override default RRF K constant (default: 60). */
  rrfK?: number;
  dedupOpts?: {
    cosineThreshold?: number;
    maxTypeRatio?: number;
    maxPerPage?: number;
  };
  decayMap?: RecencyDecayMap;
  decayFallback?: RecencyDecayConfig;
  onMeta?: (meta: HybridSearchMeta) => void;
  logger?: Logger;
  /** Optional tracer; defaults to a no-op. */
  tracer?: BrainTracer;
  /** Base attrs attached to every span (workspace_id, tenant_id, trace_id). */
  tracerAttrs?: SpanAttrs;
}

export function applyBacklinkBoost(results: SearchResult[], counts: Map<string, number>): void {
  for (const r of results) {
    const count = counts.get(r.slug) ?? 0;
    if (count > 0) {
      r.score *= 1.0 + BACKLINK_BOOST_COEF * Math.log(1 + count);
    }
  }
}

export function applySalienceBoost(
  results: SearchResult[],
  scores: Map<string, number>,
  strength: "on" | "strong",
): void {
  const k = strength === "strong" ? 0.3 : 0.15;
  for (const r of results) {
    const key = `${r.source_id ?? "default"}::${r.slug}`;
    const score = scores.get(key);
    if (!score || score <= 0) continue;
    r.score *= 1.0 + k * Math.log(1 + score);
  }
}

export function applyRecencyBoost(
  results: SearchResult[],
  dates: Map<string, Date>,
  strength: "on" | "strong",
  decayMap: RecencyDecayMap,
  fallback: RecencyDecayConfig,
  nowMs: number = Date.now(),
): void {
  const strengthMul = strength === "strong" ? 1.5 : 1.0;
  const prefixes = Object.keys(decayMap).sort((a, b) => b.length - a.length);

  for (const r of results) {
    const key = `${r.source_id ?? "default"}::${r.slug}`;
    const d = dates.get(key);
    if (!d) continue;
    const daysOld = Math.max(0, (nowMs - d.getTime()) / 86_400_000);

    let cfg: RecencyDecayConfig = fallback;
    for (const p of prefixes) {
      if (r.slug.startsWith(p)) {
        const found = decayMap[p];
        if (found) {
          cfg = found;
        }
        break;
      }
    }

    if (cfg.halflifeDays === 0 || cfg.coefficient === 0) continue;
    const recencyComponent = (cfg.coefficient * cfg.halflifeDays) / (cfg.halflifeDays + daysOld);
    const factor = 1.0 + strengthMul * recencyComponent;
    r.score *= factor;
  }
}

export interface PostFusionOpts {
  applyBacklinks: boolean;
  salience: "off" | "on" | "strong";
  recency: "off" | "on" | "strong";
  decayMap?: RecencyDecayMap;
  fallback?: RecencyDecayConfig;
}

export async function runPostFusionStages(
  adapter: SearchAdapter,
  results: SearchResult[],
  opts: PostFusionOpts,
): Promise<void> {
  if (results.length === 0) return;

  if (opts.applyBacklinks) {
    try {
      const slugs = Array.from(new Set(results.map((r) => r.slug)));
      const counts = await adapter.getBacklinkCounts(slugs);
      applyBacklinkBoost(results, counts);
    } catch {
      // non-fatal
    }
  }

  const refs = Array.from(
    new Map(
      results.map((r) => [
        `${r.source_id ?? "default"}::${r.slug}`,
        { slug: r.slug, source_id: r.source_id ?? "default" },
      ]),
    ).values(),
  );

  if (opts.salience !== "off") {
    try {
      const scores = await adapter.getSalienceScores(refs);
      applySalienceBoost(results, scores, opts.salience);
    } catch {
      // non-fatal
    }
  }

  if (opts.recency !== "off") {
    try {
      const dates = await adapter.getEffectiveDates(refs);
      applyRecencyBoost(
        results,
        dates,
        opts.recency,
        opts.decayMap ?? DEFAULT_RECENCY_DECAY,
        opts.fallback ?? DEFAULT_FALLBACK,
      );
    } catch {
      // non-fatal
    }
  }
}

export async function hybridSearch(
  adapter: SearchAdapter,
  query: string,
  opts?: HybridSearchOpts,
): Promise<SearchResult[]> {
  const tracer = opts?.tracer ?? noopTracer;
  const traceAttrs = opts?.tracerAttrs;
  return tracer.span(
    "brain.search",
    mergeAttrs(traceAttrs, { query_len: query.length, limit: opts?.limit ?? 20 }),
    () => hybridSearchInner(adapter, query, opts, tracer, traceAttrs),
  );
}

async function hybridSearchInner(
  adapter: SearchAdapter,
  query: string,
  opts: HybridSearchOpts | undefined,
  tracer: BrainTracer,
  traceAttrs: SpanAttrs | undefined,
): Promise<SearchResult[]> {
  const log = opts?.logger ?? consoleLogger;
  const limit = opts?.limit || 20;
  const offset = opts?.offset || 0;
  const innerLimit = Math.min(limit * 2, MAX_SEARCH_LIMIT);

  const suggestions = classifyQuery(query);
  const intentWeightingOn = opts?.intentWeighting !== false;
  const intentWeights = intentWeightingOn
    ? weightsForIntent(suggestions.intent)
    : weightsForIntent("general");

  const detail = opts?.detail ?? autoDetectDetail(query);
  const detailResolved: "low" | "medium" | "high" | null = detail ?? null;

  const searchOpts: SearchOpts = {
    limit: innerLimit,
    ...(detail !== undefined ? { detail } : {}),
    ...(opts?.language !== undefined ? { language: opts.language } : {}),
    ...(opts?.symbolKind !== undefined ? { symbolKind: opts.symbolKind } : {}),
    ...(opts?.types !== undefined ? { types: opts.types } : {}),
    ...((opts?.since ?? opts?.afterDate) ? { afterDate: opts.since ?? opts.afterDate } : {}),
    ...((opts?.until ?? opts?.beforeDate) ? { beforeDate: opts.until ?? opts.beforeDate } : {}),
    ...(opts?.sourceId !== undefined ? { sourceId: opts.sourceId } : {}),
    ...(opts?.sourceIds !== undefined ? { sourceIds: opts.sourceIds } : {}),
    ...(opts?.audienceFilter !== undefined ? { audienceFilter: opts.audienceFilter } : {}),
  };

  let expansionApplied = false;
  let lastResultsCount = 0;

  const emitMeta = (meta: HybridSearchMeta): void => {
    try {
      opts?.onMeta?.(meta);
    } catch (err) {
      log.warn("onMeta callback threw", { err: String(err) });
    }
  };

  const keywordResults = await tracer.childSpan(
    "brain.search",
    "brain.search.keyword",
    mergeAttrs(traceAttrs, { query_len: query.length, limit: innerLimit }),
    async (span) => {
      const r = await adapter.searchKeyword(query, searchOpts);
      span.setAttr("hits", r.length);
      return r;
    },
  );

  const legacyRecency: "off" | "on" | "strong" | undefined =
    opts?.recencyBoost === 2
      ? "strong"
      : opts?.recencyBoost === 1
        ? "on"
        : opts?.recencyBoost === 0
          ? "off"
          : undefined;

  const salienceMode: "off" | "on" | "strong" = opts?.salience ?? suggestions.suggestedSalience;
  const intentRecency =
    intentWeightingOn && intentWeights.suggestedRecency != null
      ? intentWeights.suggestedRecency
      : null;
  const recencyMode: "off" | "on" | "strong" =
    opts?.recency ??
    legacyRecency ??
    (suggestions.suggestedRecency !== "off"
      ? suggestions.suggestedRecency
      : (intentRecency ?? suggestions.suggestedRecency));

  const postFusionOpts: PostFusionOpts = {
    applyBacklinks: true,
    salience: salienceMode,
    recency: recencyMode,
    ...(opts?.decayMap !== undefined ? { decayMap: opts.decayMap } : {}),
    ...(opts?.decayFallback !== undefined ? { fallback: opts.decayFallback } : {}),
  };

  if (!opts?.embed) {
    if (keywordResults.length > 0) {
      await runPostFusionStages(adapter, keywordResults, postFusionOpts);
      keywordResults.sort((a, b) => b.score - a.score);
    }
    const deduped = await tracer.childSpan(
      "brain.search",
      "brain.search.dedup",
      mergeAttrs(traceAttrs, { candidates_in: keywordResults.length }),
      async (span) => {
        const out = dedupResults(keywordResults);
        span.setAttr("candidates_out", out.length);
        return out;
      },
    );
    const sliced = deduped.slice(offset, offset + limit);
    const { results: budgeted, meta: budgetMeta } = enforceTokenBudget(sliced, opts?.tokenBudget);
    lastResultsCount = budgeted.length;
    emitMeta({
      vector_enabled: false,
      detail_resolved: detailResolved,
      expansion_applied: false,
      intent: suggestions.intent,
      ...(opts?.tokenBudget && opts.tokenBudget > 0 ? { token_budget: budgetMeta } : {}),
    });
    void lastResultsCount;
    return budgeted;
  }

  let queries = [query];
  if (opts.expansion && opts.expandFn) {
    try {
      queries = await opts.expandFn(query);
      if (queries.length === 0) queries = [query];
      expansionApplied = queries.length > 1;
    } catch {
      // non-fatal
    }
  }

  let vectorLists: SearchResult[][] = [];
  let queryEmbedding: Float32Array | null = null;
  try {
    const embeddings = await Promise.all(queries.map((q) => opts.embed?.(q)));
    queryEmbedding = embeddings[0] ?? null;
    const queryDim = queryEmbedding ? queryEmbedding.length : 0;
    vectorLists = await tracer.childSpan(
      "brain.search",
      "brain.search.vector",
      mergeAttrs(traceAttrs, {
        query_dim: queryDim,
        limit: innerLimit,
        queries: embeddings.length,
      }),
      async (span) => {
        const lists = await Promise.all(
          embeddings
            .filter((emb): emb is Float32Array => emb !== undefined)
            .map((emb) => adapter.searchVector(emb, searchOpts)),
        );
        const total = lists.reduce((n, l) => n + l.length, 0);
        span.setAttr("hits", total);
        return lists;
      },
    );
  } catch (err) {
    log.warn("embedding failed; falling back to keyword-only", { err: String(err) });
  }

  if (vectorLists.length === 0) {
    if (keywordResults.length > 0) {
      await runPostFusionStages(adapter, keywordResults, postFusionOpts);
      keywordResults.sort((a, b) => b.score - a.score);
    }
    const deduped = await tracer.childSpan(
      "brain.search",
      "brain.search.dedup",
      mergeAttrs(traceAttrs, { candidates_in: keywordResults.length }),
      async (span) => {
        const out = dedupResults(keywordResults);
        span.setAttr("candidates_out", out.length);
        return out;
      },
    );
    const sliced = deduped.slice(offset, offset + limit);
    const { results: budgeted, meta: budgetMeta } = enforceTokenBudget(sliced, opts?.tokenBudget);
    lastResultsCount = budgeted.length;
    emitMeta({
      vector_enabled: false,
      detail_resolved: detailResolved,
      expansion_applied: expansionApplied,
      intent: suggestions.intent,
      ...(opts?.tokenBudget && opts.tokenBudget > 0 ? { token_budget: budgetMeta } : {}),
    });
    void lastResultsCount;
    return budgeted;
  }

  const baseRrfK = opts?.rrfK ?? RRF_K;
  const keywordK = effectiveRrfK(baseRrfK, intentWeights.keywordWeight);
  const vectorK = effectiveRrfK(baseRrfK, intentWeights.vectorWeight);
  const allLists: Array<{ list: SearchResult[]; k: number }> = [
    ...vectorLists.map((list) => ({ list, k: vectorK })),
    { list: keywordResults, k: keywordK },
  ];
  const candidatesIn = allLists.reduce((n, l) => n + l.list.length, 0);
  let fused = await tracer.childSpan(
    "brain.search",
    "brain.search.rrf_fusion",
    mergeAttrs(traceAttrs, { candidates_in: candidatesIn, lists: allLists.length }),
    async (span) => {
      const out = rrfFusionWeighted(allLists, detail !== "high");
      span.setAttr("candidates_out", out.length);
      return out;
    },
  );

  if (queryEmbedding) {
    const beforeRerank = fused.length;
    const topKAttr = Math.min(beforeRerank, innerLimit);
    fused = await tracer.childSpan(
      "brain.search",
      "brain.search.rerank",
      mergeAttrs(traceAttrs, { candidates_in: beforeRerank, top_k: topKAttr }),
      async () => cosineReScore(adapter, fused, queryEmbedding!),
    );
  }

  if (fused.length > 0) {
    await runPostFusionStages(adapter, fused, postFusionOpts);
    if (intentWeights.exactMatchBoost !== 1.0) {
      applyExactMatchBoost(fused, query, intentWeights);
    }
    fused.sort((a, b) => b.score - a.score);
  }

  const walkDepth = Math.min(opts?.walkDepth ?? 0, 2);
  const needsExpansion = walkDepth > 0 || Boolean(opts?.nearSymbol);
  let dedupOpts = opts?.dedupOpts;

  if (needsExpansion) {
    const anchorSet = fused.slice(0, Math.max(10, limit));
    try {
      const expanded = await expandAnchors(adapter, anchorSet, {
        walkDepth,
        ...(opts?.nearSymbol !== undefined ? { nearSymbol: opts.nearSymbol } : {}),
        ...(opts?.sourceId !== undefined ? { sourceId: opts.sourceId } : {}),
      });
      const existingIds = new Set(fused.map((r) => r.chunk_id));
      const newIds = expanded.filter((e) => !existingIds.has(e.chunk_id)).map((e) => e.chunk_id);
      if (newIds.length > 0) {
        const hydrated = await hydrateChunks(adapter, newIds);
        const scoreById = new Map(expanded.map((e) => [e.chunk_id, e.score]));
        for (const r of hydrated) {
          r.score = scoreById.get(r.chunk_id) ?? 0.01;
          fused.push(r);
        }
        fused.sort((a, b) => b.score - a.score);
      }
      const capFromWalk = Math.min(10, Math.max(walkDepth * 5, 5));
      dedupOpts = { ...(dedupOpts ?? {}), maxPerPage: capFromWalk };
    } catch {
      // non-fatal
    }
  }

  const fusedSnapshot = fused;
  const dedupedAttrs = mergeAttrs(traceAttrs, { candidates_in: fusedSnapshot.length });
  const deduped = await tracer.childSpan(
    "brain.search",
    "brain.search.dedup",
    dedupedAttrs,
    async (span) => {
      const out = dedupResults(fusedSnapshot, dedupOpts);
      span.setAttr("candidates_out", out.length);
      return out;
    },
  );

  if (deduped.length === 0 && opts?.detail === "low") {
    return hybridSearch(adapter, query, { ...opts, detail: "high" });
  }

  const sliced = deduped.slice(offset, offset + limit);
  const { results: budgeted, meta: budgetMeta } = enforceTokenBudget(sliced, opts?.tokenBudget);
  lastResultsCount = budgeted.length;
  emitMeta({
    vector_enabled: true,
    detail_resolved: detailResolved,
    expansion_applied: expansionApplied,
    intent: suggestions.intent,
    ...(opts?.tokenBudget && opts.tokenBudget > 0 ? { token_budget: budgetMeta } : {}),
  });
  void lastResultsCount;
  return budgeted;
}

/**
 * Weighted RRF. Each list contributes with its own effective k value, which
 * lets intent weighting bias keyword vs vector lists without re-weighting
 * individual scores.
 */
export function rrfFusionWeighted(
  lists: Array<{ list: SearchResult[]; k: number }>,
  applyBoost = true,
): SearchResult[] {
  const scores = new Map<string, { result: SearchResult; score: number }>();

  for (const { list, k } of lists) {
    for (let rank = 0; rank < list.length; rank++) {
      const r = list[rank];
      if (!r) continue;
      const key = `${r.slug}:${r.chunk_id ?? r.chunk_text.slice(0, 50)}`;
      const existing = scores.get(key);
      const rrfScore = 1 / (k + rank);

      if (existing) {
        existing.score += rrfScore;
      } else {
        scores.set(key, { result: r, score: rrfScore });
      }
    }
  }

  const entries = Array.from(scores.values());
  if (entries.length === 0) return [];

  const maxScore = Math.max(...entries.map((e) => e.score));
  if (maxScore > 0) {
    for (const e of entries) {
      e.score = e.score / maxScore;
      const boost =
        applyBoost && e.result.chunk_source === "compiled_truth" ? COMPILED_TRUTH_BOOST : 1.0;
      e.score *= boost;
    }
  }

  return entries
    .sort((a, b) => b.score - a.score)
    .map(({ result, score }) => ({ ...result, score }));
}

/**
 * Reciprocal Rank Fusion: merge multiple ranked lists. Each result gets
 * score = sum(1 / (K + rank)) across all lists it appears in. After
 * accumulation: normalize to 0..1, then boost compiled_truth chunks.
 */
export function rrfFusion(lists: SearchResult[][], k: number, applyBoost = true): SearchResult[] {
  return rrfFusionWeighted(
    lists.map((list) => ({ list, k })),
    applyBoost,
  );
}

async function cosineReScore(
  adapter: SearchAdapter,
  results: SearchResult[],
  queryEmbedding: Float32Array,
): Promise<SearchResult[]> {
  const chunkIds = results.map((r) => r.chunk_id).filter((id): id is number => id != null);

  if (chunkIds.length === 0) return results;

  let embeddingMap: Map<number, Float32Array>;
  try {
    embeddingMap = await adapter.getEmbeddingsByChunkIds(chunkIds);
  } catch {
    return results;
  }

  if (embeddingMap.size === 0) return results;

  const maxRrf = Math.max(...results.map((r) => r.score));

  return results
    .map((r) => {
      const chunkEmb = r.chunk_id != null ? embeddingMap.get(r.chunk_id) : undefined;
      if (!chunkEmb) return r;

      const cosine = cosineSimilarity(queryEmbedding, chunkEmb);
      const normRrf = maxRrf > 0 ? r.score / maxRrf : 0;
      const blended = 0.7 * normRrf + 0.3 * cosine;

      return { ...r, score: blended };
    })
    .sort((a, b) => b.score - a.score);
}

export function cosineSimilarity(a: Float32Array, b: Float32Array): number {
  let dot = 0;
  let magA = 0;
  let magB = 0;
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const ai = a[i] ?? 0;
    const bi = b[i] ?? 0;
    dot += ai * bi;
    magA += ai * ai;
    magB += bi * bi;
  }
  const denom = Math.sqrt(magA) * Math.sqrt(magB);
  return denom === 0 ? 0 : dot / denom;
}
