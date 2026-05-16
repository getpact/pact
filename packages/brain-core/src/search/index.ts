export type { PageRef, SearchAdapter } from "./adapter.js";
export { emptyAdapter } from "./adapter.js";
export { dedupResults } from "./dedup.js";
export type { HybridSearchOpts, PostFusionOpts } from "./hybrid.js";
export {
  applyBacklinkBoost,
  applyRecencyBoost,
  applySalienceBoost,
  cosineSimilarity,
  hybridSearch,
  rrfFusion,
  rrfFusionWeighted,
  runPostFusionStages,
} from "./hybrid.js";
export type { IntentWeights } from "./intent-weights.js";
export {
  applyExactMatchBoost,
  effectiveRrfK,
  weightsForIntent,
} from "./intent-weights.js";
export type {
  QueryIntent,
  QuerySuggestions,
  RecencyMode,
  SalienceMode,
} from "./query-intent.js";
export {
  autoDetectDetail,
  classifyQuery,
  classifyQueryIntent,
  intentToDetail,
} from "./query-intent.js";
export type { RecencyDecayConfig, RecencyDecayMap } from "./recency-decay.js";

export {
  DEFAULT_FALLBACK,
  DEFAULT_RECENCY_DECAY,
} from "./recency-decay.js";
export { DEFAULT_SOURCE_BOOSTS } from "./source-boost.js";
export { enforceTokenBudget, estimateTokens, resultTokens } from "./token-budget.js";
export type { TwoPassOpts } from "./two-pass.js";
export { expandAnchors, hydrateChunks } from "./two-pass.js";
