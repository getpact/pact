/**
 * Embedding provider recipes (metadata only) plus a thin caller contract.
 *
 * Upstream gbrain's `src/core/embedding.ts` delegated to a Vercel-AI-SDK
 * backed gateway. We deliberately drop the gateway: Pact wires its own
 * provider client and passes an `EmbedFn` into the search pipeline. The
 * recipes are kept as data so callers can introspect models, dimensions,
 * cost, and batch caps without re-typing them.
 */

export { AIConfigError, AIServiceError, AITransientError, normalizeAIError } from "./errors.js";
export type { ProbeResult } from "./probes.js";
export { probeLlamaServer, probeLMStudio, probeOllama, probeOpenAICompat } from "./probes.js";
export type {
  ChatTouchpoint,
  EmbeddingTouchpoint,
  ExpansionTouchpoint,
  Implementation,
  Recipe,
  RerankerTouchpoint,
  TouchpointKind,
} from "./types.js";

import { getRecipe as _getRecipe } from "./recipes/index.js";

export { getRecipe, listRecipes, RECIPES } from "./recipes/index.js";

/**
 * Caller-provided embedding function. The search pipeline expects a
 * Float32Array sized to the recipe's `default_dims`. Implementations are
 * free to call any provider; recipe metadata is purely advisory.
 */
export type EmbedFn = (text: string) => Promise<Float32Array>;

/** Resolve the recipe for a `provider:model` string. */
export function parseModelId(id: string): { provider: string; model: string } | null {
  const idx = id.indexOf(":");
  if (idx <= 0) return null;
  return { provider: id.slice(0, idx), model: id.slice(idx + 1) };
}

/**
 * Look up the configured embedding dimensions for a `provider:model` string.
 * Returns `undefined` when the recipe is unknown or the model is not in
 * the recipe's embedding touchpoint.
 */
export function dimsForModel(id: string): number | undefined {
  const parsed = parseModelId(id);
  if (!parsed) return undefined;
  const recipe = _getRecipe(parsed.provider);
  return recipe?.touchpoints.embedding?.default_dims;
}
