/**
 * Embedding-provider recipe types. Pure data shape - the gateway and SDK
 * wiring from upstream gbrain is intentionally not part of this fork; this
 * module exposes recipes as metadata so Pact can build its own client.
 *
 * Only the touchpoints used by the search pipeline (embedding, reranker)
 * are typed here; the full upstream Recipe also covered chat, expansion,
 * transcription, etc.
 */

export type TouchpointKind = "embedding" | "reranker" | "expansion" | "chat";

export type Implementation =
  | "native-openai"
  | "native-google"
  | "native-anthropic"
  | "openai-compatible";

export interface EmbeddingTouchpoint {
  models: string[];
  default_dims: number;
  dims_options?: number[];
  cost_per_1m_tokens_usd?: number;
  price_last_verified?: string;
  max_batch_tokens?: number;
  chars_per_token?: number;
  safety_factor?: number;
  supports_multimodal?: boolean;
  multimodal_models?: string[];
  user_provided_models?: true;
  no_batch_cap?: true;
}

export interface ExpansionTouchpoint {
  models: string[];
  cost_per_1m_tokens_usd?: number;
  price_last_verified?: string;
}

export interface RerankerTouchpoint {
  models: string[];
  default_model: string;
  cost_per_1m_tokens_usd?: number;
  price_last_verified?: string;
  max_payload_bytes: number;
}

export interface ChatTouchpoint {
  models: string[];
  supports_tools: boolean;
  supports_subagent_loop: boolean;
  supports_prompt_cache?: boolean;
  max_context_tokens?: number;
  cost_per_1m_input_usd?: number;
  cost_per_1m_output_usd?: number;
  price_last_verified?: string;
}

export interface Recipe {
  id: string;
  name: string;
  tier: "native" | "openai-compat";
  implementation: Implementation;
  base_url_default?: string;
  auth_env?: {
    required: string[];
    optional?: string[];
    setup_url?: string;
  };
  touchpoints: {
    embedding?: EmbeddingTouchpoint;
    expansion?: ExpansionTouchpoint;
    chat?: ChatTouchpoint;
    reranker?: RerankerTouchpoint;
  };
  aliases?: Record<string, string>;
  setup_hint?: string;
  /**
   * Auth resolver carried by recipes that need non-Bearer schemes (Azure
   * api-key, future OAuth providers). Optional; defaults to Bearer + first
   * `auth_env.required` env var.
   */
  resolveAuth?(env: Record<string, string | undefined>): {
    headerName: string;
    token: string;
  };
  /**
   * Templated openai-compatible config for recipes whose URL shape does not
   * fit a static `base_url_default` (Azure splices a deployment + api-version).
   */
  resolveOpenAICompatConfig?(env: Record<string, string | undefined>): {
    baseURL: string;
    fetch?: typeof fetch;
  };
  /** Optional runtime readiness check for local-server recipes (ollama, llama-server). */
  probe?(baseURL?: string): Promise<{ ready: boolean; hint?: string }>;
}
