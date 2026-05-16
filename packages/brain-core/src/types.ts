/**
 * Public type surface for @getpact/brain-core. A subset of gbrain's core
 * types, narrowed to what the search and chunking pipeline consumes.
 *
 * Removed from the upstream shape:
 *  - DB-only rows (StaleChunkRow, ChunkInput, FileRow, PageVersion, etc.)
 *  - eval and salience surfaces (EvalCandidate, AnomaliesOpts, etc.)
 *  - mode / cache config rows
 */

export type PageType =
  | "person"
  | "company"
  | "deal"
  | "project"
  | "concept"
  | "source"
  | "media"
  | "writing"
  | "analysis"
  | "guide"
  | "meeting"
  | "note"
  | "email"
  | "slack"
  | "calendar-event"
  | "code"
  | "image"
  | "synthesis";

export type EffectiveDateSource = "event_date" | "date" | "published" | "filename" | "fallback";

export type PageKind = "markdown" | "code" | "image";

export interface Page {
  id: number;
  slug: string;
  type: PageType;
  title: string;
  compiled_truth: string;
  timeline: string;
  frontmatter: Record<string, unknown>;
  content_hash?: string;
  emotional_weight?: number;
  created_at: Date;
  updated_at: Date;
  deleted_at?: Date | null;
  effective_date?: Date | null;
  effective_date_source?: EffectiveDateSource | null;
  import_filename?: string | null;
  salience_touched_at?: Date | null;
  source_id: string;
}

export interface Chunk {
  id: number;
  page_id: number;
  chunk_index: number;
  chunk_text: string;
  chunk_source: "compiled_truth" | "timeline" | "fenced_code";
  embedding: Float32Array | null;
  model: string;
  token_count: number | null;
  embedded_at: Date | null;
  language?: string | null;
  symbol_name?: string | null;
  symbol_type?: string | null;
  start_line?: number | null;
  end_line?: number | null;
  parent_symbol_path?: string[] | null;
  doc_comment?: string | null;
  symbol_name_qualified?: string | null;
}

export interface SearchResult {
  slug: string;
  page_id: number;
  title: string;
  type: PageType;
  chunk_text: string;
  chunk_source: "compiled_truth" | "timeline";
  chunk_id: number;
  chunk_index: number;
  score: number;
  stale: boolean;
  source_id?: string;
}

export interface SearchOpts {
  limit?: number;
  offset?: number;
  type?: PageType;
  types?: PageType[];
  exclude_slugs?: string[];
  exclude_slug_prefixes?: string[];
  include_slug_prefixes?: string[];
  detail?: "low" | "medium" | "high";
  language?: string;
  symbolKind?: string;
  nearSymbol?: string;
  walkDepth?: number;
  sourceId?: string;
  sourceIds?: string[];
  embeddingColumn?: "embedding" | "embedding_image";
  afterDate?: string;
  beforeDate?: string;
  since?: string;
  until?: string;
  recencyBoost?: 0 | 1 | 2;
  recency?: "off" | "on" | "strong";
  salience?: "off" | "on" | "strong";
  intentWeighting?: boolean;
  expansion?: boolean;
  tokenBudget?: number;
  useCache?: boolean;
}

/** Edge in a code or page graph. Used by two-pass structural expansion. */
export interface Edge {
  from_chunk_id?: number | null;
  to_chunk_id?: number | null;
  from_symbol_qualified?: string | null;
  to_symbol_qualified?: string | null;
  edge_type?: string;
}

/** Link between pages (markdown / frontmatter refs). Preserved for parity. */
export interface Link {
  from_slug: string;
  to_slug: string;
  link_type: string;
  context: string;
  link_source?: string | null;
  origin_slug?: string | null;
  origin_field?: string | null;
}

export interface GraphNode {
  slug: string;
  title: string;
  type: PageType;
  depth: number;
  links: { to_slug: string; link_type: string }[];
}

export interface GraphPath {
  from_slug: string;
  to_slug: string;
  link_type: string;
  context: string;
  depth: number;
}

export interface HybridSearchMeta {
  vector_enabled: boolean;
  detail_resolved: "low" | "medium" | "high" | null;
  expansion_applied: boolean;
  intent?: "entity" | "temporal" | "event" | "general";
  mode?: string;
  token_budget?: { budget: number; used: number; dropped: number; kept: number };
  cache?: { status: "hit" | "miss" | "disabled"; similarity?: number; age_seconds?: number };
}

/** Logger contract. Pass any sink that matches; defaults to console. */
export interface Logger {
  debug(msg: string, meta?: Record<string, unknown>): void;
  info(msg: string, meta?: Record<string, unknown>): void;
  warn(msg: string, meta?: Record<string, unknown>): void;
  error(msg: string, meta?: Record<string, unknown>): void;
}

export const consoleLogger: Logger = {
  debug: (m, meta) => {
    if (process.env.BRAIN_DEBUG === "1") console.error(`[brain] ${m}`, meta ?? "");
  },
  info: (m, meta) => console.error(`[brain] ${m}`, meta ?? ""),
  warn: (m, meta) => console.error(`[brain] warn: ${m}`, meta ?? ""),
  error: (m, meta) => console.error(`[brain] error: ${m}`, meta ?? ""),
};
