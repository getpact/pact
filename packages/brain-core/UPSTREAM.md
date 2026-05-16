# Upstream provenance

`@getpact/brain-core` is a one-time fork of [garrytan/gbrain](https://github.com/garrytan/gbrain).

## Fork point

- Repository: https://github.com/garrytan/gbrain
- Commit: `3933eb6a7915cb5495b8057b75567e2b1588b5ac`
- Date forked: 2026-05-16
- License: MIT (see LICENSE-UPSTREAM)

## Maintenance strategy

One-time fork plus divergence. No upstream pull. Bug fixes and improvements
land directly in this package; upstream is treated as a frozen reference,
not a tracking branch. If a worthwhile upstream change appears, it gets
ported by hand with attribution in the commit message.

## Preserved files

Adapted to swap the gbrain `BrainEngine` interface for an abstract
`SearchAdapter`, drop the AI gateway dependency, and convert to ESM with
explicit `.js` extensions. Original semantics are preserved.

- `src/types.ts` (subset of `gbrain/src/core/types.ts`)
- `src/cjk.ts` (`gbrain/src/core/cjk.ts`)
- `src/search/adapter.ts` (new abstraction layer)
- `src/search/dedup.ts` (`gbrain/src/core/search/dedup.ts`)
- `src/search/query-intent.ts` (`gbrain/src/core/search/query-intent.ts`)
- `src/search/intent-weights.ts` (`gbrain/src/core/search/intent-weights.ts`)
- `src/search/token-budget.ts` (`gbrain/src/core/search/token-budget.ts`)
- `src/search/recency-decay.ts` (`gbrain/src/core/search/recency-decay.ts`)
- `src/search/source-boost.ts` (`gbrain/src/core/search/source-boost.ts`)
- `src/search/two-pass.ts` (`gbrain/src/core/search/two-pass.ts`)
- `src/search/hybrid.ts` (`gbrain/src/core/search/hybrid.ts`, simplified)
- `src/chunkers/recursive.ts` (`gbrain/src/core/chunkers/recursive.ts`)
- `src/embedding/recipes/*.ts` (`gbrain/src/core/ai/recipes/*.ts`, metadata only)
- `src/embedding/index.ts` (new, replaces `gbrain/src/core/embedding.ts`)

## Stripped files

The following gbrain surface area is intentionally not part of this fork.
Pact does not need it, and several pieces would force heavy dependencies
(tree-sitter WASM, a 1.5 MB tokenizer, the Vercel AI SDK, postgres-js).

- `gbrain/bin/`, `gbrain/src/cli.ts`, `gbrain/src/commands/` (CLI surface)
- `gbrain/src/mcp/` (MCP server)
- `gbrain/admin/`, `gbrain/templates/` (dashboard, init flows)
- `gbrain/skills/`, `gbrain/recipes/`, `gbrain/scripts/` (skill packs, helper scripts)
- `gbrain/src/core/ai/gateway.ts` and recipe wiring (provider SDK calls)
- `gbrain/src/core/engine.ts`, `pglite-engine.ts`, `postgres-engine.ts`
  (database engines; replaced by `SearchAdapter`)
- `gbrain/src/core/chunkers/code.ts`, `edge-extractor.ts`,
  `symbol-resolver.ts`, `qualified-names.ts` (tree-sitter dependent)
- `gbrain/src/core/chunkers/llm.ts`, `semantic.ts` (LLM dependent)
- `gbrain/src/core/search/keyword.ts`, `vector.ts` (engine wrappers; the
  adapter exposes these methods directly)
- `gbrain/src/core/search/rerank.ts` (cross-encoder via AI gateway)
- `gbrain/src/core/search/expansion.ts` (LLM query expansion)
- `gbrain/src/core/search/telemetry.ts` (DB-backed search telemetry)
- `gbrain/src/core/search/query-cache.ts` (DB-backed semantic cache)
- `gbrain/src/core/search/mode.ts`, `sql-ranking.ts`, `eval.ts`
- `gbrain/test/` everything except dedup, intent-weights, query-intent,
  recency-decay, token-budget

## ASCII compliance

All source and test files have been scrubbed to ASCII-only per the Pact
repo's text style rules. The fork preserves upstream code style otherwise.

Replacements applied across `src/**/*.ts` and `test/**/*.ts`:

- em-dash and en-dash -> ` - ` (space-hyphen-space)
- right and left arrows -> `->` and `<-`
- curly single and double quotes -> straight `'` and `"`
- ellipsis -> `...`
- multiplication sign -> `x`
- bullet glyph and box-drawing characters -> `-`
- block characters -> `*`
- approximate and less-or-equal -> `~` and `<=`
- CJK brand names in recipe metadata transliterated to ASCII

`src/cjk.ts` retains CJK character ranges. Those code points are a
functional requirement of the CJK-aware chunker (script and punctuation
detection), not prose, and are kept verbatim.

## Non-goals

- Field-level redaction beyond what `SearchResult` already carries. Audience-
  aware filtering lives in the Pact policy layer above this package.
- Direct provider SDK calls. Embedding is exposed as recipe metadata plus a
  pluggable `EmbedFn`; Pact wires its own provider client.
- Storage. The `SearchAdapter` is the only contract; the caller owns the
  database schema and queries.
