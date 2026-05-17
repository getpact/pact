# @getpact/brain-core

Audience-aware search primitives used internally by the Pact MCP server.

A fork of [garrytan/gbrain](https://github.com/garrytan/gbrain) (MIT), stripped
down to the search and chunking pipeline. The CLI, dashboard, MCP server,
Postgres wiring, LLM gateway, and tree-sitter code chunkers are removed.

What ships:

- Hybrid retrieval pipeline (keyword plus vector via reciprocal rank fusion)
- Cosine re-scoring and per-page dedup with compiled-truth guarantee
- Two-pass structural expansion over a `SearchAdapter`
- Source-prefix boosts and per-prefix recency decay
- Zero-LLM query intent classifier and intent-weighted RRF
- Token budget enforcement on the final result list
- Recursive delimiter-aware text chunker with CJK support

What you bring:

- A `SearchAdapter` implementation that exposes keyword search, vector
  search, edge walks, and a handful of metadata lookups against whatever
  store you use (in Pact, that is a Drizzle schema on Cloudflare).
- An `EmbedFn` that calls your embedding provider of choice.

See `UPSTREAM.md` for the exact fork commit and the kept-versus-stripped
file lists. See `LICENSE` and `LICENSE-UPSTREAM` for licensing.

## Tracing

brain-core depends on a tiny `BrainTracer` interface (`src/otel.ts`) so
callers can attach OTel spans without pulling any OTel SDK into the
package. When no tracer is supplied, every span call becomes a passthrough
via `noopTracer`.

Hot-path spans:

- `brain.ingest` (parent) with children `brain.chunk`, `brain.embed`.
- `brain.search` (parent) with children `brain.search.keyword`,
  `brain.search.vector`, `brain.search.rrf_fusion`, `brain.search.rerank`,
  `brain.search.dedup`. Keyword-only searches emit only `keyword` and
  `dedup` children.

Every span attaches caller-supplied attrs (`workspace_id`, `tenant_id`,
`trace_id`) plus stage-specific attrs (`hits`, `query_dim`, `candidates_in`,
`candidates_out`, `top_k`, `chunks`, `chars`, etc.). brain-core does not
generate trace ids; pass one through `tracerAttrs.trace_id` so audit rows
on the caller can correlate.

### Wiring a real tracer

The Pact mcp-server, running on Cloudflare Workers, adapts
`@cloudflare/otel` (or any OTel-compatible tracer) at the app layer and
passes a `BrainTracer` into `hybridSearch` / `ingest`. Keep the adapter
outside brain-core so this package remains Worker-safe and free of Node
dependencies.

```ts
import type { BrainTracer } from '@getpact/brain-core';
import { trace } from '@cloudflare/otel';

export function makeBrainTracer(): BrainTracer {
  const tracer = trace.getTracer('brain-core');
  return {
    async span(name, attrs, fn) {
      return tracer.startActiveSpan(name, async (span) => {
        span.setAttributes(attrs);
        try {
          return await fn({
            setAttr: (k, v) => span.setAttribute(k, v as never),
            setAttrs: (a) => span.setAttributes(a as never),
          });
        } finally {
          span.end();
        }
      });
    },
    async childSpan(_parent, name, attrs, fn) {
      return tracer.startActiveSpan(name, async (span) => {
        span.setAttributes(attrs);
        try {
          return await fn({
            setAttr: (k, v) => span.setAttribute(k, v as never),
            setAttrs: (a) => span.setAttributes(a as never),
          });
        } finally {
          span.end();
        }
      });
    },
  };
}
```
