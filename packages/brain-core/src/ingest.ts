/**
 * Ingest pipeline: chunk a document, embed each chunk, return both. The
 * function exists so callers have a single place to attach a parent
 * `brain.ingest` span and so the chunker can stay synchronous while still
 * being measured.
 */

import type { ChunkOptions, TextChunk } from "./chunkers/recursive.js";
import { chunkText } from "./chunkers/recursive.js";
import type { EmbedFn } from "./embedding/index.js";
import type { BrainTracer, SpanAttrs } from "./otel.js";
import { mergeAttrs, noopTracer } from "./otel.js";

export interface IngestResult {
  chunks: TextChunk[];
  embeddings: Float32Array[];
}

export interface IngestOpts extends ChunkOptions {
  embed?: EmbedFn;
  /** Batch size for the embed step. Forwarded as a span attribute only. */
  embedBatchSize?: number;
  /** Model id (e.g. "openai:text-embedding-3-small") for the embed span. */
  embedModel?: string;
  tracer?: BrainTracer;
  tracerAttrs?: SpanAttrs;
}

export async function ingest(text: string, opts?: IngestOpts): Promise<IngestResult> {
  const tracer = opts?.tracer ?? noopTracer;
  const baseAttrs = opts?.tracerAttrs;

  return tracer.span(
    "brain.ingest",
    mergeAttrs(baseAttrs, { chars: text.length }),
    async (parent) => {
      const chunks = await tracer.childSpan(
        "brain.ingest",
        "brain.chunk",
        mergeAttrs(baseAttrs, { chars: text.length }),
        async (span) => {
          const c = chunkText(text, opts);
          span.setAttr("chunks", c.length);
          return c;
        },
      );
      parent.setAttr("chunks", chunks.length);

      const batchSize = opts?.embedBatchSize ?? Math.max(1, chunks.length);
      const model = opts?.embedModel ?? "unknown";
      const embeddings: Float32Array[] = [];

      if (!opts?.embed || chunks.length === 0) {
        await tracer.childSpan(
          "brain.ingest",
          "brain.embed",
          mergeAttrs(baseAttrs, {
            model,
            batch_size: batchSize,
            chunks: chunks.length,
            skipped: true,
          }),
          async () => undefined,
        );
        return { chunks, embeddings };
      }

      const embed = opts.embed;
      await tracer.childSpan(
        "brain.ingest",
        "brain.embed",
        mergeAttrs(baseAttrs, {
          model,
          batch_size: batchSize,
          chunks: chunks.length,
        }),
        async () => {
          for (let i = 0; i < chunks.length; i += batchSize) {
            const slice = chunks.slice(i, i + batchSize);
            const batch = await Promise.all(slice.map((c) => embed(c.text)));
            for (const v of batch) embeddings.push(v);
          }
        },
      );

      return { chunks, embeddings };
    },
  );
}
