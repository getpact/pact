import { describe, expect, test } from "vitest";
import { ingest } from "../src/ingest.js";
import type { BrainTracer, SpanAttrs, SpanHandle } from "../src/otel.js";
import { mergeAttrs, noopTracer } from "../src/otel.js";
import type { SearchAdapter } from "../src/search/adapter.js";
import { hybridSearch } from "../src/search/hybrid.js";
import type { SearchResult } from "../src/types.js";

type Recorded = {
  name: string;
  parent?: string;
  attrs: SpanAttrs;
  postAttrs: SpanAttrs;
};

function mockTracer(): { tracer: BrainTracer; spans: Recorded[] } {
  const spans: Recorded[] = [];
  const makeHandle = (rec: Recorded): SpanHandle => ({
    setAttr(key, value) {
      rec.postAttrs[key] = value;
    },
    setAttrs(extra) {
      Object.assign(rec.postAttrs, extra);
    },
  });
  const tracer: BrainTracer = {
    async span(name, attrs, fn) {
      const rec: Recorded = { name, attrs: { ...attrs }, postAttrs: {} };
      spans.push(rec);
      return fn(makeHandle(rec));
    },
    async childSpan(parent, name, attrs, fn) {
      const rec: Recorded = { name, parent, attrs: { ...attrs }, postAttrs: {} };
      spans.push(rec);
      return fn(makeHandle(rec));
    },
  };
  return { tracer, spans };
}

function makeResult(slug: string, score: number, chunkId: number): SearchResult {
  return {
    slug,
    page_id: chunkId,
    title: slug,
    type: "concept",
    chunk_text: `text for ${slug}`,
    chunk_source: "compiled_truth",
    chunk_id: chunkId,
    chunk_index: 0,
    score,
    stale: false,
    source_id: "default",
  };
}

function adapterFixture(): SearchAdapter {
  return {
    async searchKeyword() {
      return [makeResult("a", 0.9, 1), makeResult("b", 0.8, 2)];
    },
    async searchVector() {
      return [makeResult("b", 0.85, 2), makeResult("c", 0.7, 3)];
    },
    async getEmbeddingsByChunkIds(ids) {
      const m = new Map<number, Float32Array>();
      for (const id of ids) {
        m.set(id, new Float32Array([0.1, 0.2, 0.3]));
      }
      return m;
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
}

describe("noopTracer", () => {
  test("span passes the value through unchanged", async () => {
    const r = await noopTracer.span("any", { a: 1 }, async () => 42);
    expect(r).toBe(42);
  });

  test("childSpan passes the value through unchanged", async () => {
    const r = await noopTracer.childSpan("p", "c", {}, async () => "ok");
    expect(r).toBe("ok");
  });

  test("span body can use the handle without throwing", async () => {
    await noopTracer.span("any", {}, async (h) => {
      h.setAttr("k", 1);
      h.setAttrs({ a: 2, b: 3 });
    });
  });
});

describe("mergeAttrs", () => {
  test("per-call extras win", () => {
    expect(mergeAttrs({ a: 1, b: 2 }, { b: 9, c: 3 })).toEqual({ a: 1, b: 9, c: 3 });
  });

  test("absent base returns extras", () => {
    expect(mergeAttrs(undefined, { c: 3 })).toEqual({ c: 3 });
  });
});

describe("ingest tracing", () => {
  test("emits brain.ingest with brain.chunk and brain.embed children", async () => {
    const { tracer, spans } = mockTracer();
    const text = "one two three four. five six seven eight. nine ten.";
    const embed = async (_t: string): Promise<Float32Array> => new Float32Array([0.5, 0.5]);

    const out = await ingest(text, {
      tracer,
      tracerAttrs: { workspace_id: "w1", tenant_id: "t1", trace_id: "tr1" },
      embed,
      embedModel: "openai:text-embedding-3-small",
      embedBatchSize: 4,
      chunkSize: 4,
    });

    expect(out.chunks.length).toBeGreaterThan(0);
    expect(out.embeddings.length).toBe(out.chunks.length);

    const names = spans.map((s) => s.name);
    expect(names).toEqual(["brain.ingest", "brain.chunk", "brain.embed"]);

    const ingestSpan = spans[0]!;
    expect(ingestSpan.attrs.workspace_id).toBe("w1");
    expect(ingestSpan.attrs.tenant_id).toBe("t1");
    expect(ingestSpan.attrs.trace_id).toBe("tr1");
    expect(ingestSpan.attrs.chars).toBe(text.length);
    expect(ingestSpan.postAttrs.chunks).toBe(out.chunks.length);

    const chunkSpan = spans[1]!;
    expect(chunkSpan.parent).toBe("brain.ingest");
    expect(chunkSpan.attrs.chars).toBe(text.length);
    expect(chunkSpan.postAttrs.chunks).toBe(out.chunks.length);

    const embedSpan = spans[2]!;
    expect(embedSpan.parent).toBe("brain.ingest");
    expect(embedSpan.attrs.model).toBe("openai:text-embedding-3-small");
    expect(embedSpan.attrs.batch_size).toBe(4);
    expect(embedSpan.attrs.chunks).toBe(out.chunks.length);
    expect(embedSpan.attrs.workspace_id).toBe("w1");
  });

  test("skips embed work when no embed fn is supplied and still records the span", async () => {
    const { tracer, spans } = mockTracer();
    const out = await ingest("hello world", { tracer });
    expect(out.embeddings).toEqual([]);
    const names = spans.map((s) => s.name);
    expect(names).toEqual(["brain.ingest", "brain.chunk", "brain.embed"]);
    expect(spans[2]?.attrs.skipped).toBe(true);
  });
});

describe("hybridSearch tracing", () => {
  test("records all five child spans on the vector-enabled path", async () => {
    const { tracer, spans } = mockTracer();
    const adapter = adapterFixture();
    const embed = async (_t: string): Promise<Float32Array> => new Float32Array([0.1, 0.2, 0.3]);

    await hybridSearch(adapter, "what is the deal with foo", {
      tracer,
      tracerAttrs: { workspace_id: "w1", tenant_id: "t1", trace_id: "tr1" },
      embed,
      limit: 10,
    });

    const names = spans.map((s) => s.name);
    expect(names).toContain("brain.search");
    expect(names).toContain("brain.search.keyword");
    expect(names).toContain("brain.search.vector");
    expect(names).toContain("brain.search.rrf_fusion");
    expect(names).toContain("brain.search.rerank");
    expect(names).toContain("brain.search.dedup");

    const childCount = spans.filter((s) => s.parent === "brain.search").length;
    expect(childCount).toBe(5);

    for (const s of spans) {
      expect(s.attrs.workspace_id).toBe("w1");
      expect(s.attrs.tenant_id).toBe("t1");
      expect(s.attrs.trace_id).toBe("tr1");
    }

    const keyword = spans.find((s) => s.name === "brain.search.keyword")!;
    expect(keyword.attrs.query_len).toBe("what is the deal with foo".length);
    expect(keyword.postAttrs.hits).toBe(2);

    const vector = spans.find((s) => s.name === "brain.search.vector")!;
    expect(vector.attrs.query_dim).toBe(3);
    expect(vector.postAttrs.hits).toBe(2);

    const fusion = spans.find((s) => s.name === "brain.search.rrf_fusion")!;
    expect(fusion.attrs.candidates_in).toBe(4);
    expect(typeof fusion.postAttrs.candidates_out).toBe("number");

    const rerank = spans.find((s) => s.name === "brain.search.rerank")!;
    expect(typeof rerank.attrs.candidates_in).toBe("number");
    expect(typeof rerank.attrs.top_k).toBe("number");

    const dedup = spans.find((s) => s.name === "brain.search.dedup")!;
    expect(typeof dedup.postAttrs.candidates_out).toBe("number");
  });

  test("keyword-only path still records search and dedup spans", async () => {
    const { tracer, spans } = mockTracer();
    const adapter = adapterFixture();

    await hybridSearch(adapter, "foo", {
      tracer,
      limit: 5,
    });

    const names = spans.map((s) => s.name);
    expect(names).toContain("brain.search");
    expect(names).toContain("brain.search.keyword");
    expect(names).toContain("brain.search.dedup");
    expect(names).not.toContain("brain.search.vector");
    expect(names).not.toContain("brain.search.rrf_fusion");
    expect(names).not.toContain("brain.search.rerank");
  });

  test("runs without a tracer (default noop)", async () => {
    const adapter = adapterFixture();
    const out = await hybridSearch(adapter, "foo");
    expect(Array.isArray(out)).toBe(true);
  });
});

describe("async propagation", () => {
  test("parallel child spans complete and record correctly", async () => {
    const { tracer, spans } = mockTracer();
    await tracer.span("brain.parallel", {}, async () => {
      const work = [10, 20, 30].map((d, i) =>
        tracer.childSpan(
          "brain.parallel",
          `brain.parallel.leg.${i}`,
          { delay_ms: d },
          async (h) => {
            await new Promise((r) => setTimeout(r, d));
            h.setAttr("done", true);
            return d;
          },
        ),
      );
      const out = await Promise.all(work);
      expect(out).toEqual([10, 20, 30]);
    });

    const leg0 = spans.find((s) => s.name === "brain.parallel.leg.0")!;
    const leg1 = spans.find((s) => s.name === "brain.parallel.leg.1")!;
    const leg2 = spans.find((s) => s.name === "brain.parallel.leg.2")!;
    expect(leg0.postAttrs.done).toBe(true);
    expect(leg1.postAttrs.done).toBe(true);
    expect(leg2.postAttrs.done).toBe(true);
  });
});
