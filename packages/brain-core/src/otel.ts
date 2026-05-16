/**
 * Minimal tracer surface. brain-core stays free of any concrete OTel SDK so
 * it runs unchanged on Cloudflare Workers. Callers wire a real tracer (the
 * Pact mcp-server uses @cloudflare/otel) and pass it via opts; absent that,
 * the noop tracer keeps every span call a synchronous passthrough.
 *
 * Trace id propagation is the caller's job: pass `trace_id` (and any other
 * correlation ids such as `workspace_id` / `tenant_id`) through the attrs
 * bag so the caller's exporter can stitch spans into the right trace.
 */

export type SpanAttrs = Record<string, unknown>;

/**
 * In-flight handle a span body can use to record attrs derived from the
 * work itself (hit counts, candidate counts, etc.). Real adapters wire
 * this to OTel's span.setAttribute / setAttributes.
 */
export interface SpanHandle {
  setAttr(key: string, value: unknown): void;
  setAttrs(attrs: SpanAttrs): void;
}

export interface BrainTracer {
  span<T>(name: string, attrs: SpanAttrs, fn: (span: SpanHandle) => Promise<T>): Promise<T>;
  childSpan<T>(
    parentName: string,
    name: string,
    attrs: SpanAttrs,
    fn: (span: SpanHandle) => Promise<T>,
  ): Promise<T>;
}

const noopHandle: SpanHandle = {
  setAttr() {},
  setAttrs() {},
};

export const noopTracer: BrainTracer = {
  async span(_name, _attrs, fn) {
    return fn(noopHandle);
  },
  async childSpan(_parent, _name, _attrs, fn) {
    return fn(noopHandle);
  },
};

/**
 * Merge a base attrs bag with per-call extras. Caller-supplied keys win so
 * a child can override a parent attr if it knows better (e.g. a more precise
 * hit count once the stage has actually run).
 */
export function mergeAttrs(base: SpanAttrs | undefined, extra: SpanAttrs): SpanAttrs {
  if (!base) return extra;
  return { ...base, ...extra };
}
