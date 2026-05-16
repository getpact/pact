export type MetricTags = Record<string, string>;

export type AnalyticsEngineDataPoint = {
  blobs?: string[];
  doubles?: number[];
  indexes?: string[];
};

export type AnalyticsEngineDataset = {
  writeDataPoint: (point: AnalyticsEngineDataPoint) => void;
};

export type MetricsSink = {
  counter: (name: string, value: number, tags?: MetricTags) => void;
  histogram: (name: string, value: number, tags?: MetricTags) => void;
};

export type MetricsClient = MetricsSink & {
  enabled: boolean;
  observe: <T>(name: string, fn: () => Promise<T>, tags?: MetricTags) => Promise<T>;
  recordMintLatency: (durationMs: number, tags?: MetricTags) => void;
  recordVerifyLatency: (durationMs: number, tags?: MetricTags) => void;
  incRefreshReuse: (tags?: MetricTags) => void;
  incKeystoreAadMismatch: (tags?: MetricTags) => void;
  incMcpToolError: (toolName: string, tags?: MetricTags) => void;
};

export const METRIC_NAMES = {
  mintLatency: "issuer.mint_latency_p95",
  verifyLatency: "verifier.verify_latency_p95",
  refreshReuse: "refresh.reuse_count",
  keystoreAadMismatch: "keystore.aad_mismatch",
  mcpToolError: "mcp.tool_error_rate",
} as const;

const tagsToBlobs = (name: string, kind: string, tags?: MetricTags): string[] => {
  const out: string[] = [name, kind];
  if (!tags) return out;
  const keys = Object.keys(tags).sort();
  for (const k of keys) {
    const v = tags[k];
    if (v === undefined) continue;
    out.push(k, v);
  }
  return out;
};

const tagsToIndex = (name: string, tags?: MetricTags): string => {
  if (!tags || Object.keys(tags).length === 0) return name;
  const parts = Object.keys(tags)
    .sort()
    .map((k) => `${k}=${tags[k] ?? ""}`);
  return `${name}|${parts.join(",")}`;
};

export type MetricsOptions = {
  dataset?: AnalyticsEngineDataset;
  baseTags?: MetricTags;
  sink?: MetricsSink;
};

const noopSink: MetricsSink = {
  counter: () => undefined,
  histogram: () => undefined,
};

const analyticsEngineSink = (dataset: AnalyticsEngineDataset): MetricsSink => ({
  counter: (name, value, tags) => {
    dataset.writeDataPoint({
      blobs: tagsToBlobs(name, "counter", tags),
      doubles: [value],
      indexes: [tagsToIndex(name, tags)],
    });
  },
  histogram: (name, value, tags) => {
    dataset.writeDataPoint({
      blobs: tagsToBlobs(name, "histogram", tags),
      doubles: [value],
      indexes: [tagsToIndex(name, tags)],
    });
  },
});

export const createMetrics = (opts: MetricsOptions = {}): MetricsClient => {
  const baseTags = opts.baseTags ?? {};
  const explicitSink = opts.sink;
  const datasetSink = opts.dataset ? analyticsEngineSink(opts.dataset) : undefined;
  const sink = explicitSink ?? datasetSink ?? noopSink;
  const enabled = explicitSink !== undefined || datasetSink !== undefined;

  const mergeTags = (tags?: MetricTags): MetricTags | undefined => {
    if (!tags && Object.keys(baseTags).length === 0) return undefined;
    return { ...baseTags, ...(tags ?? {}) };
  };

  return {
    enabled,
    counter: (name, value, tags) => sink.counter(name, value, mergeTags(tags)),
    histogram: (name, value, tags) => sink.histogram(name, value, mergeTags(tags)),
    observe: async (name, fn, tags) => {
      const start = Date.now();
      let outcome = "ok";
      try {
        return await fn();
      } catch (err) {
        outcome = "error";
        throw err;
      } finally {
        sink.histogram(name, Date.now() - start, mergeTags({ ...(tags ?? {}), outcome }));
      }
    },
    recordMintLatency: (durationMs, tags) =>
      sink.histogram(METRIC_NAMES.mintLatency, durationMs, mergeTags(tags)),
    recordVerifyLatency: (durationMs, tags) =>
      sink.histogram(METRIC_NAMES.verifyLatency, durationMs, mergeTags(tags)),
    incRefreshReuse: (tags) => sink.counter(METRIC_NAMES.refreshReuse, 1, mergeTags(tags)),
    incKeystoreAadMismatch: (tags) =>
      sink.counter(METRIC_NAMES.keystoreAadMismatch, 1, mergeTags(tags)),
    incMcpToolError: (toolName, tags) =>
      sink.counter(
        METRIC_NAMES.mcpToolError,
        1,
        mergeTags({ tool_name: toolName, ...(tags ?? {}) }),
      ),
  };
};

export type MetricsEnv = {
  METRICS?: AnalyticsEngineDataset;
};

export const metricsFromEnv = (env: MetricsEnv, app: string): MetricsClient =>
  createMetrics({
    ...(env.METRICS ? { dataset: env.METRICS } : {}),
    baseTags: { app },
  });
