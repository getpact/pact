import { describe, expect, it } from "vitest";
import {
  type AnalyticsEngineDataPoint,
  createMetrics,
  METRIC_NAMES,
  metricsFromEnv,
} from "../metrics.js";

const recordingDataset = () => {
  const points: AnalyticsEngineDataPoint[] = [];
  return {
    points,
    writeDataPoint: (p: AnalyticsEngineDataPoint) => {
      points.push(p);
    },
  };
};

describe("metrics", () => {
  it("returns an enabled=false client when no sink or dataset is provided", () => {
    const m = createMetrics();
    expect(m.enabled).toBe(false);
    m.counter("noop", 1);
    m.histogram("noop", 1);
  });

  it("metricsFromEnv is a no-op when METRICS binding is absent", () => {
    const m = metricsFromEnv({}, "issuer");
    expect(m.enabled).toBe(false);
    m.incRefreshReuse();
  });

  it("writes counter points with name and value via dataset", () => {
    const dataset = recordingDataset();
    const m = createMetrics({ dataset, baseTags: { app: "issuer" } });
    expect(m.enabled).toBe(true);
    m.incRefreshReuse();
    expect(dataset.points).toHaveLength(1);
    const point = dataset.points[0];
    if (!point) throw new Error("expected point");
    expect(point.blobs?.[0]).toBe(METRIC_NAMES.refreshReuse);
    expect(point.blobs?.[1]).toBe("counter");
    expect(point.doubles?.[0]).toBe(1);
    expect(point.blobs).toContain("app");
    expect(point.blobs).toContain("issuer");
  });

  it("writes histogram points and merges baseTags with call tags", () => {
    const dataset = recordingDataset();
    const m = createMetrics({ dataset, baseTags: { app: "issuer" } });
    m.recordMintLatency(42, { audience: "pact-mcp" });
    const point = dataset.points[0];
    if (!point) throw new Error("expected point");
    expect(point.blobs?.[0]).toBe(METRIC_NAMES.mintLatency);
    expect(point.blobs?.[1]).toBe("histogram");
    expect(point.doubles?.[0]).toBe(42);
    expect(point.blobs).toContain("audience");
    expect(point.blobs).toContain("pact-mcp");
  });

  it("incMcpToolError tags by tool_name", () => {
    const dataset = recordingDataset();
    const m = createMetrics({ dataset });
    m.incMcpToolError("brain.list");
    const point = dataset.points[0];
    if (!point) throw new Error("expected point");
    expect(point.blobs?.[0]).toBe(METRIC_NAMES.mcpToolError);
    expect(point.blobs).toContain("tool_name");
    expect(point.blobs).toContain("brain.list");
  });

  it("observe records latency on success and failure", async () => {
    const dataset = recordingDataset();
    const m = createMetrics({ dataset });
    const result = await m.observe("foo.latency", async () => 7);
    expect(result).toBe(7);
    expect(dataset.points).toHaveLength(1);
    expect(dataset.points[0]?.blobs).toContain("outcome");
    expect(dataset.points[0]?.blobs).toContain("ok");

    await expect(
      m.observe("foo.latency", async () => {
        throw new Error("nope");
      }),
    ).rejects.toThrow("nope");
    expect(dataset.points).toHaveLength(2);
    expect(dataset.points[1]?.blobs).toContain("error");
  });

  it("explicit sink overrides dataset", () => {
    const calls: Array<{ kind: string; name: string; value: number }> = [];
    const m = createMetrics({
      sink: {
        counter: (name, value) => calls.push({ kind: "counter", name, value }),
        histogram: (name, value) => calls.push({ kind: "histogram", name, value }),
      },
    });
    m.incKeystoreAadMismatch();
    m.recordVerifyLatency(5);
    expect(calls).toEqual([
      { kind: "counter", name: METRIC_NAMES.keystoreAadMismatch, value: 1 },
      { kind: "histogram", name: METRIC_NAMES.verifyLatency, value: 5 },
    ]);
  });
});
