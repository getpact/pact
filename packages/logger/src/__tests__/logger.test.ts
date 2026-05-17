import { describe, expect, it } from "vitest";
import { createLogger, newRequestId } from "../index.js";

describe("logger", () => {
  it("emits a single json line per call", () => {
    const lines: string[] = [];
    const log = createLogger({ level: "info", sink: (l) => lines.push(l) });
    log.info("hello", { foo: "bar" });
    expect(lines.length).toBe(1);
    const parsed = JSON.parse(lines[0] as string) as Record<string, unknown>;
    expect(parsed.level).toBe("info");
    expect(parsed.msg).toBe("hello");
    expect(parsed.foo).toBe("bar");
    expect(typeof parsed.ts).toBe("string");
  });

  it("respects minimum level", () => {
    const lines: string[] = [];
    const log = createLogger({ level: "warn", sink: (l) => lines.push(l) });
    log.info("ignored");
    log.warn("kept");
    expect(lines.length).toBe(1);
    expect(JSON.parse(lines[0] as string).level).toBe("warn");
  });

  it("merges base fields and child fields", () => {
    const lines: string[] = [];
    const log = createLogger({ base: { app: "issuer" }, sink: (l) => lines.push(l) }).child({
      requestId: "r1",
    });
    log.error("boom", { extra: 1 });
    const parsed = JSON.parse(lines[0] as string) as Record<string, unknown>;
    expect(parsed.app).toBe("issuer");
    expect(parsed.requestId).toBe("r1");
    expect(parsed.extra).toBe(1);
  });

  it("serializes Error to name/message/stack", () => {
    const lines: string[] = [];
    const log = createLogger({ level: "info", sink: (l) => lines.push(l) });
    log.error("failed", { err: new Error("bad") });
    const parsed = JSON.parse(lines[0] as string) as { err: { name: string; message: string } };
    expect(parsed.err.name).toBe("Error");
    expect(parsed.err.message).toBe("bad");
  });

  it("handles circular references", () => {
    const lines: string[] = [];
    const log = createLogger({ level: "info", sink: (l) => lines.push(l) });
    const a: Record<string, unknown> = {};
    a.self = a;
    log.info("circ", { a });
    expect(lines.length).toBe(1);
    expect(lines[0]).toContain("[circular]");
  });

  it("newRequestId returns a non-empty string", () => {
    const id = newRequestId();
    expect(typeof id).toBe("string");
    expect(id.length).toBeGreaterThan(0);
  });
});
