import { describe, expect, it } from "vitest";
import {
  type Adapter,
  buildToolRegistry,
  defaultToolAuthorization,
  errorResult,
  json,
} from "../index.js";

describe("adapter sdk", () => {
  const sample: Adapter = {
    name: "sample",
    tools: [
      {
        descriptor: { name: "sample.echo", description: "echo", inputSchema: { type: "object" } },
        handler: async (args) => json({ args }),
      },
    ],
  };

  it("builds a registry from adapters", () => {
    const reg = buildToolRegistry([sample]);
    expect(reg.has("sample.echo")).toBe(true);
  });

  it("rejects duplicate tool names", () => {
    expect(() => buildToolRegistry([sample, sample])).toThrow(/duplicate tool name/);
  });

  it("json wraps a value in a content block", () => {
    const r = json({ a: 1 });
    expect(r.content[0]?.type).toBe("text");
    expect(r.content[0]?.text).toContain('"a": 1');
    expect(r.isError).toBeUndefined();
  });

  it("errorResult flags isError true", () => {
    const r = errorResult("nope");
    expect(r.isError).toBe(true);
    expect(r.content[0]?.text).toBe("nope");
  });

  it("builds default tool authorization", () => {
    expect(defaultToolAuthorization("sample.echo")).toEqual({
      action: "tool:sample.echo",
      resource: "tool:sample.echo",
    });
  });
});
