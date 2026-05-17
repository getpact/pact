import { describe, expect, it } from "vitest";
import { parseDuration, parseDurationToSeconds } from "../duration.js";

describe("parseDurationToSeconds", () => {
  it("converts unit-suffixed values to seconds", () => {
    expect(parseDurationToSeconds("30s")).toBe(30);
    expect(parseDurationToSeconds("15m")).toBe(900);
    expect(parseDurationToSeconds("1h")).toBe(3600);
    expect(parseDurationToSeconds("1d")).toBe(86400);
    expect(parseDurationToSeconds("7d")).toBe(604800);
    expect(parseDurationToSeconds("2w")).toBe(1209600);
  });

  it("accepts bare integers as raw seconds", () => {
    expect(parseDurationToSeconds("3600")).toBe(3600);
    expect(parseDurationToSeconds(" 60 ")).toBe(60);
  });

  it("rejects garbage and non-positive input with the supplied flag label", () => {
    expect(() => parseDurationToSeconds("")).toThrow();
    expect(() => parseDurationToSeconds("0d")).toThrow();
    expect(() => parseDurationToSeconds("-1")).toThrow();
    expect(() => parseDurationToSeconds("7y")).toThrow(/--ttl/);
    expect(() => parseDurationToSeconds("abc", "--max-age")).toThrow(/--max-age/);
  });
});

describe("parseDuration (sql interval)", () => {
  it("rejects bare integers so admin keeps explicit units", () => {
    expect(() => parseDuration("3600")).toThrow();
  });

  it("still produces postgres interval strings", () => {
    expect(parseDuration("7d")).toBe("7 days");
    expect(parseDuration("24h")).toBe("24 hours");
    expect(parseDuration("2w")).toBe("14 days");
  });
});
