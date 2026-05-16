/**
 * Recency decay map parse + merge tests. The upstream gbrain test also
 * exercised buildRecencyComponentSql; that lives in sql-ranking.ts which
 * is not part of this fork. The SQL surface ships with each callers
 * SearchAdapter implementation.
 */

import { describe, expect, test } from "vitest";
import {
  DEFAULT_FALLBACK,
  DEFAULT_RECENCY_DECAY,
  parseRecencyDecayEnv,
  parseRecencyDecayYaml,
  RecencyDecayParseError,
  resolveRecencyDecayMap,
} from "../src/search/recency-decay.js";

describe("parseRecencyDecayEnv", () => {
  test("empty / undefined returns empty map", () => {
    expect(parseRecencyDecayEnv(undefined)).toEqual({});
    expect(parseRecencyDecayEnv("")).toEqual({});
  });

  test("single triple", () => {
    expect(parseRecencyDecayEnv("daily/:7:1.5")).toEqual({
      "daily/": { halflifeDays: 7, coefficient: 1.5 },
    });
  });

  test("multiple triples comma-separated", () => {
    const out = parseRecencyDecayEnv("daily/:7:1.5,concepts/:0:0,custom/:30:0.5");
    expect(out["daily/"]).toEqual({ halflifeDays: 7, coefficient: 1.5 });
    expect(out["concepts/"]).toEqual({ halflifeDays: 0, coefficient: 0 });
    expect(out["custom/"]).toEqual({ halflifeDays: 30, coefficient: 0.5 });
  });

  test("throws on missing field", () => {
    expect(() => parseRecencyDecayEnv("daily/:7")).toThrow(RecencyDecayParseError);
  });
});

describe("parseRecencyDecayYaml", () => {
  test("null / undefined returns empty", () => {
    expect(parseRecencyDecayYaml(null)).toEqual({});
    expect(parseRecencyDecayYaml(undefined)).toEqual({});
  });

  test("parses well-formed yaml object", () => {
    const out = parseRecencyDecayYaml({
      recency: {
        "daily/": { halflifeDays: 14, coefficient: 1.0 },
        "archive/": { halflifeDays: 0, coefficient: 0 },
      },
    });
    expect(out["daily/"]).toEqual({ halflifeDays: 14, coefficient: 1.0 });
    expect(out["archive/"]).toEqual({ halflifeDays: 0, coefficient: 0 });
  });
});

describe("resolveRecencyDecayMap", () => {
  test("returns defaults when no overrides", () => {
    const out = resolveRecencyDecayMap({ envValue: "" });
    expect(out).toEqual(DEFAULT_RECENCY_DECAY);
  });

  test("env overrides defaults at matching prefix", () => {
    const out = resolveRecencyDecayMap({ envValue: "daily/:7:2.0" });
    expect(out["daily/"]).toEqual({ halflifeDays: 7, coefficient: 2.0 });
  });

  test("caller overrides win over yaml and env", () => {
    const out = resolveRecencyDecayMap({
      yaml: { recency: { "daily/": { halflifeDays: 14, coefficient: 1.5 } } },
      envValue: "daily/:7:2.0",
      caller: { "daily/": { halflifeDays: 3, coefficient: 3.0 } },
    });
    expect(out["daily/"]).toEqual({ halflifeDays: 3, coefficient: 3.0 });
  });
});

describe("defaults sanity", () => {
  test("fallback has a positive halflife", () => {
    expect(DEFAULT_FALLBACK.halflifeDays).toBeGreaterThan(0);
  });

  test("default map carries at least one prefix", () => {
    expect(Object.keys(DEFAULT_RECENCY_DECAY).length).toBeGreaterThan(0);
  });
});
