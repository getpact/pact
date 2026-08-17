// Cross-language conformance. The same corpus is replayed by
// packages/verifier-sdk-python/tests/test_conformance.py; both suites must
// reach the same verdict for every case. See conformance/README.md.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { JSONWebKeySet } from "jose";
import { describe, expect, it } from "vitest";
import { JwksCache } from "../jwks.js";
import { type ReplayCache, type VerifyOpts, verifyPactToken } from "../verifyPactToken.js";

type ConformanceCase = {
  name: string;
  description: string;
  sdJwt: string;
  options: {
    audience: string;
    toolName?: string;
    resource?: Record<string, unknown>;
    kbIatSkewSeconds?: number;
    kbIatMaxAgeSeconds?: number;
  };
  replaySeed?: string[];
  expect:
    | { ok: true; jti: string; workspaceId: string; audience: string; agentId?: string }
    | { ok: false; reason: string };
};

type Corpus = {
  version: number;
  nowSeconds: number;
  jwksUri: string;
  jwks: JSONWebKeySet;
  cases: ConformanceCase[];
};

const corpusPath = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../conformance/verifier-cases.json",
);
const corpus = JSON.parse(readFileSync(corpusPath, "utf8")) as Corpus;

const seededCache = (seed: string[]): ReplayCache => {
  const seen = new Set(seed);
  return {
    has: async (key) => seen.has(key),
    add: async (key) => {
      seen.add(key);
    },
  };
};

describe("verifier conformance corpus", () => {
  it("is the version this suite understands", () => {
    expect(corpus.version).toBe(1);
    expect(corpus.cases.length).toBeGreaterThan(0);
  });

  for (const testCase of corpus.cases) {
    it(`${testCase.name}: ${testCase.description}`, async () => {
      const opts: VerifyOpts = {
        jwksUri: corpus.jwksUri,
        audience: testCase.options.audience,
        // The corpus clock is in seconds; this SDK reads milliseconds.
        now: () => corpus.nowSeconds * 1000,
        jwksCache: new JwksCache({ fetcher: async () => corpus.jwks }),
        ...(testCase.options.toolName !== undefined ? { toolName: testCase.options.toolName } : {}),
        ...(testCase.options.resource !== undefined ? { resource: testCase.options.resource } : {}),
        ...(testCase.options.kbIatSkewSeconds !== undefined
          ? { kbIatSkewSeconds: testCase.options.kbIatSkewSeconds }
          : {}),
        ...(testCase.options.kbIatMaxAgeSeconds !== undefined
          ? { kbIatMaxAgeSeconds: testCase.options.kbIatMaxAgeSeconds }
          : {}),
        ...(testCase.replaySeed ? { replayCache: seededCache(testCase.replaySeed) } : {}),
      };

      const result = await verifyPactToken(testCase.sdJwt, opts);

      if (testCase.expect.ok) {
        if (!result.ok) throw new Error(`expected allow, denied with ${result.reason}`);
        expect(result.jti).toBe(testCase.expect.jti);
        expect(result.workspaceId).toBe(testCase.expect.workspaceId);
        expect(result.audience).toBe(testCase.expect.audience);
        if (testCase.expect.agentId !== undefined) {
          expect(result.agentId).toBe(testCase.expect.agentId);
        }
        return;
      }

      if (result.ok) throw new Error(`expected deny ${testCase.expect.reason}, got allow`);
      expect(result.reason).toBe(testCase.expect.reason);
    });
  }
});
