#!/usr/bin/env node
// Fail CI if any test file that is supposed to require a real database was skipped.

import { readFileSync } from "node:fs";
import { argv, exit } from "node:process";

const logPath = argv[2];
if (!logPath) {
  console.error("usage: check-db-tests-ran.mjs <vitest-log-path>");
  exit(2);
}

const log = readFileSync(logPath, "utf8");
const requiredEnv = ["DATABASE_URL", "RLS_TEST_DB"];
const missingEnv = requiredEnv.filter((name) => !process.env[name]);
if (missingEnv.length > 0) {
  console.error(`Missing DB test environment: ${missingEnv.join(", ")}`);
  exit(1);
}

const dbGated = [
  "apps/admin-api/src/__tests__/admin.test.ts",
  "apps/admin-api/src/__tests__/agents-admin.test.ts",
  "apps/admin-api/src/__tests__/audit.test.ts",
  "apps/admin-api/src/__tests__/scheduled-prune.test.ts",
  "apps/gateway/src/__tests__/gateway.test.ts",
  "apps/issuer/src/__tests__/composition-e2e.test.ts",
  "apps/issuer/src/__tests__/google.test.ts",
  "apps/issuer/src/__tests__/init-wallclock.test.ts",
  "apps/issuer/src/__tests__/issuer.test.ts",
  "apps/mcp-server/src/__tests__/mcp.test.ts",
  "apps/verifier/src/__tests__/verifier.test.ts",
  "packages/audit/src/__tests__/writer.test.ts",
  "packages/db/src/__tests__/rls.test.ts",
  "packages/keystore/src/__tests__/keystore.test.ts",
  "packages/vault/src/__tests__/store.test.ts",
];

const missed = [];
for (const file of dbGated) {
  const rel = file.replace(/^.*\/(apps|packages)\//, "$1/");
  const packageLocal = rel.split("/").slice(2).join("/");
  const idx = log.indexOf(rel) >= 0 ? log.indexOf(rel) : log.indexOf(packageLocal);
  if (idx < 0) {
    missed.push(rel);
    continue;
  }
  const nextFile = dbGated
    .filter((other) => other !== file)
    .map((other) => {
      const otherRel = other.replace(/^.*\/(apps|packages)\//, "$1/");
      const otherPackageLocal = otherRel.split("/").slice(2).join("/");
      const relIdx = log.indexOf(otherRel, idx + 1);
      const localIdx = log.indexOf(otherPackageLocal, idx + 1);
      const candidates = [relIdx, localIdx].filter((value) => value >= 0);
      return candidates.length > 0 ? Math.min(...candidates) : -1;
    })
    .filter((value) => value > idx)
    .sort((a, b) => a - b)[0];
  const taskSummary = log.indexOf("\n Tasks:", idx + 1);
  const endCandidates = [nextFile, taskSummary].filter((value) => value && value > idx);
  const end = endCandidates.length > 0 ? Math.min(...endCandidates) : idx + 4096;
  const slice = log.slice(idx, end);
  if (/\bskipped\b/.test(slice)) {
    missed.push(`${rel} (reported skipped tests)`);
  }
}

if (missed.length > 0) {
  console.error("DB-gated test files did not run in CI:");
  for (const m of missed) console.error(`  - ${m}`);
  console.error("\nDATABASE_URL must be set and tests must execute.");
  exit(1);
}

console.log(`OK: ${dbGated.length} DB-gated test files ran.`);
