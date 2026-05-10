#!/usr/bin/env node
// Fail CI if any test file that is supposed to require DATABASE_URL was skipped.
// We grep for `process.env.DATABASE_URL` test files and confirm they each
// printed at least one passing test line in the vitest output captured at
// VITEST_LOG_PATH (the CI step pipes vitest output there).

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { argv, exit } from "node:process";

const logPath = argv[2];
if (!logPath) {
  console.error("usage: check-db-tests-ran.mjs <vitest-log-path>");
  exit(2);
}

const log = readFileSync(logPath, "utf8");

const walk = (dir, out = []) => {
  for (const entry of readdirSync(dir)) {
    if (entry === "node_modules" || entry === "dist" || entry === ".turbo") continue;
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) walk(full, out);
    else if (full.endsWith(".test.ts")) out.push(full);
  }
  return out;
};

const dbGated = walk("apps").concat(walk("packages")).filter((p) => {
  const src = readFileSync(p, "utf8");
  return src.includes("process.env.DATABASE_URL") && src.includes("describe.skip");
});

const missed = [];
for (const file of dbGated) {
  const rel = file.replace(/^.*\/(apps|packages)\//, "$1/");
  if (!log.includes(rel)) {
    missed.push(rel);
    continue;
  }
  // Look for a "skipped" or "todo" pattern adjacent to this file in the log.
  const idx = log.indexOf(rel);
  const slice = log.slice(idx, idx + 4096);
  if (/skipped/.test(slice) && !/✓/.test(slice)) {
    missed.push(`${rel} (no passing assertions)`);
  }
}

if (missed.length > 0) {
  console.error("DB-gated test files did not run in CI:");
  for (const m of missed) console.error(`  - ${m}`);
  console.error("\nDATABASE_URL must be set and tests must execute.");
  exit(1);
}

console.log(`OK: ${dbGated.length} DB-gated test files ran.`);
