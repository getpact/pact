#!/usr/bin/env node
// Fail CI if any test file that is supposed to require a real database was skipped.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
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

const dbGated = walk("apps")
  .concat(walk("packages"))
  .filter((p) => {
    const src = readFileSync(p, "utf8");
    return (
      (src.includes("process.env.DATABASE_URL") || src.includes("process.env.RLS_TEST_DB")) &&
      src.includes("describe.skip")
    );
  });

const missed = [];
for (const file of dbGated) {
  const rel = file.replace(/^.*\/(apps|packages)\//, "$1/");
  const packageLocal = rel.split("/").slice(2).join("/");
  const idx = log.indexOf(rel) >= 0 ? log.indexOf(rel) : log.indexOf(packageLocal);
  if (idx < 0) {
    missed.push(rel);
    continue;
  }
  const slice = log.slice(idx, idx + 4096);
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
