#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { exit } from "node:process";

const apps = process.argv.slice(2);
const required = {
  "admin-api": ["DATABASE_URL", "MEK", "GOOGLE_OAUTH_CLIENT_ID", "GOOGLE_OAUTH_CLIENT_SECRET"],
  gateway: ["DATABASE_URL", "MEK", "VERIFIER_SERVICE_TOKEN"],
  issuer: [
    "DATABASE_URL",
    "MEK",
    "GOOGLE_OAUTH_CLIENT_ID",
    "GOOGLE_OAUTH_CLIENT_SECRET",
    "WEB_ISSUER_SERVICE_TOKEN",
  ],
  "mcp-server": [
    "DATABASE_URL",
    "MEK",
    "VERIFIER_SERVICE_TOKEN",
    "GOOGLE_OAUTH_CLIENT_ID",
    "GOOGLE_OAUTH_CLIENT_SECRET",
  ],
  verifier: ["DATABASE_URL", "MEK", "VERIFIER_SERVICE_TOKEN"],
  web: ["GOOGLE_OAUTH_CLIENT_ID", "WEB_ISSUER_SERVICE_TOKEN"],
};

const secretNames = (app) => {
  const raw = execFileSync(
    "pnpm",
    ["--dir", `apps/${app}`, "exec", "wrangler", "secret", "list", "--json"],
    {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  const parsed = JSON.parse(raw);
  if (!Array.isArray(parsed)) throw new Error(`unexpected wrangler secret list output for ${app}`);
  return new Set(parsed.map((entry) => entry?.name).filter((name) => typeof name === "string"));
};

const failures = [];
for (const app of apps) {
  const expected = required[app];
  if (!expected) continue;
  try {
    const found = secretNames(app);
    const missing = expected.filter((name) => !found.has(name));
    if (missing.length > 0) failures.push(`${app} missing secrets: ${missing.join(", ")}`);
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    failures.push(`${app} secret validation failed: ${message}`);
  }
}

if (failures.length > 0) {
  for (const failure of failures) console.error(failure);
  exit(1);
}

console.log("cloudflare secret validation complete");
