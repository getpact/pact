#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { exit } from "node:process";

const failures = [];
const warnings = [];
const checkHealth = process.argv.includes("--health");

const usage = () => {
  process.stdout.write(
    [
      "usage: node scripts/check-quickstart-local.mjs [--health]",
      "",
      "Checks the local quickstart prerequisites and generated app .dev.vars files.",
      "Use --health after starting the five local Workers.",
      "",
    ].join("\n"),
  );
};

if (process.argv.includes("--help") || process.argv.includes("-h")) {
  usage();
  exit(0);
}

const requireCommand = (command, args = ["--version"]) => {
  const result = spawnSync(command, args, { stdio: "ignore" });
  if (result.error || result.status !== 0) {
    failures.push(`missing command: ${command}`);
  }
};

const parseDevVars = (path) => {
  if (!existsSync(path)) {
    failures.push(`missing ${path}`);
    return {};
  }
  const out = {};
  const text = readFileSync(path, "utf8");
  for (const [index, line] of text.split(/\r?\n/).entries()) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const match = trimmed.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
    if (!match) {
      failures.push(`${path}:${index + 1} is not KEY=value`);
      continue;
    }
    out[match[1]] = match[2].replace(/^"(.*)"$/, "$1");
  }
  return out;
};

const requireKey = (path, vars, key) => {
  if (!vars[key]) failures.push(`${path} missing ${key}`);
};

const requireValue = (path, vars, key, expected) => {
  if (vars[key] !== expected) {
    failures.push(`${path} expected ${key}=${expected}`);
  }
};

const requireRuntimeDatabaseUrl = (path, vars) => {
  const raw = vars.DATABASE_URL;
  if (!raw) return;
  let url;
  try {
    url = new URL(raw);
  } catch {
    failures.push(`${path} DATABASE_URL is not a valid URL`);
    return;
  }
  if (url.username === "pact") {
    failures.push(`${path} uses migration/admin DATABASE_URL; use the pact_app runtime role`);
  }
};

const apps = {
  "admin-api": {
    required: ["DATABASE_URL", "MEK", "ISSUER_BASE_URL", "ENVIRONMENT", "ADMIN_AUDIENCE"],
    values: { ENVIRONMENT: "development", ADMIN_AUDIENCE: "pact-admin" },
  },
  "audit-api": {
    required: ["DATABASE_URL", "ISSUER_BASE_URL", "ENVIRONMENT", "AUDIT_AUDIENCE"],
    values: { ENVIRONMENT: "development", AUDIT_AUDIENCE: "pact-audit" },
  },
  gateway: {
    required: [
      "DATABASE_URL",
      "MEK",
      "ENVIRONMENT",
      "GATEWAY_AUDIENCE",
      "GATEWAY_AUDIT_MODE",
      "UPSTREAM_HOST_ALLOWLIST",
      "VERIFIER_URL",
    ],
    values: {
      ENVIRONMENT: "development",
      GATEWAY_AUDIENCE: "pact-gateway",
      GATEWAY_AUDIT_MODE: "required",
      VERIFIER_URL: "http://localhost:8789",
    },
  },
  issuer: {
    required: [
      "DATABASE_URL",
      "MEK",
      "ISSUER_BASE_URL",
      "ENVIRONMENT",
      "ENABLE_DEV_ISSUE",
      "DEV_ISSUE_SECRET",
    ],
    values: { ENVIRONMENT: "development", ENABLE_DEV_ISSUE: "true" },
  },
  verifier: {
    required: ["DATABASE_URL", "MEK", "ISSUER_BASE_URL", "ENVIRONMENT", "VERIFIER_AUDIENCES"],
    values: { ENVIRONMENT: "development", VERIFIER_AUDIENCES: "pact-mcp,pact-gateway" },
  },
};

const healthUrls = [
  "http://localhost:8787/health",
  "http://localhost:8788/health",
  "http://localhost:8789/health",
  "http://localhost:8790/health",
  "http://localhost:8791/health",
];

requireCommand("node");
requireCommand("pnpm");
requireCommand("curl");
requireCommand("jq");
requireCommand("openssl", ["version"]);

const localDatabase =
  !process.env.DATABASE_URL || /(?:localhost|127\.0\.0\.1)/.test(process.env.DATABASE_URL);
if (localDatabase) requireCommand("docker");

const ignore = existsSync(".gitignore") ? readFileSync(".gitignore", "utf8") : "";
if (!ignore.includes("apps/*/.dev.vars")) {
  failures.push(".gitignore must ignore apps/*/.dev.vars");
}

for (const [app, spec] of Object.entries(apps)) {
  const path = `apps/${app}/.dev.vars`;
  const vars = parseDevVars(path);
  for (const key of spec.required) requireKey(path, vars, key);
  for (const [key, expected] of Object.entries(spec.values)) {
    requireValue(path, vars, key, expected);
  }
  requireRuntimeDatabaseUrl(path, vars);
  if (vars.UPSTREAM_HOST_ALLOWLIST?.includes("*")) {
    failures.push(`${path} has broad UPSTREAM_HOST_ALLOWLIST`);
  }
}

if (checkHealth) {
  for (const url of healthUrls) {
    const result = spawnSync("curl", ["-fsS", url], { encoding: "utf8" });
    if (result.status !== 0) {
      failures.push(`health check failed: ${url}`);
      continue;
    }
    try {
      const body = JSON.parse(result.stdout);
      if (body.ok !== true) failures.push(`health check returned non-ok body: ${url}`);
    } catch {
      failures.push(`health check did not return JSON: ${url}`);
    }
  }
} else {
  warnings.push("skip Worker health checks; pass --health after starting local Workers");
}

for (const warning of warnings) console.warn(`warning: ${warning}`);

if (failures.length > 0) {
  for (const failure of failures) console.error(failure);
  exit(1);
}

console.log("quickstart local preflight passed");
