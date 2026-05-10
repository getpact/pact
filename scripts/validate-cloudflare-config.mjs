#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import { exit } from "node:process";

const apps = process.argv.slice(2);
const failures = [];

const requireFile = (path) => {
  if (!existsSync(path)) failures.push(`missing ${path}`);
};

const requireTomlValue = (path, pattern, label) => {
  const text = readFileSync(path, "utf8");
  if (!pattern.test(text)) failures.push(`${path} missing ${label}`);
};

for (const app of apps) {
  const wrangler = `apps/${app}/wrangler.toml`;
  requireFile(wrangler);
  requireFile(`apps/${app}/package.json`);
  if (existsSync(wrangler)) {
    const text = readFileSync(wrangler, "utf8");
    requireTomlValue(wrangler, /^name\s*=/m, "name");
    requireTomlValue(wrangler, /^main\s*=/m, "main");
    requireTomlValue(wrangler, /^compatibility_date\s*=/m, "compatibility_date");
    requireTomlValue(wrangler, /workers_dev\s*=\s*false/, "workers_dev=false");
    requireTomlValue(wrangler, /\[observability\][\s\S]*enabled\s*=\s*true/, "observability");
    requireTomlValue(wrangler, /ENVIRONMENT\s*=\s*"production"/, "production ENVIRONMENT var");
    if (/replace-with|changeme|todo/i.test(text))
      failures.push(`${wrangler} contains placeholder values`);
  }
}

const requireEnv = (name) => {
  if (!process.env[name]) failures.push(`missing ${name}`);
};

const gatewayEnabled = apps.includes("gateway");
if (gatewayEnabled) {
  requireEnv("PACT_GATEWAY_EGRESS_POLICY_ID");
  requireEnv("CLOUDFLARE_ACCOUNT_ID");
  requireEnv("CLOUDFLARE_API_TOKEN");
  requireTomlValue(
    "apps/admin-api/wrangler.toml",
    /UPSTREAM_HOST_ALLOWLIST\s*=\s*"[^"]+"/,
    "UPSTREAM_HOST_ALLOWLIST",
  );
  requireTomlValue(
    "apps/gateway/wrangler.toml",
    /UPSTREAM_HOST_ALLOWLIST\s*=\s*"[^"]+"/,
    "UPSTREAM_HOST_ALLOWLIST",
  );
}

if (failures.length > 0) {
  for (const failure of failures) console.error(failure);
  exit(1);
}

if (gatewayEnabled) {
  const accountId = process.env.CLOUDFLARE_ACCOUNT_ID;
  const policyId = process.env.PACT_GATEWAY_EGRESS_POLICY_ID;
  const res = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${accountId}/gateway/rules/${policyId}`,
    {
      headers: {
        authorization: `Bearer ${process.env.CLOUDFLARE_API_TOKEN}`,
        accept: "application/json",
      },
    },
  );
  const body = await res.json().catch(() => null);
  if (!res.ok || body?.success !== true) {
    console.error(`Cloudflare Zero Trust Gateway policy ${policyId} was not found`);
    exit(1);
  }
  const enabled = body.result?.enabled;
  if (enabled === false) {
    console.error(`Cloudflare Zero Trust Gateway policy ${policyId} is disabled`);
    exit(1);
  }
  console.log(`verified Cloudflare Gateway egress policy ${policyId}`);
}

console.log("cloudflare config validation complete");
