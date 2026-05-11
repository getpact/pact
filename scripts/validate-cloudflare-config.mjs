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

const rejectTomlValue = (path, pattern, label) => {
  const text = readFileSync(path, "utf8");
  if (pattern.test(text)) failures.push(`${path} must not contain ${label}`);
};

const tomlString = (path, key) => {
  const text = readFileSync(path, "utf8");
  const match = text.match(new RegExp(`^${key}\\s*=\\s*"([^"]*)"`, "m"));
  return match?.[1] ?? null;
};

const requireNarrowHostAllowlist = (path) => {
  const raw = tomlString(path, "UPSTREAM_HOST_ALLOWLIST");
  if (!raw) {
    failures.push(`${path} missing UPSTREAM_HOST_ALLOWLIST`);
    return;
  }
  const hosts = raw
    .split(",")
    .map((host) => host.trim().toLowerCase())
    .filter((host) => host.length > 0);
  const broad = hosts.filter(
    (host) =>
      host === "*" ||
      host === "*.*" ||
      /^\*\.[a-z]+$/.test(host) ||
      host.includes("/") ||
      host.includes(":"),
  );
  if (hosts.length === 0 || broad.length > 0) {
    failures.push(`${path} has unsafe UPSTREAM_HOST_ALLOWLIST entries: ${broad.join(", ")}`);
  }
};

const NEVER_FORWARD_REQUEST_HEADERS = new Set([
  "authorization",
  "cf-connecting-ip",
  "cf-ipcountry",
  "cf-ray",
  "connection",
  "content-length",
  "cookie",
  "forwarded",
  "host",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "x-api-key",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-http-method",
  "x-http-method-override",
  "x-method-override",
  "x-real-ip",
]);

const rejectDangerousForwardedHeaders = (path) => {
  const raw = tomlString(path, "GATEWAY_FORWARD_HEADER_ALLOWLIST");
  if (!raw) return;
  const dangerous = raw
    .split(",")
    .map((header) => header.trim().toLowerCase())
    .filter((header) => NEVER_FORWARD_REQUEST_HEADERS.has(header));
  if (dangerous.length > 0) {
    failures.push(`${path} forwards unsafe request headers: ${dangerous.join(", ")}`);
  }
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
    requireTomlValue(wrangler, /^routes\s*=\s*\[/m, "custom domain route");
    requireTomlValue(wrangler, /\[observability\][\s\S]*enabled\s*=\s*true/, "observability");
    requireTomlValue(wrangler, /ENVIRONMENT\s*=\s*"production"/, "production ENVIRONMENT var");
    if (/replace-with|changeme|todo/i.test(text))
      failures.push(`${wrangler} contains placeholder values`);
  }
}

const requireEnv = (name) => {
  if (!process.env[name]) failures.push(`missing ${name}`);
};

const PRIVATE_DESTINATION_MARKERS = [
  "0.0.0.0/8",
  "10.0.0.0/8",
  "100.64.0.0/10",
  "127.0.0.0/8",
  "169.254.0.0/16",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "240.0.0.0/4",
  "255.255.255.255/32",
  "::1",
  "fc00::/7",
  "fe80::/10",
  "ff00::/8",
];

const collectStrings = (value, out = []) => {
  if (typeof value === "string") out.push(value);
  else if (Array.isArray(value)) {
    for (const item of value) collectStrings(item, out);
  } else if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      if (key === "name" || key === "description") continue;
      collectStrings(item, out);
    }
  }
  return out;
};

const assertGatewayEgressPolicy = (policyId, result) => {
  const action = String(result?.action ?? "").toLowerCase();
  if (action !== "block") {
    failures.push(`Cloudflare Gateway egress policy ${policyId} action must be block`);
  }

  const expressions = collectStrings({
    conditions: result?.conditions,
    filters: result?.filters,
    traffic: result?.traffic,
  });
  const destinationExpression = expressions.find((expr) =>
    /\b(?:net\.dst\.ip|ip\.dst)\s+in\s+\{[^}\s][^}]*\}/i.test(expr),
  );
  if (!destinationExpression) {
    failures.push(
      `Cloudflare Gateway egress policy ${policyId} must use a destination IP CIDR expression`,
    );
    return;
  }
  const normalized = destinationExpression.toLowerCase();
  const missingMarkers = PRIVATE_DESTINATION_MARKERS.filter(
    (marker) => !normalized.includes(marker.toLowerCase()),
  );
  if (missingMarkers.length > 0) {
    failures.push(
      `Cloudflare Gateway egress policy ${policyId} does not mention: ${missingMarkers.join(", ")}`,
    );
  }
};

const gatewayEnabled = apps.includes("gateway");
const requireVerifierBinding = (app) => {
  const wrangler = `apps/${app}/wrangler.toml`;
  requireTomlValue(
    wrangler,
    /\[\[services\]\][\s\S]*binding\s*=\s*"VERIFIER_SERVICE"[\s\S]*service\s*=\s*"pact-verifier"/,
    "VERIFIER_SERVICE service binding",
  );
  rejectTomlValue(wrangler, /^VERIFIER_URL\s*=/m, "production VERIFIER_URL fallback");
};

if (apps.includes("gateway")) requireVerifierBinding("gateway");
if (apps.includes("mcp-server")) requireVerifierBinding("mcp-server");
if (apps.includes("web")) {
  requireTomlValue("apps/web/wrangler.toml", /^WEB_BASE_URL\s*=\s*"https:\/\//m, "WEB_BASE_URL");
}

if (gatewayEnabled) {
  requireEnv("PACT_GATEWAY_EGRESS_POLICY_ID");
  requireEnv("CLOUDFLARE_ACCOUNT_ID");
  requireEnv("CLOUDFLARE_API_TOKEN");
  requireNarrowHostAllowlist("apps/admin-api/wrangler.toml");
  requireNarrowHostAllowlist("apps/gateway/wrangler.toml");
  rejectDangerousForwardedHeaders("apps/gateway/wrangler.toml");
  requireTomlValue(
    "apps/gateway/wrangler.toml",
    /GATEWAY_AUDIT_MODE\s*=\s*"required"/,
    'GATEWAY_AUDIT_MODE="required"',
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
  if (enabled !== true)
    failures.push(`Cloudflare Gateway egress policy ${policyId} must be enabled`);
  assertGatewayEgressPolicy(policyId, body.result);
  if (failures.length > 0) {
    for (const failure of failures) console.error(failure);
    exit(1);
  }
  console.log(`verified Cloudflare Gateway egress policy ${policyId}`);
}

console.log("cloudflare config validation complete");
