#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { exit } from "node:process";

const path = "docs/openapi/pact.v1.yaml";
const spec = readFileSync(path, "utf8");
const seedRequired = ["openapi: 3.1.0"];

const routeFiles = [
  "apps/issuer/src/index.ts",
  "apps/verifier/src/index.ts",
  "apps/admin-api/src/index.ts",
  "apps/audit-api/src/index.ts",
  "apps/mcp-server/src/index.ts",
  "apps/gateway/src/index.ts",
];

const normalizeRoute = (route) => {
  const normalized = route
    .replace(/\/:id(?=\/|$)/g, "/{workspaceId}")
    .replace(/\/:workspace(?=\/|$)/g, "/{workspace}")
    .replace(/\/:brain(?=\/|$)/g, "/{brain}")
    .replace(/\/:groupId(?=\/|$)/g, "/{groupId}")
    .replace(/\/:brainId(?=\/|$)/g, "/{brainId}")
    .replace(/\/\*$/g, "/{path}");
  return `${normalized}:`;
};

const publicRoutes = new Set();
for (const routeFile of routeFiles) {
  const source = readFileSync(routeFile, "utf8");
  const routePattern = /app\.(?:get|post|put|delete|patch|all)\("([^"]+)"/g;
  for (const match of source.matchAll(routePattern)) {
    const route = match[1];
    if (route === "/health") continue;
    publicRoutes.add(normalizeRoute(route));
  }
}

const required = seedRequired.concat([...publicRoutes].sort());
const missing = required.filter((needle) => !spec.includes(needle));
if (missing.length > 0) {
  for (const needle of missing) console.error(`${path} missing ${needle}`);
  exit(1);
}

console.log(`${path} contains ${publicRoutes.size} public route contracts`);
