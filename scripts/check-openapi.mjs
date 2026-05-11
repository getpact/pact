#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { exit } from "node:process";

const path = "docs/openapi/pact.v1.yaml";
const spec = readFileSync(path, "utf8");
const failures = [];
const methods = new Set(["get", "post", "put", "delete", "patch"]);

const normalizeRoute = (route) =>
  route
    .replace(/\/:id(?=\/|$)/g, "/{workspaceId}")
    .replace(/\/:workspace(?=\/|$)/g, "/{workspace}")
    .replace(/\/:brain(?=\/|$)/g, "/{brain}")
    .replace(/\/:groupId(?=\/|$)/g, "/{groupId}")
    .replace(/\/:brainId(?=\/|$)/g, "/{brainId}")
    .replace(/\/\*$/g, "/{path}");

const lines = spec.split(/\r?\n/).map((raw, index) => ({
  index,
  indent: raw.match(/^ */)?.[0].length ?? 0,
  text: raw.trim(),
}));

const children = (start, parentIndent) => {
  const out = [];
  for (let i = start + 1; i < lines.length; i += 1) {
    if (!lines[i].text || lines[i].text.startsWith("#")) continue;
    if (lines[i].indent <= parentIndent) break;
    out.push(lines[i]);
  }
  return out;
};
const direct = (start, indent) =>
  children(start, indent).filter((line) => line.indent === indent + 2);
const has = (start, indent, pattern) =>
  children(start, indent).some((line) => pattern.test(line.text));

const routeMethodMap = new Map();
for (const routeFile of [
  "apps/issuer/src/index.ts",
  "apps/verifier/src/index.ts",
  "apps/admin-api/src/index.ts",
  "apps/audit-api/src/index.ts",
  "apps/mcp-server/src/index.ts",
  "apps/gateway/src/index.ts",
]) {
  const source = readFileSync(routeFile, "utf8");
  for (const match of source.matchAll(/app\.(get|post|put|delete|patch|all)\("([^"]+)"/g)) {
    if (match[2] === "/health") continue;
    const route = normalizeRoute(match[2]);
    const routeMethods = match[1] === "all" ? [...methods] : [match[1]];
    const set = routeMethodMap.get(route) ?? new Set();
    for (const method of routeMethods) set.add(method);
    routeMethodMap.set(route, set);
  }
}

for (const needle of [
  "openapi: 3.1.0",
  "devIssueSecretAuth:",
  "x-pact-dev-issue-secret",
  '$ref: "#/components/schemas/Audience"',
  '$ref: "#/components/schemas/Jwks"',
]) {
  if (!spec.includes(needle)) failures.push(`${path} missing ${needle}`);
}

const pathsIndex = lines.findIndex((line) => line.indent === 0 && line.text === "paths:");
if (pathsIndex < 0) failures.push(`${path} missing top-level paths`);
const documented = new Map();
if (pathsIndex >= 0) {
  for (const pathLine of direct(pathsIndex, 0).filter((line) => line.text.startsWith("/"))) {
    const openapiPath = pathLine.text.slice(0, -1);
    const methodSet = new Set();
    documented.set(openapiPath, methodSet);
    for (const methodLine of direct(pathLine.index, pathLine.indent)) {
      const method = methodLine.text.slice(0, -1);
      if (!methods.has(method)) continue;
      methodSet.add(method);
      const label = `${openapiPath} ${method.toUpperCase()}`;
      const responseLine = direct(methodLine.index, methodLine.indent).find(
        (line) => line.text === "responses:",
      );
      if (!responseLine) {
        failures.push(`${label} missing responses`);
        continue;
      }
      const statuses = direct(responseLine.index, responseLine.indent)
        .map((line) => line.text.match(/^"?([0-9]{3}|default)"?:/)?.[1])
        .filter(Boolean);
      if (!statuses.some((code) => /^2[0-9][0-9]$/.test(code))) {
        failures.push(`${label} missing 2xx response`);
      }
      if (
        openapiPath !== "/health" &&
        !statuses.some((code) => code === "default" || /^[45][0-9][0-9]$/.test(code))
      ) {
        failures.push(`${label} missing error response`);
      }
      if (
        has(methodLine.index, methodLine.indent, /^requestBody:/) &&
        !has(methodLine.index, methodLine.indent, /^schema:/)
      ) {
        failures.push(`${label} requestBody missing schema`);
      }
    }
  }
}

for (const [route, routeMethods] of routeMethodMap) {
  const documentedMethods = documented.get(route);
  if (!documentedMethods) {
    failures.push(`${path} missing route ${route}`);
    continue;
  }
  for (const method of routeMethods) {
    if (!documentedMethods.has(method))
      failures.push(`${path} missing ${method.toUpperCase()} ${route}`);
  }
}

if (failures.length > 0) {
  for (const failure of failures) console.error(failure);
  exit(1);
}

console.log(`${path} structurally covers ${documented.size} public route contracts`);
