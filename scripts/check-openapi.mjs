#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { exit } from "node:process";

const path = "docs/openapi/pact.v1.yaml";
const spec = readFileSync(path, "utf8");
const required = [
  "openapi: 3.1.0",
  "/v1/workspaces:",
  "/v1/dev/issue:",
  "/v1/oauth/google/exchange:",
  "/v1/refresh:",
  "/v1/workspaces/{workspaceId}/.well-known/jwks.json:",
  "/v1/workspaces/{workspaceId}/.well-known/audit-jwks.json:",
  "/v1/verify:",
  "/v1/workspaces/{workspaceId}/users:",
  "/v1/workspaces/{workspaceId}/groups:",
  "/v1/workspaces/{workspaceId}/groups/{groupId}/members:",
  "/v1/workspaces/{workspaceId}/policies:",
  "/v1/workspaces/{workspaceId}/revocations:",
  "/v1/workspaces/{workspaceId}/invites:",
  "/v1/workspaces/{workspaceId}/brains:",
  "/v1/workspaces/{workspaceId}/audit/events:",
  "/v1/workspaces/{workspaceId}/audit/workspace:",
  "/v1/workspaces/{workspaceId}/audit/chain:",
  "/{workspace}/mcp:",
  "/{workspace}/gateway/{brain}/{path}:",
];

const missing = required.filter((needle) => !spec.includes(needle));
if (missing.length > 0) {
  for (const needle of missing) console.error(`${path} missing ${needle}`);
  exit(1);
}

console.log(`${path} contains required route contracts`);
