// Centralized re-export of sibling app entrypoints for test wiring.
// Test files import Hono app instances from this package instead of
// reaching across into apps/<other>/src directly. This is the only
// place where cross-app source imports are allowed.

export { default as adminApiApp } from "../../../apps/admin-api/src/index.js";
export { default as issuerApp } from "../../../apps/issuer/src/index.js";
export { default as mcpServerApp } from "../../../apps/mcp-server/src/index.js";
export { default as verifierApp } from "../../../apps/verifier/src/index.js";
