#!/bin/sh
set -eu

apps="issuer verifier mcp-server admin-api audit-api"
if [ "${PACT_DEPLOY_GATEWAY:-}" = "true" ]; then
  if [ "${PACT_GATEWAY_UPSTREAM_HOST_ALLOWLIST_READY:-}" != "true" ]; then
    echo "gateway deploy requires PACT_GATEWAY_UPSTREAM_HOST_ALLOWLIST_READY=true" >&2
    echo "confirm UPSTREAM_HOST_ALLOWLIST is configured on admin-api and gateway first" >&2
    exit 1
  fi
  if [ "${PACT_GATEWAY_EGRESS_POLICY_READY:-}" != "true" ]; then
    echo "gateway deploy requires PACT_GATEWAY_EGRESS_POLICY_READY=true" >&2
    echo "confirm platform egress controls block private and metadata IPs after DNS first" >&2
    exit 1
  fi
  apps="$apps gateway"
fi

require_file() {
  if [ ! -f "$1" ]; then
    echo "missing required file: $1" >&2
    exit 1
  fi
}

command -v pnpm >/dev/null 2>&1 || {
  echo "pnpm is required" >&2
  exit 1
}

for app in $apps; do
  require_file "apps/$app/wrangler.toml"
  require_file "apps/$app/package.json"
done

pnpm typecheck
pnpm build

for app in $apps; do
  echo "deploying apps/$app"
  pnpm --dir "apps/$app" deploy
done

echo "cloudflare deploy complete"
