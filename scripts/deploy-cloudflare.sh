#!/bin/sh
set -eu

apps="issuer verifier mcp-server admin-api audit-api proxy"

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
