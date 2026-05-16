#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"

if ! command -v tsx >/dev/null 2>&1; then
  if [ ! -x "node_modules/.bin/tsx" ] && [ ! -x "../../node_modules/.bin/tsx" ]; then
    echo "tsx not found. run 'pnpm install' from the repo root first." >&2
    exit 1
  fi
fi

run_ts() {
  if command -v tsx >/dev/null 2>&1; then
    tsx "$1"
  elif [ -x "node_modules/.bin/tsx" ]; then
    node_modules/.bin/tsx "$1"
  else
    ../../node_modules/.bin/tsx "$1"
  fi
}

echo "=== before: god-mode OAuth token ==="
before_json="$(run_ts before.ts)"
echo "$before_json"

echo
echo "=== after: pact-scoped SD-JWT ==="
after_json="$(run_ts after.ts)"
echo "$after_json"

before_count="$(printf '%s' "$before_json" | grep -o '"totalFiles": *[0-9]*' | head -n 1 | grep -o '[0-9]*')"
after_count="$(printf '%s' "$after_json" | grep -o '"totalFiles": *[0-9]*' | head -n 1 | grep -o '[0-9]*')"

echo
echo "=== diff ==="
echo "before: $before_count files visible to the agent"
echo "after:  $after_count files visible to the agent"
if [ -n "$before_count" ] && [ -n "$after_count" ] && [ "$before_count" -gt 0 ]; then
  reduction=$(( (before_count - after_count) * 100 / before_count ))
  echo "reduction: ${reduction}%"
fi
