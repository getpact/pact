#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
echo "[verify] cleaning caches"
find packages -name dist -type d -exec rm -rf {} + 2>/dev/null || true
find apps -name dist -type d -exec rm -rf {} + 2>/dev/null || true
find . -name "*.tsbuildinfo" -delete 2>/dev/null || true
find . -name ".turbo" -type d -not -path "*/node_modules/*" -exec rm -rf {} + 2>/dev/null || true
echo "[verify] running pnpm install --frozen-lockfile"
pnpm install --frozen-lockfile
echo "[verify] running typecheck"
pnpm typecheck
echo "[verify] running lint"
pnpm lint
echo "[verify] OK"
