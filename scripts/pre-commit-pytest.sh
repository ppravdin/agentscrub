#!/usr/bin/env bash
# Run pytest only when Python sources or tests changed in this commit.
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "$root"

if ! command -v pytest >/dev/null 2>&1; then
  echo "pytest not found — install dev deps: pip install -e '.[dev]'" >&2
  exit 1
fi

changed="$(git diff --cached --name-only --diff-filter=ACM \
  | grep -E '^(src/|tests/|pyproject\.toml)$|^(src/|tests/).+\.py$' || true)"

if [ -z "$changed" ]; then
  exit 0
fi

exec pytest -q
