#!/bin/sh
# Usage: gate.sh <required-tool> <gate-name> -- <command...>
# Runs the command. If the tool is missing: fail in CI, warn and skip locally.
# If the command exits non-zero, that exit code is passed through unchanged.
tool="$1"
name="$2"
shift 3

if ! command -v "$tool" >/dev/null 2>&1; then
  if [ -n "$CI" ]; then
    echo "FAIL: $name requires '$tool', which is not installed in CI" >&2
    exit 1
  fi
  echo "WARN: $name skipped locally: '$tool' not installed (CI runs it and blocks)" >&2
  exit 0
fi

echo "== $name"
exec "$@"
