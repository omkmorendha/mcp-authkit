#!/usr/bin/env bash
# Python E2E runner (spec §18).
#
# Starts the Node harness, captures its handshake line, exports the URL
# and JWT into the environment, runs the Python script, and tears the
# harness down on exit (success or failure).

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

PYTHON="${PYTHON:-python3}"

# Ensure the Python interpreter has `requests` available. We don't install
# silently — bail with a clear message if it's missing.
if ! "$PYTHON" -c "import requests" >/dev/null 2>&1; then
  echo "E2E SETUP: 'requests' is not installed for $PYTHON." >&2
  echo "  Install it, e.g.:  $PYTHON -m pip install requests" >&2
  exit 1
fi

# Build the workspace once if dist artefacts are missing. Subsequent runs
# skip this and are <10s end-to-end (spec §18).
if [ ! -f "$ROOT/packages/core/dist/index.js" ]; then
  echo "E2E SETUP: building workspace..." >&2
  (cd "$ROOT" && pnpm install --frozen-lockfile && pnpm build) >&2
fi

TMPDIR_E2E="$(mktemp -d -t mcp-authkit-e2e.XXXXXX)"
HARNESS_LOG="$TMPDIR_E2E/harness.log"
HARNESS_STDOUT="$TMPDIR_E2E/harness.out"

cleanup() {
  if [ -n "${HARNESS_PID:-}" ] && kill -0 "$HARNESS_PID" 2>/dev/null; then
    kill -TERM "$HARNESS_PID" 2>/dev/null || true
    for _ in 1 2 3 4 5; do
      if ! kill -0 "$HARNESS_PID" 2>/dev/null; then break; fi
      sleep 0.2
    done
    kill -KILL "$HARNESS_PID" 2>/dev/null || true
  fi
  rm -rf "$TMPDIR_E2E"
}
trap cleanup EXIT INT TERM

# Start the harness. stdout → log file we tail; stderr → log file for debugging.
(cd "$HERE" && pnpm -s start) >"$HARNESS_STDOUT" 2>"$HARNESS_LOG" &
HARNESS_PID=$!

# Poll for the first complete stdout line (the JSON handshake). Bound the
# wait at 60s in case install/build is needed under cold cache.
HANDSHAKE=""
for _ in $(seq 1 600); do
  if ! kill -0 "$HARNESS_PID" 2>/dev/null; then
    echo "E2E FAIL: harness exited before emitting a handshake" >&2
    echo "--- harness stderr ---" >&2
    cat "$HARNESS_LOG" >&2 || true
    echo "--- harness stdout ---" >&2
    cat "$HARNESS_STDOUT" >&2 || true
    exit 1
  fi
  if [ -s "$HARNESS_STDOUT" ]; then
    HANDSHAKE="$(head -n 1 "$HARNESS_STDOUT")"
    if [ -n "$HANDSHAKE" ]; then break; fi
  fi
  sleep 0.1
done

if [ -z "$HANDSHAKE" ]; then
  echo "E2E FAIL: harness did not emit a handshake within 60s" >&2
  echo "--- harness stderr ---" >&2
  cat "$HARNESS_LOG" >&2 || true
  exit 1
fi

URL="$("$PYTHON" -c "import json,sys; print(json.loads(sys.argv[1])['url'])" "$HANDSHAKE")"
JWT="$("$PYTHON" -c "import json,sys; print(json.loads(sys.argv[1])['jwt'])" "$HANDSHAKE")"

export MCP_AUTHKIT_URL="$URL"
export MCP_AUTHKIT_JWT="$JWT"

set +e
"$PYTHON" "$HERE/e2e.py"
EXIT=$?
set -e

if [ "$EXIT" -ne 0 ]; then
  echo "--- harness stderr ---" >&2
  cat "$HARNESS_LOG" >&2 || true
fi

exit "$EXIT"
