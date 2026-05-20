#!/usr/bin/env bash
# Python E2E runner (spec v0.2 §16).
#
# Builds the workspace if needed, starts the Hono-backed harness in a
# subprocess, captures its handshake line, exports the URL / config
# path / CLI bin into the environment, runs the Python script (which
# mints a PAT via the `mcp-authkit` CLI subprocess and calls the
# `echo` tool), and tears the harness down on exit.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

PYTHON="${PYTHON:-python3}"

if ! "$PYTHON" -c "import requests" >/dev/null 2>&1; then
  echo "E2E SETUP: 'requests' is not installed for $PYTHON." >&2
  echo "  Install it, e.g.:  $PYTHON -m pip install requests" >&2
  exit 1
fi

# Build the workspace once if dist artefacts are missing. The CLI bin
# needs `packages/cli/dist/bin/mcp-authkit.js` and the harness imports
# from `packages/core/dist/`. Subsequent runs skip this and are <10s
# end-to-end (spec §16).
CLI_BIN="$ROOT/packages/cli/dist/bin/mcp-authkit.js"
if [ ! -f "$ROOT/packages/core/dist/index.js" ] || [ ! -f "$CLI_BIN" ]; then
  echo "E2E SETUP: building workspace..." >&2
  (cd "$ROOT" && pnpm install --frozen-lockfile && pnpm build) >&2
fi

TMPDIR_E2E="$(mktemp -d -t mcp-authkit-e2e.XXXXXX)"
HARNESS_LOG="$TMPDIR_E2E/harness.log"
HARNESS_STDOUT="$TMPDIR_E2E/harness.out"
DB_PATH="$TMPDIR_E2E/authkit.db"

export MCP_AUTHKIT_E2E_DB="$DB_PATH"
export MCP_AUTHKIT_E2E_CLI_BIN="$CLI_BIN"

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

(cd "$HERE" && pnpm -s start) >"$HARNESS_STDOUT" 2>"$HARNESS_LOG" &
HARNESS_PID=$!

# Poll for the first complete stdout line (the JSON handshake). Bound
# the wait at 60s in case install/build is needed under cold cache.
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
    CANDIDATE="$(head -n 1 "$HARNESS_STDOUT")"
    if [ -n "$CANDIDATE" ]; then
      if "$PYTHON" -c "
import json, sys
try:
    obj = json.loads(sys.argv[1])
except Exception:
    sys.exit(2)
needed = ('url', 'configPath', 'cliBin')
if not (isinstance(obj, dict) and all(isinstance(obj.get(k), str) for k in needed)):
    sys.exit(2)
" "$CANDIDATE" 2>/dev/null; then
        HANDSHAKE="$CANDIDATE"
        break
      fi
    fi
  fi
  sleep 0.1
done

if [ -z "$HANDSHAKE" ]; then
  echo "E2E FAIL: harness did not emit a valid handshake within 60s" >&2
  echo "--- harness stderr ---" >&2
  cat "$HARNESS_LOG" >&2 || true
  echo "--- harness stdout ---" >&2
  cat "$HARNESS_STDOUT" >&2 || true
  exit 1
fi

URL="$("$PYTHON" -c "import json,sys; print(json.loads(sys.argv[1])['url'])" "$HANDSHAKE")"
CONFIG_PATH="$("$PYTHON" -c "import json,sys; print(json.loads(sys.argv[1])['configPath'])" "$HANDSHAKE")"
CLI_BIN_OUT="$("$PYTHON" -c "import json,sys; print(json.loads(sys.argv[1])['cliBin'])" "$HANDSHAKE")"

export MCP_AUTHKIT_URL="$URL"
export MCP_AUTHKIT_CONFIG="$CONFIG_PATH"
export MCP_AUTHKIT_CLI="$CLI_BIN_OUT"
# The CLI subprocess loads the same config file as the server, so it
# needs the same DB path (already exported) and resource indicator in
# its env.
export RESOURCE_INDICATOR="${URL}/mcp"

set +e
"$PYTHON" "$HERE/e2e.py"
EXIT=$?
set -e

if [ "$EXIT" -ne 0 ]; then
  echo "--- harness stderr ---" >&2
  cat "$HARNESS_LOG" >&2 || true
fi

exit "$EXIT"
