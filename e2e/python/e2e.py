#!/usr/bin/env python3
"""End-to-end test for mcp-authkit (spec §18).

Stdlib + `requests` only. Reads ``MCP_AUTHKIT_URL`` and ``MCP_AUTHKIT_JWT``
from the environment (populated by ``run.sh`` from the Node harness
handshake line).

Flow
----
1. ``POST /pats`` with the test JWT → mint a PAT.
2. ``POST /mcp`` ``initialize`` with the PAT as Bearer → capture
   ``Mcp-Session-Id``.
3. ``POST /mcp`` ``notifications/initialized``.
4. ``POST /mcp`` ``tools/call`` for ``echo`` and assert the response
   text matches the input.

Exits 0 on success, 1 with a printed error on failure.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

import requests

ECHO_INPUT = "hello, mcp-authkit"
TIMEOUT_SECONDS = 10


def fail(msg: str, *, detail: Any = None) -> "None":
    print(f"E2E FAIL: {msg}", file=sys.stderr)
    if detail is not None:
        print(f"  detail: {detail!r}", file=sys.stderr)
    sys.exit(1)


def require_env(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        fail(f"required env var {name} is not set")
        # Unreachable; appeases type-checkers.
        return ""
    return val


def parse_mcp_response(resp: requests.Response) -> dict[str, Any]:
    """Return the JSON-RPC response body, accepting either application/json
    or text/event-stream framing (the MCP Streamable HTTP transport may
    return either depending on the negotiated capabilities)."""
    ctype = resp.headers.get("Content-Type", "")
    body = resp.text
    if ctype.startswith("application/json"):
        return resp.json()
    if "text/event-stream" in ctype:
        # SSE: find the first ``data:`` line and parse it as JSON.
        for line in body.splitlines():
            if line.startswith("data:"):
                payload = line[len("data:"):].strip()
                if payload:
                    return json.loads(payload)
        fail("SSE response had no data: frame", detail=body)
    fail(f"unexpected Content-Type {ctype!r}", detail=body)
    return {}  # Unreachable.


def main() -> None:
    base = require_env("MCP_AUTHKIT_URL").rstrip("/")
    jwt = require_env("MCP_AUTHKIT_JWT")

    session = requests.Session()
    session.headers.update({"Accept": "application/json, text/event-stream"})

    # 1. Mint a PAT using the test JWT.
    mint = session.post(
        f"{base}/pats",
        headers={"Authorization": f"Bearer {jwt}", "Content-Type": "application/json"},
        data=json.dumps({"name": "e2e", "scopes": ["echo:say"], "expiresInDays": 1}),
        timeout=TIMEOUT_SECONDS,
    )
    if mint.status_code != 201:
        fail(f"PAT mint expected 201, got {mint.status_code}", detail=mint.text)
    mint_body = mint.json()
    pat = mint_body.get("token")
    if not isinstance(pat, str) or not pat.startswith("mcp_pat_"):
        fail("mint response missing/invalid token", detail=mint_body)

    bearer = {"Authorization": f"Bearer {pat}"}

    # 2. initialize the MCP session.
    init = session.post(
        f"{base}/mcp",
        headers={**bearer, "Content-Type": "application/json"},
        data=json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "python-e2e", "version": "0.1.0"},
                },
            }
        ),
        timeout=TIMEOUT_SECONDS,
    )
    if init.status_code != 200:
        fail(f"initialize expected 200, got {init.status_code}", detail=init.text)
    session_id = init.headers.get("Mcp-Session-Id") or init.headers.get("mcp-session-id")
    if not session_id:
        fail("initialize response missing Mcp-Session-Id header")

    sess_headers = {
        **bearer,
        "Content-Type": "application/json",
        "Mcp-Session-Id": session_id,
    }

    # 3. notifications/initialized — required handshake step before further calls.
    notify = session.post(
        f"{base}/mcp",
        headers=sess_headers,
        data=json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        timeout=TIMEOUT_SECONDS,
    )
    if notify.status_code not in (200, 202):
        fail(
            f"notifications/initialized expected 200/202, got {notify.status_code}",
            detail=notify.text,
        )

    # 4. tools/call → echo.
    call = session.post(
        f"{base}/mcp",
        headers=sess_headers,
        data=json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "echo", "arguments": {"text": ECHO_INPUT}},
            }
        ),
        timeout=TIMEOUT_SECONDS,
    )
    if call.status_code != 200:
        fail(f"tools/call expected 200, got {call.status_code}", detail=call.text)

    rpc = parse_mcp_response(call)
    result = rpc.get("result") or {}
    content = result.get("content") or []
    if not content or not isinstance(content, list):
        fail("tools/call response missing content array", detail=rpc)
    first = content[0]
    if not isinstance(first, dict) or first.get("type") != "text":
        fail("tools/call first content item is not text", detail=rpc)
    text = first.get("text")
    if text != ECHO_INPUT:
        fail(f"echo mismatch: expected {ECHO_INPUT!r}, got {text!r}", detail=rpc)

    print(f"E2E OK: echoed {text!r}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        fail("interrupted")
    except requests.RequestException as exc:
        fail(f"HTTP error: {exc}")
    except Exception as exc:  # noqa: BLE001 — last-resort funnel into fail()
        fail(f"unexpected error: {exc}")
