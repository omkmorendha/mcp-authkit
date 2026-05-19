# Python E2E

Exercises the full programmatic flow against a hello-world-shaped
protected MCP server: mint a PAT via REST, call the `echo` tool, assert
the response. Defined by spec
[§18](../../docs/spec/v0.1.md#18-quality-bar-for-v01).

## Layout

| File         | Role                                                                              |
| ------------ | --------------------------------------------------------------------------------- |
| `server.ts`  | Node harness: in-process test Authorization Server + protected MCP server         |
| `e2e.py`     | Python test, stdlib + `requests` only                                             |
| `run.sh`     | Orchestrator: starts the harness, runs the script, tears down                     |

## Prerequisites

- Node 20+ and `pnpm` 10.x (same as the rest of the repo).
- Python 3.9+ available as `python3` (override with `PYTHON=<path>`).
- The `requests` package installed for that Python:
  ```bash
  python3 -m pip install requests
  ```

## Running

From the repo root:

```bash
pnpm e2e
```

…or directly:

```bash
./e2e/python/run.sh
```

The first run installs deps and builds the workspace; expect it to
complete in under 5 minutes. Subsequent runs (with `dist/` already
populated and `node_modules/` warm) complete in under 10 seconds —
they only start the harness, do the handshake, mint a PAT, call the
tool, and tear down.

On success:

```text
E2E OK: echoed 'hello, mcp-authkit'
```

On failure, the script exits non-zero, prints `E2E FAIL: <reason>`,
and dumps the harness's stderr log for context.

## What it covers

- **PAT mint** (`POST /pats`) authenticated by a real JWT from the
  in-process test AS. Bypass mode is **off** in the harness, so the
  token validation pipeline (spec §9) genuinely runs.
- **MCP session handshake** (`initialize` + `notifications/initialized`)
  using the minted PAT as a Bearer token.
- **Tool call** (`tools/call name=echo`) and response assertion.

Anything else (OAuth browser flows, refresh rotation, scope wildcards,
PAT-cannot-manage-PATs negative paths) is out of scope here and is
covered by the unit and integration test suites in the `packages/`
tree.

## Customising

| Env var          | Default              | Purpose                                       |
| ---------------- | -------------------- | --------------------------------------------- |
| `PYTHON`         | `python3`            | Python interpreter to use                     |
| `PORT`           | random free port     | Pin the harness HTTP port                     |
| `LOG_LEVEL`      | `warn`               | Harness pino log level                        |
