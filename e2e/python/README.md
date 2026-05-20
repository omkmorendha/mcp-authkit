# Python E2E

Exercises the full programmatic flow against a hello-world-shaped
protected MCP server: mint a PAT via the `mcp-authkit` CLI in a
subprocess, call the `echo` tool with that PAT as a Bearer, assert
the response. Defined by spec v0.2
[§16](../../docs/spec/v0.2.md#16-quality-bar-for-v02).

## Layout

| File                       | Role                                                                              |
| -------------------------- | --------------------------------------------------------------------------------- |
| `server.ts`                | Node harness: Hono-mounted MCP server with a SQLite-backed `TokenStore`           |
| `mcp-authkit.config.ts`    | Config loaded by both the harness AND the CLI subprocess (shared SQLite db file)  |
| `e2e.py`                   | Python test, stdlib + `requests` only; mints PAT via CLI subprocess               |
| `run.sh`                   | Orchestrator: builds (if needed), starts the harness, runs the script, tears down |

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

- **Hono adapter** mounting `/mcp`, `/.well-known/oauth-protected-resource`,
  and `/pats` routes (spec v0.2 §10).
- **CLI `mint-pat`** in a subprocess, including JSON output parsing
  (spec v0.2 §9.2).
- **SQLite token store** as the cross-process shared state (spec v0.2 §6.4).
- **MCP session handshake** (`initialize` + `notifications/initialized`)
  using the minted PAT as a Bearer token.
- **Tool call** (`tools/call name=echo`) and response assertion.

Bypass mode is OFF in the harness, so the PAT bearer round-trips the
real validation pipeline (spec v0.1 §9). Anything else (OAuth browser
flows, refresh rotation, scope wildcards, PAT-cannot-manage-PATs
negative paths) is out of scope here and covered by the unit and
integration suites in the `packages/` tree.

## Customising

| Env var          | Default              | Purpose                                       |
| ---------------- | -------------------- | --------------------------------------------- |
| `PYTHON`         | `python3`            | Python interpreter to use                     |
| `PORT`           | random free port     | Pin the harness HTTP port                     |
| `LOG_LEVEL`      | `warn`               | Harness pino log level                        |
