# filesystem

A protected MCP server identical to [`hello-world`](../hello-world/) but
backed by the durable SQLite `TokenStore` (spec
[§6.4](../../docs/spec/v0.2.md#64-sqlite-store)) and configured through
`mcp-authkit.config.ts` via the config-file loader (spec
[§5.8](../../docs/spec/v0.2.md#58-config-file-format)).

Use this example for single-process deployments where PATs and refresh
tokens must survive restarts but you do not want to run a separate
database server.

## What it exposes

| Route                                            | Purpose                                     |
| ------------------------------------------------ | ------------------------------------------- |
| `POST /mcp`                                      | MCP request handler — calls the `echo` tool |
| `GET /.well-known/oauth-protected-resource`      | RFC 9728 protected-resource metadata        |
| `POST/GET/DELETE /pats`, `POST /pats/:id/rotate` | PAT CRUD (spec §8.3)                        |

## Running

```bash
pnpm install
pnpm --filter mcp-authkit-example-filesystem build

# Run the built artifact:
pnpm --filter mcp-authkit-example-filesystem start

# Or run directly from source (tsx, dev only):
pnpm --filter mcp-authkit-example-filesystem dev
```

The server calls `tokenStore.init()` on startup, which enables
`journal_mode = WAL` and applies the package's migrations idempotently.
The database file (`./mcp-authkit.db` by default) is created on first
use, alongside the `-wal` and `-shm` sidecar files SQLite needs for WAL
mode. All three are gitignored.

Server logs `filesystem-example listening on :3000`. Bypass mode is on
by default for local dev — every request is synthesised as user
`local-dev` with scope `echo:say` (spec
[§11.1](../../docs/spec/v0.1.md#111-bypass-mode)). To require real
tokens, set `MCP_AUTHKIT_BYPASS=0`.

### Configuration

| Env var               | Default                                                | Notes                                            |
| --------------------- | ------------------------------------------------------ | ------------------------------------------------ |
| `PORT`                | `3000`                                                 | Listen port                                      |
| `RESOURCE_INDICATOR`  | `http://localhost:<PORT>/mcp`                          | RFC 8707 audience for accepted tokens            |
| `SQLITE_PATH`         | `./mcp-authkit.db`                                     | Path to the single-file SQLite database          |
| `OAUTH_ISSUER`        | `https://auth.example.com`                             | Authorization-server issuer                      |
| `OAUTH_JWKS_URI`      | `https://auth.example.com/.well-known/jwks.json`       | Authorization-server JWKS endpoint               |
| `MCP_AUTHKIT_BYPASS`  | `1` (anything but `"0"`)                               | Set to `0` to require real tokens                |

Bypass mode refuses to start when `NODE_ENV=production` unless you also
set `bypass.allowInProduction: true` in the config (this example does
not).

## Smoke test (curl)

With the server running in bypass mode:

```bash
# 1. Mint a PAT. The full token is returned exactly once. It is hashed
#    (SHA-256) in the mcp_pats table; no plaintext is stored.
curl -sX POST http://localhost:3000/pats \
  -H "Content-Type: application/json" \
  -d '{"name":"smoke","scopes":["echo:say"]}'
# {"token":"mcp_pat_...","pat":{...}}

# 2. List PATs.
curl -s http://localhost:3000/pats

# 3. Initialize an MCP session.
curl -isX POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{
       "protocolVersion":"2025-06-18","capabilities":{},
       "clientInfo":{"name":"smoke","version":"0"}}}'

# 4. Call the echo tool with the session id from step 3.
curl -sX POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Mcp-Session-Id: <id-from-step-3>" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call",
       "params":{"name":"echo","arguments":{"text":"hi"}}}'
```

Restart the server between steps 1 and 4 to confirm the PAT survives —
that is the whole point of choosing the SQLite store over
`memoryTokenStore`.

## Production notes

This example is tuned for local development and single-process
deployments. For real deployments:

- Set `MCP_AUTHKIT_BYPASS=0` and configure `authorizationServer` against
  a real issuer (Auth0, WorkOS, Keycloak, Cognito, …).
- Pick a stable `SQLITE_PATH` on a durable, locally-attached volume.
  SQLite over network filesystems (NFS, EFS) is not safe under
  concurrent writers; if you need that, use the Postgres store.
- Back the database file up like any other piece of stateful data.
  WAL-mode databases require backing up the `-wal` file along with the
  main file, or using SQLite's online-backup API.
- Set `RESOURCE_INDICATOR` to your public MCP URL so the
  audience-validation and Host-header allowlist match your deployment.
- The database handle belongs to your application (spec §6.4);
  `tokenStore.close()` is intentionally a no-op. Close the handle
  yourself on shutdown if you want a clean WAL checkpoint.
- The framework warns at startup if the database was opened readonly —
  every write path (mint PAT, rotate refresh, cache upstream
  credential) will fail in that mode.
