# hello-world

A minimal protected MCP server built with `mcp-authkit`. Exercises the
core single-tenant stack: token validation pipeline, PAT REST endpoints,
scope gating, the Express adapter, and the in-memory token store. For
Postgres, SQLite, Hono, or production stdio see the sibling examples
and [`docs/cookbook/`](../../docs/cookbook/).

The source (`src/index.ts`) fits in under 50 lines — see spec
[§6.2](../../docs/spec/v0.1.md#62-usage-hello-world-target-under-50-lines).

## What it exposes

| Route                                       | Purpose                                     |
| ------------------------------------------- | ------------------------------------------- |
| `POST /mcp`                                 | MCP request handler — calls the `echo` tool |
| `GET /.well-known/oauth-protected-resource` | RFC 9728 protected-resource metadata        |
| `POST/GET/DELETE /pats`, `POST /pats/:id/rotate` | PAT CRUD (spec §8.3)                   |

The `echo` tool requires the `echo:say` scope and returns the input
string.

## Running

```bash
pnpm install
pnpm --filter hello-world build

# Run the built artifact:
pnpm --filter hello-world start

# Or run directly from source (tsx, dev only):
pnpm --filter hello-world dev
```

Server logs `hello-world listening on :3000`. Bypass mode is on by
default for local dev — every request is synthesised as user
`local-dev` with scope `echo:say` (see spec
[§11.1](../../docs/spec/v0.1.md#111-bypass-mode)). To require real
tokens, set `MCP_AUTHKIT_BYPASS=0`.

### Configuration

| Env var                  | Default                       | Notes                                    |
| ------------------------ | ----------------------------- | ---------------------------------------- |
| `PORT`                   | `3000`                        | Listen port                              |
| `RESOURCE_INDICATOR`     | `http://localhost:<PORT>/mcp` | RFC 8707 audience for accepted tokens    |
| `MCP_AUTHKIT_BYPASS`     | `1` (anything but `"0"`)      | Set to `0` to require real tokens        |

Bypass mode refuses to start when `NODE_ENV=production` unless you also
set `bypass.allowInProduction: true` in config (this example does not).

## Smoke test (curl)

With the server running in bypass mode:

```bash
# 1. Mint a PAT. The full token is returned exactly once.
curl -sX POST http://localhost:3000/pats \
  -H "Content-Type: application/json" \
  -d '{"name":"smoke","scopes":["echo:say"]}'
# {"token":"mcp_pat_...","pat":{...}}

# 2. List PATs.
curl -s http://localhost:3000/pats

# 3. Initialize an MCP session — Streamable HTTP requires a session header
#    on subsequent calls. The Mcp-Session-Id is returned on the response.
curl -isX POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{
       "protocolVersion":"2025-06-18","capabilities":{},
       "clientInfo":{"name":"smoke","version":"0"}}}'

# 4. Call the echo tool. Use the Mcp-Session-Id from step 3 and either the
#    bypass auth (default) or a real Bearer token.
curl -sX POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Mcp-Session-Id: <id-from-step-3>" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call",
       "params":{"name":"echo","arguments":{"text":"hi"}}}'
```

Expect step 4 to return a JSON-RPC response whose `result.content[0].text`
is `"hi"`. Once bypass is disabled, all of `/pats` and `/mcp` require an
OAuth Bearer (or PAT, for `/mcp` only). PAT-authenticated requests cannot
hit `/pats` (spec §8.6).

## Production notes

This example is intentionally tuned for local development. For real
deployments:

- Set `MCP_AUTHKIT_BYPASS=0` and configure `authorizationServer` against
  a real issuer (Auth0, WorkOS, Keycloak, Cognito, …).
- Use a durable `TokenStore` (the memory store is in-process only).
- Set `RESOURCE_INDICATOR` to your public MCP URL so the
  audience-validation and Host-header allowlist match your deployment.

For an end-to-end production walkthrough — config-file loader, durable
store, CLI verification, supervisor wiring — see
[`docs/production.md`](../../docs/production.md) and the
[`docs/cookbook/`](../../docs/cookbook/) entries.
