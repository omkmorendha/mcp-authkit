# postgres

A protected MCP server identical to [`hello-world`](../hello-world/) but
backed by the durable Postgres `TokenStore` (spec
[§6.3](../../docs/spec/v0.2.md#63-postgres-store)) and configured
through `mcp-authkit.config.ts` via the config-file loader (spec
[§5.8](../../docs/spec/v0.2.md#58-config-file-format)).

Use this example as the template for any deployment where PATs and
refresh tokens must survive process restarts.

## What it exposes

| Route                                            | Purpose                                     |
| ------------------------------------------------ | ------------------------------------------- |
| `POST /mcp`                                      | MCP request handler — calls the `echo` tool |
| `GET /.well-known/oauth-protected-resource`      | RFC 9728 protected-resource metadata        |
| `POST/GET/DELETE /pats`, `POST /pats/:id/rotate` | PAT CRUD (spec §8.3)                        |

## Running

### 1. Start Postgres

```bash
docker compose -f examples/postgres/docker-compose.yml up -d
```

The container exposes `127.0.0.1:5432` with `POSTGRES_HOST_AUTH_METHOD=trust`
— local development only. Tear it down with `docker compose ... down -v`
to wipe the volume.

### 2. Install + run

```bash
pnpm install
pnpm --filter mcp-authkit-example-postgres build

# Run the built artifact:
pnpm --filter mcp-authkit-example-postgres start

# Or run directly from source (tsx, dev only):
pnpm --filter mcp-authkit-example-postgres dev
```

The server calls `tokenStore.init()` on startup, which applies the
package's migrations idempotently. You do **not** need to run psql by
hand.

Server logs `postgres-example listening on :3000`. Bypass mode is on by
default for local dev — every request is synthesised as user
`local-dev` with scope `echo:say` (spec
[§11.1](../../docs/spec/v0.1.md#111-bypass-mode)). To require real
tokens, set `MCP_AUTHKIT_BYPASS=0`.

### Configuration

| Env var               | Default                                                | Notes                                            |
| --------------------- | ------------------------------------------------------ | ------------------------------------------------ |
| `PORT`                | `3000`                                                 | Listen port                                      |
| `RESOURCE_INDICATOR`  | `http://localhost:<PORT>/mcp`                          | RFC 8707 audience for accepted tokens            |
| `DATABASE_URL`        | `postgres://authkit@localhost:5432/authkit_test`       | Read by `mcp-authkit.config.ts`                  |
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
that is the whole point of choosing the Postgres store over
`memoryTokenStore`.

## Production notes

For an end-to-end walkthrough see
[`docs/production.md`](../../docs/production.md) and the
[`postgres-store`](../../docs/cookbook/postgres-store.md) cookbook entry.

This example is tuned for local development. For real deployments:

- Set `MCP_AUTHKIT_BYPASS=0` and configure `authorizationServer` against
  a real issuer (Auth0, WorkOS, Keycloak, Cognito, …).
- Point `DATABASE_URL` at a managed Postgres with TLS and a non-root
  user. Apply your own connection-pool limits via
  `new Pool({ max, idleTimeoutMillis, ... })`.
- Set `RESOURCE_INDICATOR` to your public MCP URL so the
  audience-validation and Host-header allowlist match your deployment.
- The pool belongs to your application (spec §6.3); `tokenStore.close()`
  is intentionally a no-op. Close the pool yourself on shutdown.
