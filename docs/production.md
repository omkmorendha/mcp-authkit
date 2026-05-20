# Production deployment guide

This guide takes an operator from a Postgres connection string to a
running, OAuth-protected MCP server without reading any TypeScript. It
maps the v0.2 spec's "quality bar" checklist
([§16](spec/v0.2.md#16-quality-bar-for-v02)) onto concrete steps.

> **Audience.** Operators deploying `mcp-authkit` for the first time.
> Library users writing tool handlers should start with the
> [quickstart](quickstart.md); this guide assumes the application code
> already exists.

The reference deployment in this guide is a single Node process behind a
TLS terminator, with a managed Postgres instance for durable token
storage. Per-store, per-adapter, and per-flow variations are linked
under [cookbook entries](#7-cookbook-entries) when they apply.

---

## 1. What you need before you start

- A running **Postgres 13+** instance reachable from the application
  host. Managed Postgres (RDS, Cloud SQL, Neon, Supabase, etc.) is fine.
  TLS is required.
- An **authorization server** issuing OAuth 2.1 access tokens. The
  framework consumes its issuer + JWKS URIs; it does not run an AS.
  Examples: Auth0, WorkOS, Keycloak, Cognito, Okta.
- The **public URL** of your MCP endpoint — exactly the value you will
  use as `RESOURCE_INDICATOR` ([RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707),
  spec [§14](spec/v0.1.md#14-security-non-negotiables)). For a typical
  deployment this is `https://mcp.example.com/mcp`.
- Node.js 20+ and `pnpm` (or `npm`/`yarn`) on the application host.
- A **non-root** Postgres user that owns one application schema. The
  framework's `init()` runs migrations using this user.

If any of these are missing, stop and obtain them first. The framework
will refuse to start with a placeholder `authorizationServer` in
`NODE_ENV=production`.

---

## 2. Pick a deployment shape

Three shapes cover the v0.2 surface. Pick one before continuing.

| Shape                       | Store                                   | When to use                                                                 | Cookbook                                                  |
| --------------------------- | --------------------------------------- | --------------------------------------------------------------------------- | --------------------------------------------------------- |
| **Single process + Postgres** | `postgresTokenStore`                   | Default for HTTP deployments. Survives restarts; horizontally scalable.     | [postgres-store](cookbook/postgres-store.md)              |
| **Single process + SQLite** | `sqliteTokenStore`                      | Single host, no separate DB. Edge boxes, on-prem appliances.                | [sqlite-store](cookbook/sqlite-store.md)                  |
| **Signed-handshake stdio**  | any (typically memory or SQLite)        | Trusted local subprocess (`claude-code` style). Bypass is refused.          | [production-stdio](cookbook/production-stdio.md)          |

The remainder of this guide walks the first shape end-to-end. The other
two are documented in their cookbook entries.

---

## 3. Prepare the Postgres role

Run these statements **once** as a Postgres superuser:

```sql
CREATE ROLE authkit LOGIN PASSWORD 'redacted';
CREATE DATABASE authkit OWNER authkit;
GRANT CONNECT ON DATABASE authkit TO authkit;
```

Then, as the `authkit` role on the `authkit` database:

```sql
CREATE SCHEMA IF NOT EXISTS authkit AUTHORIZATION authkit;
SET search_path TO authkit;
```

`postgresTokenStore` will create three tables (`mcp_pats`,
`mcp_refresh_tokens`, `mcp_upstream_credentials`) plus a `mcp_migrations`
bookkeeping table inside that schema. Migrations are idempotent and
forward-only (spec [§6.3](spec/v0.2.md#63-postgres-store)).

Construct the `DATABASE_URL`:

```text
postgres://authkit:redacted@db.internal:5432/authkit?sslmode=require
```

`sslmode=require` is the minimum. Prefer `verify-full` with a CA bundle
on managed providers that expose one.

---

## 4. Configure the application

Production deployments use the config-file loader (spec
[§5.8](spec/v0.2.md#58-config-file-format)) rather than building the
config inline in `server.ts`. Save the following as
`mcp-authkit.config.ts` at the project root:

```ts
import { defineConfig } from "mcp-authkit/config"
import { postgresTokenStore } from "mcp-authkit/stores/postgres"
import { Pool } from "pg"

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 10,
  idleTimeoutMillis: 30_000,
})

export default defineConfig({
  resourceIndicator: process.env.RESOURCE_INDICATOR!,
  auth: {
    authorizationServer: {
      issuer: process.env.OAUTH_ISSUER!,
      jwksUri: process.env.OAUTH_JWKS_URI!,
    },
    tokenStore: postgresTokenStore({ pool }),
    pat: { enabled: true, prefix: "mcp_pat_" },
    bypass: { enabled: false }, // bypass refuses production by default; this is belt-and-braces
  },
  scopes: { vocabulary: {} },
  resolveUserScopes: async () => [],
})
```

Required environment variables:

| Var                  | Example                                                          | Purpose                                              |
| -------------------- | ---------------------------------------------------------------- | ---------------------------------------------------- |
| `RESOURCE_INDICATOR` | `https://mcp.example.com/mcp`                                    | RFC 8707 audience; must match the AS-issued `aud`    |
| `OAUTH_ISSUER`       | `https://auth.example.com`                                       | Authorization-server issuer                          |
| `OAUTH_JWKS_URI`     | `https://auth.example.com/.well-known/jwks.json`                 | JWKS endpoint                                        |
| `DATABASE_URL`       | `postgres://authkit:…@db.internal:5432/authkit?sslmode=require`  | Postgres DSN                                         |
| `NODE_ENV`           | `production`                                                     | Disables bypass-in-prod path; loud startup log       |
| `LOG_LEVEL`          | `info`                                                           | Pino level                                           |

Do **not** put secrets in argv. The CLI refuses to accept secrets from
flags (spec [§12](spec/v0.2.md#12-security-non-negotiables-additions)).

For per-store and per-adapter variations of this config, see the
cookbook entries linked in [§7](#7-cookbook-entries).

---

## 5. Verify before you ship

The CLI ships three subcommands that catch the most common deployment
mistakes before you take traffic. Run them in order against the
production config:

```bash
# 1. Schema validation. Exits 2 with a readable error if anything is wrong.
pnpm exec mcp-authkit verify-config

# 2. JWKS reachability. Prints key IDs and algorithms.
pnpm exec mcp-authkit jwks-fetch

# 3. Mint a smoke PAT. Use this token for the post-deploy curl test
#    in §6 — it survives restarts because the store is durable.
pnpm exec mcp-authkit mint-pat \
  --user ops-smoke \
  --name post-deploy-smoke \
  --scopes echo:say \
  --expires-in-days 7
```

`verify-config` prints a summary of the resolved values with secrets
redacted; compare it against your runbook before promoting the deploy.
`mint-pat` prints the full token exactly once — copy it into your
secrets manager immediately, the hash is all that survives in Postgres
(spec [§8](spec/v0.1.md#8-personal-access-tokens)).

---

## 6. Run the server

Use the built artifact, not `tsx`, in production:

```bash
pnpm install --prod=false   # build needs the dev deps
pnpm build
NODE_ENV=production pnpm start
```

You should see one of two startup banners. **Good**:

```text
INFO  mcp-authkit listening { port: 3000, resourceIndicator: "https://mcp.example.com/mcp" }
```

**Bad** — bypass is on and `NODE_ENV=production`:

```text
WARN  bypass.enabled=true in production; this is a deployment misconfiguration ...
```

The second case refuses to start unless `bypass.allowInProduction: true`
is set in config (spec [§14](spec/v0.1.md#14-security-non-negotiables)).
Take that as a stop-ship signal and fix the config.

### TLS termination

The framework speaks plain HTTP. Put a TLS terminator in front (Cloud
Load Balancer, nginx, Caddy, `node:tls` if you must). Two things matter:

- The terminator MUST preserve the `Host` header (or rewrite it to the
  hostname inside `RESOURCE_INDICATOR`). The framework's DNS-rebinding
  protection (spec [§14](spec/v0.1.md#14-security-non-negotiables))
  rejects requests whose `Host` is not on the allowlist.
- The terminator MUST forward `Authorization` headers unchanged. Some
  CDNs strip them by default; check before going live.

### Process supervision

Use whatever you already use — `systemd`, Kubernetes, ECS, Nomad. Two
non-negotiables:

- **Restart on exit non-zero.** The framework exits non-zero on a
  configuration mismatch (bad JWKS, unreachable Postgres) so the
  supervisor will hold the failed deploy.
- **Drain on shutdown.** Send `SIGTERM` and wait for the process to
  finish in-flight requests. The Postgres pool is owned by your
  application (spec [§6.3](spec/v0.2.md#63-postgres-store)); close it on
  shutdown for a clean exit:

  ```ts
  process.on("SIGTERM", async () => {
    server.close()
    await pool.end()
    process.exit(0)
  })
  ```

### Post-deploy smoke

Use the PAT minted in [§5](#5-verify-before-you-ship). The full
request/response shape is identical to the
[quickstart](quickstart.md#5-mint-a-pat-with-curl) — just point at the
production URL:

```bash
export PAT='mcp_pat_...'
export MCP_URL='https://mcp.example.com/mcp'

curl -isX POST "$MCP_URL" \
  -H "Authorization: Bearer $PAT" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{
       "protocolVersion":"2025-06-18","capabilities":{},
       "clientInfo":{"name":"smoke","version":"0"}}}'
```

A `200` with an `Mcp-Session-Id` response header confirms the full
pipeline: TLS terminator → host validation → token validation → MCP
session creation.

---

## 7. Cookbook entries

Each entry is self-contained: imports, code snippet, required env vars,
what to test. Pick the ones that match your deployment.

| Topic                                                                   | When to read                                                            |
| ----------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| [`postgres-store`](cookbook/postgres-store.md)                          | Default durable backend; what `init()` does, pool sizing, schema layout |
| [`sqlite-store`](cookbook/sqlite-store.md)                              | Single-host deployments; WAL, backups, file permissions                 |
| [`redis-cache`](cookbook/redis-cache.md)                                | Read-mostly cache decorator; HMAC keying, invalidation                  |
| [`hono-adapter`](cookbook/hono-adapter.md)                              | Hono-based servers; mounting middleware, streaming                      |
| [`multi-tenant`](cookbook/multi-tenant.md)                              | One process, many tenants; function-form `authorizationServer`          |
| [`upstream-credentials`](cookbook/upstream-credentials.md)              | Calling upstream APIs from a tool handler via token exchange            |
| [`production-stdio`](cookbook/production-stdio.md)                      | Signed-handshake stdio transport; HMAC keys, no bypass                  |

---

## 8. Operational checklist

A short list to copy into your deploy runbook.

- [ ] `RESOURCE_INDICATOR` exactly matches the public MCP URL.
- [ ] `authorizationServer.issuer` and `jwksUri` are real, reachable URLs.
- [ ] `DATABASE_URL` uses `sslmode=require` or stronger.
- [ ] Postgres user is **not** a superuser.
- [ ] `bypass.enabled` is `false` (or omitted) in production config.
- [ ] `NODE_ENV=production` is set in the runtime environment.
- [ ] `pnpm exec mcp-authkit verify-config` exits 0.
- [ ] `pnpm exec mcp-authkit jwks-fetch` returns at least one usable key.
- [ ] TLS terminator preserves `Host` and `Authorization` headers.
- [ ] Process supervisor restarts on non-zero exit and forwards `SIGTERM`.
- [ ] Log shipper captures stderr (pino writes there by default).
- [ ] Backup policy in place for whichever store you chose
      (Postgres: WAL-archived; SQLite: file plus `-wal` sidecar).
- [ ] Secrets (PATs, static tokens, HMAC keys) live in a secret manager,
      never in argv, never checked in.

---

## 9. Where to look next

- [`docs/spec/v0.2.md`](spec/v0.2.md) — the full v0.2 specification.
- [`examples/postgres/`](../examples/postgres/) — runnable Postgres example
  this guide mirrors.
- [`examples/filesystem/`](../examples/filesystem/) — runnable SQLite example.
- [`examples/stdio/`](../examples/stdio/) — runnable production stdio example.
- [`examples/hello-world/`](../examples/hello-world/) — minimal v0.1 stack
  for local development and the smoke matrix.

If something here is wrong, surprising, or under-specified, file a
docs issue. The v0.2 quality bar (spec
[§16](spec/v0.2.md#16-quality-bar-for-v02)) explicitly calls out
operator-readability — discrepancies are bugs.
