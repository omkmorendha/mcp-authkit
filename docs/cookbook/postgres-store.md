# Cookbook: Postgres store

Durable `TokenStore` backed by Postgres. Use this for any HTTP deployment
where PATs and refresh tokens must survive process restarts. Spec
references: [§6.3](../spec/v0.2.md#63-postgres-store),
[§5.8](../spec/v0.2.md#58-config-file-format),
[§12](../spec/v0.2.md#12-security-non-negotiables-additions).

A runnable copy of this configuration ships at
[`examples/postgres/`](../../examples/postgres/).

## Imports

```ts
import { defineConfig } from "mcp-authkit/config"
import { postgresTokenStore } from "mcp-authkit/stores/postgres"
import { Pool } from "pg"
```

## Snippet

```ts
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 10,                      // tune per-host capacity
  idleTimeoutMillis: 30_000,
  // ssl: { ca: fs.readFileSync("rds-ca.pem") }, // for verify-full
})

export default defineConfig({
  resourceIndicator: process.env.RESOURCE_INDICATOR!,
  auth: {
    authorizationServer: {
      issuer: process.env.OAUTH_ISSUER!,
      jwksUri: process.env.OAUTH_JWKS_URI!,
    },
    tokenStore: postgresTokenStore({
      pool,
      // schema: "authkit",              // default "public"
      // tableNames: { pats: "..." },    // override individual tables
      // statementTimeoutMs: 5_000,      // default 5000
    }),
    pat: { enabled: true, prefix: "mcp_pat_" },
  },
  scopes: { vocabulary: {} },
  resolveUserScopes: async () => [],
})
```

`tokenStore.init()` runs on startup and applies the package's bundled
migrations idempotently inside `LOCK TABLE mcp_migrations IN EXCLUSIVE MODE`.
Concurrent process starts are safe.

## Env vars

| Var                  | Required | Notes                                                                  |
| -------------------- | -------- | ---------------------------------------------------------------------- |
| `DATABASE_URL`       | yes      | `postgres://user:pass@host:5432/db?sslmode=require`                    |
| `RESOURCE_INDICATOR` | yes      | RFC 8707 audience; must match AS-issued `aud`                          |
| `OAUTH_ISSUER`       | yes      | Authorization-server issuer URL                                        |
| `OAUTH_JWKS_URI`     | yes      | JWKS endpoint                                                          |

## Schema layout

Three tables are created under the configured schema (default `public`):

- `mcp_pats` — PAT records. `token_hash BYTEA UNIQUE`, no plaintext.
- `mcp_refresh_tokens` — refresh-token records with `family_id`.
- `mcp_upstream_credentials` — token-exchange cache for
  `upstreamFor(...)` (spec [§6.2](../spec/v0.2.md#62-optional-cache-methods)).

Plus a `mcp_migrations` bookkeeping table. Indexes per spec
[§6.3](../spec/v0.2.md#63-postgres-store):
`mcp_pats(token_hash)` UNIQUE, `mcp_pats(user_identifier)`,
`mcp_refresh_tokens(token_hash)` UNIQUE, `mcp_refresh_tokens(family_id)`,
`mcp_upstream_credentials(cache_key, expires_at)`.

Table-name overrides are validated against `[A-Za-z0-9_]` — anything
else throws at config time.

## Pool ownership and shutdown

The pool belongs to your application. `tokenStore.close()` is a no-op.
Close it on `SIGTERM`:

```ts
process.on("SIGTERM", async () => {
  server.close()
  await pool.end()
  process.exit(0)
})
```

## What to test

- **`init()` is idempotent.** Start two replicas at once against an
  empty database; both should come up. Restart against an already-migrated
  database; startup should not fail.
- **Restart survives PATs.** Mint a PAT via `mcp-authkit mint-pat`,
  restart the process, call `/mcp` with the same PAT — it still works.
  This is the whole point of choosing Postgres over `memoryTokenStore`.
- **Schema isolation.** Configure `schema: "authkit"` and verify the
  tables are created under it (not `public`).
- **Statement timeout.** Set `statementTimeoutMs: 100`, point at a slow
  query (e.g. a manual `pg_sleep` from a parallel session holding a
  lock), and confirm the framework fails fast rather than hanging.

## Common mistakes

- **Pool sized too small.** A single-replica deployment with `max: 1`
  will serialize every request through one Postgres connection. Default
  to `10`, tune up if you see `Pool` queue waits.
- **Connecting without TLS.** Local development is fine without
  `sslmode`, but a production `DATABASE_URL` should be at minimum
  `sslmode=require`. Managed providers (RDS, Cloud SQL) reject plain
  connections by default — good.
- **Closing the pool inside the store.** Don't call `pool.end()` from
  inside `tokenStore.close()` — the pool may be shared with other
  application code.
- **String-interpolating table names.** Don't pass user input into
  `tableNames`. The framework rejects non-`[A-Za-z0-9_]` characters but
  it's still a smell.
