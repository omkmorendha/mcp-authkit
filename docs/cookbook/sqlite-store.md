# Cookbook: SQLite store

Durable single-file `TokenStore` backed by SQLite (via `better-sqlite3`).
Use for single-host deployments where PATs and refresh tokens must
survive restarts but you do not want a separate database server. Spec
references: [§6.4](../spec/v0.2.md#64-sqlite-store),
[§5.8](../spec/v0.2.md#58-config-file-format).

A runnable copy of this configuration ships at
[`examples/filesystem/`](../../examples/filesystem/).

## Imports

```ts
import Database from "better-sqlite3"
import { defineConfig } from "mcp-authkit/config"
import { sqliteTokenStore } from "mcp-authkit/stores/sqlite"
```

## Snippet

```ts
const database = new Database(process.env.SQLITE_PATH ?? "./mcp-authkit.db")

export default defineConfig({
  resourceIndicator: process.env.RESOURCE_INDICATOR!,
  auth: {
    authorizationServer: {
      issuer: process.env.OAUTH_ISSUER!,
      jwksUri: process.env.OAUTH_JWKS_URI!,
    },
    tokenStore: sqliteTokenStore({ database }),
    pat: { enabled: true, prefix: "mcp_pat_" },
  },
  scopes: { vocabulary: {} },
  resolveUserScopes: async () => [],
})
```

`tokenStore.init()` enables `journal_mode = WAL` and applies the
bundled migrations inside a `BEGIN IMMEDIATE` lock. Migrations are
idempotent.

## Env vars

| Var                  | Required | Default                       | Notes                                       |
| -------------------- | -------- | ----------------------------- | ------------------------------------------- |
| `SQLITE_PATH`        | no       | `./mcp-authkit.db`            | Use an absolute path on durable storage     |
| `RESOURCE_INDICATOR` | yes      | —                             | RFC 8707 audience                           |
| `OAUTH_ISSUER`       | yes      | —                             | AS issuer                                   |
| `OAUTH_JWKS_URI`     | yes      | —                             | JWKS endpoint                               |

## Files on disk

WAL mode creates three files alongside the main database:

```
mcp-authkit.db        # main file
mcp-authkit.db-wal    # write-ahead log
mcp-authkit.db-shm    # shared-memory index
```

All three must be on the **same filesystem** and present at backup time.
Backing up the `.db` alone, without the `-wal`, loses uncheckpointed
writes. Use SQLite's online-backup API or stop the process for a clean
copy.

## Database ownership and shutdown

The `Database` handle belongs to your application. `tokenStore.close()`
is a no-op. Close on shutdown for a clean WAL checkpoint:

```ts
process.on("SIGTERM", async () => {
  server.close()
  database.close()
  process.exit(0)
})
```

## What to test

- **`init()` is idempotent.** Start the process twice against the same
  file; second startup should not error.
- **Restart survives PATs.** Same test as the Postgres store — mint,
  restart, call.
- **Readonly refusal.** Open the database with `new Database(path,
  { readonly: true })` and confirm the framework warns at startup
  (every write path will fail in that mode).
- **WAL files survive a backup-restore.** Copy `.db`, `-wal`, and
  `-shm` to a fresh host, point the process at them, confirm PATs
  minted before the copy still authenticate.

## Common mistakes

- **NFS or EFS.** SQLite is not safe under concurrent writers on
  network filesystems. If you need multiple processes writing, use
  Postgres instead. Single-process on NFS technically works but
  performance is poor and lock recovery is fragile — locally-attached
  storage is the supported case.
- **Backing up only the `.db` file.** WAL-mode databases require the
  `-wal` sidecar to be backed up atomically with the main file. Use
  SQLite's online-backup API if you cannot quiesce the writer.
- **Sharing the file between hosts.** SQLite is a single-host store.
  Two processes on two hosts pointed at the "same" file over NFS will
  corrupt it. Use Postgres for multi-host deployments.
- **Forgetting `init()`.** Without it, the schema is empty and every
  write fails. The framework calls `init()` for you when the store is
  attached via the config-file loader, but if you wire the store
  manually you must call it yourself before `app.listen`.
