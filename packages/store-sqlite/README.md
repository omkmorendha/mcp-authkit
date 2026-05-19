# mcp-authkit-store-sqlite

SQLite `TokenStore` implementation for `mcp-authkit`, backed by
[`better-sqlite3`](https://www.npmjs.com/package/better-sqlite3).

Most users should import it through the core package:

```ts
import Database from "better-sqlite3"
import { sqliteTokenStore } from "mcp-authkit/stores/sqlite"

const db = new Database("/var/lib/myapp/authkit.db")
const store = sqliteTokenStore({ database: db })
await store.init?.()
```

`init()` is idempotent: it switches the connection to `journal_mode = WAL` and
applies bundled migrations under a `BEGIN IMMEDIATE` lock, so concurrent
startups against the same file are safe.

This store is suitable for single-process production deployments where a
SQL service is overkill. For multi-process or HA topologies, use
`mcp-authkit-store-postgres` instead.

## Notes

- The store owns neither the `Database` handle nor its lifecycle: pass an
  already-constructed instance and close it yourself. `close()` is a no-op.
- All hash comparisons use `crypto.timingSafeEqual`. Hashes are stored as
  raw `BLOB`s.
- `tableNames` overrides are validated against `[A-Za-z0-9_]` because table
  names cannot be parameterized in SQL.
- `better-sqlite3` is a `peerDependency`; install it alongside this package.
