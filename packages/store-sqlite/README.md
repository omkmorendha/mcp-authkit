# mcp-authkit-store-sqlite

Durable SQLite `TokenStore` implementation for `mcp-authkit`.

Most users should import it through the core package:

```ts
import { sqliteTokenStore } from "mcp-authkit/stores/sqlite"
import Database from "better-sqlite3"

const db = new Database("/var/lib/authkit/authkit.db")
const store = sqliteTokenStore({ database: db })

await store.init() // applies migrations and enables WAL mode
```

The database handle belongs to the consumer; `store.close()` does **not**
close it.

Single-file durability, `journal_mode = WAL`, and `BEGIN IMMEDIATE` locking
make this suitable for single-process deployments. For multi-process
deployments, use the Postgres store instead.

See [`docs/spec/v0.2.md#64-sqlite-store`](../../docs/spec/v0.2.md#64-sqlite-store)
for the contract and
[`docs/cookbook/sqlite-store.md`](../../docs/cookbook/sqlite-store.md)
for the operator-facing recipe (WAL backups, file layout, what to test).
The end-to-end deployment walkthrough is
[`docs/production.md`](../../docs/production.md).
