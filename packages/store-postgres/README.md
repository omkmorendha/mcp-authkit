# mcp-authkit-store-postgres

Durable Postgres `TokenStore` implementation for `mcp-authkit`.

Most users should import it through the core package:

```ts
import { postgresTokenStore } from "mcp-authkit/stores/postgres"
import { Pool } from "pg"

const store = postgresTokenStore({
  pool: new Pool({ connectionString: process.env.DATABASE_URL }),
})

await store.init() // runs migrations idempotently
```

The pool belongs to the consumer; `store.close()` does **not** close it.

See [`docs/spec/v0.2.md#63-postgres-store`](../../docs/spec/v0.2.md#63-postgres-store).
