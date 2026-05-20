# mcp-authkit-store-redis

Redis cache **decorator** for `mcp-authkit`. Wraps an existing `TokenStore`
and caches read-mostly paths in Redis. Not a primary store — the underlying
store remains the source of truth.

```ts
import { postgresTokenStore } from "mcp-authkit/stores/postgres"
import { redisCache } from "mcp-authkit/stores/redis"
import { Pool } from "pg"
import { Redis } from "ioredis"

const store = redisCache(
  postgresTokenStore({ pool: new Pool({ connectionString: process.env.DATABASE_URL }) }),
  { client: new Redis(process.env.REDIS_URL!), ttlSeconds: 60 },
)
```

Cached methods: `findPatByHash`, `findRefreshToken`, `findUpstreamCredential`.

Writes (`createPat`, `revokePat`, `rotatePat`, `rotateRefreshToken`,
`revokeRefreshTokenFamily`, `cacheUpstreamCredential`) invalidate the
relevant Redis entries synchronously after the underlying write succeeds.

Cache values are MessagePack-encoded and HMAC-tagged with a startup-derived
key. A wrong tag is treated as a miss and logs at `warn`.

Negative caching is OFF by default. Opt in via `negativeCacheTtlSeconds`
(capped at 5 s).

See [`docs/spec/v0.2.md#65-redis-cache-decorator`](../../docs/spec/v0.2.md#65-redis-cache-decorator).
