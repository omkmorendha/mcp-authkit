# mcp-authkit-store-redis

Redis cache decorator for an underlying `TokenStore`.

Most users should import it through the core package:

```ts
import { redisCache } from "mcp-authkit/stores/redis"
import { postgresTokenStore } from "mcp-authkit/stores/postgres"
import Redis from "ioredis"

const inner = postgresTokenStore({ pool })
const store = redisCache(inner, { client: new Redis() })
```

`redisCache` is a decorator, not a primary store. The wrapped store remains
the source of truth; Redis caches read-mostly paths (`findPatByHash`,
`findRefreshToken`, `findUpstreamCredential`). Writes invalidate the relevant
cache entries synchronously after the underlying write succeeds.

## Security

- Cache values are MessagePack-encoded `Buffer`s tagged with an HMAC-SHA256
  signature computed against a per-process random key. A wrong tag is treated
  as a cache miss and emits a `warn`-level log — a Redis tenancy bug or key
  collision cannot serve another deployment's stored row as your own.
- Negative caching (caching a `null` lookup) is OFF by default; opt in with
  `negativeCacheTtlSeconds`. The framework caps the value at 5 seconds to
  bound the DoS window for unknown-token lookups.
- Keys are namespaced under `keyPrefix` (default `mcp:authkit:`).

See [`docs/spec/v0.2.md#65-redis-cache-decorator`](../../docs/spec/v0.2.md#65-redis-cache-decorator).
