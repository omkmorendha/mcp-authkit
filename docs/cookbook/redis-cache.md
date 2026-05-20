# Cookbook: Redis cache decorator

Read-mostly cache in front of a primary `TokenStore`. Use when you have
multiple replicas hitting the same Postgres and you want to shave PAT
lookup latency. Spec references:
[§6.5](../spec/v0.2.md#65-redis-cache-decorator),
[§12](../spec/v0.2.md#12-security-non-negotiables-additions) ("Redis
values authenticated").

`redisCache` is a **decorator**, not a primary store. The wrapped store
remains the source of truth.

## Imports

```ts
import { defineConfig } from "mcp-authkit/config"
import { postgresTokenStore } from "mcp-authkit/stores/postgres"
import { redisCache } from "mcp-authkit/stores/redis"
import Redis from "ioredis"
import { Pool } from "pg"
```

## Snippet

```ts
const pool = new Pool({ connectionString: process.env.DATABASE_URL })
const client = new Redis(process.env.REDIS_URL!)

const inner = postgresTokenStore({ pool })

export default defineConfig({
  resourceIndicator: process.env.RESOURCE_INDICATOR!,
  auth: {
    authorizationServer: {
      issuer: process.env.OAUTH_ISSUER!,
      jwksUri: process.env.OAUTH_JWKS_URI!,
    },
    tokenStore: redisCache(inner, {
      client,
      ttlSeconds: 60,                     // positive cache TTL; default 60
      keyPrefix: "mcp:authkit:",          // default; namespace per deployment
      // negativeCacheTtlSeconds: 5,      // default OFF — see "DoS surface"
      // hmacKey: process.env.REDIS_HMAC_KEY
      //   ? Buffer.from(process.env.REDIS_HMAC_KEY, "base64url")
      //   : undefined,
    }),
    pat: { enabled: true, prefix: "mcp_pat_" },
  },
  scopes: { vocabulary: {} },
  resolveUserScopes: async () => [],
})
```

The decorator caches read-mostly paths: `findPatByHash`,
`findRefreshToken`, `findUpstreamCredential`. Writes (`createPat`,
`revokePat`, `rotatePat`, `rotateRefreshToken`,
`revokeRefreshTokenFamily`, `cacheUpstreamCredential`) invalidate the
relevant keys synchronously after the underlying write succeeds.

## Env vars

| Var                  | Required | Notes                                                                   |
| -------------------- | -------- | ----------------------------------------------------------------------- |
| `REDIS_URL`          | yes      | `redis://host:6379/0` or `rediss://...` for TLS                         |
| `REDIS_HMAC_KEY`     | no       | Base64url 32-byte key. Pin to enable cross-replica cache hits.          |
| Plus all vars from   | —        | [postgres-store](postgres-store.md) (or whichever primary store)        |

## HMAC keying (security-critical)

Cache values are MessagePack-encoded and **HMAC-tagged** so a Redis key
collision or tenancy bug cannot serve a different store's PAT as yours
(spec [§12](../spec/v0.2.md#12-security-non-negotiables-additions)).

Two modes:

- **Default (per-process key).** If `hmacKey` is omitted, the decorator
  generates a fresh `randomBytes(32)` at construction. Cache entries
  written by a previous process boot fail tag verification and are
  treated as misses — a clean restart invalidates the cache. Recommended
  for single-replica deployments.
- **Pinned key.** If you run multiple replicas and want shared cache
  hits, generate a 32-byte key once and inject it as `hmacKey`. All
  replicas must use the same key. Rotate by deploying with a new key
  and accepting one cold-cache restart.

```bash
# Generate a key:
pnpm exec mcp-authkit gen-secret 32
```

## DoS surface: negative caching is OFF

A "negative" entry caches the fact that a PAT hash **does not** exist.
Without rate-limiting in front of `/mcp`, that is a soft DoS vector — an
attacker can ask for arbitrarily many non-existent tokens and fill
Redis. Default is `negativeCacheTtlSeconds: undefined` (off). If you
enable it, values are clamped to 5 seconds (spec
[§6.5](../spec/v0.2.md#65-redis-cache-decorator)).

## What to test

- **Cache hit on hot PAT.** Call `/mcp` with the same PAT twice in
  quick succession. The second call should not touch Postgres
  (verify with `pg_stat_statements` or query logs).
- **Invalidation on revoke.** Mint a PAT, call `/mcp` (populates
  cache), `DELETE /pats/<id>`, call `/mcp` again — must be 401.
- **HMAC tag rejection.** Write a malformed value into Redis under one
  of the cache keys; the decorator must log a `warn` and treat the
  next read as a miss.
- **Fresh boot invalidates cache.** With no pinned `hmacKey`, restart
  the process and confirm cached entries from the previous boot are
  not honoured.
- **Negative cache is bounded.** If you opt in to negative caching,
  pass `negativeCacheTtlSeconds: 60` and confirm the decorator logs
  the clamp to 5 and the entry expires in ≤5 s.

## Common mistakes

- **Using `redisCache` as a primary store.** It refuses — the
  constructor requires an `inner` store. Use Postgres or SQLite as the
  source of truth.
- **Sharing the HMAC key across environments.** Per-environment keys
  give you a clean rotation story and prevent staging cache hits from
  appearing in production. Generate one per deployment.
- **Forgetting to namespace `keyPrefix`.** Two deployments sharing one
  Redis with the same prefix WILL collide on `mcp:authkit:pat:hash:...`.
  Use `keyPrefix: "mcp:authkit:prod:"` and `mcp:authkit:staging:"`.
- **Long positive TTLs.** A revoke invalidates synchronously, but
  network partitions can let stale entries live for the TTL window.
  Default of 60 s is a deliberate trade-off; raise only if you have
  strong revocation-latency guarantees from your network.
