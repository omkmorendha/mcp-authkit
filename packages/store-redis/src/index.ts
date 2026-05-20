/**
 * Redis cache decorator over a `TokenStore`.
 *
 * Spec: docs/spec/v0.2.md#65-redis-cache-decorator and §12 (Redis values
 * authenticated).
 *
 * Design notes
 * ------------
 * - This is a *decorator*, not a backing store. Every method delegates to
 *   the wrapped `inner` store, which is the source of truth.
 * - Cached reads: `findPatByHash`, `findRefreshToken`, `findUpstreamCredential`.
 *   On miss, we populate Redis with a positive entry after `inner` returns.
 * - Writes invalidate cache entries synchronously AFTER the underlying
 *   write resolves. We never write-through on creates — the next read
 *   populates.
 * - Cache values are MessagePack-encoded and HMAC-tagged (see `codec.ts`).
 *   A wrong tag is treated as a miss and logged at `warn`.
 * - Negative caching is OFF by default (a soft-DoS vector — see spec §6.5).
 *   Opt in via `negativeCacheTtlSeconds`; capped at 5 s.
 * - Reverse indices: PAT/refresh entries are keyed by a hash of `tokenHash`.
 *   To invalidate on id-keyed writes (`revokePat`, `rotateRefreshToken`)
 *   we maintain `pat:id:<id> -> hash-key` and a Redis Set
 *   `refresh:family:<familyId>` of hash keys.
 */

import { createHash, randomBytes } from "node:crypto"
import type { RedisClient } from "./client.js"
import { decode, encode } from "./codec.js"
import type {
  CacheUpstreamCredentialInput,
  CreatePatInput,
  CreateRefreshTokenInput,
  StoredPat,
  StoredRefreshToken,
  TokenStore,
  UpstreamCredentialEntry,
} from "./types.js"

export type { RedisClient } from "./client.js"
export type {
  CacheUpstreamCredentialInput,
  CreatePatInput,
  CreateRefreshTokenInput,
  StoredPat,
  StoredPatPublic,
  StoredRefreshToken,
  TokenStore,
  UpstreamCredentialEntry,
} from "./types.js"

/**
 * Pino-compatible subset. We only need `warn`; `info` is optional and used
 * once at construction when an option is clamped.
 */
export interface RedisCacheLogger {
  warn: (obj: object, msg?: string) => void
  info?: (obj: object, msg?: string) => void
}

export interface RedisCacheOptions {
  client: RedisClient
  /** Positive-cache TTL in seconds. Default 60. Must be > 0. */
  ttlSeconds?: number
  /** Key namespace. Default `"mcp:authkit:"`. */
  keyPrefix?: string
  /**
   * Negative-cache TTL in seconds. Default undefined (negative caching OFF).
   * Values > 5 are clamped to 5 with a warn log (spec §6.5).
   */
  negativeCacheTtlSeconds?: number
  /**
   * 32-byte HMAC key. If omitted, a fresh `randomBytes(32)` is generated at
   * construction — values written by a previous process therefore cannot be
   * authenticated and are dropped as misses, which is the spec-intended
   * "startup-derived key" behavior.
   */
  hmacKey?: Buffer
  /** Optional logger. Defaults to a no-op. */
  logger?: RedisCacheLogger
}

const DEFAULT_PREFIX = "mcp:authkit:"
const DEFAULT_TTL_SECONDS = 60
const MAX_NEGATIVE_TTL_SECONDS = 5
// Sentinel for negative-cache entries. A bare empty MessagePack map keeps the
// wire payload small; we encode it under the same HMAC key so a wrong tag
// still falls through.
const NEGATIVE_SENTINEL = { __null: true } as const

function noopLogger(): RedisCacheLogger {
  return { warn: () => {} }
}

/**
 * Hash a `Buffer` into a hex string of fixed length. Used purely as a
 * cache-key derivation — never for security boundaries (those go through
 * `crypto.timingSafeEqual` inside the underlying store).
 */
function hashKey(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex")
}

export function redisCache(inner: TokenStore, options: RedisCacheOptions): TokenStore {
  const { client } = options
  const ttlSeconds = options.ttlSeconds ?? DEFAULT_TTL_SECONDS
  if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) {
    throw new Error(`redisCache: ttlSeconds must be a positive number, got ${ttlSeconds}`)
  }
  const ttl = Math.floor(ttlSeconds)

  const prefix = options.keyPrefix ?? DEFAULT_PREFIX
  const logger = options.logger ?? noopLogger()

  let negativeTtl: number | null = null
  if (options.negativeCacheTtlSeconds !== undefined) {
    const raw = options.negativeCacheTtlSeconds
    if (!Number.isFinite(raw) || raw <= 0) {
      throw new Error(`redisCache: negativeCacheTtlSeconds must be a positive number, got ${raw}`)
    }
    if (raw > MAX_NEGATIVE_TTL_SECONDS) {
      logger.warn(
        { requested: raw, capped: MAX_NEGATIVE_TTL_SECONDS },
        "redisCache: negativeCacheTtlSeconds clamped",
      )
      negativeTtl = MAX_NEGATIVE_TTL_SECONDS
    } else {
      negativeTtl = Math.floor(raw)
    }
  }

  // Startup-derived HMAC key — spec §12. Caller may pin it (multi-process
  // deployments that genuinely want cross-replica cache hits); default is
  // per-process so a fresh boot invalidates older blobs by tag mismatch.
  const hmacKey = options.hmacKey ?? randomBytes(32)
  if (hmacKey.length < 16) {
    throw new Error("redisCache: hmacKey must be at least 16 bytes")
  }

  // ---------------------------------------------------------------------------
  // Key builders
  // ---------------------------------------------------------------------------

  const patHashKey = (hash: Buffer) => `${prefix}pat:hash:${hashKey(hash)}`
  const patIdKey = (id: string) => `${prefix}pat:id:${id}`
  const refreshHashKey = (hash: Buffer) => `${prefix}refresh:hash:${hashKey(hash)}`
  const refreshFamilyKey = (familyId: string) => `${prefix}refresh:family:${familyId}`
  const upstreamKey = (cacheKey: string) => `${prefix}upstream:${cacheKey}`

  // ---------------------------------------------------------------------------
  // Redis helpers
  // ---------------------------------------------------------------------------

  async function readBlob(key: string): Promise<Buffer | null> {
    const raw = await client.get(key)
    if (raw === null) return null
    return typeof raw === "string" ? Buffer.from(raw, "binary") : raw
  }

  /** Decode and authenticate a cached blob. Wrong-tag values fall through as `null`. */
  function safeDecode(key: string, blob: Buffer): unknown | null {
    const decoded = decode(hmacKey, blob)
    if (decoded === null) {
      logger.warn({ key }, "redisCache: HMAC tag mismatch on cached value; treating as miss")
      return null
    }
    return decoded
  }

  async function setPositive(key: string, value: unknown): Promise<void> {
    await client.set(key, encode(hmacKey, value), "EX", ttl)
  }

  async function setNegative(key: string): Promise<void> {
    if (negativeTtl === null) return
    await client.set(key, encode(hmacKey, NEGATIVE_SENTINEL), "EX", negativeTtl)
  }

  function isNegativeSentinel(decoded: unknown): boolean {
    return (
      typeof decoded === "object" &&
      decoded !== null &&
      (decoded as { __null?: unknown }).__null === true
    )
  }

  // Rehydrate Buffer-shaped fields. MessagePack returns Uint8Array for the
  // `bin` type; callers expect `Buffer`. Cheap allocation, same backing memory.
  function toBuffer(u: unknown): Buffer {
    if (Buffer.isBuffer(u)) return u
    if (u instanceof Uint8Array) return Buffer.from(u.buffer, u.byteOffset, u.byteLength)
    throw new Error("redisCache: expected Uint8Array/Buffer in cached payload")
  }

  function reviveStoredPat(raw: unknown): StoredPat {
    const r = raw as StoredPat
    return {
      id: r.id,
      userIdentifier: r.userIdentifier,
      name: r.name,
      scopes: r.scopes,
      expiresAt: r.expiresAt,
      tokenHash: toBuffer(r.tokenHash),
      display: r.display,
      createdAt: r.createdAt,
      lastUsedAt: r.lastUsedAt,
      revokedAt: r.revokedAt,
    }
  }

  function reviveStoredRefreshToken(raw: unknown): StoredRefreshToken {
    const r = raw as StoredRefreshToken
    return {
      id: r.id,
      familyId: r.familyId,
      tokenHash: toBuffer(r.tokenHash),
      subject: r.subject,
      scopes: r.scopes,
      expiresAt: r.expiresAt,
      createdAt: r.createdAt,
      rotatedAt: r.rotatedAt,
    }
  }

  function reviveUpstreamCredential(raw: unknown): UpstreamCredentialEntry {
    const r = raw as UpstreamCredentialEntry
    return { token: r.token, expiresAt: r.expiresAt }
  }

  // ---------------------------------------------------------------------------
  // Read paths (cached)
  // ---------------------------------------------------------------------------

  async function findPatByHash(hash: Buffer): Promise<StoredPat | null> {
    const key = patHashKey(hash)
    const blob = await readBlob(key)
    if (blob !== null) {
      const decoded = safeDecode(key, blob)
      if (decoded !== null) {
        if (isNegativeSentinel(decoded)) return null
        return reviveStoredPat(decoded)
      }
    }
    const fresh = await inner.findPatByHash(hash)
    if (fresh === null) {
      await setNegative(key)
      return null
    }
    await setPositive(key, fresh)
    // Reverse index for id-keyed invalidation. TTL matches the positive
    // entry — a stale reverse pointer just produces an extra harmless DEL.
    await client.set(patIdKey(fresh.id), key, "EX", ttl)
    return fresh
  }

  async function findRefreshToken(hash: Buffer): Promise<StoredRefreshToken | null> {
    const key = refreshHashKey(hash)
    const blob = await readBlob(key)
    if (blob !== null) {
      const decoded = safeDecode(key, blob)
      if (decoded !== null) {
        if (isNegativeSentinel(decoded)) return null
        return reviveStoredRefreshToken(decoded)
      }
    }
    const fresh = await inner.findRefreshToken(hash)
    if (fresh === null) {
      await setNegative(key)
      return null
    }
    await setPositive(key, fresh)
    // Track the hash key under its family so revokeRefreshTokenFamily can
    // sweep cache entries without scanning. Best-effort EXPIRE keeps the set
    // bounded if no revoke happens within the TTL window.
    const famKey = refreshFamilyKey(fresh.familyId)
    await client.sadd(famKey, key)
    await client.expire(famKey, ttl)
    return fresh
  }

  async function findUpstreamCredential(cacheKey: string): Promise<UpstreamCredentialEntry | null> {
    if (!inner.findUpstreamCredential) return null
    const key = upstreamKey(cacheKey)
    const blob = await readBlob(key)
    if (blob !== null) {
      const decoded = safeDecode(key, blob)
      if (decoded !== null) {
        if (isNegativeSentinel(decoded)) return null
        const revived = reviveUpstreamCredential(decoded)
        if (revived.expiresAt.getTime() > Date.now()) return revived
        // Stale positive: drop it so the next miss re-populates.
        await client.del(key)
      }
    }
    const fresh = await inner.findUpstreamCredential(cacheKey)
    if (fresh === null) {
      await setNegative(key)
      return null
    }
    await setPositive(key, fresh)
    return fresh
  }

  // ---------------------------------------------------------------------------
  // Write paths (invalidate AFTER inner write)
  // ---------------------------------------------------------------------------

  async function createPat(input: CreatePatInput): Promise<StoredPat> {
    const result = await inner.createPat(input)
    // No write-through: drop any negative entry that may have cached "missing".
    await client.del(patHashKey(result.tokenHash))
    return result
  }

  async function revokePat(id: string, userIdentifier: string): Promise<void> {
    await inner.revokePat(id, userIdentifier)
    const rev = await client.get(patIdKey(id))
    const revStr = typeof rev === "string" ? rev : rev?.toString("utf8")
    if (revStr) {
      await client.del(revStr, patIdKey(id))
    } else {
      await client.del(patIdKey(id))
    }
  }

  async function rotatePat(
    id: string,
    userIdentifier: string,
    next: CreatePatInput,
  ): Promise<StoredPat> {
    const result = await inner.rotatePat(id, userIdentifier, next)
    const rev = await client.get(patIdKey(id))
    const revStr = typeof rev === "string" ? rev : rev?.toString("utf8")
    const keysToDrop = [patIdKey(id), patHashKey(next.tokenHash)]
    if (revStr) keysToDrop.push(revStr)
    await client.del(...keysToDrop)
    return result
  }

  async function rotateRefreshToken(oldHash: Buffer, next: CreateRefreshTokenInput): Promise<void> {
    await inner.rotateRefreshToken(oldHash, next)
    // The old hash is no longer valid; the new hash should not have a stale
    // (negative) entry hanging around.
    await client.del(refreshHashKey(oldHash), refreshHashKey(next.tokenHash))
  }

  async function revokeRefreshTokenFamily(familyId: string): Promise<void> {
    await inner.revokeRefreshTokenFamily(familyId)
    const famKey = refreshFamilyKey(familyId)
    const members = await client.smembers(famKey)
    if (members.length > 0) {
      await client.del(...members, famKey)
    } else {
      await client.del(famKey)
    }
  }

  async function cacheUpstreamCredential(input: CacheUpstreamCredentialInput): Promise<void> {
    if (!inner.cacheUpstreamCredential) {
      throw new Error("redisCache: inner store does not implement cacheUpstreamCredential")
    }
    await inner.cacheUpstreamCredential(input)
    // Drop the cache entry; the next read will populate from the source of
    // truth (which is the inner store's upstream-credential table).
    await client.del(upstreamKey(input.cacheKey))
  }

  // ---------------------------------------------------------------------------
  // Pass-through (no caching, no invalidation)
  // ---------------------------------------------------------------------------

  const result: TokenStore = {
    createPat,
    findPatByHash,
    listPatsByUser: (userIdentifier) => inner.listPatsByUser(userIdentifier),
    revokePat,
    rotatePat,
    updatePatLastUsed: (id, ts) => inner.updatePatLastUsed(id, ts),
    createRefreshToken: (input) => inner.createRefreshToken(input),
    findRefreshToken,
    rotateRefreshToken,
    revokeRefreshTokenFamily,
  }

  // Optional methods are present iff inner implements them. The decorator
  // does NOT manufacture upstream caching on a store that doesn't support it.
  if (inner.cacheUpstreamCredential) {
    result.cacheUpstreamCredential = cacheUpstreamCredential
  }
  if (inner.findUpstreamCredential) {
    result.findUpstreamCredential = findUpstreamCredential
  }
  if (inner.init) {
    result.init = () => inner.init!()
  }
  if (inner.close) {
    result.close = () => inner.close!()
  }

  return result
}
