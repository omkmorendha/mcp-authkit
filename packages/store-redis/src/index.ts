/**
 * Redis cache decorator for an underlying {@link TokenStore}.
 *
 * Spec anchors:
 *   - docs/spec/v0.2.md#65-redis-cache-decorator
 *   - docs/spec/v0.2.md#12-security-non-negotiables-additions (Redis values authenticated)
 *
 * Design:
 *   - Decorator pattern: every method delegates to `inner`. The three
 *     read-mostly paths (`findPatByHash`, `findRefreshToken`,
 *     `findUpstreamCredential`) check Redis first.
 *   - Cache values are MessagePack-encoded payloads, prefixed with an
 *     HMAC-SHA256 tag computed with a per-process random key. A wrong tag
 *     on read is treated as a miss and logged at `warn` — the cache value
 *     is then treated as if it did not exist, and the underlying store is
 *     consulted. This defends against Redis tenancy bugs and key collisions
 *     across deployments (spec §12).
 *   - Writes invalidate the relevant cache entries synchronously AFTER the
 *     underlying write succeeds. Invalidation failures are logged but do
 *     not propagate — stale cache is bounded by TTL.
 *   - Negative caching is OFF by default. Opt-in via
 *     `negativeCacheTtlSeconds`, hard-capped at 5 s (§6.5 — soft DoS vector).
 *
 * Workspace acyclicity:
 *   The contract types are duplicated here rather than imported from
 *   `mcp-authkit` because core re-exports this package; importing the
 *   other way would close a cycle. The structural-assignability assertion
 *   in `packages/core/src/stores/redis.ts` pins the shape to the spec.
 */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto"
import { decode, encode } from "@msgpack/msgpack"
import type { Redis } from "ioredis"
import type { Logger } from "pino"

// --- v0.1 §6.1 contract types (duplicated; see file header) -----------------

export interface CreatePatInput {
  userIdentifier: string
  name: string
  scopes: readonly string[]
  expiresAt: Date
  tokenHash: Buffer
  display: string
}

export interface StoredPat extends CreatePatInput {
  id: string
  createdAt: Date
  lastUsedAt: Date | null
  revokedAt: Date | null
}

export interface StoredPatPublic {
  id: string
  name: string
  scopes: readonly string[]
  display: string
  createdAt: Date
  expiresAt: Date
  lastUsedAt: Date | null
}

export interface CreateRefreshTokenInput {
  familyId: string
  tokenHash: Buffer
  subject: string
  scopes: readonly string[]
  expiresAt: Date
}

export interface StoredRefreshToken extends CreateRefreshTokenInput {
  id: string
  createdAt: Date
  rotatedAt: Date | null
}

export interface UpstreamCredential {
  token: string
  expiresAt: Date
}

export interface TokenStore {
  createPat(input: CreatePatInput): Promise<StoredPat>
  findPatByHash(hash: Buffer): Promise<StoredPat | null>
  listPatsByUser(userIdentifier: string): Promise<StoredPatPublic[]>
  revokePat(id: string, userIdentifier: string): Promise<void>
  rotatePat(id: string, userIdentifier: string, next: CreatePatInput): Promise<StoredPat>
  updatePatLastUsed(id: string, timestamp: Date): Promise<void>
  createRefreshToken(input: CreateRefreshTokenInput): Promise<void>
  findRefreshToken(hash: Buffer): Promise<StoredRefreshToken | null>
  rotateRefreshToken(oldHash: Buffer, next: CreateRefreshTokenInput): Promise<void>
  revokeRefreshTokenFamily(familyId: string): Promise<void>
  init?(): Promise<void>
  close?(): Promise<void>
  // v0.2 §6.2 optional upstream-credential cache methods. Forwarded by the
  // decorator only when the inner store implements them.
  cacheUpstreamCredential?(input: {
    cacheKey: string
    token: string
    expiresAt: Date
  }): Promise<void>
  findUpstreamCredential?(cacheKey: string): Promise<UpstreamCredential | null>
}

// --- Decorator options ------------------------------------------------------

export interface RedisCacheOptions {
  client: Redis
  /** TTL for positive cache entries, in seconds. Default 60. */
  ttlSeconds?: number
  /** Namespace prefix for every key. Default `mcp:authkit:`. */
  keyPrefix?: string
  /**
   * If set (and > 0), cache `null` lookups for this many seconds. Capped
   * at 5 — see §6.5 (negative caching of unknown PATs is a soft DoS vector).
   * Default: undefined (negative caching OFF).
   */
  negativeCacheTtlSeconds?: number
  /**
   * Optional HMAC key for value authentication. Defaults to a 32-byte random
   * value generated at decorator-construction time. Per-process by design:
   * the cache is per-process anyway, and a fresh key on each process restart
   * invalidates any stale entries left by a previous process.
   */
  hmacKey?: Buffer
  /** Optional pino logger. A silent logger is used if absent. */
  logger?: Logger
}

// --- Internal constants -----------------------------------------------------

const DEFAULT_PREFIX = "mcp:authkit:"
const DEFAULT_TTL_SECONDS = 60
const NEGATIVE_CACHE_MAX_SECONDS = 5
const HMAC_TAG_LENGTH = 32 // SHA-256
const NEGATIVE_MARKER = 0x00
const POSITIVE_MARKER = 0x01

type Tag = "pat" | "refresh" | "upstream" | "pat-id"

// --- Wire encoders ----------------------------------------------------------

interface WireEncoder<T> {
  toWire(value: T): unknown
  fromWire(wire: unknown): T
}

// Buffers and Dates are not first-class in MessagePack with the default
// codec — we normalize to plain shapes on the wire and rebuild Buffer/Date
// on read. Keeping the wire shape explicit also makes a deliberate
// cross-version compatibility break trivial (bump a marker byte).

const patEncoder: WireEncoder<StoredPat> = {
  toWire(p) {
    return {
      id: p.id,
      userIdentifier: p.userIdentifier,
      name: p.name,
      scopes: [...p.scopes],
      expiresAt: p.expiresAt.getTime(),
      tokenHash: bufferToWire(p.tokenHash),
      display: p.display,
      createdAt: p.createdAt.getTime(),
      lastUsedAt: p.lastUsedAt === null ? null : p.lastUsedAt.getTime(),
      revokedAt: p.revokedAt === null ? null : p.revokedAt.getTime(),
    }
  },
  fromWire(wire) {
    const w = wire as {
      id: string
      userIdentifier: string
      name: string
      scopes: string[]
      expiresAt: number
      tokenHash: Uint8Array
      display: string
      createdAt: number
      lastUsedAt: number | null
      revokedAt: number | null
    }
    return {
      id: w.id,
      userIdentifier: w.userIdentifier,
      name: w.name,
      scopes: w.scopes,
      expiresAt: new Date(w.expiresAt),
      tokenHash: wireToBuffer(w.tokenHash),
      display: w.display,
      createdAt: new Date(w.createdAt),
      lastUsedAt: w.lastUsedAt === null ? null : new Date(w.lastUsedAt),
      revokedAt: w.revokedAt === null ? null : new Date(w.revokedAt),
    }
  },
}

const refreshEncoder: WireEncoder<StoredRefreshToken> = {
  toWire(r) {
    return {
      id: r.id,
      familyId: r.familyId,
      tokenHash: bufferToWire(r.tokenHash),
      subject: r.subject,
      scopes: [...r.scopes],
      expiresAt: r.expiresAt.getTime(),
      createdAt: r.createdAt.getTime(),
      rotatedAt: r.rotatedAt === null ? null : r.rotatedAt.getTime(),
    }
  },
  fromWire(wire) {
    const w = wire as {
      id: string
      familyId: string
      tokenHash: Uint8Array
      subject: string
      scopes: string[]
      expiresAt: number
      createdAt: number
      rotatedAt: number | null
    }
    return {
      id: w.id,
      familyId: w.familyId,
      tokenHash: wireToBuffer(w.tokenHash),
      subject: w.subject,
      scopes: w.scopes,
      expiresAt: new Date(w.expiresAt),
      createdAt: new Date(w.createdAt),
      rotatedAt: w.rotatedAt === null ? null : new Date(w.rotatedAt),
    }
  },
}

const upstreamEncoder: WireEncoder<UpstreamCredential> = {
  toWire(c) {
    return { token: c.token, expiresAt: c.expiresAt.getTime() }
  },
  fromWire(wire) {
    const w = wire as { token: string; expiresAt: number }
    return { token: w.token, expiresAt: new Date(w.expiresAt) }
  },
}

// pat-id stores a token hash hex string — a simple secondary index used to
// invalidate the primary `pat:<hexHash>` entry from `revokePat`/`rotatePat`,
// where the caller only supplies the row id and the framework never holds
// the plaintext token.
const patIdEncoder: WireEncoder<string> = {
  toWire(s) {
    return s
  },
  fromWire(wire) {
    return String(wire)
  },
}

function bufferToWire(buf: Buffer): Uint8Array {
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
}

function wireToBuffer(u: Uint8Array): Buffer {
  return Buffer.from(u.buffer, u.byteOffset, u.byteLength)
}

function hexHash(hash: Buffer): string {
  return hash.toString("hex")
}

// Silent logger used when the caller does not supply one. Only `warn` is
// invoked by the decorator; the no-op shape is a minimal Logger shim.
const NOOP_LOGGER: Logger = {
  warn: () => {},
  info: () => {},
  error: () => {},
  debug: () => {},
  trace: () => {},
  fatal: () => {},
  child: () => NOOP_LOGGER,
} as unknown as Logger

// --- Public factory ---------------------------------------------------------

export function redisCache(inner: TokenStore, options: RedisCacheOptions): TokenStore {
  const client = options.client
  const ttlSeconds = options.ttlSeconds ?? DEFAULT_TTL_SECONDS
  const keyPrefix = options.keyPrefix ?? DEFAULT_PREFIX
  const rawNegTtl = options.negativeCacheTtlSeconds
  const negTtlSeconds =
    rawNegTtl === undefined || rawNegTtl <= 0 ? 0 : Math.min(rawNegTtl, NEGATIVE_CACHE_MAX_SECONDS)
  const hmacKey = options.hmacKey ?? randomBytes(32)
  const logger = options.logger ?? NOOP_LOGGER

  function key(tag: Tag, id: string): string {
    return `${keyPrefix}${tag}:${id}`
  }

  function sign(payload: Buffer): Buffer {
    return createHmac("sha256", hmacKey).update(payload).digest()
  }

  function encodePositive<T>(enc: WireEncoder<T>, value: T): Buffer {
    const payload = Buffer.from(encode(enc.toWire(value)))
    const tagged = Buffer.concat([Buffer.from([POSITIVE_MARKER]), payload])
    const tag = sign(tagged)
    return Buffer.concat([tag, tagged])
  }

  function encodeNegative(): Buffer {
    const body = Buffer.from([NEGATIVE_MARKER])
    const tag = sign(body)
    return Buffer.concat([tag, body])
  }

  /**
   * Returns:
   *   - `undefined` for a true cache miss or an authentication failure
   *     (caller falls through to `inner`).
   *   - `null` for a verified negative cache hit.
   *   - the decoded value for a verified positive hit.
   */
  function decodeCached<T>(
    raw: Buffer | null,
    enc: WireEncoder<T>,
    cacheKey: string,
  ): T | null | undefined {
    if (raw === null) return undefined
    if (raw.length < HMAC_TAG_LENGTH + 1) {
      logger.warn(
        { cacheKey, length: raw.length },
        "redisCache: cached value shorter than HMAC tag — treating as miss",
      )
      return undefined
    }
    const tag = raw.subarray(0, HMAC_TAG_LENGTH)
    const body = raw.subarray(HMAC_TAG_LENGTH)
    const expected = sign(body)
    if (tag.length !== expected.length || !timingSafeEqual(tag, expected)) {
      logger.warn({ cacheKey }, "redisCache: HMAC tag mismatch on cached value — treating as miss")
      return undefined
    }
    const marker = body[0]
    if (marker === NEGATIVE_MARKER) return null
    if (marker !== POSITIVE_MARKER) {
      logger.warn({ cacheKey, marker }, "redisCache: unknown marker byte — treating as miss")
      return undefined
    }
    try {
      return enc.fromWire(decode(body.subarray(1)))
    } catch (err) {
      logger.warn(
        { cacheKey, err: err instanceof Error ? err.message : String(err) },
        "redisCache: MessagePack decode failed — treating as miss",
      )
      return undefined
    }
  }

  async function readCache<T>(
    tag: Tag,
    id: string,
    enc: WireEncoder<T>,
  ): Promise<T | null | undefined> {
    const cacheKey = key(tag, id)
    let raw: Buffer | null
    try {
      raw = await client.getBuffer(cacheKey)
    } catch (err) {
      logger.warn(
        { cacheKey, err: err instanceof Error ? err.message : String(err) },
        "redisCache: GET failed — treating as miss",
      )
      return undefined
    }
    return decodeCached(raw, enc, cacheKey)
  }

  async function writePositive<T>(
    tag: Tag,
    id: string,
    enc: WireEncoder<T>,
    value: T,
  ): Promise<void> {
    if (ttlSeconds <= 0) return
    const cacheKey = key(tag, id)
    try {
      await client.set(cacheKey, encodePositive(enc, value), "EX", ttlSeconds)
    } catch (err) {
      logger.warn(
        { cacheKey, err: err instanceof Error ? err.message : String(err) },
        "redisCache: SET failed — continuing without cache fill",
      )
    }
  }

  async function writeNegative(tag: Tag, id: string): Promise<void> {
    if (negTtlSeconds <= 0) return
    const cacheKey = key(tag, id)
    try {
      await client.set(cacheKey, encodeNegative(), "EX", negTtlSeconds)
    } catch (err) {
      logger.warn(
        { cacheKey, err: err instanceof Error ? err.message : String(err) },
        "redisCache: SET (negative) failed — continuing without cache fill",
      )
    }
  }

  async function invalidate(tag: Tag, id: string): Promise<void> {
    const cacheKey = key(tag, id)
    try {
      await client.del(cacheKey)
    } catch (err) {
      logger.warn(
        { cacheKey, err: err instanceof Error ? err.message : String(err) },
        "redisCache: DEL failed during invalidation — entry will expire via TTL",
      )
    }
  }

  // `revokePat` and `rotatePat` receive only the PAT id; the framework never
  // holds plaintext, so we cannot recompute the hash to invalidate the
  // primary `pat:<hexHash>` entry. The decorator maintains a secondary
  // `pat-id:<id>` index from id → hex hash, written on cache fill, read on
  // invalidation.
  async function readPatIdMapping(patId: string): Promise<string | null> {
    const mapping = await readCache("pat-id", patId, patIdEncoder)
    if (mapping === undefined) return null
    return mapping
  }

  async function writePatIdMapping(patId: string, tokenHashHex: string): Promise<void> {
    await writePositive("pat-id", patId, patIdEncoder, tokenHashHex)
  }

  // --- Wrapped methods ------------------------------------------------------

  const wrapped: TokenStore = {
    async createPat(input) {
      const stored = await inner.createPat(input)
      const hh = hexHash(stored.tokenHash)
      await writePositive("pat", hh, patEncoder, stored)
      await writePatIdMapping(stored.id, hh)
      return stored
    },

    async findPatByHash(hash) {
      const id = hexHash(hash)
      const cached = await readCache("pat", id, patEncoder)
      if (cached !== undefined) return cached
      const fresh = await inner.findPatByHash(hash)
      if (fresh === null) {
        await writeNegative("pat", id)
      } else {
        await writePositive("pat", id, patEncoder, fresh)
        await writePatIdMapping(fresh.id, id)
      }
      return fresh
    },

    async listPatsByUser(userIdentifier) {
      return inner.listPatsByUser(userIdentifier)
    },

    async revokePat(id, userIdentifier) {
      const mapping = await readPatIdMapping(id)
      await inner.revokePat(id, userIdentifier)
      if (mapping !== null) {
        await invalidate("pat", mapping)
        await invalidate("pat-id", id)
      }
    },

    async rotatePat(id, userIdentifier, next) {
      const previousMapping = await readPatIdMapping(id)
      const stored = await inner.rotatePat(id, userIdentifier, next)
      // Invalidate the predecessor's primary cache entry. The successor is
      // a fresh row; warm its cache.
      if (previousMapping !== null) {
        await invalidate("pat", previousMapping)
        await invalidate("pat-id", id)
      }
      const newHh = hexHash(stored.tokenHash)
      await writePositive("pat", newHh, patEncoder, stored)
      await writePatIdMapping(stored.id, newHh)
      return stored
    },

    async updatePatLastUsed(id, timestamp) {
      // lastUsedAt is observational only and does not affect authorization
      // decisions; the cached row's older lastUsedAt is tolerable until
      // the TTL refreshes it. The id→hash index lets us still narrow the
      // invalidation if the operator wants strict freshness in a future
      // option, but the default behavior leaves the cache untouched.
      await inner.updatePatLastUsed(id, timestamp)
    },

    async createRefreshToken(input) {
      await inner.createRefreshToken(input)
      const fresh = await inner.findRefreshToken(input.tokenHash)
      if (fresh !== null) {
        await writePositive("refresh", hexHash(input.tokenHash), refreshEncoder, fresh)
      }
    },

    async findRefreshToken(hash) {
      const id = hexHash(hash)
      const cached = await readCache("refresh", id, refreshEncoder)
      if (cached !== undefined) return cached
      const fresh = await inner.findRefreshToken(hash)
      if (fresh === null) {
        await writeNegative("refresh", id)
      } else {
        await writePositive("refresh", id, refreshEncoder, fresh)
      }
      return fresh
    },

    async rotateRefreshToken(oldHash, next) {
      await inner.rotateRefreshToken(oldHash, next)
      await invalidate("refresh", hexHash(oldHash))
      const fresh = await inner.findRefreshToken(next.tokenHash)
      if (fresh !== null) {
        await writePositive("refresh", hexHash(next.tokenHash), refreshEncoder, fresh)
      }
    },

    async revokeRefreshTokenFamily(familyId) {
      // The inner store deletes every member of the family. The cache is
      // keyed by token hash, not family id; without a family→hash index
      // we cannot enumerate the affected entries. Family revocation is
      // rare (reuse detection), so a SCAN-based flush of the refresh
      // namespace is acceptable — correctness over micro-optimization.
      await inner.revokeRefreshTokenFamily(familyId)
      await scanAndDelete(client, `${keyPrefix}refresh:*`, logger)
    },
  }

  if (inner.init) wrapped.init = inner.init.bind(inner)
  if (inner.close) wrapped.close = inner.close.bind(inner)

  // --- Optional v0.2 §6.2 upstream-credential cache methods ----------------

  if (typeof inner.findUpstreamCredential === "function") {
    const find = inner.findUpstreamCredential.bind(inner)
    wrapped.findUpstreamCredential = async (cacheKey) => {
      const cached = await readCache("upstream", cacheKey, upstreamEncoder)
      if (cached !== undefined) return cached
      const fresh = await find(cacheKey)
      if (fresh === null) {
        await writeNegative("upstream", cacheKey)
      } else {
        await writePositive("upstream", cacheKey, upstreamEncoder, fresh)
      }
      return fresh
    }
  }
  if (typeof inner.cacheUpstreamCredential === "function") {
    const cache = inner.cacheUpstreamCredential.bind(inner)
    wrapped.cacheUpstreamCredential = async (input) => {
      await cache(input)
      await writePositive("upstream", input.cacheKey, upstreamEncoder, {
        token: input.token,
        expiresAt: input.expiresAt,
      })
    }
  }

  return wrapped
}

// Iterate keys matching a pattern under the cache's prefix and delete them.
// SCAN avoids the O(N) blocking that KEYS would impose on the server.
async function scanAndDelete(client: Redis, pattern: string, logger: Logger): Promise<void> {
  let cursor = "0"
  try {
    do {
      const result = await client.scan(cursor, "MATCH", pattern, "COUNT", 100)
      cursor = result[0]
      const keys = result[1]
      if (keys.length > 0) await client.del(...keys)
    } while (cursor !== "0")
  } catch (err) {
    logger.warn(
      { pattern, err: err instanceof Error ? err.message : String(err) },
      "redisCache: SCAN/DEL failed — entries will expire via TTL",
    )
  }
}
