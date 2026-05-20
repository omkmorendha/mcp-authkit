import { createHash, randomBytes } from "node:crypto"
import { memoryTokenStore } from "mcp-authkit-store-memory"
import { beforeEach, describe, expect, it, vi } from "vitest"
import { encode } from "./codec.js"
import { FakeRedis } from "./fake-redis.js"
import { type RedisCacheOptions, redisCache } from "./index.js"
import type {
  CreatePatInput,
  CreateRefreshTokenInput,
  TokenStore,
  UpstreamCredentialEntry,
} from "./types.js"

function sha256(buf: Buffer): Buffer {
  return createHash("sha256").update(buf).digest()
}

function patInput(overrides: Partial<CreatePatInput> = {}): CreatePatInput {
  const tokenHash = overrides.tokenHash ?? sha256(randomBytes(32))
  return {
    userIdentifier: "user-1",
    name: "test pat",
    scopes: ["read"],
    expiresAt: new Date(Date.now() + 60_000),
    tokenHash,
    display: "mcp_pat_abc...xyz",
    ...overrides,
  }
}

function refreshInput(overrides: Partial<CreateRefreshTokenInput> = {}): CreateRefreshTokenInput {
  const tokenHash = overrides.tokenHash ?? sha256(randomBytes(32))
  return {
    familyId: "fam-1",
    tokenHash,
    subject: "user-1",
    scopes: ["read"],
    expiresAt: new Date(Date.now() + 60_000),
    ...overrides,
  }
}

interface Logger {
  warn: ReturnType<typeof vi.fn>
  info: ReturnType<typeof vi.fn>
}

/**
 * Wrap a memoryTokenStore with a real upstream-credential cache backed by a
 * plain `Map`. `memoryTokenStore` deliberately doesn't implement the upstream
 * methods (they're v0.2 optionals); we add them here just for tests that need
 * to exercise the decorator's upstream code path.
 */
function withUpstream(inner: TokenStore): TokenStore {
  const cache = new Map<string, { token: string; expiresAt: Date }>()
  inner.cacheUpstreamCredential = async ({ cacheKey, token, expiresAt }) => {
    cache.set(cacheKey, { token, expiresAt })
  }
  inner.findUpstreamCredential = async (cacheKey: string) => {
    const e = cache.get(cacheKey)
    if (!e) return null
    if (e.expiresAt.getTime() <= Date.now()) return null
    return e
  }
  return inner
}

function setup(extra: Partial<RedisCacheOptions> = {}): {
  client: FakeRedis
  inner: TokenStore
  innerSpies: {
    findPatByHash: ReturnType<typeof vi.spyOn>
    findRefreshToken: ReturnType<typeof vi.spyOn>
  }
  cache: TokenStore
  logger: Logger
  hmacKey: Buffer
} {
  const client = new FakeRedis()
  const inner = memoryTokenStore() as TokenStore
  const innerSpies = {
    findPatByHash: vi.spyOn(inner, "findPatByHash"),
    findRefreshToken: vi.spyOn(inner, "findRefreshToken"),
  }
  const logger: Logger = { warn: vi.fn(), info: vi.fn() }
  const hmacKey = randomBytes(32)
  const cache = redisCache(inner, { client, hmacKey, logger, ...extra })
  return { client, inner, innerSpies, cache, logger, hmacKey }
}

describe("redisCache", () => {
  describe("findPatByHash", () => {
    it("populates cache on miss; second call is served without invoking inner", async () => {
      const { cache, inner, innerSpies } = setup()
      const input = patInput()
      await inner.createPat(input)

      const first = await cache.findPatByHash(input.tokenHash)
      expect(first).not.toBeNull()
      expect(innerSpies.findPatByHash).toHaveBeenCalledTimes(1)

      const second = await cache.findPatByHash(input.tokenHash)
      expect(second).not.toBeNull()
      expect(innerSpies.findPatByHash).toHaveBeenCalledTimes(1)
      expect(Buffer.from(second!.tokenHash).equals(input.tokenHash)).toBe(true)
      expect(second!.expiresAt).toBeInstanceOf(Date)
    })

    it("does NOT negative-cache by default", async () => {
      const { cache, innerSpies } = setup()
      const hash = sha256(randomBytes(32))

      const a = await cache.findPatByHash(hash)
      const b = await cache.findPatByHash(hash)
      expect(a).toBeNull()
      expect(b).toBeNull()
      expect(innerSpies.findPatByHash).toHaveBeenCalledTimes(2)
    })

    it("negative-caches when negativeCacheTtlSeconds is opt-in", async () => {
      const { cache, innerSpies } = setup({ negativeCacheTtlSeconds: 2 })
      const hash = sha256(randomBytes(32))

      const a = await cache.findPatByHash(hash)
      const b = await cache.findPatByHash(hash)
      expect(a).toBeNull()
      expect(b).toBeNull()
      expect(innerSpies.findPatByHash).toHaveBeenCalledTimes(1)
    })

    it("clamps negativeCacheTtlSeconds to 5 and logs a warning", async () => {
      const { logger } = setup({ negativeCacheTtlSeconds: 60 })
      expect(logger.warn).toHaveBeenCalledWith(
        expect.objectContaining({ requested: 60, capped: 5 }),
        expect.stringContaining("clamped"),
      )
    })

    it("treats an HMAC tag mismatch as a miss and logs at warn", async () => {
      const { client, cache, inner, innerSpies, logger } = setup()
      const input = patInput()
      const pat = await inner.createPat(input)

      // Write a value signed with a DIFFERENT key under the cache key.
      const otherKey = randomBytes(32)
      const bogus = encode(otherKey, pat)
      const key = `mcp:authkit:pat:hash:${sha256(input.tokenHash).toString("hex")}`
      client.rawSet(key, bogus, 60)

      const result = await cache.findPatByHash(input.tokenHash)
      expect(result).not.toBeNull()
      expect(innerSpies.findPatByHash).toHaveBeenCalledTimes(1)
      expect(logger.warn).toHaveBeenCalledWith(
        expect.objectContaining({ key }),
        expect.stringContaining("HMAC tag mismatch"),
      )
    })
  })

  describe("findRefreshToken", () => {
    it("populates cache on miss; hit avoids inner", async () => {
      const { cache, inner, innerSpies } = setup()
      const input = refreshInput()
      await inner.createRefreshToken(input)

      const a = await cache.findRefreshToken(input.tokenHash)
      expect(a).not.toBeNull()
      const b = await cache.findRefreshToken(input.tokenHash)
      expect(b).not.toBeNull()
      expect(innerSpies.findRefreshToken).toHaveBeenCalledTimes(1)
    })
  })

  describe("findUpstreamCredential", () => {
    it("populates and serves from cache; expired entries fall through", async () => {
      const client = new FakeRedis()
      const inner = withUpstream(memoryTokenStore() as TokenStore)
      const cache = redisCache(inner, { client })

      const entry: UpstreamCredentialEntry = {
        token: "abc",
        expiresAt: new Date(Date.now() + 60_000),
      }
      await inner.cacheUpstreamCredential?.({
        cacheKey: "k1",
        token: entry.token,
        expiresAt: entry.expiresAt,
      })
      const findSpy = vi.spyOn(inner, "findUpstreamCredential" as never)

      const first = await cache.findUpstreamCredential?.("k1")
      expect(first?.token).toBe("abc")
      expect(findSpy).toHaveBeenCalledTimes(1)

      const second = await cache.findUpstreamCredential?.("k1")
      expect(second?.token).toBe("abc")
      expect(findSpy).toHaveBeenCalledTimes(1)

      // k2 has an explicitly-expired upstream entry; inner returns null and
      // (with default negative caching off) the cache stays empty.
      await inner.cacheUpstreamCredential?.({
        cacheKey: "k2",
        token: "old",
        expiresAt: new Date(Date.now() - 1000),
      })
      const stale = await cache.findUpstreamCredential?.("k2")
      expect(stale).toBeNull()
      expect(client.has("mcp:authkit:upstream:k2")).toBe(false)
    })

    it("omits findUpstreamCredential when the inner store does not implement it", () => {
      const client = new FakeRedis()
      const inner = memoryTokenStore() as TokenStore
      // memoryTokenStore doesn't define the optional methods — confirm the
      // decorator faithfully omits them too.
      expect(inner.findUpstreamCredential).toBeUndefined()
      const cache = redisCache(inner, { client })
      expect(cache.findUpstreamCredential).toBeUndefined()
      expect(cache.cacheUpstreamCredential).toBeUndefined()
    })
  })

  describe("write invalidation", () => {
    it("revokePat invalidates the hash cache entry", async () => {
      const { client, cache, inner, innerSpies } = setup()
      const input = patInput()
      const pat = await inner.createPat(input)

      // Populate cache.
      await cache.findPatByHash(input.tokenHash)
      const cacheKey = `mcp:authkit:pat:hash:${sha256(input.tokenHash).toString("hex")}`
      expect(client.has(cacheKey)).toBe(true)

      await cache.revokePat(pat.id, pat.userIdentifier)
      expect(client.has(cacheKey)).toBe(false)
      expect(client.has(`mcp:authkit:pat:id:${pat.id}`)).toBe(false)

      // Next read goes to inner and now returns null (revoked).
      const after = await cache.findPatByHash(input.tokenHash)
      expect(after).toBeNull()
      expect(innerSpies.findPatByHash).toHaveBeenCalledTimes(2)
    })

    it("rotatePat invalidates predecessor cache entry", async () => {
      const { client, cache, inner } = setup()
      const oldInput = patInput()
      const pat = await inner.createPat(oldInput)
      await cache.findPatByHash(oldInput.tokenHash)
      const oldKey = `mcp:authkit:pat:hash:${sha256(oldInput.tokenHash).toString("hex")}`
      expect(client.has(oldKey)).toBe(true)

      const nextInput = patInput({ userIdentifier: pat.userIdentifier })
      await cache.rotatePat(pat.id, pat.userIdentifier, nextInput)
      expect(client.has(oldKey)).toBe(false)
    })

    it("rotateRefreshToken invalidates predecessor and any negative entry for successor", async () => {
      const { client, cache, inner } = setup({ negativeCacheTtlSeconds: 5 })
      const oldInput = refreshInput()
      await inner.createRefreshToken(oldInput)
      await cache.findRefreshToken(oldInput.tokenHash)
      const oldKey = `mcp:authkit:refresh:hash:${sha256(oldInput.tokenHash).toString("hex")}`
      expect(client.has(oldKey)).toBe(true)

      const nextInput = refreshInput({ familyId: oldInput.familyId })
      // Seed a negative entry for the successor hash.
      await cache.findRefreshToken(nextInput.tokenHash)
      const newKey = `mcp:authkit:refresh:hash:${sha256(nextInput.tokenHash).toString("hex")}`
      expect(client.has(newKey)).toBe(true) // negative-cached null

      await cache.rotateRefreshToken(oldInput.tokenHash, nextInput)
      expect(client.has(oldKey)).toBe(false)
      expect(client.has(newKey)).toBe(false)
    })

    it("revokeRefreshTokenFamily sweeps every hash in the family", async () => {
      const { client, cache, inner } = setup()
      const a = refreshInput({ familyId: "fam-A" })
      const b = refreshInput({ familyId: "fam-A" })
      const c = refreshInput({ familyId: "fam-B" })
      await inner.createRefreshToken(a)
      await inner.createRefreshToken(b)
      await inner.createRefreshToken(c)

      await cache.findRefreshToken(a.tokenHash)
      await cache.findRefreshToken(b.tokenHash)
      await cache.findRefreshToken(c.tokenHash)

      const keyA = `mcp:authkit:refresh:hash:${sha256(a.tokenHash).toString("hex")}`
      const keyB = `mcp:authkit:refresh:hash:${sha256(b.tokenHash).toString("hex")}`
      const keyC = `mcp:authkit:refresh:hash:${sha256(c.tokenHash).toString("hex")}`
      expect(client.has(keyA) && client.has(keyB) && client.has(keyC)).toBe(true)

      await cache.revokeRefreshTokenFamily("fam-A")
      expect(client.has(keyA)).toBe(false)
      expect(client.has(keyB)).toBe(false)
      expect(client.has(keyC)).toBe(true) // unrelated family untouched
    })

    it("cacheUpstreamCredential invalidates the cache entry", async () => {
      const client = new FakeRedis()
      const inner = withUpstream(memoryTokenStore() as TokenStore)
      const cache = redisCache(inner, { client })

      await inner.cacheUpstreamCredential?.({
        cacheKey: "k1",
        token: "first",
        expiresAt: new Date(Date.now() + 60_000),
      })
      await cache.findUpstreamCredential?.("k1")
      const key = "mcp:authkit:upstream:k1"
      expect(client.has(key)).toBe(true)

      await cache.cacheUpstreamCredential?.({
        cacheKey: "k1",
        token: "second",
        expiresAt: new Date(Date.now() + 60_000),
      })
      expect(client.has(key)).toBe(false)
      const after = await cache.findUpstreamCredential?.("k1")
      expect(after?.token).toBe("second")
    })

    it("createPat clears any stale negative entry", async () => {
      const { client, cache, inner } = setup({ negativeCacheTtlSeconds: 5 })
      const input = patInput()
      // Trigger negative cache.
      await cache.findPatByHash(input.tokenHash)
      const key = `mcp:authkit:pat:hash:${sha256(input.tokenHash).toString("hex")}`
      expect(client.has(key)).toBe(true)

      // Create through the decorator — write-through (drop negative).
      await cache.createPat(input)
      expect(client.has(key)).toBe(false)

      // Subsequent find now correctly returns the PAT.
      const found = await cache.findPatByHash(input.tokenHash)
      expect(found).not.toBeNull()
      // sanity: inner store contains the PAT
      const innerFound = await inner.findPatByHash(input.tokenHash)
      expect(innerFound).not.toBeNull()
    })
  })

  describe("pass-through", () => {
    it("delegates non-cached methods to inner", async () => {
      const { cache, inner } = setup()
      const listSpy = vi.spyOn(inner, "listPatsByUser")
      const updateSpy = vi.spyOn(inner, "updatePatLastUsed")
      const createRefreshSpy = vi.spyOn(inner, "createRefreshToken")

      await cache.listPatsByUser("u")
      await cache.updatePatLastUsed("id", new Date())
      await cache.createRefreshToken(refreshInput())

      expect(listSpy).toHaveBeenCalledOnce()
      expect(updateSpy).toHaveBeenCalledOnce()
      expect(createRefreshSpy).toHaveBeenCalledOnce()
    })

    it("forwards init() and close() only when inner defines them", () => {
      const client = new FakeRedis()
      const innerWith: TokenStore = Object.assign(memoryTokenStore() as TokenStore, {
        init: async () => {},
        close: async () => {},
      })
      const a = redisCache(innerWith, { client })
      expect(a.init).toBeTypeOf("function")
      expect(a.close).toBeTypeOf("function")

      const b = redisCache(memoryTokenStore() as TokenStore, { client })
      expect(b.init).toBeUndefined()
      expect(b.close).toBeUndefined()
    })
  })

  describe("key prefix isolation", () => {
    it("two decorators with different prefixes do not collide on the same client", async () => {
      const client = new FakeRedis()
      const innerA = memoryTokenStore() as TokenStore
      const innerB = memoryTokenStore() as TokenStore
      const a = redisCache(innerA, { client, keyPrefix: "tenant-a:" })
      const b = redisCache(innerB, { client, keyPrefix: "tenant-b:" })

      const inputA = patInput({ userIdentifier: "user-a" })
      const inputB = patInput({ userIdentifier: "user-b", tokenHash: inputA.tokenHash })
      await innerA.createPat(inputA)
      await innerB.createPat(inputB)

      const fromA = await a.findPatByHash(inputA.tokenHash)
      const fromB = await b.findPatByHash(inputB.tokenHash)
      expect(fromA?.userIdentifier).toBe("user-a")
      expect(fromB?.userIdentifier).toBe("user-b")

      // Distinct keys.
      const keyHex = sha256(inputA.tokenHash).toString("hex")
      expect(client.has(`tenant-a:pat:hash:${keyHex}`)).toBe(true)
      expect(client.has(`tenant-b:pat:hash:${keyHex}`)).toBe(true)
    })
  })

  describe("construction validation", () => {
    it("rejects non-positive ttlSeconds", () => {
      const client = new FakeRedis()
      const inner = memoryTokenStore() as TokenStore
      expect(() => redisCache(inner, { client, ttlSeconds: 0 })).toThrow(/positive/)
      expect(() => redisCache(inner, { client, ttlSeconds: -1 })).toThrow(/positive/)
    })

    it("rejects non-positive negativeCacheTtlSeconds", () => {
      const client = new FakeRedis()
      const inner = memoryTokenStore() as TokenStore
      expect(() => redisCache(inner, { client, negativeCacheTtlSeconds: 0 })).toThrow(/positive/)
    })

    it("rejects an undersized hmacKey", () => {
      const client = new FakeRedis()
      const inner = memoryTokenStore() as TokenStore
      expect(() => redisCache(inner, { client, hmacKey: Buffer.alloc(8) })).toThrow(/16 bytes/)
    })
  })

  describe("beforeEach reset for isolation across describes", () => {
    beforeEach(() => {
      vi.restoreAllMocks()
    })

    it("noop placeholder so the beforeEach binds correctly", () => {
      expect(true).toBe(true)
    })
  })
})
