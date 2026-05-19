import { createHash, randomBytes } from "node:crypto"
import { Redis } from "ioredis"
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest"
import { memoryTokenStore } from "../../store-memory/src/index.js"
import type { CreatePatInput, CreateRefreshTokenInput, TokenStore } from "./index.js"
import { redisCache } from "./index.js"

const REDIS_URL = process.env.REDIS_URL ?? "redis://127.0.0.1:6379"

// Tests run against a real Redis service. CI starts one as a Docker service
// (see .github/workflows/ci.yml). Locally, `redis-server --daemonize yes`
// works.
function makeClient(db: number): Redis {
  return new Redis(REDIS_URL, { db, lazyConnect: false, maxRetriesPerRequest: 1 })
}

function hashOf(token: string): Buffer {
  return createHash("sha256").update(token).digest()
}

function patInput(overrides: Partial<CreatePatInput> = {}): CreatePatInput {
  return {
    userIdentifier: "user-a",
    name: "test-pat",
    scopes: ["read"],
    expiresAt: new Date(Date.now() + 86_400_000),
    tokenHash: hashOf(randomBytes(16).toString("hex")),
    display: "mcp_pat_abcd…wxyz",
    ...overrides,
  }
}

function refreshInput(overrides: Partial<CreateRefreshTokenInput> = {}): CreateRefreshTokenInput {
  return {
    familyId: "fam-1",
    tokenHash: hashOf(randomBytes(16).toString("hex")),
    subject: "user-a",
    scopes: ["read"],
    expiresAt: new Date(Date.now() + 86_400_000),
    ...overrides,
  }
}

let client: Redis

beforeAll(async () => {
  client = makeClient(15)
})

beforeEach(async () => {
  await client.flushdb()
})

afterAll(async () => {
  await client.quit()
})

describe("redisCache — pass-through semantics", () => {
  it("delegates every method to the inner store", async () => {
    const inner = memoryTokenStore()
    const store = redisCache(inner, { client })
    const input = patInput()
    const stored = await store.createPat(input)
    expect(stored.userIdentifier).toBe("user-a")

    // listPatsByUser is a pure pass-through (not cached).
    const list = await store.listPatsByUser("user-a")
    expect(list).toHaveLength(1)
    expect(list[0]?.id).toBe(stored.id)

    await store.revokePat(stored.id, "user-a")
    expect(await store.listPatsByUser("user-a")).toHaveLength(0)
  })

  it("findPatByHash returns the inner row on first call (miss → fill)", async () => {
    const inner = memoryTokenStore()
    const store = redisCache(inner, { client })
    const input = patInput()
    await store.createPat(input)
    const found = await store.findPatByHash(input.tokenHash)
    expect(found).not.toBeNull()
    expect(found?.tokenHash.equals(input.tokenHash)).toBe(true)
  })
})

describe("redisCache — hit / miss / write invalidation", () => {
  it("caches findPatByHash and serves subsequent lookups from Redis", async () => {
    const inner = memoryTokenStore()
    const findSpy = vi.spyOn(inner, "findPatByHash")
    const store = redisCache(inner, { client })
    const input = patInput()
    await store.createPat(input)
    // createPat warmed the cache; first findPatByHash should hit Redis only.
    findSpy.mockClear()
    const first = await store.findPatByHash(input.tokenHash)
    expect(first).not.toBeNull()
    expect(findSpy).not.toHaveBeenCalled()
    // Second call also serves from Redis.
    const second = await store.findPatByHash(input.tokenHash)
    expect(second?.id).toBe(first?.id)
    expect(findSpy).not.toHaveBeenCalled()
  })

  it("populates the cache on a cold findPatByHash", async () => {
    const inner = memoryTokenStore()
    const stored = await inner.createPat(patInput()) // bypass decorator: no cache fill.
    const findSpy = vi.spyOn(inner, "findPatByHash")
    const store = redisCache(inner, { client })

    const first = await store.findPatByHash(stored.tokenHash)
    expect(first?.id).toBe(stored.id)
    expect(findSpy).toHaveBeenCalledTimes(1)

    const second = await store.findPatByHash(stored.tokenHash)
    expect(second?.id).toBe(stored.id)
    expect(findSpy).toHaveBeenCalledTimes(1) // hit
  })

  it("revokePat invalidates the cached entry synchronously after the inner write", async () => {
    const inner = memoryTokenStore()
    const store = redisCache(inner, { client })
    const input = patInput()
    const stored = await store.createPat(input)
    // Warm the cache.
    await store.findPatByHash(input.tokenHash)

    await store.revokePat(stored.id, stored.userIdentifier)
    // After revoke the cached row would still claim the PAT is active.
    // Invalidation must force a refresh from the inner store, which now
    // returns null (revoked).
    const after = await store.findPatByHash(input.tokenHash)
    expect(after).toBeNull()
  })

  it("rotatePat invalidates the predecessor cached entry", async () => {
    const inner = memoryTokenStore()
    const store = redisCache(inner, { client })
    const oldInput = patInput()
    const oldStored = await store.createPat(oldInput)
    await store.findPatByHash(oldInput.tokenHash) // warm

    const innerSpy = vi.spyOn(inner, "findPatByHash")
    const nextInput = patInput({ name: "rotated" })
    await store.rotatePat(oldStored.id, oldStored.userIdentifier, nextInput)

    innerSpy.mockClear()
    await store.findPatByHash(oldInput.tokenHash)
    // After rotate the predecessor cache is gone; lookup falls through.
    expect(innerSpy).toHaveBeenCalledTimes(1)
  })

  it("rotateRefreshToken invalidates the predecessor's cached refresh entry", async () => {
    const inner = memoryTokenStore()
    const store = redisCache(inner, { client })
    const oldInput = refreshInput()
    await store.createRefreshToken(oldInput)
    await store.findRefreshToken(oldInput.tokenHash) // warm

    const nextInput = refreshInput()
    await store.rotateRefreshToken(oldInput.tokenHash, nextInput)

    const innerSpy = vi.spyOn(inner, "findRefreshToken")
    await store.findRefreshToken(oldInput.tokenHash)
    expect(innerSpy).toHaveBeenCalled()
  })

  it("revokeRefreshTokenFamily flushes the refresh-cache namespace", async () => {
    const inner = memoryTokenStore()
    const store = redisCache(inner, { client })
    const a = refreshInput({ familyId: "famA" })
    const b = refreshInput({ familyId: "famA" })
    await store.createRefreshToken(a)
    await store.createRefreshToken(b)
    await store.findRefreshToken(a.tokenHash)
    await store.findRefreshToken(b.tokenHash)

    await store.revokeRefreshTokenFamily("famA")
    expect(await store.findRefreshToken(a.tokenHash)).toBeNull()
    expect(await store.findRefreshToken(b.tokenHash)).toBeNull()
  })
})

describe("redisCache — negative cache", () => {
  it("is OFF by default — every miss falls through to the inner store", async () => {
    const inner = memoryTokenStore()
    const findSpy = vi.spyOn(inner, "findPatByHash")
    const store = redisCache(inner, { client })

    const missHash = hashOf("never-seen")
    await store.findPatByHash(missHash)
    await store.findPatByHash(missHash)
    await store.findPatByHash(missHash)
    expect(findSpy).toHaveBeenCalledTimes(3)
  })

  it("opt-in via negativeCacheTtlSeconds suppresses repeated inner lookups", async () => {
    const inner = memoryTokenStore()
    const findSpy = vi.spyOn(inner, "findPatByHash")
    const store = redisCache(inner, { client, negativeCacheTtlSeconds: 2 })

    const missHash = hashOf("absent-pat")
    await store.findPatByHash(missHash)
    await store.findPatByHash(missHash)
    await store.findPatByHash(missHash)
    expect(findSpy).toHaveBeenCalledTimes(1)
  })

  it("caps the negative-cache TTL at 5 seconds", async () => {
    const inner = memoryTokenStore()
    const store = redisCache(inner, { client, negativeCacheTtlSeconds: 60, keyPrefix: "cap:" })
    const missHash = hashOf("absent")
    await store.findPatByHash(missHash)
    const ttl = await client.ttl(`cap:pat:${missHash.toString("hex")}`)
    expect(ttl).toBeGreaterThan(0)
    expect(ttl).toBeLessThanOrEqual(5)
  })
})

describe("redisCache — HMAC tag verification", () => {
  it("treats a value with a wrong HMAC tag as a miss and warns", async () => {
    const inner = memoryTokenStore()
    const warn = vi.fn()
    // Pino loggers accept (obj, msg). The decorator only calls .warn.
    const logger = {
      warn,
      info: () => {},
      error: () => {},
      debug: () => {},
      trace: () => {},
      fatal: () => {},
      child: () => logger,
    } as unknown as Parameters<typeof redisCache>[1]["logger"]
    const store = redisCache(inner, { client, logger })

    const input = patInput()
    const stored = await store.createPat(input)
    const cacheKey = `mcp:authkit:pat:${stored.tokenHash.toString("hex")}`
    const raw = await client.getBuffer(cacheKey)
    if (raw === null) throw new Error("expected cache fill")
    // Flip a byte INSIDE the HMAC tag (the first 32 bytes) so the value
    // is still well-formed but the tag mismatches.
    raw[0] = (raw[0] ?? 0) ^ 0xff
    await client.set(cacheKey, raw)

    const findSpy = vi.spyOn(inner, "findPatByHash")
    const found = await store.findPatByHash(stored.tokenHash)
    // Falls through to inner store, which still has the row.
    expect(found?.id).toBe(stored.id)
    expect(findSpy).toHaveBeenCalledTimes(1)
    expect(warn).toHaveBeenCalled()
    const firstCallArgs = warn.mock.calls[0]
    expect(firstCallArgs?.[1]).toMatch(/HMAC tag mismatch/)
  })

  it("rejects a value whose payload bytes were tampered (HMAC catches it)", async () => {
    const inner = memoryTokenStore()
    const store = redisCache(inner, { client })
    const input = patInput()
    const stored = await store.createPat(input)
    const cacheKey = `mcp:authkit:pat:${stored.tokenHash.toString("hex")}`
    const raw = await client.getBuffer(cacheKey)
    if (raw === null) throw new Error("expected cache fill")
    // Flip a byte in the payload (past the 32-byte HMAC tag).
    raw[40] = (raw[40] ?? 0) ^ 0xff
    await client.set(cacheKey, raw)

    const findSpy = vi.spyOn(inner, "findPatByHash")
    const found = await store.findPatByHash(stored.tokenHash)
    expect(found?.id).toBe(stored.id)
    expect(findSpy).toHaveBeenCalled()
  })

  it("a decorator with a different hmacKey cannot read another decorator's cache", async () => {
    const inner = memoryTokenStore()
    const writer = redisCache(inner, { client, hmacKey: Buffer.alloc(32, 0x11) })
    const reader = redisCache(inner, { client, hmacKey: Buffer.alloc(32, 0x22) })

    const input = patInput()
    const stored = await writer.createPat(input)

    const readerInner = vi.spyOn(inner, "findPatByHash")
    const out = await reader.findPatByHash(input.tokenHash)
    // Reader sees a tag mismatch → treats as miss → consults inner.
    expect(out?.id).toBe(stored.id)
    expect(readerInner).toHaveBeenCalledTimes(1)
  })
})

describe("redisCache — key prefix isolation", () => {
  it("two decorators with different prefixes do not collide", async () => {
    const inner = memoryTokenStore()
    const a = redisCache(inner, { client, keyPrefix: "a:" })
    const b = redisCache(inner, { client, keyPrefix: "b:" })
    const input = patInput()
    await a.createPat(input)
    const hh = input.tokenHash.toString("hex")
    expect(await client.exists(`a:pat:${hh}`)).toBe(1)
    expect(await client.exists(`b:pat:${hh}`)).toBe(0)
    // b's findPatByHash misses cache (different prefix), falls through.
    const found = await b.findPatByHash(input.tokenHash)
    expect(found).not.toBeNull()
    expect(await client.exists(`b:pat:${hh}`)).toBe(1)
  })

  it("default key prefix is `mcp:authkit:`", async () => {
    const inner = memoryTokenStore()
    const store = redisCache(inner, { client })
    const input = patInput()
    await store.createPat(input)
    const keys = await client.keys("mcp:authkit:pat:*")
    expect(keys.length).toBeGreaterThan(0)
  })
})

describe("redisCache — upstream credential methods (optional)", () => {
  it("are omitted when the inner store does not implement them", () => {
    const inner = memoryTokenStore()
    const store = redisCache(inner, { client })
    expect(store.findUpstreamCredential).toBeUndefined()
    expect(store.cacheUpstreamCredential).toBeUndefined()
  })

  it("are wired and cache when the inner store implements them", async () => {
    // Build a minimal inner with the v0.2 §6.2 methods.
    const storage = new Map<string, { token: string; expiresAt: Date }>()
    const inner: TokenStore = {
      ...memoryTokenStore(),
      async cacheUpstreamCredential({ cacheKey, token, expiresAt }) {
        storage.set(cacheKey, { token, expiresAt })
      },
      async findUpstreamCredential(cacheKey) {
        return storage.get(cacheKey) ?? null
      },
    }
    const findSpy = vi.spyOn(inner, "findUpstreamCredential")
    const store = redisCache(inner, { client })

    await store.cacheUpstreamCredential?.({
      cacheKey: "sub|aud|read",
      token: "tok-xyz",
      expiresAt: new Date(Date.now() + 60_000),
    })

    findSpy.mockClear()
    const a = await store.findUpstreamCredential?.("sub|aud|read")
    expect(a?.token).toBe("tok-xyz")
    expect(findSpy).not.toHaveBeenCalled()

    const b = await store.findUpstreamCredential?.("sub|aud|read")
    expect(b?.token).toBe("tok-xyz")
    expect(findSpy).not.toHaveBeenCalled()
  })
})

describe("redisCache — security", () => {
  it("the per-process HMAC key is independent of the prefix", async () => {
    // Two decorators with the same prefix but different keys: writes from
    // one are unreadable by the other (treated as misses).
    const inner = memoryTokenStore()
    const opts = { client, keyPrefix: "same:" }
    const writer = redisCache(inner, { ...opts, hmacKey: Buffer.alloc(32, 0xaa) })
    const reader = redisCache(inner, { ...opts, hmacKey: Buffer.alloc(32, 0xbb) })

    const input = patInput()
    await writer.createPat(input)
    const innerSpy = vi.spyOn(inner, "findPatByHash")
    await reader.findPatByHash(input.tokenHash)
    expect(innerSpy).toHaveBeenCalled()
  })

  it("does not log the cached value or the token hash plaintext on miss", async () => {
    const inner = memoryTokenStore()
    const warn = vi.fn()
    const logger = {
      warn,
      info: () => {},
      error: () => {},
      debug: () => {},
      trace: () => {},
      fatal: () => {},
      child: () => logger,
    } as unknown as Parameters<typeof redisCache>[1]["logger"]
    const store = redisCache(inner, { client, logger })
    const stored = await store.createPat(patInput())
    const cacheKey = `mcp:authkit:pat:${stored.tokenHash.toString("hex")}`
    const raw = await client.getBuffer(cacheKey)
    if (raw === null) throw new Error("expected fill")
    raw[0] = (raw[0] ?? 0) ^ 0xff
    await client.set(cacheKey, raw)
    await store.findPatByHash(stored.tokenHash)

    const serialized = warn.mock.calls.map((c) => JSON.stringify(c)).join("")
    // The cache key is logged (operator needs it). The token plaintext is
    // never observed by this layer, so it cannot be logged. The PAT row's
    // display field must NOT appear in any warn log.
    expect(serialized).not.toContain(stored.display)
  })
})

afterEach(async () => {
  // Vitest restores spies between tests, but we also clean Redis state so
  // tests are order-independent.
  vi.restoreAllMocks()
})
