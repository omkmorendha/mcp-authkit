/**
 * Integration tests against a real Redis. Skipped when `INTEGRATION_REDIS_URL`
 * is unset, mirroring the `store-postgres` convention.
 */

import { createHash, randomBytes } from "node:crypto"
import { memoryTokenStore } from "mcp-authkit-store-memory"
import { afterAll, beforeAll, describe, expect, it } from "vitest"
import { redisCache } from "./index.js"
import type { CreatePatInput, CreateRefreshTokenInput, TokenStore } from "./types.js"

const url = process.env.INTEGRATION_REDIS_URL
const itIf = url ? it : it.skip
const describeIf = url ? describe : describe.skip

interface IoRedisLike {
  get(key: string): Promise<Buffer | null>
  set(key: string, value: Buffer | string, mode: "EX", ttl: number): Promise<unknown>
  del(...keys: string[]): Promise<unknown>
  sadd(key: string, ...members: string[]): Promise<unknown>
  smembers(key: string): Promise<string[]>
  expire(key: string, seconds: number): Promise<unknown>
  flushdb(): Promise<unknown>
  quit(): Promise<unknown>
}

function sha256(buf: Buffer): Buffer {
  return createHash("sha256").update(buf).digest()
}

function patInput(overrides: Partial<CreatePatInput> = {}): CreatePatInput {
  return {
    userIdentifier: "user-1",
    name: "integration",
    scopes: ["read"],
    expiresAt: new Date(Date.now() + 60_000),
    tokenHash: sha256(randomBytes(32)),
    display: "mcp_pat_abc...xyz",
    ...overrides,
  }
}

function refreshInput(overrides: Partial<CreateRefreshTokenInput> = {}): CreateRefreshTokenInput {
  return {
    familyId: "fam-1",
    tokenHash: sha256(randomBytes(32)),
    subject: "user-1",
    scopes: ["read"],
    expiresAt: new Date(Date.now() + 60_000),
    ...overrides,
  }
}

describeIf("redisCache integration", () => {
  let client: IoRedisLike
  let cache: TokenStore
  let inner: TokenStore

  beforeAll(async () => {
    // Lazy import so type/lint don't fail when ioredis isn't installed.
    const { Redis } = await import("ioredis")
    // `ioredis` returns string-typed replies by default; we configure binary
    // GET via the `Buffer` overload only where needed. The decorator already
    // handles both forms in `readBlob`.
    client = new Redis(url!) as unknown as IoRedisLike
    await client.flushdb()
    inner = memoryTokenStore() as TokenStore
    cache = redisCache(inner, {
      client: client,
      keyPrefix: "itest:",
      hmacKey: randomBytes(32),
    })
  })

  afterAll(async () => {
    if (client) {
      try {
        await client.flushdb()
      } finally {
        await client.quit()
      }
    }
  })

  itIf("PAT mint → hit → revoke invalidates", async () => {
    const input = patInput()
    const pat = await cache.createPat(input)

    const a = await cache.findPatByHash(input.tokenHash)
    expect(a?.id).toBe(pat.id)

    // Sanity: a second read still returns the row even though we can't easily
    // observe the inner-spy count across processes here.
    const b = await cache.findPatByHash(input.tokenHash)
    expect(b?.id).toBe(pat.id)

    await cache.revokePat(pat.id, pat.userIdentifier)
    const c = await cache.findPatByHash(input.tokenHash)
    expect(c).toBeNull()
  })

  itIf("refresh rotation and family revocation sweep cache", async () => {
    const a = refreshInput({ familyId: "fam-real" })
    const b = refreshInput({ familyId: "fam-real" })
    await cache.createRefreshToken(a)
    await cache.createRefreshToken(b)

    expect((await cache.findRefreshToken(a.tokenHash))?.familyId).toBe("fam-real")
    expect((await cache.findRefreshToken(b.tokenHash))?.familyId).toBe("fam-real")

    await cache.revokeRefreshTokenFamily("fam-real")
    expect(await cache.findRefreshToken(a.tokenHash)).toBeNull()
    expect(await cache.findRefreshToken(b.tokenHash)).toBeNull()
  })
})
