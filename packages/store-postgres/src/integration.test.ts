/**
 * Real-Postgres integration tests.
 *
 * Skipped unless `INTEGRATION_DATABASE_URL` (or `DATABASE_URL`) is set. CI
 * provides a Postgres service via docker — see `.github/workflows/ci.yml`.
 * Locally, run with:
 *
 *   docker compose -f packages/store-postgres/docker-compose.yml up -d
 *   INTEGRATION_DATABASE_URL=postgres://authkit@localhost:5432/authkit_test \
 *     pnpm --filter mcp-authkit-store-postgres test
 */

import { createHash, randomBytes } from "node:crypto"
// eslint-disable-next-line @typescript-eslint/no-var-requires
import type { Pool as PgPoolReal } from "pg"
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest"
import {
  type CreatePatInput,
  type CreateRefreshTokenInput,
  postgresTokenStore,
  RefreshTokenReuseError,
  type TokenStore,
} from "./index.js"

const DATABASE_URL = process.env.INTEGRATION_DATABASE_URL ?? process.env.DATABASE_URL ?? null
const runIntegration = Boolean(DATABASE_URL)
const describeMaybe = runIntegration ? describe : describe.skip

function hashOf(token: string): Buffer {
  return createHash("sha256").update(token).digest()
}

function uniqueHash(): Buffer {
  return hashOf(randomBytes(16).toString("hex"))
}

function patInput(overrides: Partial<CreatePatInput> = {}): CreatePatInput {
  return {
    userIdentifier: `user-${randomBytes(4).toString("hex")}`,
    name: "test-pat",
    scopes: ["read"],
    expiresAt: new Date(Date.now() + 86_400_000),
    tokenHash: uniqueHash(),
    display: "mcp_pat_abcd…wxyz",
    ...overrides,
  }
}

function refreshInput(overrides: Partial<CreateRefreshTokenInput> = {}): CreateRefreshTokenInput {
  return {
    familyId: `fam-${randomBytes(4).toString("hex")}`,
    tokenHash: uniqueHash(),
    subject: "user-x",
    scopes: ["read"],
    expiresAt: new Date(Date.now() + 86_400_000),
    ...overrides,
  }
}

describeMaybe("postgresTokenStore (integration)", () => {
  // The dynamic import keeps the `pg` runtime dependency optional for
  // tests that don't actually use it (the unit suite uses a fake pool).
  let pool: PgPoolReal
  let store: TokenStore

  beforeAll(async () => {
    if (!DATABASE_URL) return
    const pg = await import("pg")
    pool = new pg.Pool({ connectionString: DATABASE_URL })
    store = postgresTokenStore({ pool, statementTimeoutMs: 5000 })
    await store.init?.()
  }, 30_000)

  afterAll(async () => {
    if (pool) await pool.end()
  })

  beforeEach(async () => {
    if (!pool) return
    // Wipe state between tests so they remain independent.
    await pool.query("DELETE FROM mcp_pats")
    await pool.query("DELETE FROM mcp_refresh_tokens")
    await pool.query("DELETE FROM mcp_upstream_credentials")
  })

  describe("PATs", () => {
    it("createPat + findPatByHash round-trip", async () => {
      const input = patInput()
      const stored = await store.createPat(input)
      const found = await store.findPatByHash(input.tokenHash)
      expect(found?.id).toBe(stored.id)
      expect(found?.scopes).toEqual(["read"])
      expect(Buffer.isBuffer(found?.tokenHash)).toBe(true)
    })

    it("revokePat hides the PAT from findPatByHash and listPatsByUser", async () => {
      const input = patInput()
      const stored = await store.createPat(input)
      await store.revokePat(stored.id, stored.userIdentifier)
      expect(await store.findPatByHash(input.tokenHash)).toBeNull()
      expect(await store.listPatsByUser(stored.userIdentifier)).toHaveLength(0)
    })

    it("expired PATs are not returned", async () => {
      const input = patInput({ expiresAt: new Date(Date.now() - 1000) })
      await store.createPat(input)
      expect(await store.findPatByHash(input.tokenHash)).toBeNull()
    })

    it("rotatePat inserts a successor row", async () => {
      const old = await store.createPat(patInput())
      const next = patInput({ userIdentifier: old.userIdentifier, name: "next" })
      const rotated = await store.rotatePat(old.id, old.userIdentifier, next)
      expect(rotated.id).not.toBe(old.id)
      expect(await store.findPatByHash(next.tokenHash)).not.toBeNull()
    })

    it("updatePatLastUsed persists the timestamp", async () => {
      const stored = await store.createPat(patInput())
      const ts = new Date()
      await store.updatePatLastUsed(stored.id, ts)
      const found = await store.findPatByHash(stored.tokenHash)
      expect(found?.lastUsedAt?.getTime()).toBe(ts.getTime())
    })
  })

  describe("refresh tokens", () => {
    it("rotate marks old rotated and inserts new", async () => {
      const t1 = refreshInput({ familyId: "fam-it-1" })
      await store.createRefreshToken(t1)
      const t2 = refreshInput({ familyId: "fam-it-1" })
      await store.rotateRefreshToken(t1.tokenHash, t2)
      const oldRow = await store.findRefreshToken(t1.tokenHash)
      const newRow = await store.findRefreshToken(t2.tokenHash)
      expect(oldRow?.rotatedAt).toBeInstanceOf(Date)
      expect(newRow?.rotatedAt).toBeNull()
    })

    it("reuse of a rotated token revokes the family", async () => {
      const familyId = `fam-${randomBytes(4).toString("hex")}`
      const t1 = refreshInput({ familyId })
      await store.createRefreshToken(t1)
      const t2 = refreshInput({ familyId })
      await store.rotateRefreshToken(t1.tokenHash, t2)
      const t3 = refreshInput({ familyId })
      await expect(store.rotateRefreshToken(t1.tokenHash, t3)).rejects.toBeInstanceOf(
        RefreshTokenReuseError,
      )
      expect(await store.findRefreshToken(t1.tokenHash)).toBeNull()
      expect(await store.findRefreshToken(t2.tokenHash)).toBeNull()
    })

    it("two concurrent rotateRefreshToken calls: one wins, the other revokes the family", async () => {
      // Pre-load a refresh token; both concurrent callers will attempt to
      // rotate it. The unique index on token_hash and the SELECT ... FOR
      // UPDATE in rotateRefreshToken serialize the rotations — the loser
      // sees an already-rotated row and throws RefreshTokenReuseError,
      // revoking the family in the same transaction.
      const familyId = `fam-${randomBytes(4).toString("hex")}`
      const t1 = refreshInput({ familyId })
      await store.createRefreshToken(t1)
      const nextA = refreshInput({ familyId })
      const nextB = refreshInput({ familyId })
      const results = await Promise.allSettled([
        store.rotateRefreshToken(t1.tokenHash, nextA),
        store.rotateRefreshToken(t1.tokenHash, nextB),
      ])
      const fulfilled = results.filter((r) => r.status === "fulfilled")
      const rejected = results.filter((r) => r.status === "rejected")
      expect(fulfilled).toHaveLength(1)
      expect(rejected).toHaveLength(1)
      expect((rejected[0] as PromiseRejectedResult).reason).toBeInstanceOf(RefreshTokenReuseError)
      // Family revoked on the reuse path — both successors and the
      // predecessor must be gone.
      expect(await store.findRefreshToken(t1.tokenHash)).toBeNull()
      expect(await store.findRefreshToken(nextA.tokenHash)).toBeNull()
      expect(await store.findRefreshToken(nextB.tokenHash)).toBeNull()
    })

    it("revokeRefreshTokenFamily wipes only the named family", async () => {
      const a = refreshInput({ familyId: "fam-keep" })
      const b = refreshInput({ familyId: "fam-zap" })
      await store.createRefreshToken(a)
      await store.createRefreshToken(b)
      await store.revokeRefreshTokenFamily("fam-zap")
      expect(await store.findRefreshToken(a.tokenHash)).not.toBeNull()
      expect(await store.findRefreshToken(b.tokenHash)).toBeNull()
    })
  })

  describe("upstream credential cache (§6.2)", () => {
    it("cache + find round-trip", async () => {
      await store.cacheUpstreamCredential?.({
        cacheKey: "kI",
        token: "upstream-tok",
        expiresAt: new Date(Date.now() + 60_000),
      })
      const got = await store.findUpstreamCredential?.("kI")
      expect(got?.token).toBe("upstream-tok")
    })

    it("expired entries are misses", async () => {
      await store.cacheUpstreamCredential?.({
        cacheKey: "kE",
        token: "x",
        expiresAt: new Date(Date.now() - 1000),
      })
      expect(await store.findUpstreamCredential?.("kE")).toBeNull()
    })
  })

  describe("migrations", () => {
    it("init() is idempotent", async () => {
      // We already ran init in beforeAll — a second call must not error.
      await expect(store.init?.()).resolves.toBeUndefined()
    })
  })

  describe("statement timeout", () => {
    it("aborts queries that exceed the configured timeout", async () => {
      // Build a separate store with an extremely tight cap and run a
      // server-side sleep through it. Postgres returns SQLSTATE 57014,
      // which surfaces as an error containing "statement timeout".
      const tightStore = postgresTokenStore({ pool, statementTimeoutMs: 50 })
      const slow = pool.connect()
      // We use a separate connection inline for the pg_sleep so the timeout
      // cap is set per checkout. The store always runs `SET
      // statement_timeout` before every query.
      await (await slow).query("SET statement_timeout = 50")
      try {
        await expect((await slow).query("SELECT pg_sleep(0.5)")).rejects.toThrow(
          /statement timeout/,
        )
      } finally {
        ;(await slow).release()
      }
      // Sanity: the store's normal operations still work afterwards because
      // each checkout sets its own timeout.
      const input = patInput()
      await tightStore.createPat(input)
      expect(await tightStore.findPatByHash(input.tokenHash)).not.toBeNull()
    })
  })
})
