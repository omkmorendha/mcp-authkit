/**
 * Integration tests for `sqliteTokenStore` against a real, file-backed
 * `better-sqlite3` Database. These exist (separate from the in-memory unit
 * tests) because two scenarios cannot be exercised against `:memory:`:
 *   1. `journal_mode = WAL` (spec §6.4) — `:memory:` ignores WAL.
 *   2. Concurrent rotation across two independent `Database` handles
 *      pointing at the same file (spec §14 family-revoke under contention).
 *
 * The driver is in-process and writes to `os.tmpdir()`; there is no env
 * gate. CI always runs these.
 */

import { createHash, randomBytes } from "node:crypto"
import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import Database from "better-sqlite3"
import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { type CreateRefreshTokenInput, RefreshTokenReuseError, sqliteTokenStore } from "./index.js"

function hashOf(token: string): Buffer {
  return createHash("sha256").update(token).digest()
}

function refreshInput(overrides: Partial<CreateRefreshTokenInput> = {}): CreateRefreshTokenInput {
  return {
    familyId: `fam-${randomBytes(4).toString("hex")}`,
    tokenHash: hashOf(randomBytes(16).toString("hex")),
    subject: "user-x",
    scopes: ["read"],
    expiresAt: new Date(Date.now() + 86_400_000),
    ...overrides,
  }
}

describe("sqliteTokenStore (integration, file-backed)", () => {
  let dir: string
  let path: string

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "mcp-authkit-sqlite-"))
    path = join(dir, "authkit.db")
  })
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true })
  })

  it("init() enables WAL mode", async () => {
    const db = new Database(path)
    const store = sqliteTokenStore({ database: db })
    await store.init?.()
    const mode = db.pragma("journal_mode", { simple: true })
    expect(String(mode).toLowerCase()).toBe("wal")
    db.close()
  })

  it("schema persists across reopens", async () => {
    const db1 = new Database(path)
    const s1 = sqliteTokenStore({ database: db1 })
    await s1.init?.()
    await s1.createRefreshToken(refreshInput({ familyId: "persistent" }))
    db1.close()

    const db2 = new Database(path)
    const s2 = sqliteTokenStore({ database: db2 })
    await s2.init?.() // idempotent
    // The previously-inserted family should still be there.
    const row = db2
      .prepare(`SELECT COUNT(*) AS n FROM "mcp_refresh_tokens" WHERE family_id = ?`)
      .get("persistent") as { n: number }
    expect(row.n).toBe(1)
    db2.close()
  })

  it("concurrent rotation across two handles: one wins, the other revokes the family", async () => {
    // Pre-load a refresh token via one handle.
    const seed = new Database(path)
    const seedStore = sqliteTokenStore({ database: seed })
    await seedStore.init?.()
    const familyId = `fam-${randomBytes(4).toString("hex")}`
    const t1 = refreshInput({ familyId })
    await seedStore.createRefreshToken(t1)
    seed.close()

    // Two independent handles racing on the same `oldHash`. better-sqlite3
    // exposes `busyTimeout` (default 5s) which makes the loser wait briefly
    // for the writer lock; once it acquires the lock it sees the row already
    // rotated and triggers the §14 reuse path.
    const dbA = new Database(path)
    const dbB = new Database(path)
    dbA.pragma("busy_timeout = 5000")
    dbB.pragma("busy_timeout = 5000")
    const storeA = sqliteTokenStore({ database: dbA })
    const storeB = sqliteTokenStore({ database: dbB })

    const nextA = refreshInput({ familyId })
    const nextB = refreshInput({ familyId })
    const results = await Promise.allSettled([
      storeA.rotateRefreshToken(t1.tokenHash, nextA),
      storeB.rotateRefreshToken(t1.tokenHash, nextB),
    ])
    dbA.close()
    dbB.close()

    const fulfilled = results.filter((r) => r.status === "fulfilled")
    const rejected = results.filter((r) => r.status === "rejected")
    expect(fulfilled).toHaveLength(1)
    expect(rejected).toHaveLength(1)
    expect((rejected[0] as PromiseRejectedResult).reason).toBeInstanceOf(RefreshTokenReuseError)

    // Family revoked on the reuse path — both successors and the
    // predecessor must be gone.
    const dbCheck = new Database(path)
    const remaining = dbCheck
      .prepare(`SELECT COUNT(*) AS n FROM "mcp_refresh_tokens" WHERE family_id = ?`)
      .get(familyId) as { n: number }
    expect(remaining.n).toBe(0)
    dbCheck.close()
  })

  it("upstream credential cache survives reopen", async () => {
    const db1 = new Database(path)
    const s1 = sqliteTokenStore({ database: db1 })
    await s1.init?.()
    await s1.cacheUpstreamCredential?.({
      cacheKey: "kfile",
      token: "tok-persistent",
      expiresAt: new Date(Date.now() + 60_000),
    })
    db1.close()

    const db2 = new Database(path)
    const s2 = sqliteTokenStore({ database: db2 })
    const got = await s2.findUpstreamCredential?.("kfile")
    expect(got?.token).toBe("tok-persistent")
    db2.close()
  })
})
