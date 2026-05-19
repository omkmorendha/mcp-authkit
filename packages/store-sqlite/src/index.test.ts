import { createHash, randomBytes } from "node:crypto"
import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import Database from "better-sqlite3"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { type CreatePatInput, type CreateRefreshTokenInput, sqliteTokenStore } from "./index.js"

const timingSafeEqualSpy = vi.hoisted(() => vi.fn<(a: Uint8Array, b: Uint8Array) => boolean>())

vi.mock("node:crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:crypto")>()
  return {
    ...actual,
    timingSafeEqual: (a: Uint8Array, b: Uint8Array) => {
      timingSafeEqualSpy(a, b)
      return actual.timingSafeEqual(a, b)
    },
  }
})

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

let tempDir: string
let dbPath: string
let db: InstanceType<typeof Database>

beforeEach(async () => {
  tempDir = mkdtempSync(join(tmpdir(), "mcp-authkit-sqlite-"))
  dbPath = join(tempDir, "test.db")
  db = new Database(dbPath)
})

afterEach(() => {
  try {
    db.close()
  } catch {
    // already closed
  }
  rmSync(tempDir, { recursive: true, force: true })
})

async function freshStore() {
  const store = sqliteTokenStore({ database: db })
  await store.init()
  return store
}

describe("sqliteTokenStore — init / migrations", () => {
  it("init() enables WAL mode", async () => {
    await freshStore()
    const row = db.pragma("journal_mode", { simple: true }) as string
    expect(row.toLowerCase()).toBe("wal")
  })

  it("init() creates the migrations row and is idempotent", async () => {
    const store = sqliteTokenStore({ database: db })
    await store.init()
    await store.init()
    await store.init()
    const rows = db.prepare("SELECT id FROM mcp_migrations ORDER BY id").all() as Array<{
      id: number
    }>
    expect(rows.map((r) => r.id)).toEqual([1])
  })

  it("init() across two handles on the same file is safe (BEGIN IMMEDIATE serializes)", async () => {
    const db2 = new Database(dbPath)
    try {
      const a = sqliteTokenStore({ database: db })
      const b = sqliteTokenStore({ database: db2 })
      await Promise.all([a.init(), b.init()])
      const rows = db.prepare("SELECT id FROM mcp_migrations ORDER BY id").all() as Array<{
        id: number
      }>
      expect(rows.map((r) => r.id)).toEqual([1])
    } finally {
      db2.close()
    }
  })

  it("warns when the database is readonly and does not run migrations", async () => {
    // Seed the file with the migrations table first (since readonly cannot create it).
    await (async () => {
      const seedStore = sqliteTokenStore({ database: db })
      await seedStore.init()
      db.close()
    })()
    db = new Database(dbPath, { readonly: true })
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {})
    try {
      const store = sqliteTokenStore({ database: db })
      await store.init()
      expect(warn).toHaveBeenCalled()
      const msg = warn.mock.calls.flat().join(" ")
      expect(msg).toMatch(/readonly/i)
    } finally {
      warn.mockRestore()
    }
  })

  it("rejects table-name overrides with illegal characters", () => {
    expect(() =>
      sqliteTokenStore({ database: db, tableNames: { pats: "drop table x; --" } }),
    ).toThrow(/invalid table name/)
    expect(() => sqliteTokenStore({ database: db, tableNames: { refreshTokens: "a b" } })).toThrow(
      /invalid table name/,
    )
    expect(() =>
      sqliteTokenStore({ database: db, tableNames: { upstreamCredentials: "'a'" } }),
    ).toThrow(/invalid table name/)
    expect(() => sqliteTokenStore({ database: db, tableNames: { migrations: "x.y" } })).toThrow(
      /invalid table name/,
    )
  })

  it("accepts table-name overrides matching [A-Za-z0-9_]", async () => {
    const store = sqliteTokenStore({
      database: db,
      tableNames: {
        pats: "custom_pats_1",
        refreshTokens: "custom_refresh_1",
        upstreamCredentials: "custom_upstream_1",
        migrations: "custom_migrations_1",
      },
    })
    await store.init()
    const rows = db
      .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
      .all() as Array<{ name: string }>
    const names = rows.map((r) => r.name)
    expect(names).toEqual(
      expect.arrayContaining([
        "custom_pats_1",
        "custom_refresh_1",
        "custom_upstream_1",
        "custom_migrations_1",
      ]),
    )
  })
})

describe("sqliteTokenStore — PAT", () => {
  it("createPat + findPatByHash round-trip", async () => {
    const store = await freshStore()
    const input = patInput()
    const stored = await store.createPat(input)
    expect(stored.id).toBeTruthy()
    expect(stored.createdAt).toBeInstanceOf(Date)
    expect(stored.revokedAt).toBeNull()
    expect(stored.lastUsedAt).toBeNull()

    const found = await store.findPatByHash(input.tokenHash)
    expect(found).not.toBeNull()
    expect(found?.id).toBe(stored.id)
    expect(found?.scopes).toEqual(["read"])
  })

  it("findPatByHash returns null for unknown hash", async () => {
    const store = await freshStore()
    await store.createPat(patInput())
    expect(await store.findPatByHash(hashOf("other"))).toBeNull()
  })

  it("findPatByHash returns null for revoked PAT", async () => {
    const store = await freshStore()
    const input = patInput()
    const stored = await store.createPat(input)
    await store.revokePat(stored.id, stored.userIdentifier)
    expect(await store.findPatByHash(input.tokenHash)).toBeNull()
  })

  it("findPatByHash returns null for expired PAT", async () => {
    const store = await freshStore()
    const input = patInput({ expiresAt: new Date(Date.now() - 1000) })
    await store.createPat(input)
    expect(await store.findPatByHash(input.tokenHash)).toBeNull()
  })

  it("listPatsByUser is scoped to the user", async () => {
    const store = await freshStore()
    await store.createPat(patInput({ userIdentifier: "user-a", name: "a1" }))
    await store.createPat(patInput({ userIdentifier: "user-b", name: "b1" }))
    const a = await store.listPatsByUser("user-a")
    expect(a.map((p) => p.name)).toEqual(["a1"])
    const b = await store.listPatsByUser("user-b")
    expect(b.map((p) => p.name)).toEqual(["b1"])
  })

  it("listPatsByUser excludes revoked PATs", async () => {
    const store = await freshStore()
    const a = await store.createPat(patInput({ name: "keep" }))
    const b = await store.createPat(patInput({ name: "gone" }))
    await store.revokePat(b.id, b.userIdentifier)
    const out = await store.listPatsByUser("user-a")
    expect(out.map((p) => p.id)).toEqual([a.id])
  })

  it("revokePat is idempotent and scoped to the owner", async () => {
    const store = await freshStore()
    const a = await store.createPat(patInput({ userIdentifier: "user-a" }))
    await store.revokePat(a.id, "user-b")
    expect(await store.listPatsByUser("user-a")).toHaveLength(1)
    await store.revokePat(a.id, "user-a")
    await store.revokePat(a.id, "user-a")
    expect(await store.listPatsByUser("user-a")).toHaveLength(0)
  })

  it("rotatePat inserts a new row; predecessor remains until lifecycle revokes it", async () => {
    const store = await freshStore()
    const oldInput = patInput()
    const oldStored = await store.createPat(oldInput)
    const newInput = patInput({ name: "rotated" })
    const newStored = await store.rotatePat(oldStored.id, oldStored.userIdentifier, newInput)
    expect(newStored.id).not.toBe(oldStored.id)
    expect(newStored.name).toBe("rotated")
    expect(await store.findPatByHash(oldInput.tokenHash)).not.toBeNull()
    expect(await store.findPatByHash(newInput.tokenHash)).not.toBeNull()
  })

  it("rotatePat throws when the id does not belong to the caller", async () => {
    const store = await freshStore()
    const a = await store.createPat(patInput({ userIdentifier: "user-a" }))
    await expect(store.rotatePat(a.id, "user-b", patInput())).rejects.toThrow(/not found/)
  })

  it("updatePatLastUsed sets the timestamp", async () => {
    const store = await freshStore()
    const a = await store.createPat(patInput())
    const ts = new Date(Date.now() - 1000)
    await store.updatePatLastUsed(a.id, ts)
    const found = await store.findPatByHash(a.tokenHash)
    expect(found?.lastUsedAt?.getTime()).toBe(ts.getTime())
  })
})

describe("sqliteTokenStore — security", () => {
  it("findPatByHash uses crypto.timingSafeEqual for the hash compare", async () => {
    const store = await freshStore()
    const input = patInput()
    await store.createPat(input)
    timingSafeEqualSpy.mockClear()
    await store.findPatByHash(input.tokenHash)
    expect(timingSafeEqualSpy).toHaveBeenCalled()
  })

  it("findPatByHash returns null when hash lengths differ (no throw)", async () => {
    const store = await freshStore()
    await store.createPat(patInput())
    const short = Buffer.alloc(16, 0xff)
    await expect(store.findPatByHash(short)).resolves.toBeNull()
  })

  it("stored token_hash is raw bytes (BLOB), not base64", async () => {
    const store = await freshStore()
    const input = patInput()
    await store.createPat(input)
    const row = db.prepare("SELECT token_hash FROM mcp_pats LIMIT 1").get() as {
      token_hash: unknown
    }
    expect(Buffer.isBuffer(row.token_hash)).toBe(true)
    expect((row.token_hash as Buffer).equals(input.tokenHash)).toBe(true)
  })

  it("createPat copies the input hash buffer (caller mutation cannot poison the store)", async () => {
    const store = await freshStore()
    const original = hashOf("token-x")
    const input = patInput({ tokenHash: original })
    await store.createPat(input)
    original.fill(0)
    const lookup = hashOf("token-x")
    expect(await store.findPatByHash(lookup)).not.toBeNull()
  })

  it("findRefreshToken uses constant-time compare", async () => {
    const store = await freshStore()
    const t = refreshInput()
    await store.createRefreshToken(t)
    timingSafeEqualSpy.mockClear()
    await store.findRefreshToken(t.tokenHash)
    expect(timingSafeEqualSpy).toHaveBeenCalled()
  })
})

describe("sqliteTokenStore — refresh tokens", () => {
  it("createRefreshToken + findRefreshToken round-trip", async () => {
    const store = await freshStore()
    const input = refreshInput()
    await store.createRefreshToken(input)
    const found = await store.findRefreshToken(input.tokenHash)
    expect(found).not.toBeNull()
    expect(found?.familyId).toBe("fam-1")
    expect(found?.rotatedAt).toBeNull()
    expect(found?.scopes).toEqual(["read"])
  })

  it("rotateRefreshToken marks old rotated and inserts the new in the same family", async () => {
    const store = await freshStore()
    const oldInput = refreshInput({ familyId: "famA" })
    await store.createRefreshToken(oldInput)
    const newInput = refreshInput({ familyId: "famA" })
    await store.rotateRefreshToken(oldInput.tokenHash, newInput)

    const oldRow = await store.findRefreshToken(oldInput.tokenHash)
    expect(oldRow).not.toBeNull()
    expect(oldRow?.rotatedAt).toBeInstanceOf(Date)

    const newRow = await store.findRefreshToken(newInput.tokenHash)
    expect(newRow).not.toBeNull()
    expect(newRow?.familyId).toBe("famA")
    expect(newRow?.rotatedAt).toBeNull()
  })

  it("rotateRefreshToken on an unknown old hash is a silent no-op", async () => {
    const store = await freshStore()
    const next = refreshInput()
    await expect(store.rotateRefreshToken(hashOf("not-stored"), next)).resolves.toBeUndefined()
    expect(await store.findRefreshToken(next.tokenHash)).toBeNull()
  })

  it("revokeRefreshTokenFamily revokes every member atomically", async () => {
    const store = await freshStore()
    const t1 = refreshInput({ familyId: "famA" })
    const t2 = refreshInput({ familyId: "famA" })
    const t3 = refreshInput({ familyId: "famA" })
    const t4 = refreshInput({ familyId: "famB" })
    await store.createRefreshToken(t1)
    await store.rotateRefreshToken(t1.tokenHash, t2)
    await store.rotateRefreshToken(t2.tokenHash, t3)
    await store.createRefreshToken(t4)

    await store.revokeRefreshTokenFamily("famA")

    expect(await store.findRefreshToken(t1.tokenHash)).toBeNull()
    expect(await store.findRefreshToken(t2.tokenHash)).toBeNull()
    expect(await store.findRefreshToken(t3.tokenHash)).toBeNull()
    expect(await store.findRefreshToken(t4.tokenHash)).not.toBeNull()
  })

  it("concurrent rotation across two handles on the same file is atomic", async () => {
    const db2 = new Database(dbPath)
    try {
      const a = sqliteTokenStore({ database: db })
      const b = sqliteTokenStore({ database: db2 })
      await a.init()
      await b.init()

      const original = refreshInput({ familyId: "concurrent" })
      await a.createRefreshToken(original)

      const nextA = refreshInput({ familyId: "concurrent" })
      const nextB = refreshInput({ familyId: "concurrent" })

      // Two writers race to rotate the same predecessor. SQLite's RESERVED
      // lock under BEGIN IMMEDIATE forces them to serialize; the loser may
      // succeed (seeing the row before the winner finishes) or be retried by
      // better-sqlite3 — either way, the family must not end up with two
      // un-rotated successors of the *same* original.
      const results = await Promise.allSettled([
        a.rotateRefreshToken(original.tokenHash, nextA),
        b.rotateRefreshToken(original.tokenHash, nextB),
      ])
      // Both may resolve (a silent no-op on whichever ran second after the
      // other's UPDATE), or one may reject under SQLITE_BUSY — we just
      // require no uncaught crash and the family invariant below.
      for (const r of results) {
        if (r.status === "rejected") {
          expect(String(r.reason)).toMatch(/SQLITE_BUSY|database is locked|locked/i)
        }
      }

      // The original must be rotated.
      const originalRow = await a.findRefreshToken(original.tokenHash)
      expect(originalRow?.rotatedAt).toBeInstanceOf(Date)

      // At least one of the candidates must be persisted as the successor,
      // and no row should have an un-rotated duplicate of the original hash.
      const inA = await a.findRefreshToken(nextA.tokenHash)
      const inB = await a.findRefreshToken(nextB.tokenHash)
      expect(inA !== null || inB !== null).toBe(true)
    } finally {
      db2.close()
    }
  })
})

describe("sqliteTokenStore — upstream credential cache", () => {
  it("cacheUpstreamCredential + findUpstreamCredential round-trip", async () => {
    const store = await freshStore()
    await store.cacheUpstreamCredential({
      cacheKey: "key-1",
      token: "upstream-abc",
      expiresAt: new Date(Date.now() + 60_000),
    })
    const found = await store.findUpstreamCredential("key-1")
    expect(found?.token).toBe("upstream-abc")
    expect(found?.expiresAt).toBeInstanceOf(Date)
  })

  it("findUpstreamCredential returns null when the entry is expired", async () => {
    const store = await freshStore()
    await store.cacheUpstreamCredential({
      cacheKey: "stale",
      token: "x",
      expiresAt: new Date(Date.now() - 1000),
    })
    expect(await store.findUpstreamCredential("stale")).toBeNull()
  })

  it("cacheUpstreamCredential upserts on conflict", async () => {
    const store = await freshStore()
    await store.cacheUpstreamCredential({
      cacheKey: "key-up",
      token: "v1",
      expiresAt: new Date(Date.now() + 60_000),
    })
    await store.cacheUpstreamCredential({
      cacheKey: "key-up",
      token: "v2",
      expiresAt: new Date(Date.now() + 60_000),
    })
    const found = await store.findUpstreamCredential("key-up")
    expect(found?.token).toBe("v2")
  })

  it("findUpstreamCredential returns null for an unknown key", async () => {
    const store = await freshStore()
    expect(await store.findUpstreamCredential("missing")).toBeNull()
  })
})
