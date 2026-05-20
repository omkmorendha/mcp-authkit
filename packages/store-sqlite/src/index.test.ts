/**
 * Unit tests for `sqliteTokenStore` against a real in-memory `better-sqlite3`
 * `Database`. SQLite is in-process and has no native deps beyond the
 * `better-sqlite3` prebuild, so we do not gate these tests on env vars —
 * they always run.
 *
 * Integration scenarios that require file-backed durability (WAL mode,
 * concurrent rotation across two handles) live in integration.test.ts.
 */

import { createHash, randomBytes } from "node:crypto"
import Database from "better-sqlite3"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { InvalidIdentifierError } from "./identifiers.js"
import {
  type CreatePatInput,
  type CreateRefreshTokenInput,
  RefreshTokenReuseError,
  sqliteTokenStore,
  type TokenStore,
} from "./index.js"

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

async function makeStore(
  opts: { tableNames?: Parameters<typeof sqliteTokenStore>[0]["tableNames"] } = {},
): Promise<{ store: TokenStore; db: Database.Database }> {
  // `:memory:` is always file-private; each test gets a fresh DB.
  const db = new Database(":memory:")
  const store = sqliteTokenStore({
    database: db,
    ...(opts.tableNames ? { tableNames: opts.tableNames } : {}),
  })
  await store.init?.()
  return { store, db }
}

describe("sqliteTokenStore — construction", () => {
  it.each([
    ["pats", { pats: "x; DROP TABLE pats; --" }],
    ["refreshTokens", { refreshTokens: 'foo"bar' }],
    ["upstreamCredentials", { upstreamCredentials: "with space" }],
    ["migrations", { migrations: "schema.table" }],
  ] as const)("rejects %s table override with disallowed chars", (_label, overrides) => {
    const db = new Database(":memory:")
    expect(() => sqliteTokenStore({ database: db, tableNames: overrides })).toThrow(
      InvalidIdentifierError,
    )
    db.close()
  })

  it("accepts valid overrides and uses them in the schema", async () => {
    const db = new Database(":memory:")
    const store = sqliteTokenStore({
      database: db,
      tableNames: { pats: "p", refreshTokens: "r", upstreamCredentials: "u" },
    })
    await store.init?.()
    const input = patInput()
    await store.createPat(input)
    const row = db
      .prepare(`SELECT user_identifier FROM "p" WHERE user_identifier = ?`)
      .get(input.userIdentifier)
    expect(row).toBeTruthy()
    db.close()
  })

  it("warns when the database is opened readonly", async () => {
    const warn = vi.fn<(m: string) => void>()
    // Create a file with the schema applied, then reopen readonly.
    const path = `/tmp/mcp-authkit-readonly-${randomBytes(6).toString("hex")}.db`
    const writer = new Database(path)
    const wstore = sqliteTokenStore({ database: writer })
    await wstore.init?.()
    writer.close()
    const reader = new Database(path, { readonly: true })
    sqliteTokenStore({ database: reader, warn })
    expect(warn).toHaveBeenCalledTimes(1)
    expect(warn.mock.calls[0]?.[0]).toMatch(/readonly/)
    reader.close()
  })
})

describe("sqliteTokenStore — PAT", () => {
  let store: TokenStore
  let db: Database.Database

  beforeEach(async () => {
    ;({ store, db } = await makeStore())
  })
  afterEach(() => db.close())

  it("createPat + findPatByHash round-trip", async () => {
    const input = patInput()
    const stored = await store.createPat(input)
    expect(stored.id).toBeTruthy()
    expect(stored.createdAt).toBeInstanceOf(Date)
    expect(stored.revokedAt).toBeNull()
    expect(stored.lastUsedAt).toBeNull()
    expect(Buffer.isBuffer(stored.tokenHash)).toBe(true)

    const found = await store.findPatByHash(input.tokenHash)
    expect(found).not.toBeNull()
    expect(found?.id).toBe(stored.id)
    expect(found?.scopes).toEqual(["read"])
  })

  it("findPatByHash returns null for unknown hash", async () => {
    await store.createPat(patInput())
    expect(await store.findPatByHash(hashOf("other"))).toBeNull()
  })

  it("findPatByHash returns null for revoked PAT", async () => {
    const input = patInput()
    const stored = await store.createPat(input)
    await store.revokePat(stored.id, stored.userIdentifier)
    expect(await store.findPatByHash(input.tokenHash)).toBeNull()
  })

  it("findPatByHash returns null for expired PAT", async () => {
    const input = patInput({ expiresAt: new Date(Date.now() - 1000) })
    await store.createPat(input)
    expect(await store.findPatByHash(input.tokenHash)).toBeNull()
  })

  it("listPatsByUser is scoped to the user and excludes revoked PATs", async () => {
    await store.createPat(patInput({ userIdentifier: "user-a", name: "a1" }))
    const b = await store.createPat(patInput({ userIdentifier: "user-a", name: "a2" }))
    await store.createPat(patInput({ userIdentifier: "user-b", name: "b1" }))
    await store.revokePat(b.id, b.userIdentifier)
    const a = await store.listPatsByUser("user-a")
    expect(a.map((p) => p.name)).toEqual(["a1"])
    const allB = await store.listPatsByUser("user-b")
    expect(allB.map((p) => p.name)).toEqual(["b1"])
  })

  it("revokePat is idempotent and scoped to the owner", async () => {
    const a = await store.createPat(patInput({ userIdentifier: "user-a" }))
    await store.revokePat(a.id, "user-b") // wrong user — no-op
    expect(await store.listPatsByUser("user-a")).toHaveLength(1)
    await store.revokePat(a.id, "user-a")
    await store.revokePat(a.id, "user-a")
    expect(await store.listPatsByUser("user-a")).toHaveLength(0)
  })

  it("rotatePat inserts a successor and leaves the predecessor", async () => {
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
    const a = await store.createPat(patInput({ userIdentifier: "user-a" }))
    await expect(
      store.rotatePat(a.id, "user-b", patInput({ userIdentifier: "user-b" })),
    ).rejects.toThrow(/not found/)
  })

  it("rotatePat rejects a `next` whose userIdentifier does not match", async () => {
    const a = await store.createPat(patInput({ userIdentifier: "user-a" }))
    await expect(
      store.rotatePat(a.id, "user-a", patInput({ userIdentifier: "user-b" })),
    ).rejects.toThrow(/user mismatch/)
  })

  it("updatePatLastUsed sets the timestamp", async () => {
    const a = await store.createPat(patInput())
    const ts = new Date()
    await store.updatePatLastUsed(a.id, ts)
    const found = await store.findPatByHash(a.tokenHash)
    expect(found?.lastUsedAt?.getTime()).toBe(ts.getTime())
  })
})

describe("sqliteTokenStore — refresh tokens", () => {
  let store: TokenStore
  let db: Database.Database

  beforeEach(async () => {
    ;({ store, db } = await makeStore())
  })
  afterEach(() => db.close())

  it("createRefreshToken + findRefreshToken round-trip", async () => {
    const input = refreshInput()
    await store.createRefreshToken(input)
    const found = await store.findRefreshToken(input.tokenHash)
    expect(found?.familyId).toBe("fam-1")
    expect(found?.rotatedAt).toBeNull()
    expect(found?.scopes).toEqual(["read"])
  })

  it("rotateRefreshToken marks old rotated and inserts new in same family", async () => {
    const oldT = refreshInput({ familyId: "famA" })
    await store.createRefreshToken(oldT)
    const newT = refreshInput({ familyId: "famA" })
    await store.rotateRefreshToken(oldT.tokenHash, newT)
    const oldRow = await store.findRefreshToken(oldT.tokenHash)
    expect(oldRow?.rotatedAt).toBeInstanceOf(Date)
    const newRow = await store.findRefreshToken(newT.tokenHash)
    expect(newRow?.familyId).toBe("famA")
    expect(newRow?.rotatedAt).toBeNull()
  })

  it("rotateRefreshToken on an unknown hash is a silent no-op", async () => {
    await expect(
      store.rotateRefreshToken(hashOf("missing"), refreshInput()),
    ).resolves.toBeUndefined()
  })

  it("rotateRefreshToken on an already-rotated hash throws and revokes the family", async () => {
    const t1 = refreshInput({ familyId: "famA" })
    await store.createRefreshToken(t1)
    const t2 = refreshInput({ familyId: "famA" })
    await store.rotateRefreshToken(t1.tokenHash, t2)
    const t3 = refreshInput({ familyId: "famA" })
    await expect(store.rotateRefreshToken(t1.tokenHash, t3)).rejects.toBeInstanceOf(
      RefreshTokenReuseError,
    )
    expect(await store.findRefreshToken(t1.tokenHash)).toBeNull()
    expect(await store.findRefreshToken(t2.tokenHash)).toBeNull()
    expect(await store.findRefreshToken(t3.tokenHash)).toBeNull()
  })

  it("revokeRefreshTokenFamily removes only the named family", async () => {
    const a = refreshInput({ familyId: "famA" })
    const b = refreshInput({ familyId: "famB" })
    await store.createRefreshToken(a)
    await store.createRefreshToken(b)
    await store.revokeRefreshTokenFamily("famA")
    expect(await store.findRefreshToken(a.tokenHash)).toBeNull()
    expect(await store.findRefreshToken(b.tokenHash)).not.toBeNull()
  })

  it("reuse path commits the family DELETE before throwing", async () => {
    const t1 = refreshInput({ familyId: "famX" })
    await store.createRefreshToken(t1)
    const t2 = refreshInput({ familyId: "famX" })
    await store.rotateRefreshToken(t1.tokenHash, t2)
    const t3 = refreshInput({ familyId: "famX" })
    await expect(store.rotateRefreshToken(t1.tokenHash, t3)).rejects.toBeInstanceOf(
      RefreshTokenReuseError,
    )
    // Family wiped — defining property of the spec §14 family-revoke
    // semantics. If the throw rolled back the DELETE, the row would still
    // exist.
    const row = db
      .prepare(`SELECT COUNT(*) AS n FROM "mcp_refresh_tokens" WHERE family_id = ?`)
      .get("famX") as { n: number }
    expect(row.n).toBe(0)
  })
})

describe("sqliteTokenStore — security", () => {
  it("findPatByHash uses crypto.timingSafeEqual after the SQL lookup", async () => {
    timingSafeEqualSpy.mockClear()
    const { store, db } = await makeStore()
    try {
      const input = patInput()
      await store.createPat(input)
      await store.findPatByHash(input.tokenHash)
      expect(timingSafeEqualSpy).toHaveBeenCalled()
    } finally {
      db.close()
    }
  })

  it("findRefreshToken uses constant-time compare after the SQL lookup", async () => {
    timingSafeEqualSpy.mockClear()
    const { store, db } = await makeStore()
    try {
      const t = refreshInput()
      await store.createRefreshToken(t)
      await store.findRefreshToken(t.tokenHash)
      expect(timingSafeEqualSpy).toHaveBeenCalled()
    } finally {
      db.close()
    }
  })

  it("createPat defensively copies the input hash buffer", async () => {
    const { store, db } = await makeStore()
    try {
      const original = hashOf("token-x")
      await store.createPat(patInput({ tokenHash: original }))
      original.fill(0)
      expect(await store.findPatByHash(hashOf("token-x"))).not.toBeNull()
    } finally {
      db.close()
    }
  })

  it("user-supplied strings flow through parameters, never SQL interpolation", async () => {
    const { store, db } = await makeStore()
    try {
      const evilUser = "user'; DROP TABLE mcp_pats; --"
      await store.createPat(patInput({ userIdentifier: evilUser, name: evilUser }))
      // The PATs table still exists and contains the row with the literal
      // string as a parameter value — proves it went through the bind path,
      // not the SQL string.
      const row = db
        .prepare(`SELECT user_identifier FROM "mcp_pats" WHERE user_identifier = ?`)
        .get(evilUser) as { user_identifier: string } | undefined
      expect(row?.user_identifier).toBe(evilUser)
      // Sanity: the table is intact.
      const count = db.prepare(`SELECT COUNT(*) AS n FROM "mcp_pats"`).get() as { n: number }
      expect(count.n).toBe(1)
    } finally {
      db.close()
    }
  })
})

describe("sqliteTokenStore — upstream credential cache (spec §6.2)", () => {
  let store: TokenStore
  let db: Database.Database

  beforeEach(async () => {
    ;({ store, db } = await makeStore())
  })
  afterEach(() => db.close())

  it("cacheUpstreamCredential / findUpstreamCredential round-trip", async () => {
    expect(store.cacheUpstreamCredential).toBeTypeOf("function")
    expect(store.findUpstreamCredential).toBeTypeOf("function")
    await store.cacheUpstreamCredential?.({
      cacheKey: "k1",
      token: "tok-upstream",
      expiresAt: new Date(Date.now() + 60_000),
    })
    const got = await store.findUpstreamCredential?.("k1")
    expect(got?.token).toBe("tok-upstream")
  })

  it("findUpstreamCredential returns null for missing keys", async () => {
    expect(await store.findUpstreamCredential?.("nope")).toBeNull()
  })

  it("findUpstreamCredential treats expired entries as miss", async () => {
    await store.cacheUpstreamCredential?.({
      cacheKey: "k2",
      token: "tok",
      expiresAt: new Date(Date.now() - 1000),
    })
    expect(await store.findUpstreamCredential?.("k2")).toBeNull()
  })

  it("cacheUpstreamCredential overwrites the previous value (UPSERT)", async () => {
    await store.cacheUpstreamCredential?.({
      cacheKey: "k3",
      token: "v1",
      expiresAt: new Date(Date.now() + 60_000),
    })
    await store.cacheUpstreamCredential?.({
      cacheKey: "k3",
      token: "v2",
      expiresAt: new Date(Date.now() + 60_000),
    })
    expect((await store.findUpstreamCredential?.("k3"))?.token).toBe("v2")
  })
})

describe("sqliteTokenStore — init / migrations", () => {
  it("applies migrations and records them in mcp_migrations", async () => {
    const db = new Database(":memory:")
    const store = sqliteTokenStore({ database: db })
    await store.init?.()
    const rows = db.prepare(`SELECT id, name FROM "mcp_migrations" ORDER BY id`).all() as Array<{
      id: number
      name: string
    }>
    expect(rows).toHaveLength(1)
    expect(rows[0]?.name).toBe("001_init")
    db.close()
  })

  it("is idempotent — re-running init does not re-apply migrations", async () => {
    const db = new Database(":memory:")
    const store = sqliteTokenStore({ database: db })
    await store.init?.()
    await store.init?.()
    await store.init?.()
    const rows = db.prepare(`SELECT id FROM "mcp_migrations"`).all() as Array<{ id: number }>
    expect(rows).toHaveLength(1)
    db.close()
  })

  it("close() is a no-op — does not close the database", async () => {
    const { store, db } = await makeStore()
    await expect(store.close?.()).resolves.toBeUndefined()
    // DB is still usable after store.close().
    await store.createPat(patInput())
    db.close()
  })
})
