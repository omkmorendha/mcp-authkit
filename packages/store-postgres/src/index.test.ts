import { createHash, randomBytes } from "node:crypto"
import { describe, expect, it, vi } from "vitest"
import { createFakePool } from "./fake-pg.js"
import { InvalidIdentifierError } from "./identifiers.js"
import {
  type CreatePatInput,
  type CreateRefreshTokenInput,
  postgresTokenStore,
  RefreshTokenReuseError,
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

describe("postgresTokenStore — construction", () => {
  it("rejects schema overrides outside [A-Za-z0-9_]", () => {
    const { pool } = createFakePool()
    expect(() => postgresTokenStore({ pool, schema: "pub;DROP" })).toThrow(InvalidIdentifierError)
  })

  it.each([
    ["pats", { pats: "x; DROP TABLE pats; --" }],
    ["refreshTokens", { refreshTokens: 'foo"bar' }],
    ["upstreamCredentials", { upstreamCredentials: "with space" }],
    ["migrations", { migrations: "schema.table" }],
  ] as const)("rejects %s table override with disallowed chars", (_label, overrides) => {
    const { pool } = createFakePool()
    expect(() => postgresTokenStore({ pool, tableNames: overrides })).toThrow(
      InvalidIdentifierError,
    )
  })

  it("accepts valid overrides and qualifies them with the schema", async () => {
    const ctrl = createFakePool()
    const store = postgresTokenStore({
      pool: ctrl.pool,
      schema: "authkit",
      tableNames: { pats: "p", refreshTokens: "r", upstreamCredentials: "u" },
    })
    await store.createPat?.(patInput())
    const insert = ctrl.queries.find((q) => /INSERT INTO "authkit"\."p"/.test(q.sql))
    expect(insert).toBeTruthy()
  })
})

describe("postgresTokenStore — PAT", () => {
  it("createPat + findPatByHash round-trip", async () => {
    const ctrl = createFakePool()
    const store = postgresTokenStore({ pool: ctrl.pool })
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
  })

  it("findPatByHash returns null for unknown hash", async () => {
    const ctrl = createFakePool()
    const store = postgresTokenStore({ pool: ctrl.pool })
    await store.createPat(patInput())
    expect(await store.findPatByHash(hashOf("other"))).toBeNull()
  })

  it("findPatByHash returns null for revoked PAT", async () => {
    const ctrl = createFakePool()
    const store = postgresTokenStore({ pool: ctrl.pool })
    const input = patInput()
    const stored = await store.createPat(input)
    await store.revokePat(stored.id, stored.userIdentifier)
    expect(await store.findPatByHash(input.tokenHash)).toBeNull()
  })

  it("findPatByHash returns null for expired PAT", async () => {
    const ctrl = createFakePool()
    const store = postgresTokenStore({ pool: ctrl.pool })
    const input = patInput({ expiresAt: new Date(Date.now() - 1000) })
    await store.createPat(input)
    expect(await store.findPatByHash(input.tokenHash)).toBeNull()
  })

  it("listPatsByUser is scoped to the user and excludes revoked PATs", async () => {
    const ctrl = createFakePool()
    const store = postgresTokenStore({ pool: ctrl.pool })
    await store.createPat(patInput({ userIdentifier: "user-a", name: "a1" }))
    const b = await store.createPat(patInput({ userIdentifier: "user-a", name: "a2" }))
    await store.createPat(patInput({ userIdentifier: "user-b", name: "b1" }))
    await store.revokePat(b.id, b.userIdentifier)
    const a = await store.listPatsByUser("user-a")
    expect(a.map((p) => p.name)).toEqual(["a1"])
    const all = await store.listPatsByUser("user-b")
    expect(all.map((p) => p.name)).toEqual(["b1"])
  })

  it("revokePat is idempotent and scoped to the owner", async () => {
    const ctrl = createFakePool()
    const store = postgresTokenStore({ pool: ctrl.pool })
    const a = await store.createPat(patInput({ userIdentifier: "user-a" }))
    await store.revokePat(a.id, "user-b") // wrong user — no-op
    expect(await store.listPatsByUser("user-a")).toHaveLength(1)
    await store.revokePat(a.id, "user-a")
    await store.revokePat(a.id, "user-a")
    expect(await store.listPatsByUser("user-a")).toHaveLength(0)
  })

  it("rotatePat inserts a successor and leaves the predecessor", async () => {
    const ctrl = createFakePool()
    const store = postgresTokenStore({ pool: ctrl.pool })
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
    const ctrl = createFakePool()
    const store = postgresTokenStore({ pool: ctrl.pool })
    const a = await store.createPat(patInput({ userIdentifier: "user-a" }))
    await expect(store.rotatePat(a.id, "user-b", patInput())).rejects.toThrow(/not found/)
  })

  it("updatePatLastUsed sets the timestamp", async () => {
    const ctrl = createFakePool()
    const store = postgresTokenStore({ pool: ctrl.pool })
    const a = await store.createPat(patInput())
    const ts = new Date()
    await store.updatePatLastUsed(a.id, ts)
    const found = await store.findPatByHash(a.tokenHash)
    expect(found?.lastUsedAt?.getTime()).toBe(ts.getTime())
  })
})

describe("postgresTokenStore — security", () => {
  it("findPatByHash uses crypto.timingSafeEqual after the SQL lookup", async () => {
    timingSafeEqualSpy.mockClear()
    const ctrl = createFakePool()
    const store = postgresTokenStore({ pool: ctrl.pool })
    const input = patInput()
    await store.createPat(input)
    await store.findPatByHash(input.tokenHash)
    expect(timingSafeEqualSpy).toHaveBeenCalled()
  })

  it("findRefreshToken uses constant-time compare after the SQL lookup", async () => {
    timingSafeEqualSpy.mockClear()
    const ctrl = createFakePool()
    const store = postgresTokenStore({ pool: ctrl.pool })
    const t = refreshInput()
    await store.createRefreshToken(t)
    await store.findRefreshToken(t.tokenHash)
    expect(timingSafeEqualSpy).toHaveBeenCalled()
  })

  it("createPat defensively copies the input hash buffer", async () => {
    const ctrl = createFakePool()
    const store = postgresTokenStore({ pool: ctrl.pool })
    const original = hashOf("token-x")
    await store.createPat(patInput({ tokenHash: original }))
    original.fill(0)
    expect(await store.findPatByHash(hashOf("token-x"))).not.toBeNull()
  })

  it("every PAT/refresh query is parameterized — user-supplied strings are passed as params, not interpolated", async () => {
    const ctrl = createFakePool()
    const store = postgresTokenStore({ pool: ctrl.pool })
    const evilUser = "user'; DROP TABLE mcp_pats; --"
    await store.createPat(patInput({ userIdentifier: evilUser, name: evilUser }))
    // The SQL of every recorded statement must not contain the evil string.
    for (const q of ctrl.queries) {
      expect(q.sql).not.toContain(evilUser)
    }
    // ...and the evil string must appear at least once as a parameter value
    // (proving it was passed through the parameter path).
    const evilParams = ctrl.queries.flatMap((q) => q.params).filter((p) => p === evilUser)
    expect(evilParams.length).toBeGreaterThan(0)
  })
})

describe("postgresTokenStore — refresh tokens", () => {
  it("createRefreshToken + findRefreshToken round-trip", async () => {
    const ctrl = createFakePool()
    const store = postgresTokenStore({ pool: ctrl.pool })
    const input = refreshInput()
    await store.createRefreshToken(input)
    const found = await store.findRefreshToken(input.tokenHash)
    expect(found?.familyId).toBe("fam-1")
    expect(found?.rotatedAt).toBeNull()
  })

  it("rotateRefreshToken marks old rotated and inserts new in same family", async () => {
    const ctrl = createFakePool()
    const store = postgresTokenStore({ pool: ctrl.pool })
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
    const ctrl = createFakePool()
    const store = postgresTokenStore({ pool: ctrl.pool })
    await expect(
      store.rotateRefreshToken(hashOf("missing"), refreshInput()),
    ).resolves.toBeUndefined()
  })

  it("rotateRefreshToken on an already-rotated hash throws and revokes the family", async () => {
    const ctrl = createFakePool()
    const store = postgresTokenStore({ pool: ctrl.pool })
    const t1 = refreshInput({ familyId: "famA" })
    await store.createRefreshToken(t1)
    const t2 = refreshInput({ familyId: "famA" })
    await store.rotateRefreshToken(t1.tokenHash, t2)
    // Reuse of t1: throws and the family is gone.
    const t3 = refreshInput({ familyId: "famA" })
    await expect(store.rotateRefreshToken(t1.tokenHash, t3)).rejects.toBeInstanceOf(
      RefreshTokenReuseError,
    )
    expect(await store.findRefreshToken(t1.tokenHash)).toBeNull()
    expect(await store.findRefreshToken(t2.tokenHash)).toBeNull()
    expect(await store.findRefreshToken(t3.tokenHash)).toBeNull()
  })

  it("revokeRefreshTokenFamily removes only the named family", async () => {
    const ctrl = createFakePool()
    const store = postgresTokenStore({ pool: ctrl.pool })
    const a = refreshInput({ familyId: "famA" })
    const b = refreshInput({ familyId: "famB" })
    await store.createRefreshToken(a)
    await store.createRefreshToken(b)
    await store.revokeRefreshTokenFamily("famA")
    expect(await store.findRefreshToken(a.tokenHash)).toBeNull()
    expect(await store.findRefreshToken(b.tokenHash)).not.toBeNull()
  })

  it("rotateRefreshToken runs inside a single BEGIN/COMMIT transaction", async () => {
    const ctrl = createFakePool()
    const store = postgresTokenStore({ pool: ctrl.pool })
    const t1 = refreshInput()
    await store.createRefreshToken(t1)
    ctrl.queries.length = 0
    await store.rotateRefreshToken(t1.tokenHash, refreshInput({ familyId: "fam-1" }))
    const ordered = ctrl.queries.map((q) => q.sql.trim().split(/\s+/)[0]?.toUpperCase())
    expect(ordered).toContain("BEGIN")
    expect(ordered).toContain("COMMIT")
    expect(ordered.indexOf("BEGIN")).toBeLessThan(ordered.indexOf("COMMIT"))
  })

  it("rotateRefreshToken reuse path commits the family DELETE before throwing", async () => {
    const ctrl = createFakePool()
    const store = postgresTokenStore({ pool: ctrl.pool })
    const t1 = refreshInput({ familyId: "famX" })
    await store.createRefreshToken(t1)
    const t2 = refreshInput({ familyId: "famX" })
    await store.rotateRefreshToken(t1.tokenHash, t2)
    ctrl.queries.length = 0
    const t3 = refreshInput({ familyId: "famX" })
    await expect(store.rotateRefreshToken(t1.tokenHash, t3)).rejects.toBeInstanceOf(
      RefreshTokenReuseError,
    )
    // Spec §14: reuse revokes the family. The DELETE MUST be committed,
    // so the transaction must COMMIT, then the RefreshTokenReuseError is
    // thrown outside the transaction. Real-engine semantics tested in
    // integration.test.ts; here we assert the SQL ordering.
    const sqls = ctrl.queries.map((q) => q.sql)
    expect(sqls.some((s) => /^BEGIN$/.test(s.trim()))).toBe(true)
    expect(sqls.some((s) => /^COMMIT$/.test(s.trim()))).toBe(true)
    expect(sqls.some((s) => /^ROLLBACK$/.test(s.trim()))).toBe(false)
    expect(sqls.some((s) => /DELETE FROM .* WHERE family_id/i.test(s))).toBe(true)
  })
})

describe("postgresTokenStore — upstream credential cache (spec §6.2)", () => {
  it("cacheUpstreamCredential / findUpstreamCredential round-trip", async () => {
    const ctrl = createFakePool()
    const store = postgresTokenStore({ pool: ctrl.pool })
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
    const ctrl = createFakePool()
    const store = postgresTokenStore({ pool: ctrl.pool })
    expect(await store.findUpstreamCredential?.("nope")).toBeNull()
  })

  it("findUpstreamCredential treats expired entries as miss", async () => {
    const ctrl = createFakePool()
    const store = postgresTokenStore({ pool: ctrl.pool })
    await store.cacheUpstreamCredential?.({
      cacheKey: "k2",
      token: "tok",
      expiresAt: new Date(Date.now() - 1000),
    })
    expect(await store.findUpstreamCredential?.("k2")).toBeNull()
  })

  it("cacheUpstreamCredential overwrites the previous value (UPSERT)", async () => {
    const ctrl = createFakePool()
    const store = postgresTokenStore({ pool: ctrl.pool })
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

describe("postgresTokenStore — init / migrations", () => {
  it("applies migrations and records them in mcp_migrations", async () => {
    const ctrl = createFakePool()
    const store = postgresTokenStore({ pool: ctrl.pool })
    await store.init?.()
    expect(ctrl.migrationsTable.size).toBe(1)
    expect([...ctrl.migrationsTable.values()][0]?.name).toBe("001_init")
  })

  it("is idempotent — re-running init does not re-apply migrations", async () => {
    const ctrl = createFakePool()
    const store = postgresTokenStore({ pool: ctrl.pool })
    await store.init?.()
    const firstCount = ctrl.queries.filter((q) =>
      /^INSERT INTO ".+"\.".+" \(id, name\) VALUES/.test(q.sql.trim()),
    ).length
    await store.init?.()
    const secondCount = ctrl.queries.filter((q) =>
      /^INSERT INTO ".+"\.".+" \(id, name\) VALUES/.test(q.sql.trim()),
    ).length
    expect(firstCount).toBe(1)
    expect(secondCount).toBe(1) // unchanged — the second init() applied nothing.
  })

  it("init takes LOCK TABLE mcp_migrations IN EXCLUSIVE MODE before applying", async () => {
    const ctrl = createFakePool()
    const store = postgresTokenStore({ pool: ctrl.pool })
    await store.init?.()
    const lockIdx = ctrl.queries.findIndex((q) =>
      /^LOCK TABLE ".+"\."mcp_migrations" IN EXCLUSIVE MODE$/.test(q.sql.trim()),
    )
    const applyIdx = ctrl.queries.findIndex((q) =>
      /CREATE TABLE IF NOT EXISTS ".+"\."mcp_pats"/.test(q.sql.trim()),
    )
    expect(lockIdx).toBeGreaterThan(-1)
    expect(applyIdx).toBeGreaterThan(-1)
    expect(lockIdx).toBeLessThan(applyIdx)
  })
})

describe("postgresTokenStore — statement timeout", () => {
  it("sets statement_timeout on every checked-out connection", async () => {
    const ctrl = createFakePool()
    const store = postgresTokenStore({ pool: ctrl.pool, statementTimeoutMs: 1234 })
    await store.createPat(patInput())
    const sets = ctrl.queries.filter((q) =>
      /^SET (?:LOCAL )?statement_timeout = \d+$/.test(q.sql.trim()),
    )
    expect(sets.length).toBeGreaterThan(0)
    for (const q of sets) expect(q.sql).toContain("1234")
  })

  it("defaults to 5000ms", async () => {
    const ctrl = createFakePool()
    const store = postgresTokenStore({ pool: ctrl.pool })
    await store.createPat(patInput())
    const sets = ctrl.queries.filter((q) =>
      /^SET (?:LOCAL )?statement_timeout = \d+$/.test(q.sql.trim()),
    )
    expect(sets.length).toBeGreaterThan(0)
    for (const q of sets) expect(q.sql).toContain("5000")
  })

  it("transaction uses SET LOCAL inside BEGIN/COMMIT (auto-resets at commit)", async () => {
    const ctrl = createFakePool()
    const store = postgresTokenStore({ pool: ctrl.pool, statementTimeoutMs: 250 })
    const t1 = refreshInput()
    await store.createRefreshToken(t1)
    ctrl.queries.length = 0
    await store.rotateRefreshToken(t1.tokenHash, refreshInput({ familyId: "fam-1" }))
    const ix = ctrl.queries.map((q) => q.sql.trim())
    const beginIdx = ix.indexOf("BEGIN")
    const setLocalIdx = ix.findIndex((s) => /^SET LOCAL statement_timeout = 250$/.test(s))
    expect(beginIdx).toBeGreaterThanOrEqual(0)
    expect(setLocalIdx).toBeGreaterThan(beginIdx)
  })

  it("does not silently swallow query-level timeouts", async () => {
    const ctrl = createFakePool()
    ctrl.beforeQuery = async (sql) => {
      if (/SELECT \* FROM/.test(sql)) {
        const err = new Error("canceling statement due to statement timeout") as Error & {
          code?: string
        }
        err.code = "57014"
        throw err
      }
    }
    const store = postgresTokenStore({ pool: ctrl.pool })
    await expect(store.findPatByHash(Buffer.alloc(32))).rejects.toThrow(/statement timeout/)
  })

  it("clamps non-positive timeouts to 1ms (defensive)", async () => {
    const ctrl = createFakePool()
    const store = postgresTokenStore({ pool: ctrl.pool, statementTimeoutMs: 0 })
    await store.createPat(patInput())
    const sets = ctrl.queries.filter((q) => /^SET statement_timeout = 1$/.test(q.sql.trim()))
    expect(sets.length).toBeGreaterThan(0)
  })
})

describe("postgresTokenStore — close()", () => {
  it("does not close the pool", async () => {
    const ctrl = createFakePool()
    const store = postgresTokenStore({ pool: ctrl.pool })
    // No `end` method on the fake pool; the store's close() must not try to
    // call anything pool-shaped beyond `connect`/`query`.
    await expect(store.close?.()).resolves.toBeUndefined()
    // Pool is still usable.
    await store.createPat(patInput())
  })
})
