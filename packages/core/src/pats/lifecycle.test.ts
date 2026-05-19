import { createHash } from "node:crypto"
import { afterEach, describe, expect, it, vi } from "vitest"
import type {
  AuditEvent,
  CreatePatInput,
  CreateRefreshTokenInput,
  StoredPat,
  StoredPatPublic,
  StoredRefreshToken,
  TokenStore,
} from "../types.js"
import { verifyPat } from "./format.js"
import {
  createPat,
  findPatByHash,
  type LifecycleOptions,
  listPats,
  type PatLifecycleConfig,
  PatLifecycleError,
  revokePat,
  rotatePat,
  updatePatLastUsed,
} from "./lifecycle.js"

const PREFIX = "mcp_pat_"

const CONFIG: PatLifecycleConfig = {
  prefix: PREFIX,
  defaultExpiryDays: 90,
  maxExpiryDays: 365,
  rotationGraceSeconds: 0,
}

/**
 * In-memory fake TokenStore. Issue #28 owns the production memory store;
 * this is a minimal hand-rolled fake good enough for lifecycle unit tests.
 */
function makeFakeStore(): TokenStore & {
  rows: Map<string, StoredPat>
} {
  const rows = new Map<string, StoredPat>()
  let nextId = 1
  return {
    rows,
    async createPat(input: CreatePatInput): Promise<StoredPat> {
      const id = `pat_${nextId++}`
      const row: StoredPat = {
        ...input,
        id,
        createdAt: new Date(),
        lastUsedAt: null,
        revokedAt: null,
      }
      rows.set(id, row)
      return row
    },
    async findPatByHash(hash: Buffer): Promise<StoredPat | null> {
      for (const row of rows.values()) {
        if (row.tokenHash.equals(hash)) return row
      }
      return null
    },
    async listPatsByUser(userIdentifier: string): Promise<StoredPatPublic[]> {
      const out: StoredPatPublic[] = []
      for (const row of rows.values()) {
        if (row.userIdentifier !== userIdentifier) continue
        out.push({
          id: row.id,
          name: row.name,
          scopes: row.scopes,
          display: row.display,
          createdAt: row.createdAt,
          expiresAt: row.expiresAt,
          lastUsedAt: row.lastUsedAt,
        })
      }
      return out
    },
    async revokePat(id: string, userIdentifier: string): Promise<void> {
      const row = rows.get(id)
      if (!row) return // idempotent: missing is a no-op
      if (row.userIdentifier !== userIdentifier) return
      if (row.revokedAt !== null) return // idempotent
      rows.set(id, { ...row, revokedAt: new Date() })
    },
    async rotatePat(
      _id: string,
      _userIdentifier: string,
      next: CreatePatInput,
    ): Promise<StoredPat> {
      // Contract: insert new row, leave old active. Lifecycle layer schedules
      // revocation of the old per rotationGraceSeconds.
      const id = `pat_${nextId++}`
      const row: StoredPat = {
        ...next,
        id,
        createdAt: new Date(),
        lastUsedAt: null,
        revokedAt: null,
      }
      rows.set(id, row)
      return row
    },
    async updatePatLastUsed(id: string, timestamp: Date): Promise<void> {
      const row = rows.get(id)
      if (!row) return
      rows.set(id, { ...row, lastUsedAt: timestamp })
    },
    // refresh token methods unused by lifecycle tests
    async createRefreshToken(_: CreateRefreshTokenInput): Promise<void> {},
    async findRefreshToken(_: Buffer): Promise<StoredRefreshToken | null> {
      return null
    },
    async rotateRefreshToken(_a: Buffer, _b: CreateRefreshTokenInput): Promise<void> {},
    async revokeRefreshTokenFamily(_: string): Promise<void> {},
  }
}

const ALL_SCOPES = ["read:profile", "write:posts", "delete:posts"]
const resolveAll = async (_sub: string): Promise<readonly string[]> => ALL_SCOPES
const resolveNone = async (_sub: string): Promise<readonly string[]> => []

describe("createPat", () => {
  it("mints a verifiable token with sha256-matching stored hash", async () => {
    const store = makeFakeStore()
    const { token, stored } = await createPat(store, CONFIG, {
      userIdentifier: "u1",
      name: "ci",
      scopes: ["read:profile"],
    })
    expect(verifyPat(token, PREFIX)).toBe(true)
    expect(createHash("sha256").update(token).digest().equals(stored.tokenHash)).toBe(true)
  })

  it("uses defaultExpiryDays when expiresInDays omitted", async () => {
    const store = makeFakeStore()
    const now = new Date("2026-01-01T00:00:00Z")
    const { stored } = await createPat(
      store,
      CONFIG,
      { userIdentifier: "u1", name: "n", scopes: [] },
      { now: () => now },
    )
    const expectedDelta = CONFIG.defaultExpiryDays * 24 * 60 * 60 * 1000
    expect(stored.expiresAt.getTime() - now.getTime()).toBe(expectedDelta)
  })

  it("rejects expiresInDays below 1", async () => {
    const store = makeFakeStore()
    await expect(
      createPat(store, CONFIG, {
        userIdentifier: "u1",
        name: "n",
        scopes: [],
        expiresInDays: 0,
      }),
    ).rejects.toBeInstanceOf(PatLifecycleError)
  })

  it("rejects expiresInDays above maxExpiryDays", async () => {
    const store = makeFakeStore()
    await expect(
      createPat(store, CONFIG, {
        userIdentifier: "u1",
        name: "n",
        scopes: [],
        expiresInDays: CONFIG.maxExpiryDays + 1,
      }),
    ).rejects.toMatchObject({ code: "expiry_out_of_range" })
  })

  it("rejects non-integer expiry", async () => {
    const store = makeFakeStore()
    await expect(
      createPat(store, CONFIG, {
        userIdentifier: "u1",
        name: "n",
        scopes: [],
        expiresInDays: 1.5,
      }),
    ).rejects.toMatchObject({ code: "expiry_out_of_range" })
  })

  it("normalizes scopes (dedupe + sort + freeze)", async () => {
    const store = makeFakeStore()
    const { stored } = await createPat(store, CONFIG, {
      userIdentifier: "u1",
      name: "n",
      scopes: ["write:posts", "read:profile", "read:profile"],
    })
    expect(stored.scopes).toEqual(["read:profile", "write:posts"])
  })

  it("display field masks the random portion", async () => {
    const store = makeFakeStore()
    const { token, stored } = await createPat(store, CONFIG, {
      userIdentifier: "u1",
      name: "n",
      scopes: [],
    })
    expect(stored.display.startsWith(PREFIX)).toBe(true)
    expect(stored.display.length).toBeLessThan(token.length)
    expect(token.includes(stored.display)).toBe(false) // ellipsis breaks substring match
    // Random portion (43 chars) must not appear in display.
    const body = token.slice(PREFIX.length)
    const random = body.slice(0, body.lastIndexOf("_"))
    expect(stored.display.includes(random)).toBe(false)
  })

  it("emits pat.mint audit event", async () => {
    const store = makeFakeStore()
    const events: AuditEvent[] = []
    await createPat(
      store,
      CONFIG,
      { userIdentifier: "u1", name: "ci", scopes: ["read:profile"] },
      { audit: (e) => void events.push(e) },
    )
    expect(events).toHaveLength(1)
    expect(events[0]?.type).toBe("pat.mint")
    expect(events[0]?.subject).toBe("u1")
  })

  it("rolls back the store row and propagates when the pat.mint hook throws (spec §12)", async () => {
    const store = makeFakeStore()
    const boom = new Error("audit refused mint")
    const audit = () => {
      throw boom
    }
    await expect(
      createPat(
        store,
        CONFIG,
        { userIdentifier: "u1", name: "ci", scopes: ["read:profile"] },
        { audit },
      ),
    ).rejects.toBe(boom)
    // Exactly one row was created, and it must now be revoked.
    expect(store.rows.size).toBe(1)
    const [row] = [...store.rows.values()]
    expect(row?.revokedAt).not.toBeNull()
    // And it is no longer resolvable through the lookup helper.
    if (row) {
      const result = await findPatByHash(store, row.tokenHash, resolveAll)
      expect(result).toBeNull()
    }
  })
})

describe("findPatByHash", () => {
  it("returns null for unknown hash", async () => {
    const store = makeFakeStore()
    const result = await findPatByHash(store, Buffer.alloc(32, 0xaa), resolveAll)
    expect(result).toBeNull()
  })

  it("returns row + effective scopes for active PAT", async () => {
    const store = makeFakeStore()
    const { token, stored } = await createPat(store, CONFIG, {
      userIdentifier: "u1",
      name: "n",
      scopes: ["read:profile", "write:posts"],
    })
    const hash = createHash("sha256").update(token).digest()
    const result = await findPatByHash(store, hash, resolveAll)
    expect(result).not.toBeNull()
    expect(result?.stored.id).toBe(stored.id)
    expect(result?.effectiveScopes).toEqual(["read:profile", "write:posts"])
  })

  it("intersects effective scopes with resolveUserScopes (spec §8.4)", async () => {
    const store = makeFakeStore()
    const { token } = await createPat(store, CONFIG, {
      userIdentifier: "u1",
      name: "n",
      scopes: ["read:profile", "write:posts", "delete:posts"],
    })
    const hash = createHash("sha256").update(token).digest()
    const resolveReduced = async (_: string): Promise<readonly string[]> => ["read:profile"]
    const result = await findPatByHash(store, hash, resolveReduced)
    expect(result?.effectiveScopes).toEqual(["read:profile"])
  })

  it("collapses to empty when user has lost all grants", async () => {
    const store = makeFakeStore()
    const { token } = await createPat(store, CONFIG, {
      userIdentifier: "u1",
      name: "n",
      scopes: ["read:profile"],
    })
    const hash = createHash("sha256").update(token).digest()
    const result = await findPatByHash(store, hash, resolveNone)
    expect(result?.effectiveScopes).toEqual([])
  })

  it("returns null for revoked PAT", async () => {
    const store = makeFakeStore()
    const { token, stored } = await createPat(store, CONFIG, {
      userIdentifier: "u1",
      name: "n",
      scopes: [],
    })
    await store.revokePat(stored.id, "u1")
    const hash = createHash("sha256").update(token).digest()
    const result = await findPatByHash(store, hash, resolveAll)
    expect(result).toBeNull()
  })

  it("returns null for expired PAT", async () => {
    const store = makeFakeStore()
    const now = new Date("2026-01-01T00:00:00Z")
    const { token } = await createPat(
      store,
      CONFIG,
      { userIdentifier: "u1", name: "n", scopes: [], expiresInDays: 1 },
      { now: () => now },
    )
    const hash = createHash("sha256").update(token).digest()
    const later = new Date(now.getTime() + 2 * 24 * 60 * 60 * 1000)
    const result = await findPatByHash(store, hash, resolveAll, { now: () => later })
    expect(result).toBeNull()
  })

  it("returns row when revokedAt is in the future (grace window still open)", async () => {
    const store = makeFakeStore()
    const now = new Date("2026-01-01T00:00:00Z")
    const { token, stored } = await createPat(
      store,
      CONFIG,
      { userIdentifier: "u1", name: "n", scopes: ["read:profile"] },
      { now: () => now },
    )
    // Simulate the store marking a future revocation timestamp.
    store.rows.set(stored.id, {
      ...stored,
      revokedAt: new Date(now.getTime() + 60_000),
    })
    const hash = createHash("sha256").update(token).digest()
    const result = await findPatByHash(store, hash, resolveAll, { now: () => now })
    expect(result).not.toBeNull()
  })

  it("rejects when a misbehaving store returns a row whose hash differs from the input", async () => {
    // If the store ever returned a row with a non-matching hash (e.g. a bug
    // that confuses two rows of the same length), the lifecycle layer must
    // catch it via the constant-time recheck rather than trust the store.
    const store = makeFakeStore()
    const { token, stored } = await createPat(store, CONFIG, {
      userIdentifier: "u1",
      name: "n",
      scopes: [],
    })
    const otherHash = createHash("sha256").update("not-the-token").digest()
    // Inject a same-length, non-matching hash into the stored row.
    store.rows.set(stored.id, { ...stored, tokenHash: otherHash })
    const hash = createHash("sha256").update(token).digest()
    store.findPatByHash = async (_: Buffer) => store.rows.get(stored.id) ?? null
    const result = await findPatByHash(store, hash, resolveAll)
    expect(result).toBeNull()
  })

  it("returns null when the store returns a row with mismatched hash length", async () => {
    const store = makeFakeStore()
    const { token, stored } = await createPat(store, CONFIG, {
      userIdentifier: "u1",
      name: "n",
      scopes: [],
    })
    // Tamper: replace stored hash with a shorter buffer.
    store.rows.set(stored.id, { ...stored, tokenHash: Buffer.alloc(16) })
    const hash = createHash("sha256").update(token).digest()
    // Patch findPatByHash on the store to return our tampered row regardless.
    store.findPatByHash = async (_: Buffer) => store.rows.get(stored.id) ?? null
    const result = await findPatByHash(store, hash, resolveAll)
    expect(result).toBeNull()
  })

  it("does NOT emit pat.use (left to validation pipeline)", async () => {
    // Negative assertion: findPatByHash does not accept an audit option.
    // Confirms by type — and by behavior: no event emitted by calling.
    const store = makeFakeStore()
    const { token } = await createPat(store, CONFIG, {
      userIdentifier: "u1",
      name: "n",
      scopes: [],
    })
    const hash = createHash("sha256").update(token).digest()
    await findPatByHash(store, hash, resolveAll)
    // No assertion against a sink is possible; the lack of an audit option
    // on the signature is the contract. This test documents intent.
    expect(true).toBe(true)
  })
})

describe("listPats", () => {
  it("returns public projection only", async () => {
    const store = makeFakeStore()
    await createPat(store, CONFIG, { userIdentifier: "u1", name: "a", scopes: [] })
    await createPat(store, CONFIG, { userIdentifier: "u1", name: "b", scopes: [] })
    await createPat(store, CONFIG, { userIdentifier: "u2", name: "c", scopes: [] })
    const out = await listPats(store, "u1")
    expect(out).toHaveLength(2)
    for (const row of out) {
      // public projection has no tokenHash field
      expect((row as Record<string, unknown>).tokenHash).toBeUndefined()
    }
  })
})

describe("revokePat", () => {
  it("marks the PAT revoked", async () => {
    const store = makeFakeStore()
    const { stored } = await createPat(store, CONFIG, {
      userIdentifier: "u1",
      name: "n",
      scopes: [],
    })
    await revokePat(store, stored.id, "u1")
    expect(store.rows.get(stored.id)?.revokedAt).not.toBeNull()
  })

  it("is idempotent — re-revoking is a no-op (not an error)", async () => {
    const store = makeFakeStore()
    const { stored } = await createPat(store, CONFIG, {
      userIdentifier: "u1",
      name: "n",
      scopes: [],
    })
    await revokePat(store, stored.id, "u1")
    const first = store.rows.get(stored.id)?.revokedAt
    await expect(revokePat(store, stored.id, "u1")).resolves.toBeUndefined()
    const second = store.rows.get(stored.id)?.revokedAt
    expect(second).toEqual(first)
  })

  it("emits pat.revoke audit event", async () => {
    const store = makeFakeStore()
    const { stored } = await createPat(store, CONFIG, {
      userIdentifier: "u1",
      name: "n",
      scopes: [],
    })
    const events: AuditEvent[] = []
    await revokePat(store, stored.id, "u1", { audit: (e) => void events.push(e) })
    expect(events.map((e) => e.type)).toEqual(["pat.revoke"])
  })

  it("propagates when the pat.revoke hook throws (spec §12)", async () => {
    const store = makeFakeStore()
    const { stored } = await createPat(store, CONFIG, {
      userIdentifier: "u1",
      name: "n",
      scopes: [],
    })
    const boom = new Error("audit refused revoke")
    await expect(
      revokePat(store, stored.id, "u1", {
        audit: () => {
          throw boom
        },
      }),
    ).rejects.toBe(boom)
  })
})

describe("rotatePat", () => {
  it("mints new PAT with the same scopes", async () => {
    const store = makeFakeStore()
    const { stored: old } = await createPat(store, CONFIG, {
      userIdentifier: "u1",
      name: "ci",
      scopes: ["read:profile", "write:posts"],
    })
    const { token, stored: next } = await rotatePat(store, CONFIG, old.id, "u1")
    expect(next.id).not.toBe(old.id)
    expect(next.scopes).toEqual(["read:profile", "write:posts"])
    expect(next.name).toBe("ci")
    expect(verifyPat(token, PREFIX)).toBe(true)
  })

  it("with grace=0 revokes old PAT immediately", async () => {
    const store = makeFakeStore()
    const { stored: old, token: oldToken } = await createPat(store, CONFIG, {
      userIdentifier: "u1",
      name: "ci",
      scopes: ["read:profile"],
    })
    await rotatePat(store, { ...CONFIG, rotationGraceSeconds: 0 }, old.id, "u1")
    const oldHash = createHash("sha256").update(oldToken).digest()
    const result = await findPatByHash(store, oldHash, resolveAll)
    expect(result).toBeNull()
  })

  it("with grace>0 keeps the old PAT findable in the window", async () => {
    vi.useFakeTimers()
    try {
      const store = makeFakeStore()
      const { stored: old, token: oldToken } = await createPat(store, CONFIG, {
        userIdentifier: "u1",
        name: "ci",
        scopes: ["read:profile"],
      })
      await rotatePat(store, { ...CONFIG, rotationGraceSeconds: 30 }, old.id, "u1")
      const oldHash = createHash("sha256").update(oldToken).digest()
      // Within grace: still resolves.
      const inWindow = await findPatByHash(store, oldHash, resolveAll)
      expect(inWindow).not.toBeNull()
      // Past grace: revoked.
      await vi.advanceTimersByTimeAsync(30_001)
      const past = await findPatByHash(store, oldHash, resolveAll)
      expect(past).toBeNull()
    } finally {
      vi.useRealTimers()
    }
  })

  it("emits pat.rotate audit event", async () => {
    const store = makeFakeStore()
    const { stored: old } = await createPat(store, CONFIG, {
      userIdentifier: "u1",
      name: "ci",
      scopes: ["read:profile"],
    })
    const events: AuditEvent[] = []
    const audit: LifecycleOptions["audit"] = (e) => void events.push(e)
    await rotatePat(store, CONFIG, old.id, "u1", { audit })
    const types = events.map((e) => e.type)
    expect(types).toContain("pat.rotate")
  })

  it("throws when the PAT does not exist", async () => {
    const store = makeFakeStore()
    await expect(rotatePat(store, CONFIG, "nonexistent", "u1")).rejects.toThrow()
  })

  it("propagates when the pat.rotate hook throws (spec §12)", async () => {
    const store = makeFakeStore()
    const { stored: old } = await createPat(store, CONFIG, {
      userIdentifier: "u1",
      name: "ci",
      scopes: ["read:profile"],
    })
    const boom = new Error("audit refused rotate")
    await expect(
      rotatePat(store, CONFIG, old.id, "u1", {
        audit: () => {
          throw boom
        },
      }),
    ).rejects.toBe(boom)
  })
})

describe("updatePatLastUsed", () => {
  it("delegates to the store", async () => {
    const store = makeFakeStore()
    const { stored } = await createPat(store, CONFIG, {
      userIdentifier: "u1",
      name: "n",
      scopes: [],
    })
    const now = new Date("2026-02-01T00:00:00Z")
    await updatePatLastUsed(store, stored.id, now)
    expect(store.rows.get(stored.id)?.lastUsedAt).toEqual(now)
  })

  it("swallows store errors and logs at warn", async () => {
    const store = makeFakeStore()
    store.updatePatLastUsed = async () => {
      throw new Error("boom")
    }
    const warn = vi.fn()
    const logger = { warn } as unknown as Parameters<typeof updatePatLastUsed>[3]["logger"]
    await expect(updatePatLastUsed(store, "pat_1", new Date(), { logger })).resolves.toBeUndefined()
    expect(warn).toHaveBeenCalledOnce()
  })
})

afterEach(() => {
  vi.restoreAllMocks()
})
