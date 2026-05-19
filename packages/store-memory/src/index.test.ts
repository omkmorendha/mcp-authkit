import { createHash, randomBytes } from "node:crypto"
import { describe, expect, it, vi } from "vitest"
import { type CreatePatInput, type CreateRefreshTokenInput, memoryTokenStore } from "./index.js"

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

describe("memoryTokenStore — PAT", () => {
  it("createPat + findPatByHash round-trip", async () => {
    const store = memoryTokenStore()
    const input = patInput()
    const stored = await store.createPat(input)
    expect(stored.id).toBeTruthy()
    expect(stored.createdAt).toBeInstanceOf(Date)
    expect(stored.revokedAt).toBeNull()
    expect(stored.lastUsedAt).toBeNull()

    const found = await store.findPatByHash(input.tokenHash)
    expect(found).not.toBeNull()
    expect(found?.id).toBe(stored.id)
  })

  it("findPatByHash returns null for unknown hash", async () => {
    const store = memoryTokenStore()
    await store.createPat(patInput())
    const found = await store.findPatByHash(hashOf("other"))
    expect(found).toBeNull()
  })

  it("findPatByHash returns null for revoked PAT", async () => {
    const store = memoryTokenStore()
    const input = patInput()
    const stored = await store.createPat(input)
    await store.revokePat(stored.id, stored.userIdentifier)
    expect(await store.findPatByHash(input.tokenHash)).toBeNull()
  })

  it("findPatByHash returns null for expired PAT", async () => {
    const store = memoryTokenStore()
    const input = patInput({ expiresAt: new Date(Date.now() - 1000) })
    await store.createPat(input)
    expect(await store.findPatByHash(input.tokenHash)).toBeNull()
  })

  it("listPatsByUser is scoped to the user — no cross-user leak", async () => {
    const store = memoryTokenStore()
    await store.createPat(patInput({ userIdentifier: "user-a", name: "a1" }))
    await store.createPat(patInput({ userIdentifier: "user-b", name: "b1" }))
    const a = await store.listPatsByUser("user-a")
    expect(a.map((p) => p.name)).toEqual(["a1"])
    const b = await store.listPatsByUser("user-b")
    expect(b.map((p) => p.name)).toEqual(["b1"])
  })

  it("listPatsByUser excludes revoked PATs by default", async () => {
    const store = memoryTokenStore()
    const a = await store.createPat(patInput({ name: "keep" }))
    const b = await store.createPat(patInput({ name: "gone" }))
    await store.revokePat(b.id, b.userIdentifier)
    const out = await store.listPatsByUser("user-a")
    expect(out.map((p) => p.id)).toEqual([a.id])
  })

  it("revokePat is idempotent and scoped to the owner", async () => {
    const store = memoryTokenStore()
    const a = await store.createPat(patInput({ userIdentifier: "user-a" }))
    await store.revokePat(a.id, "user-b") // wrong user — no-op
    expect(await store.listPatsByUser("user-a")).toHaveLength(1)
    await store.revokePat(a.id, "user-a")
    await store.revokePat(a.id, "user-a") // second revoke — no throw
    expect(await store.listPatsByUser("user-a")).toHaveLength(0)
  })

  it("rotatePat inserts a new row; predecessor remains until lifecycle revokes it", async () => {
    const store = memoryTokenStore()
    const oldInput = patInput()
    const oldStored = await store.createPat(oldInput)
    const newInput = patInput({ name: "rotated" })
    const newStored = await store.rotatePat(oldStored.id, oldStored.userIdentifier, newInput)
    expect(newStored.id).not.toBe(oldStored.id)
    expect(newStored.name).toBe("rotated")
    // Old row still findable until the lifecycle layer revokes it.
    expect(await store.findPatByHash(oldInput.tokenHash)).not.toBeNull()
    expect(await store.findPatByHash(newInput.tokenHash)).not.toBeNull()
  })

  it("rotatePat throws when the id does not belong to the caller", async () => {
    const store = memoryTokenStore()
    const a = await store.createPat(patInput({ userIdentifier: "user-a" }))
    await expect(store.rotatePat(a.id, "user-b", patInput())).rejects.toThrow(/not found/)
  })

  it("updatePatLastUsed sets the timestamp", async () => {
    const store = memoryTokenStore()
    const a = await store.createPat(patInput())
    const ts = new Date()
    await store.updatePatLastUsed(a.id, ts)
    const found = await store.findPatByHash(a.tokenHash)
    expect(found?.lastUsedAt?.getTime()).toBe(ts.getTime())
  })
})

describe("memoryTokenStore — security", () => {
  it("findPatByHash uses crypto.timingSafeEqual for the hash compare", async () => {
    timingSafeEqualSpy.mockClear()
    const store = memoryTokenStore()
    const input = patInput()
    await store.createPat(input)
    await store.findPatByHash(input.tokenHash)
    expect(timingSafeEqualSpy).toHaveBeenCalled()
  })

  it("findPatByHash returns null when hash lengths differ (no timingSafeEqual throw)", async () => {
    const store = memoryTokenStore()
    await store.createPat(patInput())
    // 16-byte hash vs the stored 32-byte SHA-256: must not throw.
    const short = Buffer.alloc(16, 0xff)
    await expect(store.findPatByHash(short)).resolves.toBeNull()
  })

  it("PAT hashes are stored as Buffer; no plaintext is ever held by the store", async () => {
    const plaintext = "mcp_pat_supersecret"
    const input = patInput({ tokenHash: hashOf(plaintext) })
    const store = memoryTokenStore()
    const stored = await store.createPat(input)
    expect(Buffer.isBuffer(stored.tokenHash)).toBe(true)
    // The stored display must not contain the plaintext; the stored hash
    // must not equal a buffer of the plaintext bytes.
    expect(stored.display.includes(plaintext)).toBe(false)
    expect(stored.tokenHash.equals(Buffer.from(plaintext))).toBe(false)
    // None of the stored row's string fields equals the plaintext.
    for (const v of Object.values(stored)) {
      if (typeof v === "string") expect(v).not.toBe(plaintext)
    }
  })

  it("createPat copies the input hash buffer (caller mutation cannot poison the store)", async () => {
    const store = memoryTokenStore()
    const original = hashOf("token-x")
    const input = patInput({ tokenHash: original })
    await store.createPat(input)
    original.fill(0)
    const lookup = hashOf("token-x")
    expect(await store.findPatByHash(lookup)).not.toBeNull()
  })
})

describe("memoryTokenStore — refresh tokens", () => {
  it("createRefreshToken + findRefreshToken round-trip", async () => {
    const store = memoryTokenStore()
    const input = refreshInput()
    await store.createRefreshToken(input)
    const found = await store.findRefreshToken(input.tokenHash)
    expect(found).not.toBeNull()
    expect(found?.familyId).toBe("fam-1")
    expect(found?.rotatedAt).toBeNull()
  })

  it("rotateRefreshToken marks the old row rotated and stores the new in the same family", async () => {
    const store = memoryTokenStore()
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

  it("revokeRefreshTokenFamily revokes every member (the §14 reuse-detection primitive)", async () => {
    const store = memoryTokenStore()
    // Build a chain: t1 -> t2 -> t3, all in famA. Plus an unrelated t4 in famB.
    const t1 = refreshInput({ familyId: "famA" })
    const t2 = refreshInput({ familyId: "famA" })
    const t3 = refreshInput({ familyId: "famA" })
    const t4 = refreshInput({ familyId: "famB" })
    await store.createRefreshToken(t1)
    await store.rotateRefreshToken(t1.tokenHash, t2)
    await store.rotateRefreshToken(t2.tokenHash, t3)
    await store.createRefreshToken(t4)

    // Reuse of t1 (the rotated-out token) is detected at the pipeline layer;
    // the pipeline then calls:
    await store.revokeRefreshTokenFamily("famA")

    expect(await store.findRefreshToken(t1.tokenHash)).toBeNull()
    expect(await store.findRefreshToken(t2.tokenHash)).toBeNull()
    expect(await store.findRefreshToken(t3.tokenHash)).toBeNull()
    // Unrelated family untouched.
    expect(await store.findRefreshToken(t4.tokenHash)).not.toBeNull()
  })

  it("findRefreshToken uses constant-time compare", async () => {
    timingSafeEqualSpy.mockClear()
    const store = memoryTokenStore()
    const t = refreshInput()
    await store.createRefreshToken(t)
    await store.findRefreshToken(t.tokenHash)
    expect(timingSafeEqualSpy).toHaveBeenCalled()
  })

  it("rotateRefreshToken on an unknown old hash is a silent no-op", async () => {
    const store = memoryTokenStore()
    const next = refreshInput()
    await expect(store.rotateRefreshToken(hashOf("not-stored"), next)).resolves.toBeUndefined()
    expect(await store.findRefreshToken(next.tokenHash)).toBeNull()
  })
})
