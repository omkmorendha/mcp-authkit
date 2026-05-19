/**
 * In-memory implementation of {@link TokenStore}.
 *
 * Backs unit tests and the hello-world example. Single-process, non-durable.
 * Hash equality is checked with `crypto.timingSafeEqual` (length-guarded) to
 * keep the §14 constant-time guarantee at the storage boundary. PAT and
 * refresh-token hashes are stored as `Buffer`; the framework never holds the
 * plaintext.
 *
 * Spec anchors:
 *   - docs/spec/v0.1.md#61-core-types-this-is-the-contract
 *   - docs/spec/v0.1.md#14-security-non-negotiables
 */
import { randomUUID, timingSafeEqual } from "node:crypto"

// Contract types from spec §6.1. Duplicated here (rather than imported from
// `mcp-authkit`) to keep the workspace build acyclic: core depends on
// store-memory, so store-memory cannot depend on core. The shapes are pinned
// by the spec; any drift between this file and `packages/core/src/types.ts`
// is a spec violation and will be caught by the structural assignability
// check in `packages/core/src/stores/memory.ts`.

export interface CreatePatInput {
  userIdentifier: string
  name: string
  scopes: readonly string[]
  expiresAt: Date
  tokenHash: Buffer
  display: string
}

export interface StoredPat extends CreatePatInput {
  id: string
  createdAt: Date
  lastUsedAt: Date | null
  revokedAt: Date | null
}

export interface StoredPatPublic {
  id: string
  name: string
  scopes: readonly string[]
  display: string
  createdAt: Date
  expiresAt: Date
  lastUsedAt: Date | null
}

export interface CreateRefreshTokenInput {
  familyId: string
  tokenHash: Buffer
  subject: string
  scopes: readonly string[]
  expiresAt: Date
}

export interface StoredRefreshToken extends CreateRefreshTokenInput {
  id: string
  createdAt: Date
  rotatedAt: Date | null
}

export interface TokenStore {
  createPat(input: CreatePatInput): Promise<StoredPat>
  findPatByHash(hash: Buffer): Promise<StoredPat | null>
  listPatsByUser(userIdentifier: string): Promise<StoredPatPublic[]>
  revokePat(id: string, userIdentifier: string): Promise<void>
  rotatePat(id: string, userIdentifier: string, next: CreatePatInput): Promise<StoredPat>
  updatePatLastUsed(id: string, timestamp: Date): Promise<void>
  createRefreshToken(input: CreateRefreshTokenInput): Promise<void>
  findRefreshToken(hash: Buffer): Promise<StoredRefreshToken | null>
  rotateRefreshToken(oldHash: Buffer, next: CreateRefreshTokenInput): Promise<void>
  revokeRefreshTokenFamily(familyId: string): Promise<void>
  init?(): Promise<void>
  close?(): Promise<void>
}

function copyBuffer(buf: Buffer): Buffer {
  const out = Buffer.allocUnsafe(buf.length)
  buf.copy(out)
  return out
}

function constantTimeEqual(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false
  return timingSafeEqual(a, b)
}

function toPublic(p: StoredPat): StoredPatPublic {
  return {
    id: p.id,
    name: p.name,
    scopes: p.scopes,
    display: p.display,
    createdAt: p.createdAt,
    expiresAt: p.expiresAt,
    lastUsedAt: p.lastUsedAt,
  }
}

export function memoryTokenStore(): TokenStore {
  const pats = new Map<string, StoredPat>()
  const refresh = new Map<string, StoredRefreshToken>()

  async function createPat(input: CreatePatInput): Promise<StoredPat> {
    const id = randomUUID()
    const stored: StoredPat = {
      ...input,
      scopes: [...input.scopes],
      tokenHash: copyBuffer(input.tokenHash),
      id,
      createdAt: new Date(),
      lastUsedAt: null,
      revokedAt: null,
    }
    pats.set(id, stored)
    return stored
  }

  async function findPatByHash(hash: Buffer): Promise<StoredPat | null> {
    const now = Date.now()
    for (const row of pats.values()) {
      if (!constantTimeEqual(row.tokenHash, hash)) continue
      if (row.revokedAt !== null && row.revokedAt.getTime() <= now) return null
      if (row.expiresAt.getTime() <= now) return null
      return row
    }
    return null
  }

  async function listPatsByUser(userIdentifier: string): Promise<StoredPatPublic[]> {
    const out: StoredPatPublic[] = []
    for (const row of pats.values()) {
      if (row.userIdentifier !== userIdentifier) continue
      if (row.revokedAt !== null) continue
      out.push(toPublic(row))
    }
    return out
  }

  async function revokePat(id: string, userIdentifier: string): Promise<void> {
    const row = pats.get(id)
    if (!row) return
    if (row.userIdentifier !== userIdentifier) return
    if (row.revokedAt !== null) return
    pats.set(id, { ...row, revokedAt: new Date() })
  }

  async function rotatePat(
    id: string,
    userIdentifier: string,
    next: CreatePatInput,
  ): Promise<StoredPat> {
    const existing = pats.get(id)
    if (!existing || existing.userIdentifier !== userIdentifier) {
      throw new Error(`PAT not found: ${id}`)
    }
    // Insert the successor row. The lifecycle layer decides when (or whether)
    // to revoke the predecessor — that's the rotation grace window.
    return createPat(next)
  }

  async function updatePatLastUsed(id: string, timestamp: Date): Promise<void> {
    const row = pats.get(id)
    if (!row) return
    pats.set(id, { ...row, lastUsedAt: timestamp })
  }

  async function createRefreshToken(input: CreateRefreshTokenInput): Promise<void> {
    const id = randomUUID()
    const stored: StoredRefreshToken = {
      ...input,
      scopes: [...input.scopes],
      tokenHash: copyBuffer(input.tokenHash),
      id,
      createdAt: new Date(),
      rotatedAt: null,
    }
    refresh.set(id, stored)
  }

  async function findRefreshToken(hash: Buffer): Promise<StoredRefreshToken | null> {
    for (const row of refresh.values()) {
      if (!constantTimeEqual(row.tokenHash, hash)) continue
      return row
    }
    return null
  }

  async function rotateRefreshToken(oldHash: Buffer, next: CreateRefreshTokenInput): Promise<void> {
    let oldRow: StoredRefreshToken | null = null
    for (const row of refresh.values()) {
      if (constantTimeEqual(row.tokenHash, oldHash)) {
        oldRow = row
        break
      }
    }
    if (oldRow === null) {
      // No-op: caller will see the missing row on the next findRefreshToken
      // and can choose its policy (the pipeline treats unknown-or-rotated
      // both as "reject"; reuse detection is its concern).
      return
    }
    refresh.set(oldRow.id, { ...oldRow, rotatedAt: new Date() })
    await createRefreshToken(next)
  }

  async function revokeRefreshTokenFamily(familyId: string): Promise<void> {
    for (const [id, row] of refresh) {
      if (row.familyId === familyId) refresh.delete(id)
    }
  }

  return {
    createPat,
    findPatByHash,
    listPatsByUser,
    revokePat,
    rotatePat,
    updatePatLastUsed,
    createRefreshToken,
    findRefreshToken,
    rotateRefreshToken,
    revokeRefreshTokenFamily,
  }
}
