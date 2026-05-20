/**
 * Contract types from spec §6.1 (and §6.2 for the upstream-credential cache).
 *
 * Duplicated from `packages/core/src/types.ts` to keep this package free of a
 * core dependency — the workspace already does the structural-assignability
 * check elsewhere (see `packages/core/src/stores/sqlite.ts`).
 */

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

export interface UpstreamCredentialEntry {
  token: string
  expiresAt: Date
}

export interface CacheUpstreamCredentialInput {
  cacheKey: string
  token: string
  expiresAt: Date
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

  cacheUpstreamCredential?(input: CacheUpstreamCredentialInput): Promise<void>
  findUpstreamCredential?(cacheKey: string): Promise<UpstreamCredentialEntry | null>

  init?(): Promise<void>
  close?(): Promise<void>
}
