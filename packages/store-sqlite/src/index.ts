/**
 * SQLite implementation of {@link TokenStore} (spec v0.2 §6.4).
 *
 * The schema is the same logical shape as the Postgres store but uses SQLite
 * types (`BLOB`, `INTEGER PRIMARY KEY`, `WITHOUT ROWID` on hash-keyed tables).
 *
 * Hash comparisons run in application code with `crypto.timingSafeEqual`
 * after the index seek — no SQL-side hashing. Hashes are stored as raw
 * `BLOB`s. PAT row ids are UUIDs; we do not use the integer rowid as a
 * stable identifier because the rest of the framework treats `StoredPat.id`
 * as opaque text.
 *
 * Rotation and family revocation execute inside `IMMEDIATE` transactions
 * so that concurrent writers on the same file see a consistent view and
 * cannot interleave a "find old / mark rotated / insert new" sequence.
 *
 * Spec anchors:
 *   - docs/spec/v0.2.md#64-sqlite-store
 *   - docs/spec/v0.2.md#61-required-tokenstore-semantics
 *   - docs/spec/v0.2.md#62-optional-cache-methods
 *   - docs/spec/v0.2.md#12-security-non-negotiables-additions
 *   - docs/spec/v0.1.md#61-core-types-this-is-the-contract
 */
import { randomUUID, timingSafeEqual } from "node:crypto"
import type { Database } from "better-sqlite3"
import type { Logger } from "pino"

// Contract types from spec §6.1. Duplicated here (rather than imported from
// `mcp-authkit`) to keep the workspace build acyclic: core depends on the
// store packages, so store packages cannot depend on core. The shapes are
// pinned by the spec; drift is caught by the structural assignability check
// in `packages/core/src/stores/sqlite.ts`.

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

export interface CacheUpstreamCredentialInput {
  cacheKey: string
  token: string
  expiresAt: Date
}

export interface UpstreamCredential {
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
  cacheUpstreamCredential(input: CacheUpstreamCredentialInput): Promise<void>
  findUpstreamCredential(cacheKey: string): Promise<UpstreamCredential | null>
  init(): Promise<void>
  close(): Promise<void>
}

export interface TableNames {
  pats?: string
  refreshTokens?: string
  upstreamCredentials?: string
  migrations?: string
}

export interface SqliteTokenStoreOptions {
  database: Database
  tableNames?: TableNames
  /** Optional pino logger. Used for the readonly-database warning and migrations. */
  logger?: Logger
}

const DEFAULT_TABLE_NAMES = {
  pats: "mcp_pats",
  refreshTokens: "mcp_refresh_tokens",
  upstreamCredentials: "mcp_upstream_credentials",
  migrations: "mcp_migrations",
} as const

const IDENT_RE = /^[A-Za-z0-9_]+$/

function validateIdent(name: string, role: string): string {
  if (!IDENT_RE.test(name)) {
    throw new Error(
      `mcp-authkit-store-sqlite: invalid table name for ${role}: ${JSON.stringify(name)}. ` +
        `Only [A-Za-z0-9_] is allowed.`,
    )
  }
  return name
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

function toBuffer(value: unknown): Buffer {
  // better-sqlite3 returns BLOBs as `Buffer` already, but the `Database` types
  // widen to `unknown` after the JSON-shape assertions below. Be defensive.
  if (Buffer.isBuffer(value)) return value
  if (value instanceof Uint8Array) return Buffer.from(value)
  throw new Error("Expected BLOB column to deserialize as Buffer")
}

function toDate(epochMs: number): Date {
  return new Date(epochMs)
}

function nullableDate(epochMs: number | null): Date | null {
  return epochMs === null ? null : new Date(epochMs)
}

// Bundled migrations. Forward-only. The migration `id` is the file-style
// numeric prefix; the SQL is run inside the same transaction as the row
// insert into the migrations table so a partial apply rolls back cleanly.
interface Migration {
  id: number
  name: string
  sql: (tables: Required<TableNames>) => string
}

const MIGRATIONS: Migration[] = [
  {
    id: 1,
    name: "init",
    sql: (t) => `
      CREATE TABLE IF NOT EXISTS ${t.pats} (
        id TEXT PRIMARY KEY,
        user_identifier TEXT NOT NULL,
        name TEXT NOT NULL,
        scopes TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        token_hash BLOB NOT NULL,
        display TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_used_at INTEGER,
        revoked_at INTEGER
      ) WITHOUT ROWID;
      CREATE UNIQUE INDEX IF NOT EXISTS ${t.pats}_token_hash_idx
        ON ${t.pats}(token_hash);
      CREATE INDEX IF NOT EXISTS ${t.pats}_user_idx
        ON ${t.pats}(user_identifier);

      CREATE TABLE IF NOT EXISTS ${t.refreshTokens} (
        id TEXT PRIMARY KEY,
        family_id TEXT NOT NULL,
        token_hash BLOB NOT NULL,
        subject TEXT NOT NULL,
        scopes TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        rotated_at INTEGER
      ) WITHOUT ROWID;
      CREATE UNIQUE INDEX IF NOT EXISTS ${t.refreshTokens}_token_hash_idx
        ON ${t.refreshTokens}(token_hash);
      CREATE INDEX IF NOT EXISTS ${t.refreshTokens}_family_idx
        ON ${t.refreshTokens}(family_id);

      CREATE TABLE IF NOT EXISTS ${t.upstreamCredentials} (
        cache_key TEXT PRIMARY KEY,
        token TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      ) WITHOUT ROWID;
      CREATE INDEX IF NOT EXISTS ${t.upstreamCredentials}_expires_idx
        ON ${t.upstreamCredentials}(expires_at);
    `,
  },
]

interface PatRow {
  id: string
  user_identifier: string
  name: string
  scopes: string
  expires_at: number
  token_hash: Buffer
  display: string
  created_at: number
  last_used_at: number | null
  revoked_at: number | null
}

interface RefreshRow {
  id: string
  family_id: string
  token_hash: Buffer
  subject: string
  scopes: string
  expires_at: number
  created_at: number
  rotated_at: number | null
}

interface UpstreamRow {
  cache_key: string
  token: string
  expires_at: number
}

function rowToPat(row: PatRow): StoredPat {
  return {
    id: row.id,
    userIdentifier: row.user_identifier,
    name: row.name,
    scopes: JSON.parse(row.scopes) as readonly string[],
    expiresAt: toDate(row.expires_at),
    tokenHash: toBuffer(row.token_hash),
    display: row.display,
    createdAt: toDate(row.created_at),
    lastUsedAt: nullableDate(row.last_used_at),
    revokedAt: nullableDate(row.revoked_at),
  }
}

function rowToPatPublic(row: PatRow): StoredPatPublic {
  return {
    id: row.id,
    name: row.name,
    scopes: JSON.parse(row.scopes) as readonly string[],
    display: row.display,
    createdAt: toDate(row.created_at),
    expiresAt: toDate(row.expires_at),
    lastUsedAt: nullableDate(row.last_used_at),
  }
}

function rowToRefresh(row: RefreshRow): StoredRefreshToken {
  return {
    id: row.id,
    familyId: row.family_id,
    tokenHash: toBuffer(row.token_hash),
    subject: row.subject,
    scopes: JSON.parse(row.scopes) as readonly string[],
    expiresAt: toDate(row.expires_at),
    createdAt: toDate(row.created_at),
    rotatedAt: nullableDate(row.rotated_at),
  }
}

export function sqliteTokenStore(options: SqliteTokenStoreOptions): TokenStore {
  const { database, logger } = options
  const tables: Required<TableNames> = {
    pats: validateIdent(options.tableNames?.pats ?? DEFAULT_TABLE_NAMES.pats, "pats"),
    refreshTokens: validateIdent(
      options.tableNames?.refreshTokens ?? DEFAULT_TABLE_NAMES.refreshTokens,
      "refreshTokens",
    ),
    upstreamCredentials: validateIdent(
      options.tableNames?.upstreamCredentials ?? DEFAULT_TABLE_NAMES.upstreamCredentials,
      "upstreamCredentials",
    ),
    migrations: validateIdent(
      options.tableNames?.migrations ?? DEFAULT_TABLE_NAMES.migrations,
      "migrations",
    ),
  }

  async function init(): Promise<void> {
    if (database.readonly) {
      const msg =
        "mcp-authkit-store-sqlite: database opened readonly; init() cannot apply migrations " +
        "and writes will fail at the SQLite layer. Open the database in read/write mode."
      if (logger) logger.warn({ readonly: true }, msg)
      else console.warn(msg)
      return
    }

    // WAL is recommended for concurrent readers; switch eagerly so the very
    // first transaction below is already in WAL mode.
    database.pragma("journal_mode = WAL")
    database.pragma("foreign_keys = ON")

    database.exec(
      `CREATE TABLE IF NOT EXISTS ${tables.migrations} (
         id INTEGER PRIMARY KEY,
         name TEXT NOT NULL,
         applied_at INTEGER NOT NULL
       )`,
    )

    // BEGIN IMMEDIATE acquires the RESERVED lock up-front, so two startups
    // racing on the same file serialize at the lock rather than deadlock at
    // the first write.
    const txn = database.transaction((): void => {
      const applied = new Set<number>()
      const rows = database.prepare(`SELECT id FROM ${tables.migrations}`).all() as Array<{
        id: number
      }>
      for (const r of rows) applied.add(r.id)

      const insert = database.prepare(
        `INSERT INTO ${tables.migrations} (id, name, applied_at) VALUES (?, ?, ?)`,
      )
      for (const m of MIGRATIONS) {
        if (applied.has(m.id)) continue
        database.exec(m.sql(tables))
        insert.run(m.id, m.name, Date.now())
      }
    })
    txn.immediate()
  }

  async function close(): Promise<void> {
    // The Database handle's lifecycle belongs to the caller (mirrors the
    // Postgres store's pool-ownership rule). Nothing to release here.
  }

  function selectPatByHashStmt() {
    return database.prepare<[Buffer], PatRow>(
      `SELECT id, user_identifier, name, scopes, expires_at, token_hash, display,
              created_at, last_used_at, revoked_at
         FROM ${tables.pats}
        WHERE token_hash = ?`,
    )
  }

  async function createPat(input: CreatePatInput): Promise<StoredPat> {
    const id = randomUUID()
    const now = Date.now()
    const stored: StoredPat = {
      ...input,
      scopes: [...input.scopes],
      tokenHash: copyBuffer(input.tokenHash),
      id,
      createdAt: new Date(now),
      lastUsedAt: null,
      revokedAt: null,
    }
    database
      .prepare(
        `INSERT INTO ${tables.pats}
           (id, user_identifier, name, scopes, expires_at, token_hash, display, created_at,
            last_used_at, revoked_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)`,
      )
      .run(
        id,
        input.userIdentifier,
        input.name,
        JSON.stringify(input.scopes),
        input.expiresAt.getTime(),
        input.tokenHash,
        input.display,
        now,
      )
    return stored
  }

  async function findPatByHash(hash: Buffer): Promise<StoredPat | null> {
    const row = selectPatByHashStmt().get(hash)
    if (!row) return null
    const stored = rowToPat(row)
    // Defense in depth: even though SQLite has already matched by equality
    // on an indexed BLOB, we still verify with a constant-time compare so
    // we share one code path with every other store and so that any future
    // expression-index or collation change cannot bypass §14.
    if (!constantTimeEqual(stored.tokenHash, hash)) return null
    const now = Date.now()
    if (stored.revokedAt !== null && stored.revokedAt.getTime() <= now) return null
    if (stored.expiresAt.getTime() <= now) return null
    return stored
  }

  async function listPatsByUser(userIdentifier: string): Promise<StoredPatPublic[]> {
    const rows = database
      .prepare<[string], PatRow>(
        `SELECT id, user_identifier, name, scopes, expires_at, token_hash, display,
                created_at, last_used_at, revoked_at
           FROM ${tables.pats}
          WHERE user_identifier = ? AND revoked_at IS NULL
          ORDER BY created_at ASC`,
      )
      .all(userIdentifier)
    return rows.map(rowToPatPublic)
  }

  async function revokePat(id: string, userIdentifier: string): Promise<void> {
    database
      .prepare(
        `UPDATE ${tables.pats}
            SET revoked_at = ?
          WHERE id = ? AND user_identifier = ? AND revoked_at IS NULL`,
      )
      .run(Date.now(), id, userIdentifier)
  }

  async function rotatePat(
    id: string,
    userIdentifier: string,
    next: CreatePatInput,
  ): Promise<StoredPat> {
    const newId = randomUUID()
    const now = Date.now()
    const insertNext = database.prepare(
      `INSERT INTO ${tables.pats}
         (id, user_identifier, name, scopes, expires_at, token_hash, display, created_at,
          last_used_at, revoked_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)`,
    )
    const findExisting = database.prepare<[string, string], { id: string }>(
      `SELECT id FROM ${tables.pats} WHERE id = ? AND user_identifier = ?`,
    )
    const txn = database.transaction((): void => {
      const existing = findExisting.get(id, userIdentifier)
      if (!existing) {
        throw new Error(`PAT not found: ${id}`)
      }
      insertNext.run(
        newId,
        next.userIdentifier,
        next.name,
        JSON.stringify(next.scopes),
        next.expiresAt.getTime(),
        next.tokenHash,
        next.display,
        now,
      )
    })
    txn.immediate()
    return {
      ...next,
      scopes: [...next.scopes],
      tokenHash: copyBuffer(next.tokenHash),
      id: newId,
      createdAt: new Date(now),
      lastUsedAt: null,
      revokedAt: null,
    }
  }

  async function updatePatLastUsed(id: string, timestamp: Date): Promise<void> {
    database
      .prepare(`UPDATE ${tables.pats} SET last_used_at = ? WHERE id = ?`)
      .run(timestamp.getTime(), id)
  }

  async function createRefreshToken(input: CreateRefreshTokenInput): Promise<void> {
    const id = randomUUID()
    const now = Date.now()
    database
      .prepare(
        `INSERT INTO ${tables.refreshTokens}
           (id, family_id, token_hash, subject, scopes, expires_at, created_at, rotated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
      )
      .run(
        id,
        input.familyId,
        input.tokenHash,
        input.subject,
        JSON.stringify(input.scopes),
        input.expiresAt.getTime(),
        now,
      )
  }

  function selectRefreshByHashStmt() {
    return database.prepare<[Buffer], RefreshRow>(
      `SELECT id, family_id, token_hash, subject, scopes, expires_at, created_at, rotated_at
         FROM ${tables.refreshTokens}
        WHERE token_hash = ?`,
    )
  }

  async function findRefreshToken(hash: Buffer): Promise<StoredRefreshToken | null> {
    const row = selectRefreshByHashStmt().get(hash)
    if (!row) return null
    const stored = rowToRefresh(row)
    if (!constantTimeEqual(stored.tokenHash, hash)) return null
    return stored
  }

  async function rotateRefreshToken(oldHash: Buffer, next: CreateRefreshTokenInput): Promise<void> {
    const newId = randomUUID()
    const now = Date.now()
    const select = database.prepare<[Buffer], RefreshRow>(
      `SELECT id, family_id, token_hash, subject, scopes, expires_at, created_at, rotated_at
         FROM ${tables.refreshTokens}
        WHERE token_hash = ?`,
    )
    const markRotated = database.prepare(
      `UPDATE ${tables.refreshTokens} SET rotated_at = ? WHERE id = ?`,
    )
    const insertNext = database.prepare(
      `INSERT INTO ${tables.refreshTokens}
         (id, family_id, token_hash, subject, scopes, expires_at, created_at, rotated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
    )
    const txn = database.transaction((): void => {
      const row = select.get(oldHash)
      if (!row) return
      // Constant-time recheck inside the transaction.
      if (!constantTimeEqual(toBuffer(row.token_hash), oldHash)) return
      markRotated.run(now, row.id)
      insertNext.run(
        newId,
        next.familyId,
        next.tokenHash,
        next.subject,
        JSON.stringify(next.scopes),
        next.expiresAt.getTime(),
        now,
      )
    })
    txn.immediate()
  }

  async function revokeRefreshTokenFamily(familyId: string): Promise<void> {
    const del = database.prepare(`DELETE FROM ${tables.refreshTokens} WHERE family_id = ?`)
    const txn = database.transaction((): void => {
      del.run(familyId)
    })
    txn.immediate()
  }

  async function cacheUpstreamCredential(input: CacheUpstreamCredentialInput): Promise<void> {
    database
      .prepare(
        `INSERT INTO ${tables.upstreamCredentials} (cache_key, token, expires_at)
         VALUES (?, ?, ?)
         ON CONFLICT(cache_key) DO UPDATE SET token = excluded.token, expires_at = excluded.expires_at`,
      )
      .run(input.cacheKey, input.token, input.expiresAt.getTime())
  }

  async function findUpstreamCredential(cacheKey: string): Promise<UpstreamCredential | null> {
    const row = database
      .prepare<[string], UpstreamRow>(
        `SELECT cache_key, token, expires_at
           FROM ${tables.upstreamCredentials}
          WHERE cache_key = ?`,
      )
      .get(cacheKey)
    if (!row) return null
    if (row.expires_at <= Date.now()) return null
    return { token: row.token, expiresAt: toDate(row.expires_at) }
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
    cacheUpstreamCredential,
    findUpstreamCredential,
    init,
    close,
  }
}
