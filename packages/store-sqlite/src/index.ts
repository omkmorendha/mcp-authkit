/**
 * SQLite implementation of `TokenStore` (spec §6.4).
 *
 * - One `better-sqlite3` `Database` parameter; the handle belongs to the
 *   consumer. `close()` does NOT close it.
 * - Three tables (`mcp_pats`, `mcp_refresh_tokens`,
 *   `mcp_upstream_credentials`) with overrides validated against
 *   `/^[A-Za-z0-9_]+$/`.
 * - All queries parameterized with `?`; no string interpolation of user
 *   data — only validated identifiers are interpolated, and only at
 *   construction time.
 * - `tokenHash` stored as `BLOB`. Equality comparisons happen via the
 *   index seek and are then re-checked in app code via
 *   `crypto.timingSafeEqual` (spec §14).
 * - `rotateRefreshToken` and `revokeRefreshTokenFamily` are atomic; reuse
 *   of an already-rotated refresh token revokes the entire family.
 * - `init()` is idempotent; it enables `journal_mode = WAL` and applies
 *   migrations under a `BEGIN IMMEDIATE` transaction.
 * - Warns at startup if the database was opened readonly.
 * - `better-sqlite3` is synchronous; we still return `Promise`s to match
 *   the `TokenStore` contract.
 */

import { randomUUID, timingSafeEqual } from "node:crypto"
import { migrations } from "./migrations.js"
import { type ResolvedNames, resolveNames, type TableNameOverrides } from "./names.js"
import type { SqliteDatabase, SqliteStatement } from "./sqlite.js"
import type {
  CacheUpstreamCredentialInput,
  CreatePatInput,
  CreateRefreshTokenInput,
  StoredPat,
  StoredPatPublic,
  StoredRefreshToken,
  TokenStore,
  UpstreamCredentialEntry,
} from "./types.js"

export { InvalidIdentifierError } from "./identifiers.js"

export type { TableNameOverrides } from "./names.js"
export type { SqliteDatabase } from "./sqlite.js"
export type {
  CacheUpstreamCredentialInput,
  CreatePatInput,
  CreateRefreshTokenInput,
  StoredPat,
  StoredPatPublic,
  StoredRefreshToken,
  TokenStore,
  UpstreamCredentialEntry,
} from "./types.js"

export interface SqliteTokenStoreOptions {
  database: SqliteDatabase
  /** Per-table name overrides. Each validated against `[A-Za-z0-9_]`. */
  tableNames?: TableNameOverrides
  /**
   * Optional override for the warning emitter (testing only). Defaults to
   * `console.warn`.
   */
  warn?: (message: string) => void
}

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
  token: string
  expires_at: number
}

function toBuffer(value: unknown): Buffer {
  // better-sqlite3 returns BLOBs as Buffer; some environments may surface
  // them as Uint8Array. Normalize to Node Buffer for ergonomic equality.
  if (Buffer.isBuffer(value)) return value
  if (value instanceof Uint8Array) return Buffer.from(value)
  throw new Error("sqliteTokenStore: expected BLOB column to be Buffer-like")
}

function toDate(ms: number): Date {
  return new Date(ms)
}

function maybeDate(ms: number | null): Date | null {
  return ms === null ? null : new Date(ms)
}

function rowToPat(row: PatRow): StoredPat {
  return {
    id: row.id,
    userIdentifier: row.user_identifier,
    name: row.name,
    scopes: JSON.parse(row.scopes) as string[],
    expiresAt: toDate(row.expires_at),
    tokenHash: toBuffer(row.token_hash),
    display: row.display,
    createdAt: toDate(row.created_at),
    lastUsedAt: maybeDate(row.last_used_at),
    revokedAt: maybeDate(row.revoked_at),
  }
}

function rowToPatPublic(row: PatRow): StoredPatPublic {
  return {
    id: row.id,
    name: row.name,
    scopes: JSON.parse(row.scopes) as string[],
    display: row.display,
    createdAt: toDate(row.created_at),
    expiresAt: toDate(row.expires_at),
    lastUsedAt: maybeDate(row.last_used_at),
  }
}

function rowToRefresh(row: RefreshRow): StoredRefreshToken {
  return {
    id: row.id,
    familyId: row.family_id,
    tokenHash: toBuffer(row.token_hash),
    subject: row.subject,
    scopes: JSON.parse(row.scopes) as string[],
    expiresAt: toDate(row.expires_at),
    createdAt: toDate(row.created_at),
    rotatedAt: maybeDate(row.rotated_at),
  }
}

/**
 * Constant-time equality. Lengths are compared up front — returning `false`
 * early on a length mismatch is the contract everywhere in mcp-authkit and
 * matches store-memory.
 */
function constantTimeEqual(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false
  return timingSafeEqual(a, b)
}

function copyBuffer(buf: Buffer): Buffer {
  const out = Buffer.allocUnsafe(buf.length)
  buf.copy(out)
  return out
}

export function sqliteTokenStore(options: SqliteTokenStoreOptions): TokenStore {
  const { database: db } = options
  const names: ResolvedNames = resolveNames(options.tableNames)
  const warn = options.warn ?? ((m: string) => console.warn(m))

  if (db.readonly) {
    // Spec §6.4: the framework warns if `database.readonly` is true. PATs,
    // refresh tokens, and migrations are all writes — a readonly handle
    // will fail every mutating call.
    warn(
      "mcp-authkit-store-sqlite: database opened readonly — writes (createPat, init, etc.) will fail.",
    )
  }

  // ---------------------------------------------------------------------------
  // Prepared statements. Identifiers are interpolated once (at first
  // preparation); all user data flows through `?` placeholders.
  //
  // We prepare lazily because `better-sqlite3`'s `prepare()` requires the
  // referenced table to already exist — `init()` is what creates the schema.
  // Preparing at construction would forbid the spec-mandated workflow of
  // `const s = sqliteTokenStore({db}); await s.init()`. Preparation is
  // memoized so the per-statement compile cost is paid once.
  // ---------------------------------------------------------------------------

  type Stmts = {
    insertPat: SqliteStatement
    selectPatByHash: SqliteStatement<PatRow>
    selectPatsByUser: SqliteStatement<PatRow>
    revokePat: SqliteStatement
    selectPatOwnerForUpdate: SqliteStatement<{ id: string }>
    updatePatLastUsed: SqliteStatement
    insertRefresh: SqliteStatement
    selectRefreshByHash: SqliteStatement<RefreshRow>
    markRefreshRotated: SqliteStatement
    deleteRefreshFamily: SqliteStatement
    upsertUpstream: SqliteStatement
    selectUpstream: SqliteStatement<UpstreamRow>
  }

  let _stmts: Stmts | null = null

  function stmts(): Stmts {
    if (_stmts !== null) return _stmts
    _stmts = {
      insertPat: db.prepare(
        `INSERT INTO ${names.pats}
           (id, user_identifier, name, scopes, expires_at, token_hash, display,
            created_at, last_used_at, revoked_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)`,
      ),
      selectPatByHash: db.prepare<PatRow>(
        `SELECT * FROM ${names.pats} WHERE token_hash = ? LIMIT 1`,
      ),
      selectPatsByUser: db.prepare<PatRow>(
        `SELECT * FROM ${names.pats}
         WHERE user_identifier = ? AND revoked_at IS NULL
         ORDER BY created_at ASC, id ASC`,
      ),
      revokePat: db.prepare(
        `UPDATE ${names.pats}
         SET revoked_at = ?
         WHERE id = ? AND user_identifier = ? AND revoked_at IS NULL`,
      ),
      selectPatOwnerForUpdate: db.prepare<{ id: string }>(
        `SELECT id FROM ${names.pats} WHERE id = ? AND user_identifier = ?`,
      ),
      updatePatLastUsed: db.prepare(`UPDATE ${names.pats} SET last_used_at = ? WHERE id = ?`),

      insertRefresh: db.prepare(
        `INSERT INTO ${names.refreshTokens}
           (id, family_id, token_hash, subject, scopes, expires_at, created_at,
            rotated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
      ),
      selectRefreshByHash: db.prepare<RefreshRow>(
        `SELECT * FROM ${names.refreshTokens} WHERE token_hash = ? LIMIT 1`,
      ),
      markRefreshRotated: db.prepare(
        `UPDATE ${names.refreshTokens} SET rotated_at = ? WHERE id = ?`,
      ),
      deleteRefreshFamily: db.prepare(`DELETE FROM ${names.refreshTokens} WHERE family_id = ?`),

      upsertUpstream: db.prepare(
        `INSERT INTO ${names.upstreamCredentials}
           (cache_key, token, expires_at, created_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(cache_key) DO UPDATE
           SET token = excluded.token, expires_at = excluded.expires_at`,
      ),
      selectUpstream: db.prepare<UpstreamRow>(
        `SELECT token, expires_at FROM ${names.upstreamCredentials}
         WHERE cache_key = ? LIMIT 1`,
      ),
    }
    return _stmts
  }

  // ---------------------------------------------------------------------------
  // init — enable WAL, bootstrap the migrations table, apply pending
  // migrations inside a single BEGIN IMMEDIATE transaction.
  // ---------------------------------------------------------------------------

  async function init(): Promise<void> {
    // Set durability/concurrency pragmas before any writes. `journal_mode =
    // WAL` is required by spec §6.4; `foreign_keys = ON` is the modern
    // default we want even though no FKs are declared yet.
    db.pragma("journal_mode = WAL")
    db.pragma("foreign_keys = ON")

    // The migrations table is bootstrapped outside the transaction — this
    // is the only DDL outside the lock, and it is idempotent.
    db.exec(
      `CREATE TABLE IF NOT EXISTS ${names.migrations} (
         id          INTEGER PRIMARY KEY,
         name        TEXT NOT NULL,
         applied_at  INTEGER NOT NULL
       )`,
    )

    // `better-sqlite3`'s `transaction()` returns a wrapper with `.immediate()`
    // / `.exclusive()` modes. Spec §6.4 mandates `BEGIN IMMEDIATE` so two
    // concurrent process startups serialize on the writer lock immediately
    // instead of upgrading mid-transaction.
    // Prepare migration-table statements inline — they're only used here
    // and the rest of the store's prepared statements depend on the
    // user-data tables that this transaction creates.
    const selectMigrationIds = db.prepare<{ id: number }>(
      `SELECT id FROM ${names.migrations} ORDER BY id ASC`,
    )
    const insertMigration = db.prepare(
      `INSERT INTO ${names.migrations} (id, name, applied_at) VALUES (?, ?, ?)`,
    )
    const applyTx = db.transaction(() => {
      const applied = selectMigrationIds.all()
      const appliedIds = new Set(applied.map((r) => r.id))
      for (const migration of migrations) {
        if (appliedIds.has(migration.id)) continue
        db.exec(migration.build(names))
        insertMigration.run(migration.id, migration.name, Date.now())
      }
    })
    // `.immediate` is a property of the transaction wrapper (better-sqlite3
    // shape: `(...args) => R` with `default | deferred | immediate |
    // exclusive` variants). We narrow via a structural cast.
    const immediate = (applyTx as unknown as { immediate: () => void }).immediate
    if (typeof immediate === "function") {
      immediate.call(applyTx)
    } else {
      // Fallback: a runtime without the variant property. Run the default
      // transaction — still atomic, but deferred-lock semantics.
      applyTx()
    }
  }

  // ---------------------------------------------------------------------------
  // PAT
  // ---------------------------------------------------------------------------

  async function createPat(input: CreatePatInput): Promise<StoredPat> {
    const id = randomUUID()
    const createdAt = Date.now()
    stmts().insertPat.run(
      id,
      input.userIdentifier,
      input.name,
      JSON.stringify([...input.scopes]),
      input.expiresAt.getTime(),
      copyBuffer(input.tokenHash),
      input.display,
      createdAt,
    )
    return {
      id,
      userIdentifier: input.userIdentifier,
      name: input.name,
      scopes: [...input.scopes],
      expiresAt: new Date(input.expiresAt.getTime()),
      tokenHash: copyBuffer(input.tokenHash),
      display: input.display,
      createdAt: new Date(createdAt),
      lastUsedAt: null,
      revokedAt: null,
    }
  }

  async function findPatByHash(hash: Buffer): Promise<StoredPat | null> {
    // Spec §14: constant-time compare AFTER the index seek. The unique index
    // on token_hash means equality at the SQL layer is fine for the lookup;
    // the app-side timingSafeEqual is defense in depth (and the same check
    // the in-memory store performs at this boundary).
    const row = stmts().selectPatByHash.get(hash)
    if (!row) return null
    const stored = toBuffer(row.token_hash)
    if (!constantTimeEqual(stored, hash)) return null
    const now = Date.now()
    if (row.revoked_at !== null) return null
    if (row.expires_at <= now) return null
    return rowToPat(row)
  }

  async function listPatsByUser(userIdentifier: string): Promise<StoredPatPublic[]> {
    const rows = stmts().selectPatsByUser.all(userIdentifier)
    return rows.map(rowToPatPublic)
  }

  async function revokePat(id: string, userIdentifier: string): Promise<void> {
    // Scope to the owner; idempotent — already-revoked rows are untouched.
    stmts().revokePat.run(Date.now(), id, userIdentifier)
  }

  async function rotatePat(
    id: string,
    userIdentifier: string,
    next: CreatePatInput,
  ): Promise<StoredPat> {
    if (next.userIdentifier !== userIdentifier) {
      throw new Error("rotatePat user mismatch")
    }
    // Atomic: verify ownership, then insert the successor row. Lifecycle
    // layer decides when to revoke the predecessor (rotation grace window).
    const newId = randomUUID()
    const createdAt = Date.now()
    const tx = db.transaction(() => {
      const owner = stmts().selectPatOwnerForUpdate.get(id, userIdentifier)
      if (!owner) {
        throw new Error(`PAT not found: ${id}`)
      }
      stmts().insertPat.run(
        newId,
        userIdentifier,
        next.name,
        JSON.stringify([...next.scopes]),
        next.expiresAt.getTime(),
        copyBuffer(next.tokenHash),
        next.display,
        createdAt,
      )
    })
    const immediate = (tx as unknown as { immediate: () => void }).immediate
    if (typeof immediate === "function") {
      immediate.call(tx)
    } else {
      tx()
    }
    return {
      id: newId,
      userIdentifier,
      name: next.name,
      scopes: [...next.scopes],
      expiresAt: new Date(next.expiresAt.getTime()),
      tokenHash: copyBuffer(next.tokenHash),
      display: next.display,
      createdAt: new Date(createdAt),
      lastUsedAt: null,
      revokedAt: null,
    }
  }

  async function updatePatLastUsed(id: string, timestamp: Date): Promise<void> {
    stmts().updatePatLastUsed.run(timestamp.getTime(), id)
  }

  // ---------------------------------------------------------------------------
  // Refresh tokens
  // ---------------------------------------------------------------------------

  async function createRefreshToken(input: CreateRefreshTokenInput): Promise<void> {
    const id = randomUUID()
    const createdAt = Date.now()
    stmts().insertRefresh.run(
      id,
      input.familyId,
      copyBuffer(input.tokenHash),
      input.subject,
      JSON.stringify([...input.scopes]),
      input.expiresAt.getTime(),
      createdAt,
    )
  }

  async function findRefreshToken(hash: Buffer): Promise<StoredRefreshToken | null> {
    const row = stmts().selectRefreshByHash.get(hash)
    if (!row) return null
    const stored = toBuffer(row.token_hash)
    if (!constantTimeEqual(stored, hash)) return null
    return rowToRefresh(row)
  }

  async function rotateRefreshToken(oldHash: Buffer, next: CreateRefreshTokenInput): Promise<void> {
    // Atomic per spec §6.1 + §6.4:
    //   1. SELECT the row matching `oldHash` inside BEGIN IMMEDIATE.
    //   2. If absent: silent no-op (matches store-memory semantics — the
    //      pipeline already handles "not found" as reject).
    //   3. If already rotated: REUSE DETECTED. Revoke the entire family
    //      inside the same transaction and signal the caller to throw
    //      `RefreshTokenReuseError` AFTER COMMIT, so the DELETE is durable.
    //   4. Otherwise: mark `rotated_at = now()`, INSERT the successor row.
    //
    // The UNIQUE index on token_hash means a concurrent rotation that races
    // on the same `oldHash` will serialize on the writer lock; the loser
    // then sees the row already rotated and triggers the reuse path. That
    // is exactly the §14 family-revocation behavior we want.
    let reuseFamilyId: string | null = null
    const tx = db.transaction(() => {
      const old = stmts().selectRefreshByHash.get(oldHash)
      if (!old) {
        return
      }
      const storedHash = toBuffer(old.token_hash)
      if (!constantTimeEqual(storedHash, oldHash)) {
        // Defense in depth — should not happen given the unique index.
        return
      }
      if (old.rotated_at !== null) {
        // Reuse of a rotated token. Revoke the family in-transaction and
        // signal the caller to throw AFTER COMMIT.
        stmts().deleteRefreshFamily.run(old.family_id)
        reuseFamilyId = old.family_id
        return
      }
      stmts().markRefreshRotated.run(Date.now(), old.id)
      const newId = randomUUID()
      stmts().insertRefresh.run(
        newId,
        old.family_id,
        copyBuffer(next.tokenHash),
        next.subject,
        JSON.stringify([...next.scopes]),
        next.expiresAt.getTime(),
        Date.now(),
      )
    })
    const immediate = (tx as unknown as { immediate: () => void }).immediate
    if (typeof immediate === "function") {
      immediate.call(tx)
    } else {
      tx()
    }
    if (reuseFamilyId !== null) {
      throw new RefreshTokenReuseError(reuseFamilyId)
    }
  }

  async function revokeRefreshTokenFamily(familyId: string): Promise<void> {
    stmts().deleteRefreshFamily.run(familyId)
  }

  // ---------------------------------------------------------------------------
  // Upstream-credential cache (spec §6.2)
  // ---------------------------------------------------------------------------

  async function cacheUpstreamCredential(input: CacheUpstreamCredentialInput): Promise<void> {
    // UPSERT — same cacheKey overwrites. The expires_at column carries TTL.
    stmts().upsertUpstream.run(input.cacheKey, input.token, input.expiresAt.getTime(), Date.now())
  }

  async function findUpstreamCredential(cacheKey: string): Promise<UpstreamCredentialEntry | null> {
    // Expired entries are treated as misses. We do not delete on read — a
    // periodic cleanup is out of scope for v0.2 (consumers can run their
    // own vacuum/job).
    const row = stmts().selectUpstream.get(cacheKey)
    if (!row) return null
    if (row.expires_at <= Date.now()) return null
    return { token: row.token, expiresAt: toDate(row.expires_at) }
  }

  async function close(): Promise<void> {
    // Per spec §6.4: the database handle belongs to the consumer.
    // Intentionally a no-op.
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

/**
 * Thrown by `rotateRefreshToken` when the caller presents a refresh token
 * that has already been rotated. The store revokes the entire family before
 * throwing — the pipeline only needs to surface a 401.
 */
export class RefreshTokenReuseError extends Error {
  readonly familyId: string
  constructor(familyId: string) {
    super(`refresh token reuse detected; family revoked: ${familyId}`)
    this.name = "RefreshTokenReuseError"
    this.familyId = familyId
  }
}

// Type-only: `SqliteStatement` is consumed only via the `db.prepare` return.
// Re-export so consumers writing their own structural `Database` types can
// match the contract.
export type { SqliteStatement }
