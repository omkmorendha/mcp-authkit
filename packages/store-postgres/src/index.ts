/**
 * Postgres implementation of `TokenStore` (spec §6.3).
 *
 * - One Postgres `Pool` parameter; the pool belongs to the consumer.
 * - Three tables (`mcp_pats`, `mcp_refresh_tokens`,
 *   `mcp_upstream_credentials`) with overrides validated against
 *   `/^[A-Za-z0-9_]+$/`.
 * - All queries parameterized with `$n`; no string interpolation of user
 *   data — only validated identifiers are interpolated, and only at
 *   construction time.
 * - `tokenHash` stored as `BYTEA`. Equality comparisons happen via the
 *   index seek and are then re-checked in app code via
 *   `crypto.timingSafeEqual` (spec §14).
 * - `rotateRefreshToken` and `revokeRefreshTokenFamily` are atomic; reuse
 *   of an already-rotated refresh token revokes the entire family.
 * - `init()` is idempotent; migrations apply under `LOCK TABLE
 *   mcp_migrations IN EXCLUSIVE MODE`.
 * - `statementTimeoutMs` (default 5000) wraps every query.
 * - `close()` does NOT close the pool.
 */

import { randomUUID, timingSafeEqual } from "node:crypto"
import { migrations } from "./migrations.js"
import { type ResolvedNames, resolveNames, type TableNameOverrides } from "./names.js"
import type { PgClient, PgPool, PgQueryResultRow } from "./pg.js"
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

export interface PostgresTokenStoreOptions {
  pool: PgPool
  /** Postgres schema (default `public`). Validated against `[A-Za-z0-9_]`. */
  schema?: string
  /** Per-table name overrides. Each validated against `[A-Za-z0-9_]`. */
  tableNames?: TableNameOverrides
  /** Server-side statement timeout (ms). Default 5000. */
  statementTimeoutMs?: number
}

const DEFAULT_STATEMENT_TIMEOUT_MS = 5000

interface PatRow extends PgQueryResultRow {
  id: string
  user_identifier: string
  name: string
  scopes: string[]
  expires_at: Date
  token_hash: Buffer
  display: string
  created_at: Date
  last_used_at: Date | null
  revoked_at: Date | null
}

interface RefreshRow extends PgQueryResultRow {
  id: string
  family_id: string
  token_hash: Buffer
  subject: string
  scopes: string[]
  expires_at: Date
  created_at: Date
  rotated_at: Date | null
}

interface UpstreamRow extends PgQueryResultRow {
  token: string
  expires_at: Date
}

function rowToPat(row: PatRow): StoredPat {
  return {
    id: row.id,
    userIdentifier: row.user_identifier,
    name: row.name,
    scopes: row.scopes,
    expiresAt: row.expires_at,
    tokenHash: row.token_hash,
    display: row.display,
    createdAt: row.created_at,
    lastUsedAt: row.last_used_at,
    revokedAt: row.revoked_at,
  }
}

function rowToPatPublic(row: PatRow): StoredPatPublic {
  return {
    id: row.id,
    name: row.name,
    scopes: row.scopes,
    display: row.display,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    lastUsedAt: row.last_used_at,
  }
}

function rowToRefresh(row: RefreshRow): StoredRefreshToken {
  return {
    id: row.id,
    familyId: row.family_id,
    tokenHash: row.token_hash,
    subject: row.subject,
    scopes: row.scopes,
    expiresAt: row.expires_at,
    createdAt: row.created_at,
    rotatedAt: row.rotated_at,
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

export function postgresTokenStore(options: PostgresTokenStoreOptions): TokenStore {
  const { pool } = options
  const names: ResolvedNames = resolveNames(options.schema, options.tableNames)
  const rawStatementTimeoutMs = options.statementTimeoutMs ?? DEFAULT_STATEMENT_TIMEOUT_MS
  const statementTimeoutMs = Math.max(
    1,
    Number.isFinite(rawStatementTimeoutMs)
      ? Math.floor(rawStatementTimeoutMs)
      : DEFAULT_STATEMENT_TIMEOUT_MS,
  )

  /**
   * Run a single statement on a pooled client with `statement_timeout` set
   * for the duration of that statement only.
   */
  async function runQuery<R extends PgQueryResultRow = PgQueryResultRow>(
    sql: string,
    params: readonly unknown[] = [],
  ): Promise<{ rows: R[]; rowCount: number }> {
    const client = await pool.connect()
    try {
      await client.query(`SET statement_timeout = ${statementTimeoutMs}`)
      const res = await client.query<R>(sql, params)
      return { rows: res.rows, rowCount: res.rowCount ?? 0 }
    } finally {
      try {
        await client.query("RESET statement_timeout")
      } catch {
        // best-effort cleanup — the original error (if any) is what callers care about
      }
      client.release()
    }
  }

  /**
   * Run `fn` inside a `BEGIN ... COMMIT` block on a single client. The
   * statement timeout is set at the start of the transaction via
   * `SET LOCAL` so it auto-resets at commit/rollback.
   */
  async function runTx<T>(fn: (client: PgClient) => Promise<T>): Promise<T> {
    const client = await pool.connect()
    try {
      await client.query("BEGIN")
      try {
        await client.query(`SET LOCAL statement_timeout = ${statementTimeoutMs}`)
        const result = await fn(client)
        await client.query("COMMIT")
        return result
      } catch (err) {
        try {
          await client.query("ROLLBACK")
        } catch {
          // Swallow rollback errors — the original error is what callers
          // care about. The client release below still happens.
        }
        throw err
      }
    } finally {
      client.release()
    }
  }

  // -------------------------------------------------------------------------
  // init
  // -------------------------------------------------------------------------

  async function init(): Promise<void> {
    // The migrations table itself is bootstrapped with a plain CREATE — this
    // is the only DDL outside the lock, and it is idempotent.
    const bootstrap = `
      CREATE TABLE IF NOT EXISTS ${names.migrations} (
        id          INTEGER PRIMARY KEY,
        name        TEXT NOT NULL,
        applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `
    await runQuery(bootstrap)

    await runTx(async (client) => {
      // Spec §6.3: concurrent process startups must serialize through this
      // lock so two replicas don't race on `CREATE TABLE`. LOCK is
      // transaction-scoped and releases at COMMIT.
      await client.query(`LOCK TABLE ${names.migrations} IN EXCLUSIVE MODE`)

      const applied = await client.query<{ id: number }>(
        `SELECT id FROM ${names.migrations} ORDER BY id ASC`,
      )
      const appliedIds = new Set(applied.rows.map((r) => r.id))

      for (const migration of migrations) {
        if (appliedIds.has(migration.id)) continue
        await client.query(migration.build(names))
        await client.query(`INSERT INTO ${names.migrations} (id, name) VALUES ($1, $2)`, [
          migration.id,
          migration.name,
        ])
      }
    })
  }

  // -------------------------------------------------------------------------
  // PAT
  // -------------------------------------------------------------------------

  async function createPat(input: CreatePatInput): Promise<StoredPat> {
    const id = randomUUID()
    const createdAt = new Date()
    const sql = `
      INSERT INTO ${names.pats}
        (id, user_identifier, name, scopes, expires_at, token_hash, display,
         created_at, last_used_at, revoked_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, NULL)
      RETURNING *
    `
    const { rows } = await runQuery<PatRow>(sql, [
      id,
      input.userIdentifier,
      input.name,
      [...input.scopes],
      input.expiresAt,
      copyBuffer(input.tokenHash),
      input.display,
      createdAt,
    ])
    const row = rows[0]
    if (!row) throw new Error("postgresTokenStore.createPat: missing RETURNING row")
    return rowToPat(row)
  }

  async function findPatByHash(hash: Buffer): Promise<StoredPat | null> {
    // Spec §14: constant-time compare AFTER the index seek. The unique index
    // on token_hash means equality at the SQL layer is fine for the lookup;
    // the app-side timingSafeEqual is defense in depth (and the same check
    // the in-memory store performs at this boundary).
    const sql = `
      SELECT * FROM ${names.pats}
      WHERE token_hash = $1
      LIMIT 1
    `
    const { rows } = await runQuery<PatRow>(sql, [hash])
    const row = rows[0]
    if (!row) return null
    if (!constantTimeEqual(row.token_hash, hash)) return null
    const now = Date.now()
    if (row.revoked_at !== null) return null
    if (row.expires_at.getTime() <= now) return null
    return rowToPat(row)
  }

  async function listPatsByUser(userIdentifier: string): Promise<StoredPatPublic[]> {
    const sql = `
      SELECT * FROM ${names.pats}
      WHERE user_identifier = $1 AND revoked_at IS NULL
      ORDER BY created_at ASC, id ASC
    `
    const { rows } = await runQuery<PatRow>(sql, [userIdentifier])
    return rows.map(rowToPatPublic)
  }

  async function revokePat(id: string, userIdentifier: string): Promise<void> {
    // Scope to the owner; idempotent — already-revoked rows are untouched.
    const sql = `
      UPDATE ${names.pats}
      SET revoked_at = now()
      WHERE id = $1 AND user_identifier = $2 AND revoked_at IS NULL
    `
    await runQuery(sql, [id, userIdentifier])
  }

  async function rotatePat(
    id: string,
    userIdentifier: string,
    next: CreatePatInput,
  ): Promise<StoredPat> {
    // Atomic: verify ownership, then insert the successor row. Lifecycle
    // layer decides when to revoke the predecessor (rotation grace window).
    return runTx<StoredPat>(async (client) => {
      const owner = await client.query<{ id: string }>(
        `SELECT id FROM ${names.pats}
         WHERE id = $1 AND user_identifier = $2
         FOR UPDATE`,
        [id, userIdentifier],
      )
      if (owner.rowCount === 0 || !owner.rows[0]) {
        throw new Error(`PAT not found: ${id}`)
      }
      if (next.userIdentifier !== userIdentifier) {
        throw new Error("rotatePat user mismatch")
      }
      const newId = randomUUID()
      const createdAt = new Date()
      const insert = await client.query<PatRow>(
        `INSERT INTO ${names.pats}
          (id, user_identifier, name, scopes, expires_at, token_hash, display,
           created_at, last_used_at, revoked_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, NULL)
         RETURNING *`,
        [
          newId,
          userIdentifier,
          next.name,
          [...next.scopes],
          next.expiresAt,
          copyBuffer(next.tokenHash),
          next.display,
          createdAt,
        ],
      )
      const row = insert.rows[0]
      if (!row) throw new Error("postgresTokenStore.rotatePat: missing RETURNING row")
      return rowToPat(row)
    })
  }

  async function updatePatLastUsed(id: string, timestamp: Date): Promise<void> {
    await runQuery(`UPDATE ${names.pats} SET last_used_at = $2 WHERE id = $1`, [id, timestamp])
  }

  // -------------------------------------------------------------------------
  // Refresh tokens
  // -------------------------------------------------------------------------

  async function createRefreshToken(input: CreateRefreshTokenInput): Promise<void> {
    const id = randomUUID()
    const createdAt = new Date()
    await runQuery(
      `INSERT INTO ${names.refreshTokens}
         (id, family_id, token_hash, subject, scopes, expires_at, created_at,
          rotated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NULL)`,
      [
        id,
        input.familyId,
        copyBuffer(input.tokenHash),
        input.subject,
        [...input.scopes],
        input.expiresAt,
        createdAt,
      ],
    )
  }

  async function findRefreshToken(hash: Buffer): Promise<StoredRefreshToken | null> {
    const sql = `
      SELECT * FROM ${names.refreshTokens}
      WHERE token_hash = $1
      LIMIT 1
    `
    const { rows } = await runQuery<RefreshRow>(sql, [hash])
    const row = rows[0]
    if (!row) return null
    if (!constantTimeEqual(row.token_hash, hash)) return null
    return rowToRefresh(row)
  }

  async function rotateRefreshToken(oldHash: Buffer, next: CreateRefreshTokenInput): Promise<void> {
    // Atomic per spec §6.1 + §6.3:
    //   1. SELECT ... FOR UPDATE the row matching `oldHash`.
    //   2. If absent: silent no-op (matches store-memory semantics — the
    //      pipeline already handles "not found" as reject).
    //   3. If already rotated: REUSE DETECTED. Revoke the entire family
    //      inside the same transaction and throw `RefreshTokenReuseError`.
    //   4. Otherwise: mark `rotated_at = now()`, INSERT the successor row.
    //
    // The UNIQUE index on token_hash means a concurrent rotation that races
    // on the same `oldHash` will serialize on the row lock; the loser then
    // sees the row already rotated and triggers the reuse path. That is
    // exactly the §14 family-revocation behavior we want.
    const reuseFamilyId = await runTx<string | null>(async (client) => {
      const sel = await client.query<RefreshRow>(
        `SELECT * FROM ${names.refreshTokens}
         WHERE token_hash = $1
         FOR UPDATE`,
        [oldHash],
      )
      const old = sel.rows[0]
      if (!old) {
        return null
      }
      if (!constantTimeEqual(old.token_hash, oldHash)) {
        // Defense in depth — should not happen given the unique index.
        return null
      }
      if (old.rotated_at !== null) {
        // Reuse of a rotated token. Revoke the family in-transaction and
        // signal the caller to throw AFTER the transaction commits, so the
        // DELETE is durable. Throwing here would trigger a ROLLBACK and
        // un-revoke the family — spec §14 violation.
        await client.query(`DELETE FROM ${names.refreshTokens} WHERE family_id = $1`, [
          old.family_id,
        ])
        return old.family_id
      }

      await client.query(`UPDATE ${names.refreshTokens} SET rotated_at = now() WHERE id = $1`, [
        old.id,
      ])
      const newId = randomUUID()
      const createdAt = new Date()
      await client.query(
        `INSERT INTO ${names.refreshTokens}
           (id, family_id, token_hash, subject, scopes, expires_at, created_at,
            rotated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, NULL)`,
        [
          newId,
          old.family_id,
          copyBuffer(next.tokenHash),
          next.subject,
          [...next.scopes],
          next.expiresAt,
          createdAt,
        ],
      )
      return null
    })
    if (reuseFamilyId !== null) {
      throw new RefreshTokenReuseError(reuseFamilyId)
    }
  }

  async function revokeRefreshTokenFamily(familyId: string): Promise<void> {
    await runTx(async (client) => {
      await client.query(`DELETE FROM ${names.refreshTokens} WHERE family_id = $1`, [familyId])
    })
  }

  // -------------------------------------------------------------------------
  // Upstream-credential cache (spec §6.2)
  // -------------------------------------------------------------------------

  async function cacheUpstreamCredential(input: CacheUpstreamCredentialInput): Promise<void> {
    // UPSERT — same cacheKey overwrites. The expires_at column carries TTL.
    await runQuery(
      `INSERT INTO ${names.upstreamCredentials}
         (cache_key, token, expires_at)
       VALUES ($1, $2, $3)
       ON CONFLICT (cache_key) DO UPDATE
         SET token = EXCLUDED.token, expires_at = EXCLUDED.expires_at`,
      [input.cacheKey, input.token, input.expiresAt],
    )
  }

  async function findUpstreamCredential(cacheKey: string): Promise<UpstreamCredentialEntry | null> {
    // Expired entries are treated as misses. We do not delete on read — a
    // periodic cleanup is out of scope for v0.2 (consumers can run their
    // own vacuum/job).
    const { rows } = await runQuery<UpstreamRow>(
      `SELECT token, expires_at FROM ${names.upstreamCredentials}
       WHERE cache_key = $1
       LIMIT 1`,
      [cacheKey],
    )
    const row = rows[0]
    if (!row) return null
    if (row.expires_at.getTime() <= Date.now()) return null
    return { token: row.token, expiresAt: row.expires_at }
  }

  async function close(): Promise<void> {
    // Per spec §6.3: the pool belongs to the consumer. Intentionally a no-op.
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
