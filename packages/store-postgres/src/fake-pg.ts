/**
 * Test-only in-memory mock of the subset of `pg` we use.
 *
 * It is NOT a SQL engine — it pattern-matches the literal SQL strings the
 * Postgres store emits, executes the matching effect against in-memory
 * maps, and records every issued query so tests can assert on cardinality
 * and parameters. The real-Postgres integration tests (gated by
 * `INTEGRATION_DATABASE_URL`) cover correctness against a live engine.
 *
 * Keeping this self-contained means the unit-test layer runs without
 * Docker, which keeps `pnpm test` viable on a laptop.
 */

import type { PgClient, PgPool, PgQueryResult, PgQueryResultRow } from "./pg.js"

interface PatRow {
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

interface RefreshRow {
  id: string
  family_id: string
  token_hash: Buffer
  subject: string
  scopes: string[]
  expires_at: Date
  created_at: Date
  rotated_at: Date | null
}

interface UpstreamRow {
  cache_key: string
  token: string
  expires_at: Date
  created_at: Date
}

interface MigrationRow {
  id: number
  name: string
  applied_at: Date
}

export interface FakePoolControls {
  pool: PgPool
  pats: Map<string, PatRow>
  refresh: Map<string, RefreshRow>
  upstream: Map<string, UpstreamRow>
  migrationsTable: Map<number, MigrationRow>
  queries: Array<{ sql: string; params: readonly unknown[] }>
  /** Hook to inject latency / artificial timeouts. */
  beforeQuery: ((sql: string, params: readonly unknown[]) => Promise<void>) | null
  connections: { current: number; peak: number; opened: number }
}

const TIMEOUT_RE = /^SET (?:LOCAL )?statement_timeout = (\d+)$/

export function createFakePool(): FakePoolControls {
  const controls: FakePoolControls = {
    pool: null as unknown as PgPool,
    pats: new Map(),
    refresh: new Map(),
    upstream: new Map(),
    migrationsTable: new Map(),
    queries: [],
    beforeQuery: null,
    connections: { current: 0, peak: 0, opened: 0 },
  }

  let currentTimeout = Number.POSITIVE_INFINITY

  function findRefreshByHash(hash: Buffer): RefreshRow | undefined {
    for (const row of controls.refresh.values()) {
      if (row.token_hash.equals(hash)) return row
    }
    return undefined
  }

  function findPatByHash(hash: Buffer): PatRow | undefined {
    for (const row of controls.pats.values()) {
      if (row.token_hash.equals(hash)) return row
    }
    return undefined
  }

  async function execute(
    sql: string,
    params: readonly unknown[] = [],
  ): Promise<PgQueryResult<PgQueryResultRow>> {
    controls.queries.push({ sql, params })
    if (controls.beforeQuery) await controls.beforeQuery(sql, params)

    const trimmed = sql.trim().replace(/\s+/g, " ")

    // statement_timeout management — capture the value so timeout tests can
    // assert it's set on every query.
    const tm = TIMEOUT_RE.exec(trimmed)
    if (tm) {
      const ms = Number(tm[1])
      currentTimeout = ms
      return { rows: [], rowCount: 0 }
    }
    if (trimmed === "RESET statement_timeout") {
      currentTimeout = Number.POSITIVE_INFINITY
      return { rows: [], rowCount: 0 }
    }
    if (trimmed === "BEGIN" || trimmed === "COMMIT" || trimmed === "ROLLBACK") {
      return { rows: [], rowCount: 0 }
    }

    // Migrations table.
    if (/^CREATE TABLE IF NOT EXISTS "[^"]+"\."[^"]+" \( id +INTEGER PRIMARY KEY/.test(trimmed)) {
      return { rows: [], rowCount: 0 }
    }
    if (/^LOCK TABLE "[^"]+"\."[^"]+" IN EXCLUSIVE MODE$/.test(trimmed)) {
      return { rows: [], rowCount: 0 }
    }
    if (/^SELECT id FROM "[^"]+"\."[^"]+" ORDER BY id ASC$/.test(trimmed)) {
      const rows = [...controls.migrationsTable.values()]
        .sort((a, b) => a.id - b.id)
        .map((r) => ({ id: r.id }))
      return { rows, rowCount: rows.length }
    }
    if (/^INSERT INTO "[^"]+"\."[^"]+" \(id, name\) VALUES \(\$1, \$2\)$/.test(trimmed)) {
      const [id, name] = params as [number, string]
      controls.migrationsTable.set(id, { id, name, applied_at: new Date() })
      return { rows: [], rowCount: 1 }
    }
    // Schema-creating migrations from `migrations.ts`. We do not parse the
    // CREATE TABLE statements — they're applied successfully as a unit.
    if (/^CREATE TABLE IF NOT EXISTS/.test(trimmed)) {
      return { rows: [], rowCount: 0 }
    }

    // ---- PATs ----
    if (/^INSERT INTO "[^"]+"\."[^"]+" \(id, user_identifier, name, scopes/.test(trimmed)) {
      const [id, userIdentifier, name, scopes, expiresAt, tokenHash, display, createdAt] =
        params as [string, string, string, string[], Date, Buffer, string, Date]
      const row: PatRow = {
        id,
        user_identifier: userIdentifier,
        name,
        scopes,
        expires_at: expiresAt,
        token_hash: Buffer.from(tokenHash),
        display,
        created_at: createdAt,
        last_used_at: null,
        revoked_at: null,
      }
      controls.pats.set(id, row)
      if (/RETURNING \*/.test(trimmed)) {
        return { rows: [row as unknown as PgQueryResultRow], rowCount: 1 }
      }
      return { rows: [], rowCount: 1 }
    }
    if (/^SELECT \* FROM "[^"]+"\."[^"]+" WHERE token_hash = \$1 LIMIT 1$/.test(trimmed)) {
      // Could match pats or refresh — disambiguate via params shape (Buffer).
      const hash = params[0] as Buffer
      const pat = findPatByHash(hash)
      if (pat) return { rows: [pat as unknown as PgQueryResultRow], rowCount: 1 }
      const rt = findRefreshByHash(hash)
      if (rt) return { rows: [rt as unknown as PgQueryResultRow], rowCount: 1 }
      return { rows: [], rowCount: 0 }
    }
    if (
      /^SELECT \* FROM "[^"]+"\."[^"]+" WHERE user_identifier = \$1 AND revoked_at IS NULL ORDER BY created_at ASC, id ASC$/.test(
        trimmed,
      )
    ) {
      const [userId] = params as [string]
      const rows = [...controls.pats.values()]
        .filter((r) => r.user_identifier === userId && r.revoked_at === null)
        .sort((a, b) =>
          a.created_at.getTime() === b.created_at.getTime()
            ? a.id.localeCompare(b.id)
            : a.created_at.getTime() - b.created_at.getTime(),
        )
      return { rows: rows as unknown as PgQueryResultRow[], rowCount: rows.length }
    }
    if (
      /^UPDATE "[^"]+"\."[^"]+" SET revoked_at = now\(\) WHERE id = \$1 AND user_identifier = \$2 AND revoked_at IS NULL$/.test(
        trimmed,
      )
    ) {
      const [id, userId] = params as [string, string]
      const row = controls.pats.get(id)
      if (!row || row.user_identifier !== userId || row.revoked_at !== null) {
        return { rows: [], rowCount: 0 }
      }
      row.revoked_at = new Date()
      controls.pats.set(id, row)
      return { rows: [], rowCount: 1 }
    }
    if (
      /^SELECT id FROM "[^"]+"\."[^"]+" WHERE id = \$1 AND user_identifier = \$2 FOR UPDATE$/.test(
        trimmed,
      )
    ) {
      const [id, userId] = params as [string, string]
      const row = controls.pats.get(id)
      if (!row || row.user_identifier !== userId) {
        return { rows: [], rowCount: 0 }
      }
      return { rows: [{ id }], rowCount: 1 }
    }
    if (/^UPDATE "[^"]+"\."[^"]+" SET last_used_at = \$2 WHERE id = \$1$/.test(trimmed)) {
      const [id, ts] = params as [string, Date]
      const row = controls.pats.get(id)
      if (!row) return { rows: [], rowCount: 0 }
      row.last_used_at = ts
      controls.pats.set(id, row)
      return { rows: [], rowCount: 1 }
    }

    // ---- Refresh tokens ----
    if (/^INSERT INTO "[^"]+"\."[^"]+" \(id, family_id, token_hash/.test(trimmed)) {
      const [id, familyId, tokenHash, subject, scopes, expiresAt, createdAt] = params as [
        string,
        string,
        Buffer,
        string,
        string[],
        Date,
        Date,
      ]
      const row: RefreshRow = {
        id,
        family_id: familyId,
        token_hash: Buffer.from(tokenHash),
        subject,
        scopes,
        expires_at: expiresAt,
        created_at: createdAt,
        rotated_at: null,
      }
      controls.refresh.set(id, row)
      return { rows: [], rowCount: 1 }
    }
    if (/^SELECT \* FROM "[^"]+"\."[^"]+" WHERE token_hash = \$1 FOR UPDATE$/.test(trimmed)) {
      const hash = params[0] as Buffer
      const row = findRefreshByHash(hash)
      if (!row) return { rows: [], rowCount: 0 }
      return { rows: [row as unknown as PgQueryResultRow], rowCount: 1 }
    }
    if (/^UPDATE "[^"]+"\."[^"]+" SET rotated_at = now\(\) WHERE id = \$1$/.test(trimmed)) {
      const [id] = params as [string]
      const row = controls.refresh.get(id)
      if (!row) return { rows: [], rowCount: 0 }
      row.rotated_at = new Date()
      controls.refresh.set(id, row)
      return { rows: [], rowCount: 1 }
    }
    if (/^DELETE FROM "[^"]+"\."[^"]+" WHERE family_id = \$1$/.test(trimmed)) {
      const [familyId] = params as [string]
      let n = 0
      for (const [id, row] of controls.refresh) {
        if (row.family_id === familyId) {
          controls.refresh.delete(id)
          n += 1
        }
      }
      return { rows: [], rowCount: n }
    }

    // ---- Upstream credentials ----
    if (
      /^INSERT INTO "[^"]+"\."[^"]+" \(cache_key, token, expires_at\) VALUES \(\$1, \$2, \$3\) ON CONFLICT \(cache_key\) DO UPDATE/.test(
        trimmed,
      )
    ) {
      const [key, token, expiresAt] = params as [string, string, Date]
      controls.upstream.set(key, {
        cache_key: key,
        token,
        expires_at: expiresAt,
        created_at: new Date(),
      })
      return { rows: [], rowCount: 1 }
    }
    if (
      /^SELECT token, expires_at FROM "[^"]+"\."[^"]+" WHERE cache_key = \$1 LIMIT 1$/.test(trimmed)
    ) {
      const [key] = params as [string]
      const row = controls.upstream.get(key)
      if (!row) return { rows: [], rowCount: 0 }
      return {
        rows: [{ token: row.token, expires_at: row.expires_at } as PgQueryResultRow],
        rowCount: 1,
      }
    }

    throw new Error(`fake-pg: unhandled SQL ${JSON.stringify(trimmed.slice(0, 120))}`)
  }

  const client: PgClient = {
    async query(sql, params) {
      return execute(sql, params ?? []) as Promise<PgQueryResult<PgQueryResultRow>>
    },
    release() {
      controls.connections.current -= 1
    },
  }

  controls.pool = {
    async connect() {
      controls.connections.current += 1
      controls.connections.opened += 1
      if (controls.connections.current > controls.connections.peak) {
        controls.connections.peak = controls.connections.current
      }
      return client
    },
    async query(sql, params) {
      return execute(sql, params ?? []) as Promise<PgQueryResult<PgQueryResultRow>>
    },
  }

  // Expose currentTimeout via a getter for test assertions.
  Object.defineProperty(controls, "currentTimeout", {
    get: () => currentTimeout,
  })

  return controls
}
