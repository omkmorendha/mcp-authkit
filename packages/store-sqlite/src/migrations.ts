/**
 * Idempotent, forward-only migrations for the SQLite token store.
 *
 * Spec §6.4:
 *   - Migrations are bundled and run via `init()`.
 *   - Applied inside a transaction wrapped in `BEGIN IMMEDIATE` (acquired
 *     via `better-sqlite3`'s `transaction()` helper which we configure
 *     with `IMMEDIATE`).
 *   - `journal_mode = WAL` is set before migrations run.
 *   - Idempotent: `init()` may be called any number of times.
 *
 * Table identifiers below are resolved from the configured names — they are
 * validated against `/^[A-Za-z0-9_]+$/` (see ./identifiers.ts) before any
 * interpolation happens. The runtime never substitutes user-controlled data
 * into identifier positions.
 *
 * Storage-type notes:
 *   - `token_hash` is `BLOB` (raw bytes; spec §6.1 forbids base64 in storage).
 *   - `scopes` is a JSON-encoded `TEXT` array. SQLite has no array type;
 *     comparisons are never made against this column.
 *   - Timestamps are stored as INTEGER (Unix epoch milliseconds) to avoid
 *     SQLite's loose date typing.
 */

import type { ResolvedNames } from "./names.js"

export interface Migration {
  /** Strictly increasing integer; gaps are not permitted. */
  id: number
  /** Human label, recorded in `mcp_migrations.name`. */
  name: string
  /** Build the migration SQL against the resolved (validated) identifiers. */
  build: (names: ResolvedNames) => string
}

export const migrations: readonly Migration[] = [
  {
    id: 1,
    name: "001_init",
    build: ({ pats, refreshTokens, upstreamCredentials }) => `
      CREATE TABLE IF NOT EXISTS ${pats} (
        id              TEXT PRIMARY KEY,
        user_identifier TEXT NOT NULL,
        name            TEXT NOT NULL,
        scopes          TEXT NOT NULL,
        expires_at      INTEGER NOT NULL,
        token_hash      BLOB NOT NULL,
        display         TEXT NOT NULL,
        created_at      INTEGER NOT NULL,
        last_used_at    INTEGER,
        revoked_at      INTEGER
      );

      CREATE UNIQUE INDEX IF NOT EXISTS mcp_pats_token_hash_uidx
        ON ${pats} (token_hash);

      CREATE INDEX IF NOT EXISTS mcp_pats_user_identifier_idx
        ON ${pats} (user_identifier);

      CREATE TABLE IF NOT EXISTS ${refreshTokens} (
        id          TEXT PRIMARY KEY,
        family_id   TEXT NOT NULL,
        token_hash  BLOB NOT NULL,
        subject     TEXT NOT NULL,
        scopes      TEXT NOT NULL,
        expires_at  INTEGER NOT NULL,
        created_at  INTEGER NOT NULL,
        rotated_at  INTEGER
      );

      CREATE UNIQUE INDEX IF NOT EXISTS mcp_refresh_tokens_token_hash_uidx
        ON ${refreshTokens} (token_hash);

      CREATE INDEX IF NOT EXISTS mcp_refresh_tokens_family_id_idx
        ON ${refreshTokens} (family_id);

      CREATE TABLE IF NOT EXISTS ${upstreamCredentials} (
        cache_key   TEXT PRIMARY KEY,
        token       TEXT NOT NULL,
        expires_at  INTEGER NOT NULL,
        created_at  INTEGER NOT NULL
      ) WITHOUT ROWID;

      CREATE INDEX IF NOT EXISTS mcp_upstream_credentials_key_exp_idx
        ON ${upstreamCredentials} (cache_key, expires_at);
    `,
  },
]
