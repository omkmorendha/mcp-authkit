/**
 * Idempotent, forward-only migrations for the Postgres token store.
 *
 * Spec §6.3:
 *   - Migrations are bundled and run via `init()`.
 *   - Applied inside a transaction holding `LOCK TABLE mcp_migrations IN
 *     EXCLUSIVE MODE` so concurrent process startups serialize cleanly.
 *   - Idempotent: `init()` may be called any number of times.
 *
 * Table identifiers below are resolved from the configured names — they are
 * validated against `/^[A-Za-z0-9_]+$/` (see ./identifiers.ts) before any
 * interpolation happens. The runtime never substitutes user-controlled data
 * into identifier positions.
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
        id              UUID PRIMARY KEY,
        user_identifier TEXT NOT NULL,
        name            TEXT NOT NULL,
        scopes          TEXT[] NOT NULL,
        expires_at      TIMESTAMPTZ NOT NULL,
        token_hash      BYTEA NOT NULL,
        display         TEXT NOT NULL,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_used_at    TIMESTAMPTZ,
        revoked_at      TIMESTAMPTZ
      );

      CREATE UNIQUE INDEX IF NOT EXISTS mcp_pats_token_hash_uidx
        ON ${pats} (token_hash);

      CREATE INDEX IF NOT EXISTS mcp_pats_user_identifier_idx
        ON ${pats} (user_identifier);

      CREATE TABLE IF NOT EXISTS ${refreshTokens} (
        id          UUID PRIMARY KEY,
        family_id   TEXT NOT NULL,
        token_hash  BYTEA NOT NULL,
        subject     TEXT NOT NULL,
        scopes      TEXT[] NOT NULL,
        expires_at  TIMESTAMPTZ NOT NULL,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
        rotated_at  TIMESTAMPTZ
      );

      CREATE UNIQUE INDEX IF NOT EXISTS mcp_refresh_tokens_token_hash_uidx
        ON ${refreshTokens} (token_hash);

      CREATE INDEX IF NOT EXISTS mcp_refresh_tokens_family_id_idx
        ON ${refreshTokens} (family_id);

      CREATE TABLE IF NOT EXISTS ${upstreamCredentials} (
        cache_key   TEXT PRIMARY KEY,
        token       TEXT NOT NULL,
        expires_at  TIMESTAMPTZ NOT NULL,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      CREATE INDEX IF NOT EXISTS mcp_upstream_credentials_key_exp_idx
        ON ${upstreamCredentials} (cache_key, expires_at);
    `,
  },
]
