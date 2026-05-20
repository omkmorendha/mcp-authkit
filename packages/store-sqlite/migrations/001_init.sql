-- 001_init.sql
-- Initial schema for mcp-authkit-store-sqlite.
--
-- Spec: docs/spec/v0.2.md#64-sqlite-store
--
-- Table names below are placeholders. At runtime the package validates and
-- substitutes the configured names; the SQL run against SQLite uses the
-- resolved identifiers. See packages/store-sqlite/src/migrations.ts.

CREATE TABLE IF NOT EXISTS mcp_pats (
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
  ON mcp_pats (token_hash);

CREATE INDEX IF NOT EXISTS mcp_pats_user_identifier_idx
  ON mcp_pats (user_identifier);

CREATE TABLE IF NOT EXISTS mcp_refresh_tokens (
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
  ON mcp_refresh_tokens (token_hash);

CREATE INDEX IF NOT EXISTS mcp_refresh_tokens_family_id_idx
  ON mcp_refresh_tokens (family_id);

CREATE TABLE IF NOT EXISTS mcp_upstream_credentials (
  cache_key   TEXT PRIMARY KEY,
  token       TEXT NOT NULL,
  expires_at  INTEGER NOT NULL,
  created_at  INTEGER NOT NULL
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS mcp_upstream_credentials_key_exp_idx
  ON mcp_upstream_credentials (cache_key, expires_at);
