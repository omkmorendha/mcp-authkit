-- 001_init.sql
-- Initial schema for mcp-authkit-store-postgres.
--
-- Spec: docs/spec/v0.2.md#63-postgres-store
--
-- Table names below are placeholders. At runtime the package validates and
-- substitutes the configured names; the SQL run against Postgres uses the
-- resolved identifiers. See packages/store-postgres/src/migrations.ts.

CREATE TABLE IF NOT EXISTS mcp_pats (
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
  ON mcp_pats (token_hash);

CREATE INDEX IF NOT EXISTS mcp_pats_user_identifier_idx
  ON mcp_pats (user_identifier);

CREATE TABLE IF NOT EXISTS mcp_refresh_tokens (
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
  ON mcp_refresh_tokens (token_hash);

CREATE INDEX IF NOT EXISTS mcp_refresh_tokens_family_id_idx
  ON mcp_refresh_tokens (family_id);

CREATE TABLE IF NOT EXISTS mcp_upstream_credentials (
  cache_key   TEXT PRIMARY KEY,
  token       TEXT NOT NULL,
  expires_at  TIMESTAMPTZ NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS mcp_upstream_credentials_key_exp_idx
  ON mcp_upstream_credentials (cache_key, expires_at);
