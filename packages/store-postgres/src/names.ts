/**
 * Resolved, validated, quoted table identifiers.
 *
 * Construction validates every identifier exactly once — at store
 * instantiation. Per-query code reads pre-quoted strings and never touches
 * raw user-supplied names.
 */

import { quoteIdent, quoteQualified } from "./identifiers.js"

export interface TableNameOverrides {
  pats?: string
  refreshTokens?: string
  upstreamCredentials?: string
  migrations?: string
}

/**
 * Pre-quoted, schema-qualified identifiers — safe to interpolate into SQL.
 */
export interface ResolvedNames {
  schema: string
  pats: string
  refreshTokens: string
  upstreamCredentials: string
  migrations: string
  /** Migration-table name in raw (unquoted) form for `LOCK TABLE` and lookups. */
  migrationsUnquoted: string
}

export const DEFAULT_TABLE_NAMES = {
  pats: "mcp_pats",
  refreshTokens: "mcp_refresh_tokens",
  upstreamCredentials: "mcp_upstream_credentials",
  migrations: "mcp_migrations",
} as const

export function resolveNames(
  schema: string | undefined,
  overrides: TableNameOverrides | undefined,
): ResolvedNames {
  const s = schema ?? "public"
  // Validate schema once.
  quoteIdent(s, "schema")

  const pats = overrides?.pats ?? DEFAULT_TABLE_NAMES.pats
  const refresh = overrides?.refreshTokens ?? DEFAULT_TABLE_NAMES.refreshTokens
  const upstream = overrides?.upstreamCredentials ?? DEFAULT_TABLE_NAMES.upstreamCredentials
  const mig = overrides?.migrations ?? DEFAULT_TABLE_NAMES.migrations

  return {
    schema: s,
    pats: quoteQualified(s, pats),
    refreshTokens: quoteQualified(s, refresh),
    upstreamCredentials: quoteQualified(s, upstream),
    migrations: quoteQualified(s, mig),
    migrationsUnquoted: mig,
  }
}
