/**
 * Resolved, validated, quoted table identifiers.
 *
 * Construction validates every identifier exactly once — at store
 * instantiation. Per-query code reads pre-quoted strings and never touches
 * raw user-supplied names.
 *
 * SQLite has no schema concept (databases are files); only table-name
 * overrides are accepted.
 */

import { quoteIdent } from "./identifiers.js"

export interface TableNameOverrides {
  pats?: string
  refreshTokens?: string
  upstreamCredentials?: string
  migrations?: string
}

/**
 * Pre-quoted identifiers — safe to interpolate into SQL.
 */
export interface ResolvedNames {
  pats: string
  refreshTokens: string
  upstreamCredentials: string
  migrations: string
  /** Migration-table name in raw (unquoted) form for lookups. */
  migrationsUnquoted: string
}

export const DEFAULT_TABLE_NAMES = {
  pats: "mcp_pats",
  refreshTokens: "mcp_refresh_tokens",
  upstreamCredentials: "mcp_upstream_credentials",
  migrations: "mcp_migrations",
} as const

export function resolveNames(overrides: TableNameOverrides | undefined): ResolvedNames {
  const pats = overrides?.pats ?? DEFAULT_TABLE_NAMES.pats
  const refresh = overrides?.refreshTokens ?? DEFAULT_TABLE_NAMES.refreshTokens
  const upstream = overrides?.upstreamCredentials ?? DEFAULT_TABLE_NAMES.upstreamCredentials
  const mig = overrides?.migrations ?? DEFAULT_TABLE_NAMES.migrations

  return {
    pats: quoteIdent(pats, "table"),
    refreshTokens: quoteIdent(refresh, "table"),
    upstreamCredentials: quoteIdent(upstream, "table"),
    migrations: quoteIdent(mig, "table"),
    migrationsUnquoted: mig,
  }
}
