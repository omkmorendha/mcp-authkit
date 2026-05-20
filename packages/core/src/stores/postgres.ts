/**
 * Re-export of the Postgres `TokenStore` implementation.
 *
 * `mcp-authkit-store-postgres` declares its own copy of the contract types
 * from spec §6.1 (it cannot depend on this package without creating a
 * workspace cycle). The structural-assignability assertion below ensures
 * the two declarations stay in lockstep — any drift fails `pnpm typecheck`.
 *
 * Public import path: `mcp-authkit/stores/postgres` (see core's `exports`).
 *
 * Spec: docs/spec/v0.2.md#63-postgres-store
 */
import {
  InvalidIdentifierError as _InvalidIdentifierError,
  postgresTokenStore as _postgresTokenStore,
  RefreshTokenReuseError as _RefreshTokenReuseError,
  type PostgresTokenStoreOptions,
} from "mcp-authkit-store-postgres"
import type { TokenStore } from "../types.js"

// Compile-time check: store-postgres's TokenStore must satisfy core's
// TokenStore. The cache methods (`cacheUpstreamCredential` /
// `findUpstreamCredential`) are optional in the core contract — the v0.1
// `TokenStore` doesn't declare them, so structural compatibility holds even
// while the Postgres store ships them as concrete methods.
const _typecheck: (options: PostgresTokenStoreOptions) => TokenStore = _postgresTokenStore
void _typecheck

export const postgresTokenStore: (options: PostgresTokenStoreOptions) => TokenStore =
  _postgresTokenStore

export type { PostgresTokenStoreOptions, TableNameOverrides } from "mcp-authkit-store-postgres"

export const RefreshTokenReuseError = _RefreshTokenReuseError
export const InvalidIdentifierError = _InvalidIdentifierError
