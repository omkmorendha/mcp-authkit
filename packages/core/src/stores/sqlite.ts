/**
 * Re-export of the SQLite `TokenStore` implementation.
 *
 * `mcp-authkit-store-sqlite` declares its own copy of the contract types
 * from spec §6.1 (it cannot depend on this package without creating a
 * workspace cycle). The structural-assignability assertion below ensures
 * the two declarations stay in lockstep — any drift fails `pnpm typecheck`.
 *
 * Public import path: `mcp-authkit/stores/sqlite` (see core's `exports`).
 *
 * Spec: docs/spec/v0.2.md#64-sqlite-store
 */
import {
  InvalidIdentifierError as _InvalidIdentifierError,
  RefreshTokenReuseError as _RefreshTokenReuseError,
  sqliteTokenStore as _sqliteTokenStore,
  type SqliteTokenStoreOptions,
} from "mcp-authkit-store-sqlite"
import type { TokenStore } from "../types.js"

// Compile-time check: store-sqlite's TokenStore must satisfy core's
// TokenStore. The cache methods (`cacheUpstreamCredential` /
// `findUpstreamCredential`) are optional in the core contract — the v0.1
// `TokenStore` doesn't declare them, so structural compatibility holds even
// while the SQLite store ships them as concrete methods.
const _typecheck: (options: SqliteTokenStoreOptions) => TokenStore = _sqliteTokenStore
void _typecheck

export const sqliteTokenStore: (options: SqliteTokenStoreOptions) => TokenStore = _sqliteTokenStore

export type {
  SqliteDatabase,
  SqliteTokenStoreOptions,
  TableNameOverrides,
} from "mcp-authkit-store-sqlite"

export const RefreshTokenReuseError = _RefreshTokenReuseError
export const InvalidIdentifierError = _InvalidIdentifierError
