/**
 * Re-export of the SQLite `TokenStore` implementation.
 *
 * `mcp-authkit-store-sqlite` declares its own copy of the contract types
 * from spec §6.1 (it cannot depend on this package without creating a
 * workspace cycle). The structural-assignability assertion below ensures
 * the two declarations stay in lockstep — any drift fails `pnpm typecheck`.
 */
import {
  sqliteTokenStore as _sqliteTokenStore,
  type SqliteTokenStoreOptions,
} from "mcp-authkit-store-sqlite"
import type { TokenStore } from "../types.js"

// Compile-time check: store-sqlite's TokenStore must satisfy core's TokenStore.
const _typecheck: (options: SqliteTokenStoreOptions) => TokenStore = _sqliteTokenStore
void _typecheck

export const sqliteTokenStore: (options: SqliteTokenStoreOptions) => TokenStore = _sqliteTokenStore
export type { SqliteTokenStoreOptions, TableNames } from "mcp-authkit-store-sqlite"
