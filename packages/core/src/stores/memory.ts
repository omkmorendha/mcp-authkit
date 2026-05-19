/**
 * Re-export of the in-memory `TokenStore` implementation.
 *
 * `mcp-authkit-store-memory` declares its own copy of the contract types
 * from spec §6.1 (it cannot depend on this package without creating a
 * workspace cycle). The structural-assignability assertion below ensures
 * the two declarations stay in lockstep — any drift fails `pnpm typecheck`.
 */
import { memoryTokenStore as _memoryTokenStore } from "mcp-authkit-store-memory"
import type { TokenStore } from "../types.js"

// Compile-time check: store-memory's TokenStore must satisfy core's TokenStore.
const _typecheck: () => TokenStore = _memoryTokenStore
void _typecheck

export const memoryTokenStore: () => TokenStore = _memoryTokenStore
