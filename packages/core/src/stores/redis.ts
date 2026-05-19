/**
 * Re-export of the Redis cache decorator.
 *
 * `mcp-authkit-store-redis` declares its own copy of the contract types
 * from spec §6.1 (it cannot depend on this package without creating a
 * workspace cycle). The structural-assignability assertion below ensures
 * the two declarations stay in lockstep — any drift fails `pnpm typecheck`.
 */
import { redisCache as _redisCache } from "mcp-authkit-store-redis"
import type { TokenStore } from "../types.js"

// Compile-time check: store-redis's TokenStore must satisfy core's TokenStore.
// We probe with the public factory's return shape.
const _typecheck: (inner: TokenStore, options: Parameters<typeof _redisCache>[1]) => TokenStore =
  _redisCache
void _typecheck

export const redisCache: (
  inner: TokenStore,
  options: Parameters<typeof _redisCache>[1],
) => TokenStore = _redisCache

export type { RedisCacheOptions } from "mcp-authkit-store-redis"
