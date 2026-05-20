/**
 * Re-export of the Redis cache decorator.
 *
 * `mcp-authkit-store-redis` declares its own copy of the contract types
 * from spec §6.1 (it cannot depend on this package without creating a
 * workspace cycle). The structural-assignability assertion below ensures
 * the two declarations stay in lockstep — any drift fails `pnpm typecheck`.
 *
 * Public import path: `mcp-authkit/stores/redis` (see core's `exports`).
 *
 * Spec: docs/spec/v0.2.md#65-redis-cache-decorator
 */
import {
  type RedisCacheOptions as _RedisCacheOptions,
  redisCache as _redisCache,
} from "mcp-authkit-store-redis"
import type { TokenStore } from "../types.js"

// Compile-time check: store-redis's TokenStore must satisfy core's TokenStore.
// The decorator takes an `inner: TokenStore` and returns a `TokenStore` — both
// sides of the function must align with the core contract.
const _typecheck: (inner: TokenStore, options: _RedisCacheOptions) => TokenStore = _redisCache
void _typecheck

export const redisCache: (inner: TokenStore, options: _RedisCacheOptions) => TokenStore =
  _redisCache

export type { RedisCacheLogger, RedisCacheOptions, RedisClient } from "mcp-authkit-store-redis"
