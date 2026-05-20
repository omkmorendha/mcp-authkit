/**
 * Minimal structural Redis client interface.
 *
 * Spec §2 locks the client choice to `ioredis`, but the decorator only needs
 * three operations and keeping the interface narrow lets consumers pass a
 * mock or a thin wrapper. An `ioredis.Redis` instance satisfies this
 * interface without modification.
 */
export interface RedisClient {
  /** GET — returns `null` for a missing key. Buffer or string per client config. */
  get(key: string): Promise<Buffer | string | null>
  /** SET key value EX <seconds> — positive integer TTL required by this decorator. */
  set(key: string, value: Buffer | string, mode: "EX", ttl: number): Promise<unknown>
  /** DEL one or more keys; missing keys are ignored by Redis. */
  del(...keys: string[]): Promise<unknown>
  /** SADD member to set — used to track per-family refresh-token hashes for invalidation. */
  sadd(key: string, ...members: string[]): Promise<unknown>
  /** SMEMBERS — returns all members of a set, or [] if the key is missing. */
  smembers(key: string): Promise<string[]>
  /** EXPIRE key seconds — best-effort TTL on the reverse-index set. */
  expire(key: string, seconds: number): Promise<unknown>
}
