/**
 * In-memory `RedisClient` for unit tests. Implements only the surface the
 * decorator uses (`get`, `set EX`, `del`, `sadd`, `smembers`, `expire`).
 *
 * TTLs are honored against `Date.now()`; no timers are scheduled. Vitest's
 * `vi.useFakeTimers()` is not required — callers can advance "time" by
 * `client.advance(ms)` if a test needs to observe expiry.
 */

import type { RedisClient } from "./client.js"

interface Entry {
  value: Buffer
  expiresAtMs: number
}

interface SetEntry {
  members: Set<string>
  expiresAtMs: number
}

export class FakeRedis implements RedisClient {
  private kv = new Map<string, Entry>()
  private sets = new Map<string, SetEntry>()
  private nowMs: number = Date.now()
  /** Counters for assertions. */
  public calls = {
    get: 0,
    set: 0,
    del: 0,
    sadd: 0,
    smembers: 0,
    expire: 0,
  }

  advance(ms: number): void {
    this.nowMs += ms
  }

  setNow(ms: number): void {
    this.nowMs = ms
  }

  private now(): number {
    return this.nowMs
  }

  private expired(e: { expiresAtMs: number }): boolean {
    return e.expiresAtMs <= this.now()
  }

  async get(key: string): Promise<Buffer | null> {
    this.calls.get++
    const e = this.kv.get(key)
    if (!e) return null
    if (this.expired(e)) {
      this.kv.delete(key)
      return null
    }
    return e.value
  }

  async set(key: string, value: Buffer | string, mode: "EX", ttl: number): Promise<unknown> {
    this.calls.set++
    if (mode !== "EX") throw new Error(`FakeRedis: unsupported mode ${mode}`)
    if (!Number.isInteger(ttl) || ttl <= 0) {
      throw new Error(`FakeRedis: invalid TTL ${ttl}`)
    }
    const buf = typeof value === "string" ? Buffer.from(value, "utf8") : Buffer.from(value)
    this.kv.set(key, { value: buf, expiresAtMs: this.now() + ttl * 1000 })
    return "OK"
  }

  async del(...keys: string[]): Promise<unknown> {
    this.calls.del++
    let count = 0
    for (const k of keys) {
      if (this.kv.delete(k)) count++
      if (this.sets.delete(k)) count++
    }
    return count
  }

  async sadd(key: string, ...members: string[]): Promise<unknown> {
    this.calls.sadd++
    let entry = this.sets.get(key)
    if (!entry || this.expired(entry)) {
      entry = { members: new Set(), expiresAtMs: Number.POSITIVE_INFINITY }
      this.sets.set(key, entry)
    }
    let added = 0
    for (const m of members) {
      if (!entry.members.has(m)) {
        entry.members.add(m)
        added++
      }
    }
    return added
  }

  async smembers(key: string): Promise<string[]> {
    this.calls.smembers++
    const entry = this.sets.get(key)
    if (!entry) return []
    if (this.expired(entry)) {
      this.sets.delete(key)
      return []
    }
    return Array.from(entry.members)
  }

  async expire(key: string, seconds: number): Promise<unknown> {
    this.calls.expire++
    const entry = this.sets.get(key)
    if (entry) {
      entry.expiresAtMs = this.now() + seconds * 1000
      return 1
    }
    const kv = this.kv.get(key)
    if (kv) {
      kv.expiresAtMs = this.now() + seconds * 1000
      return 1
    }
    return 0
  }

  // Test helpers
  has(key: string): boolean {
    return this.kv.has(key)
  }
  rawSet(key: string, value: Buffer, ttlSeconds: number): void {
    this.kv.set(key, { value, expiresAtMs: this.now() + ttlSeconds * 1000 })
  }
}
