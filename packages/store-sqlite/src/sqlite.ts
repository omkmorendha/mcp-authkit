/**
 * Minimal structural typing of the parts of `better-sqlite3` we depend on.
 *
 * The package's runtime dependency is `better-sqlite3` (declared as a peer);
 * the types are kept narrow on purpose so the store can be exercised against
 * any driver that exposes the same `prepare`/`exec`/`pragma`/`transaction`
 * shape.
 */

export interface SqliteRunResult {
  changes: number
  lastInsertRowid: number | bigint
}

export interface SqliteStatement<R = unknown> {
  run(...params: readonly unknown[]): SqliteRunResult
  get(...params: readonly unknown[]): R | undefined
  all(...params: readonly unknown[]): R[]
}

export interface SqliteDatabase {
  prepare<R = unknown>(sql: string): SqliteStatement<R>
  exec(sql: string): unknown
  pragma(source: string, options?: { simple?: boolean }): unknown
  transaction<A extends unknown[], R>(fn: (...args: A) => R): (...args: A) => R
  readonly readonly: boolean
}
