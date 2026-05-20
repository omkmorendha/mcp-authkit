/**
 * Minimal structural typing of the parts of `pg` we depend on.
 *
 * The package's runtime dependency is `pg` (declared as a peer); the types
 * are kept narrow on purpose so the store can be exercised against any
 * driver that exposes the same `query`/`connect` shape (e.g. a connection
 * pool wrapper in user code).
 */

export interface PgQueryResultRow {
  [column: string]: unknown
}

export interface PgQueryResult<R extends PgQueryResultRow = PgQueryResultRow> {
  rows: R[]
  rowCount: number | null
}

export interface PgClient {
  query<R extends PgQueryResultRow = PgQueryResultRow>(
    sql: string,
    params?: readonly unknown[],
  ): Promise<PgQueryResult<R>>
  release(err?: Error | boolean): void
}

export interface PgPool {
  connect(): Promise<PgClient>
  query<R extends PgQueryResultRow = PgQueryResultRow>(
    sql: string,
    params?: readonly unknown[],
  ): Promise<PgQueryResult<R>>
}
