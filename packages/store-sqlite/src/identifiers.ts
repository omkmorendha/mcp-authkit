/**
 * Identifier validation and quoting for SQLite.
 *
 * Spec §6.4 / §12: SQL queries are parameterized; table-name overrides must
 * match `[A-Za-z0-9_]`. SQLite does not permit identifiers as bound
 * parameters, so they are validated against a strict whitelist and then
 * double-quoted before being interpolated into the SQL string at
 * *construction time* — never per request, never derived from user-controlled
 * input at runtime.
 */

const IDENT_RE = /^[A-Za-z0-9_]+$/

export class InvalidIdentifierError extends Error {
  constructor(kind: string, value: string) {
    super(`Invalid ${kind} identifier ${JSON.stringify(value)}: must match /^[A-Za-z0-9_]+$/`)
    this.name = "InvalidIdentifierError"
  }
}

/**
 * Validate and quote a SQLite identifier. The input MUST match
 * `[A-Za-z0-9_]+`; anything else throws. The output is wrapped in double
 * quotes for safe interpolation into prepared SQL.
 */
export function quoteIdent(value: string, kind = "identifier"): string {
  if (typeof value !== "string" || !IDENT_RE.test(value)) {
    throw new InvalidIdentifierError(kind, value)
  }
  return `"${value}"`
}
