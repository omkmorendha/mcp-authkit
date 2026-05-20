import { describe, expect, it } from "vitest"
import { InvalidIdentifierError } from "./identifiers.js"
import { resolveNames } from "./names.js"

describe("resolveNames", () => {
  it("uses the spec-mandated default table names", () => {
    const n = resolveNames(undefined)
    expect(n.pats).toBe('"mcp_pats"')
    expect(n.refreshTokens).toBe('"mcp_refresh_tokens"')
    expect(n.upstreamCredentials).toBe('"mcp_upstream_credentials"')
    expect(n.migrations).toBe('"mcp_migrations"')
    expect(n.migrationsUnquoted).toBe("mcp_migrations")
  })

  it("honors overrides", () => {
    const n = resolveNames({
      pats: "my_pats",
      refreshTokens: "my_refresh",
      upstreamCredentials: "my_upstream",
      migrations: "my_migrations",
    })
    expect(n.pats).toBe('"my_pats"')
    expect(n.refreshTokens).toBe('"my_refresh"')
    expect(n.upstreamCredentials).toBe('"my_upstream"')
    expect(n.migrations).toBe('"my_migrations"')
    expect(n.migrationsUnquoted).toBe("my_migrations")
  })

  it.each([
    ["pats override with dash", { pats: "my-pats" }],
    ["refresh override with dot", { refreshTokens: "schema.tbl" }],
    ["upstream override with space", { upstreamCredentials: "foo bar" }],
    ["migrations override empty", { migrations: "" }],
    ["pats override with quote", { pats: 'foo"bar' }],
  ] as const)("rejects %s", (_label, overrides) => {
    expect(() => resolveNames(overrides)).toThrow(InvalidIdentifierError)
  })
})
