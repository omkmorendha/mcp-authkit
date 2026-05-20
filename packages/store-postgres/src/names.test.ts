import { describe, expect, it } from "vitest"
import { InvalidIdentifierError } from "./identifiers.js"
import { resolveNames } from "./names.js"

describe("resolveNames", () => {
  it("defaults schema to public and uses the spec-mandated table names", () => {
    const n = resolveNames(undefined, undefined)
    expect(n.schema).toBe("public")
    expect(n.pats).toBe('"public"."mcp_pats"')
    expect(n.refreshTokens).toBe('"public"."mcp_refresh_tokens"')
    expect(n.upstreamCredentials).toBe('"public"."mcp_upstream_credentials"')
    expect(n.migrations).toBe('"public"."mcp_migrations"')
    expect(n.migrationsUnquoted).toBe("mcp_migrations")
  })

  it("honors overrides", () => {
    const n = resolveNames("authkit", {
      pats: "my_pats",
      refreshTokens: "my_refresh",
      upstreamCredentials: "my_upstream",
      migrations: "my_migrations",
    })
    expect(n.schema).toBe("authkit")
    expect(n.pats).toBe('"authkit"."my_pats"')
    expect(n.refreshTokens).toBe('"authkit"."my_refresh"')
    expect(n.upstreamCredentials).toBe('"authkit"."my_upstream"')
    expect(n.migrations).toBe('"authkit"."my_migrations"')
    expect(n.migrationsUnquoted).toBe("my_migrations")
  })

  it.each([
    ["schema with semicolon", "ev;DROP", undefined],
    ["schema with quote", 'pub"lic', undefined],
    ["pats override with dash", undefined, { pats: "my-pats" }],
    ["refresh override with dot", undefined, { refreshTokens: "schema.tbl" }],
    ["upstream override with space", undefined, { upstreamCredentials: "foo bar" }],
    ["migrations override empty", undefined, { migrations: "" }],
  ] as const)("rejects %s", (_label, schema, overrides) => {
    expect(() => resolveNames(schema, overrides)).toThrow(InvalidIdentifierError)
  })
})
