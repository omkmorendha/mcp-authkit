import { describe, expect, it } from "vitest"
import { InvalidIdentifierError, quoteIdent, quoteQualified } from "./identifiers.js"

describe("identifier validation", () => {
  it("accepts valid identifiers", () => {
    expect(quoteIdent("mcp_pats")).toBe('"mcp_pats"')
    expect(quoteIdent("a")).toBe('"a"')
    expect(quoteIdent("A1_b2")).toBe('"A1_b2"')
  })

  it.each([
    ["empty string", ""],
    ["with space", "foo bar"],
    ["semicolon", "foo;DROP TABLE x"],
    ["quote", 'foo"bar'],
    ["double-quote injection", 'pats"; DROP TABLE pats; --'],
    ["dash", "foo-bar"],
    ["dot", "schema.table"],
    ["unicode", "fü"],
    ["newline", "foo\nbar"],
    ["backslash", "foo\\bar"],
    ["asterisk", "*"],
    ["sql comment", "--"],
  ])("rejects %s", (_label, value) => {
    expect(() => quoteIdent(value)).toThrow(InvalidIdentifierError)
  })

  it("quoteQualified validates both halves", () => {
    expect(quoteQualified("public", "mcp_pats")).toBe('"public"."mcp_pats"')
    expect(() => quoteQualified("pub;DROP", "mcp_pats")).toThrow(InvalidIdentifierError)
    expect(() => quoteQualified("public", "pats;--")).toThrow(InvalidIdentifierError)
  })

  it("error message identifies the kind", () => {
    try {
      quoteIdent("bad name", "table")
    } catch (err) {
      expect(err).toBeInstanceOf(InvalidIdentifierError)
      expect((err as Error).message).toMatch(/Invalid table identifier/)
      return
    }
    throw new Error("expected throw")
  })
})
