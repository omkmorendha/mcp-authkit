import { describe, expect, it } from "vitest"
import { assertHeldScope, assertRequiredScope, matchesAny, scopeMatches } from "./matcher.js"

describe("scopeMatches", () => {
  it("matches identical literal scopes", () => {
    expect(scopeMatches("db:select:foo", "db:select:foo")).toBe(true)
  })

  it("rejects mismatched namespaces", () => {
    expect(scopeMatches("db:select:foo", "fs:select:foo")).toBe(false)
  })

  it("rejects mismatched operations", () => {
    expect(scopeMatches("db:select:foo", "db:update:foo")).toBe(false)
  })

  it("rejects mismatched resources without wildcards", () => {
    expect(scopeMatches("db:select:foo", "db:select:bar")).toBe(false)
  })

  describe("single-segment wildcard *", () => {
    it("matches one segment in the resource position", () => {
      expect(scopeMatches("db:select:foo", "db:select:*")).toBe(true)
    })

    it("does not span multiple segments", () => {
      expect(scopeMatches("db:select:foo:bar", "db:select:*")).toBe(false)
    })

    it("matches in mid-resource positions", () => {
      expect(scopeMatches("db:select:tenant1:table1", "db:select:*:table1")).toBe(true)
    })

    it("matches literally in namespace position", () => {
      // `*` at position 0 is NOT a wildcard (spec §7.2). A held scope like
      // `*:select:foo` does not match any concrete required scope.
      expect(scopeMatches("db:select:foo", "*:select:foo")).toBe(false)
    })

    it("matches literally in operation position", () => {
      expect(scopeMatches("db:select:foo", "db:*:foo")).toBe(false)
    })
  })

  describe("multi-segment wildcard **", () => {
    it("matches a single trailing segment", () => {
      expect(scopeMatches("db:select:foo", "db:select:**")).toBe(true)
    })

    it("matches multiple trailing segments", () => {
      expect(scopeMatches("db:select:foo:bar:baz", "db:select:**")).toBe(true)
    })

    it("requires at least one trailing segment", () => {
      // `db:select` (2 segments) is a legal held scope but `**` adds one
      // or more, so a 2-segment required scope cannot be satisfied by
      // `db:select:**`.
      expect(scopeMatches("db:select", "db:select:**")).toBe(false)
    })

    it("does not honor ** in namespace position", () => {
      expect(scopeMatches("db:select:foo", "**:select:foo")).toBe(false)
    })

    it("does not honor ** in operation position", () => {
      expect(scopeMatches("db:select:foo", "db:**:foo")).toBe(false)
    })
  })

  it("treats `*` segments inside resource literals as literal characters", () => {
    // `analytics.*` is one segment whose text happens to contain `*`.
    // This is not the wildcard — the whole segment must be `*` alone for
    // the wildcard interpretation.
    expect(scopeMatches("db:select:analytics.events", "db:select:analytics.*")).toBe(false)
    expect(scopeMatches("db:select:analytics.*", "db:select:analytics.*")).toBe(true)
  })
})

describe("matchesAny", () => {
  it("returns true if any held scope matches", () => {
    expect(matchesAny("db:select:foo", ["fs:read", "db:select:*"])).toBe(true)
  })

  it("returns false if no held scope matches", () => {
    expect(matchesAny("db:select:foo", ["fs:read", "db:update:foo"])).toBe(false)
  })

  it("returns false on empty held set", () => {
    expect(matchesAny("db:select:foo", [])).toBe(false)
  })
})

describe("assertRequiredScope", () => {
  it("accepts a 2-segment scope", () => {
    expect(() => assertRequiredScope("db:select")).not.toThrow()
  })

  it("accepts a multi-segment scope", () => {
    expect(() => assertRequiredScope("db:select:t1:c1")).not.toThrow()
  })

  it("rejects empty string", () => {
    expect(() => assertRequiredScope("")).toThrow(TypeError)
  })

  it("rejects single-segment scope", () => {
    expect(() => assertRequiredScope("db")).toThrow(TypeError)
  })

  it("rejects empty segments", () => {
    expect(() => assertRequiredScope("db::foo")).toThrow(TypeError)
  })

  it("rejects scopes containing `*`", () => {
    expect(() => assertRequiredScope("db:select:*")).toThrow(/wildcard/i)
  })

  it("rejects scopes containing `**`", () => {
    expect(() => assertRequiredScope("db:select:**")).toThrow(/wildcard/i)
  })
})

describe("assertHeldScope", () => {
  it("accepts scopes with wildcards", () => {
    expect(() => assertHeldScope("db:select:*")).not.toThrow()
    expect(() => assertHeldScope("db:select:**")).not.toThrow()
  })

  it("rejects empty segments", () => {
    expect(() => assertHeldScope("db::foo")).toThrow(TypeError)
  })

  it("rejects empty string", () => {
    expect(() => assertHeldScope("")).toThrow(TypeError)
  })
})
