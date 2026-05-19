import { describe, expect, it } from "vitest"
import type { AuthContext, ScopeMatcher } from "../types.js"
import { satisfies } from "./satisfies.js"

const auth: AuthContext = {
  subject: "user_123",
  tokenType: "oauth",
  tokenId: "jti_123",
  scopes: [],
  expiresAt: null,
  raw: {},
}
const ctx = { auth, input: undefined }

describe("satisfies", () => {
  it("returns true when the string matcher approves", async () => {
    expect(await satisfies("db:select:foo", ["db:select:*"], ctx)).toBe(true)
  })

  it("does not invoke custom matchers when the string matcher approves", async () => {
    let called = 0
    const matcher: ScopeMatcher = () => {
      called++
      return true
    }
    await satisfies("db:select:foo", ["db:select:foo"], ctx, [matcher])
    expect(called).toBe(0)
  })

  it("falls back to a custom matcher when string matching fails", async () => {
    const matcher: ScopeMatcher = (req) => req === "db:row:42"
    expect(await satisfies("db:row:42", [], ctx, [matcher])).toBe(true)
  })

  it("supports async custom matchers", async () => {
    const matcher: ScopeMatcher = async () => true
    expect(await satisfies("db:select:foo", [], ctx, [matcher])).toBe(true)
  })

  it("returns false when string and all custom matchers refuse", async () => {
    const matcher: ScopeMatcher = () => false
    expect(await satisfies("db:select:foo", ["fs:read"], ctx, [matcher])).toBe(false)
  })

  it("returns false with no custom matchers and no string match", async () => {
    expect(await satisfies("db:select:foo", ["fs:read"], ctx)).toBe(false)
  })

  it("rejects wildcards in the required scope", async () => {
    await expect(satisfies("db:select:*", ["db:select:*"], ctx)).rejects.toThrow(/wildcard/i)
  })

  it("short-circuits on the first approving custom matcher", async () => {
    let secondCalled = 0
    const first: ScopeMatcher = () => true
    const second: ScopeMatcher = () => {
      secondCalled++
      return true
    }
    expect(await satisfies("x:y:z", [], ctx, [first, second])).toBe(true)
    expect(secondCalled).toBe(0)
  })
})
