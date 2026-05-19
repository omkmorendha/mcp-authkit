import { describe, expect, it } from "vitest"
import { intersect, normalize, subtract } from "./set.js"

describe("normalize", () => {
  it("dedupes and stably sorts", () => {
    expect(normalize(["b:y", "a:x", "b:y", "a:x:z"])).toEqual(["a:x", "a:x:z", "b:y"])
  })

  it("returns empty array for empty input", () => {
    expect(normalize([])).toEqual([])
  })

  it("rejects malformed scopes", () => {
    expect(() => normalize(["ok:read", ""])).toThrow(TypeError)
    expect(() => normalize(["bare"])).toThrow(TypeError)
  })

  it("freezes the result", () => {
    const out = normalize(["a:b"])
    expect(Object.isFrozen(out)).toBe(true)
  })
})

describe("intersect", () => {
  it("returns the string-level intersection", () => {
    expect(intersect(["a:r", "b:r"], ["b:r", "c:r"])).toEqual(["b:r"])
  })

  it("returns empty array on disjoint sets", () => {
    expect(intersect(["a:r"], ["b:r"])).toEqual([])
  })

  it("returns empty array when either side is empty", () => {
    expect(intersect([], ["b:r"])).toEqual([])
    expect(intersect(["a:r"], [])).toEqual([])
  })

  it("treats duplicates idempotently", () => {
    expect(intersect(["a:r", "a:r"], ["a:r", "a:r"])).toEqual(["a:r"])
  })

  it("is string-level, not match-level", () => {
    // wildcards and literals do not collapse via intersect
    expect(intersect(["db:select:*"], ["db:select:foo"])).toEqual([])
  })
})

describe("subtract", () => {
  it("removes elements present in b", () => {
    expect(subtract(["a:r", "b:r", "c:r"], ["b:r"])).toEqual(["a:r", "c:r"])
  })

  it("subtract(a, a) is empty", () => {
    expect(subtract(["a:r", "b:r"], ["a:r", "b:r"])).toEqual([])
  })

  it("subtract(a, []) equals normalize(a)", () => {
    expect(subtract(["b:r", "a:r", "a:r"], [])).toEqual(["a:r", "b:r"])
  })

  it("subtract([], a) is empty", () => {
    expect(subtract([], ["a:r"])).toEqual([])
  })
})
