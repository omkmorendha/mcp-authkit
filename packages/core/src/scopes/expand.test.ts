import { describe, expect, it } from "vitest"
import type { ScopeVocabulary } from "../types.js"
import { expand } from "./expand.js"

describe("expand", () => {
  it("returns the input when nothing implies anything", () => {
    const vocab: ScopeVocabulary = {
      "db:select": { description: "" },
    }
    expect(expand(["db:select:t1"], vocab)).toEqual(["db:select:t1"])
  })

  it("resolves a direct implication A -> B", () => {
    const vocab: ScopeVocabulary = {
      "db:write": { description: "", implies: ["db:update"] },
      "db:update": { description: "" },
    }
    expect(expand(["db:write:t1"], vocab)).toEqual(["db:update:t1", "db:write:t1"])
  })

  it("resolves a chain A -> B -> C transitively", () => {
    const vocab: ScopeVocabulary = {
      "db:admin": { description: "", implies: ["db:write"] },
      "db:write": { description: "", implies: ["db:update"] },
      "db:update": { description: "" },
    }
    expect(expand(["db:admin:t1"], vocab)).toEqual(["db:admin:t1", "db:update:t1", "db:write:t1"])
  })

  it("terminates on cycles A -> B -> A", () => {
    const vocab: ScopeVocabulary = {
      "x:a": { description: "", implies: ["x:b"] },
      "x:b": { description: "", implies: ["x:a"] },
    }
    expect(expand(["x:a:r"], vocab)).toEqual(["x:a:r", "x:b:r"])
  })

  it("propagates trailing segments to implied scopes", () => {
    const vocab: ScopeVocabulary = {
      "db:write": { description: "", implies: ["db:update", "db:delete"] },
    }
    expect(expand(["db:write:tenant:table"], vocab)).toEqual([
      "db:delete:tenant:table",
      "db:update:tenant:table",
      "db:write:tenant:table",
    ])
  })

  it("emits implied scopes whose key is not in the vocabulary", () => {
    const vocab: ScopeVocabulary = {
      "db:write": { description: "", implies: ["db:notify"] },
    }
    expect(expand(["db:write:t1"], vocab)).toEqual(["db:notify:t1", "db:write:t1"])
  })

  it("passes through scopes whose key is not in the vocabulary", () => {
    const vocab: ScopeVocabulary = {}
    expect(expand(["foo:bar:baz"], vocab)).toEqual(["foo:bar:baz"])
  })

  it("dedupes and sorts the output", () => {
    const vocab: ScopeVocabulary = {
      "db:write": { description: "", implies: ["db:update"] },
    }
    expect(expand(["db:update:t1", "db:write:t1"], vocab)).toEqual(["db:update:t1", "db:write:t1"])
  })

  it("rejects malformed input", () => {
    expect(() => expand([""], {})).toThrow(TypeError)
  })
})
