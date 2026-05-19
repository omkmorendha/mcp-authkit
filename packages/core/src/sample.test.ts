import { describe, expect, it } from "vitest"

describe("vitest workspace configuration", () => {
  it("discovers tests colocated with package source", () => {
    expect("packages/core/src/sample.test.ts").toContain("packages/core/src")
  })
})
