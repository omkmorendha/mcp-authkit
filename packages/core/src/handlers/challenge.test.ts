import { describe, expect, it } from "vitest"
import { buildChallengeHeader, metadataUrlFor } from "./challenge.js"

describe("buildChallengeHeader", () => {
  it("contains resource_metadata first per RFC 9728 §5.1", () => {
    const header = buildChallengeHeader({
      resourceMetadataUrl: "https://api.example.com/.well-known/oauth-protected-resource",
    })
    expect(header).toBe(
      'Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"',
    )
  })

  it("includes error and error_description per RFC 6750 §3", () => {
    const header = buildChallengeHeader({
      resourceMetadataUrl: "https://api.example.com/.well-known/oauth-protected-resource",
      error: "invalid_token",
      errorDescription: "expired",
    })
    expect(header).toContain('error="invalid_token"')
    expect(header).toContain('error_description="expired"')
  })

  it("escapes embedded quotes and backslashes (RFC 7235 quoted-string)", () => {
    const header = buildChallengeHeader({
      resourceMetadataUrl: 'https://api.example.com/x"y\\z',
    })
    expect(header).toContain('"https://api.example.com/x\\"y\\\\z"')
  })
})

describe("metadataUrlFor", () => {
  it("appends well-known path", () => {
    expect(metadataUrlFor("https://api.example.com/mcp")).toBe(
      "https://api.example.com/mcp/.well-known/oauth-protected-resource",
    )
  })
  it("collapses trailing slash", () => {
    expect(metadataUrlFor("https://api.example.com/mcp/")).toBe(
      "https://api.example.com/mcp/.well-known/oauth-protected-resource",
    )
  })
})
