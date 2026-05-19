import type { IncomingMessage } from "node:http"
import { describe, expect, it } from "vitest"
import { hostFromResourceIndicator, validateHost } from "./host.js"

function reqWithHost(host: string | undefined): IncomingMessage {
  return { headers: host === undefined ? {} : { host } } as unknown as IncomingMessage
}

describe("hostFromResourceIndicator", () => {
  it("returns lower-cased host[:port]", () => {
    expect(hostFromResourceIndicator("https://API.example.com:3000/mcp")).toBe(
      "api.example.com:3000",
    )
  })
  it("returns host without port for standard ports", () => {
    expect(hostFromResourceIndicator("https://api.example.com/mcp")).toBe("api.example.com")
  })
  it("returns null for unparseable input", () => {
    expect(hostFromResourceIndicator("not a url")).toBeNull()
  })
})

describe("validateHost", () => {
  it("accepts exact match on host:port", () => {
    const r = validateHost(reqWithHost("api.example.com:3000"), {
      allowedHosts: ["api.example.com:3000"],
    })
    expect(r.ok).toBe(true)
  })

  it("is case-insensitive on Host header", () => {
    const r = validateHost(reqWithHost("API.Example.COM:3000"), {
      allowedHosts: ["api.example.com:3000"],
    })
    expect(r.ok).toBe(true)
  })

  it("port-less allowlist entry matches any port", () => {
    const r = validateHost(reqWithHost("api.example.com:8080"), {
      allowedHosts: ["api.example.com"],
    })
    expect(r.ok).toBe(true)
  })

  it("port-specific allowlist entry rejects other ports", () => {
    const r = validateHost(reqWithHost("api.example.com:8080"), {
      allowedHosts: ["api.example.com:3000"],
    })
    expect(r.ok).toBe(false)
  })

  it("rejects a forged host", () => {
    const r = validateHost(reqWithHost("evil.com"), { allowedHosts: ["api.example.com"] })
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.reason).toBe("disallowed")
  })

  it("rejects when Host header is missing", () => {
    const r = validateHost(reqWithHost(undefined), { allowedHosts: ["api.example.com"] })
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.reason).toBe("missing")
  })

  it("empty allowlist disables validation (explicit opt-out)", () => {
    const r = validateHost(reqWithHost("anything.test"), { allowedHosts: [] })
    expect(r.ok).toBe(true)
  })
})
