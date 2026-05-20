/**
 * Tests for signed stdio config validation (v0.2 §11).
 */
import { describe, expect, it, vi } from "vitest"
import type { AuthKitConfig } from "../types.js"
import { checkSignedStdioConfig, SignedStdioConfigError } from "./config.js"

function makeLogger() {
  return {
    warn: vi.fn(),
    debug: vi.fn(),
    info: vi.fn(),
    error: vi.fn(),
    trace: vi.fn(),
    fatal: vi.fn(),
    child: vi.fn(),
    level: "info",
    // biome-ignore lint/suspicious/noExplicitAny: test stub
  } as any
}

function baseConfig(): AuthKitConfig {
  return {
    resourceIndicator: "https://mcp.example.test/",
    auth: {
      tokenStore: null as unknown as AuthKitConfig["auth"]["tokenStore"],
      pat: { enabled: false },
    },
    scopes: { vocabulary: {} },
    resolveUserScopes: async () => [],
  }
}

describe("checkSignedStdioConfig", () => {
  it("is a no-op when stdio is not configured", () => {
    const logger = makeLogger()
    const config = baseConfig()
    expect(() => checkSignedStdioConfig({ config, logger })).not.toThrow()
    expect(logger.warn).not.toHaveBeenCalled()
  })

  it("emits a warn naming the mode and key fingerprint", () => {
    const logger = makeLogger()
    const config = baseConfig()
    config.auth.stdio = { mode: "signed", hmacKey: Buffer.from("k".repeat(32)) }
    checkSignedStdioConfig({ config, logger })

    expect(logger.warn).toHaveBeenCalledOnce()
    const [obj, msg] = logger.warn.mock.calls[0] as [
      { stdio: { mode: string; keyFingerprint: string } },
      string,
    ]
    expect(msg).toContain("Production stdio")
    expect(obj.stdio.mode).toBe("signed")
    expect(obj.stdio.keyFingerprint).toMatch(/^[0-9a-f]{8}$/)
  })

  it("does NOT log the hmac key value (security non-negotiable)", () => {
    const logger = makeLogger()
    const config = baseConfig()
    const secret = "this-is-a-super-secret-hmac-key"
    config.auth.stdio = { mode: "signed", hmacKey: secret }
    checkSignedStdioConfig({ config, logger })

    const serialised = JSON.stringify(logger.warn.mock.calls)
    expect(serialised).not.toContain(secret)
    expect(serialised).not.toContain("super-secret")
  })

  it("throws SignedStdioConfigError when bypass.enabled is true", () => {
    const logger = makeLogger()
    const config = baseConfig()
    config.auth.bypass = { enabled: true, user: "dev", scopes: ["read"] }
    config.auth.stdio = { mode: "signed", hmacKey: "k" }
    expect(() => checkSignedStdioConfig({ config, logger })).toThrow(SignedStdioConfigError)
  })

  it("does NOT throw when bypass.enabled is false even if a bypass block is present", () => {
    const logger = makeLogger()
    const config = baseConfig()
    config.auth.bypass = { enabled: false, user: "dev", scopes: [] }
    config.auth.stdio = { mode: "signed", hmacKey: "k" }
    expect(() => checkSignedStdioConfig({ config, logger })).not.toThrow()
  })

  it("throws on unknown mode", () => {
    const logger = makeLogger()
    const config = baseConfig()
    // biome-ignore lint/suspicious/noExplicitAny: deliberate invalid mode
    config.auth.stdio = { mode: "plaintext" as any, hmacKey: "k" }
    expect(() => checkSignedStdioConfig({ config, logger })).toThrow(SignedStdioConfigError)
  })

  it("throws on an empty hmacKey", () => {
    const logger = makeLogger()
    const config = baseConfig()
    config.auth.stdio = { mode: "signed", hmacKey: "" }
    expect(() => checkSignedStdioConfig({ config, logger })).toThrow(/empty/)
  })
})
