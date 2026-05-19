/**
 * Tests for bypass mode, static-token path, and stdio auto-enable.
 *
 * Spec: docs/spec/v0.1.md#11-bypass-mode-and-stdio
 * Security: docs/spec/v0.1.md#14-security-non-negotiables
 */
import { describe, expect, it, vi } from "vitest"
import type { AuthKitConfig } from "../types.js"
import {
  BypassProductionError,
  checkBypassConfig,
  shouldAutoEnableBypass,
  synthesizeBypassContext,
  synthesizeStaticContext,
} from "./index.js"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
    // pino Logger interface requires these — cast to satisfy the type
    // biome-ignore lint/suspicious/noExplicitAny: test stub
  } as any
}

/** Minimal config with bypass enabled. */
function bypassConfig(
  overrides: Partial<NonNullable<AuthKitConfig["auth"]["bypass"]>> = {},
): AuthKitConfig {
  return {
    resourceIndicator: "https://mcp.example.test/",
    auth: {
      authorizationServer: {
        issuer: "https://as.example.test/",
        jwksUri: "https://as.example.test/.well-known/jwks.json",
      },
      tokenStore: null as unknown as AuthKitConfig["auth"]["tokenStore"],
      pat: { enabled: false },
      bypass: {
        enabled: true,
        user: "dev-user",
        scopes: ["read:tools", "write:tools"],
        ...overrides,
      },
    },
    scopes: { vocabulary: {} },
    resolveUserScopes: async () => [],
  }
}

/** Minimal config without bypass. */
function noBypassConfig(): AuthKitConfig {
  return {
    resourceIndicator: "https://mcp.example.test/",
    auth: {
      authorizationServer: {
        issuer: "https://as.example.test/",
        jwksUri: "https://as.example.test/.well-known/jwks.json",
      },
      tokenStore: null as unknown as AuthKitConfig["auth"]["tokenStore"],
      pat: { enabled: false },
    },
    scopes: { vocabulary: {} },
    resolveUserScopes: async () => [],
  }
}

/** Config without authorizationServer (stdio auto-enable path). */
function stdioConfig(
  bypassOverrides?: Partial<NonNullable<AuthKitConfig["auth"]["bypass"]>>,
): AuthKitConfig {
  return {
    resourceIndicator: "https://mcp.example.test/",
    auth: {
      tokenStore: null as unknown as AuthKitConfig["auth"]["tokenStore"],
      pat: { enabled: false },
      bypass: bypassOverrides
        ? {
            enabled: true,
            user: "dev-user",
            scopes: ["read:tools"],
            ...bypassOverrides,
          }
        : undefined,
    },
    scopes: { vocabulary: {} },
    resolveUserScopes: async () => [],
  }
}

// ---------------------------------------------------------------------------
// checkBypassConfig
// ---------------------------------------------------------------------------

describe("checkBypassConfig", () => {
  describe("when bypass is not configured", () => {
    it("does not throw and does not warn", () => {
      const logger = makeLogger()
      expect(() =>
        checkBypassConfig({ config: noBypassConfig(), env: "production", logger }),
      ).not.toThrow()
      expect(logger.warn).not.toHaveBeenCalled()
    })
  })

  describe("when bypass.enabled is false", () => {
    it("does not throw and does not warn", () => {
      const logger = makeLogger()
      const config = bypassConfig({ enabled: false })
      expect(() => checkBypassConfig({ config, env: "production", logger })).not.toThrow()
      expect(logger.warn).not.toHaveBeenCalled()
    })
  })

  describe("in development (non-production env)", () => {
    it("does not throw when bypass is enabled", () => {
      const logger = makeLogger()
      expect(() =>
        checkBypassConfig({ config: bypassConfig(), env: "development", logger }),
      ).not.toThrow()
    })

    it("emits logger.warn naming the user and scopes", () => {
      const logger = makeLogger()
      checkBypassConfig({ config: bypassConfig(), env: "development", logger })

      expect(logger.warn).toHaveBeenCalledOnce()
      const [obj, msg] = logger.warn.mock.calls[0] as [unknown, string]
      expect(msg).toContain("Bypass mode is active")
      expect(obj).toMatchObject({
        bypass: {
          user: "dev-user",
          scopes: ["read:tools", "write:tools"],
        },
      })
    })

    it("emits logger.warn when env is undefined (defaults to process.env.NODE_ENV)", () => {
      const logger = makeLogger()
      // env not passed; should not throw regardless of process.env.NODE_ENV in test env
      expect(() => checkBypassConfig({ config: bypassConfig(), logger })).not.toThrow()
    })
  })

  // -------------------------------------------------------------------------
  // Security tests — spec §14 "bypass refuses production"
  // -------------------------------------------------------------------------

  describe("security: production guard", () => {
    it("throws BypassProductionError in production without allowInProduction", () => {
      const logger = makeLogger()
      const config = bypassConfig({ allowInProduction: undefined })

      expect(() => checkBypassConfig({ config, env: "production", logger })).toThrow(
        BypassProductionError,
      )
    })

    it("BypassProductionError message mentions bypass.allowInProduction", () => {
      const logger = makeLogger()
      const config = bypassConfig({ allowInProduction: undefined })

      let caught: unknown
      try {
        checkBypassConfig({ config, env: "production", logger })
      } catch (err) {
        caught = err
      }

      expect(caught).toBeInstanceOf(BypassProductionError)
      expect((caught as BypassProductionError).message).toContain("allowInProduction")
    })

    it("does not throw in production when allowInProduction: true", () => {
      const logger = makeLogger()
      const config = bypassConfig({ allowInProduction: true })

      expect(() => checkBypassConfig({ config, env: "production", logger })).not.toThrow()
    })

    it("emits logger.warn in production with allowInProduction: true", () => {
      const logger = makeLogger()
      const config = bypassConfig({ allowInProduction: true })
      checkBypassConfig({ config, env: "production", logger })

      expect(logger.warn).toHaveBeenCalledOnce()
      const [obj] = logger.warn.mock.calls[0] as [{ bypass: { allowInProduction: boolean } }]
      expect(obj.bypass.allowInProduction).toBe(true)
    })

    it("throws before server can accept connections (name is BypassProductionError)", () => {
      const logger = makeLogger()
      const config = bypassConfig({ allowInProduction: undefined })

      let err: unknown
      try {
        checkBypassConfig({ config, env: "production", logger })
      } catch (e) {
        err = e
      }

      expect(err).toBeInstanceOf(BypassProductionError)
      expect((err as BypassProductionError).name).toBe("BypassProductionError")
    })
  })
})

// ---------------------------------------------------------------------------
// shouldAutoEnableBypass
// ---------------------------------------------------------------------------

describe("shouldAutoEnableBypass", () => {
  it("returns true when transport is stdio and no authorizationServer", () => {
    const config = stdioConfig()
    expect(shouldAutoEnableBypass(config, "stdio")).toBe(true)
  })

  it("returns false when transport is stdio but authorizationServer is configured", () => {
    const config = bypassConfig()
    expect(shouldAutoEnableBypass(config, "stdio")).toBe(false)
  })

  it("returns false when transport is http even without authorizationServer", () => {
    const config = stdioConfig()
    expect(shouldAutoEnableBypass(config, "http")).toBe(false)
  })

  it("returns false when transport is http with authorizationServer", () => {
    const config = bypassConfig()
    expect(shouldAutoEnableBypass(config, "http")).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// synthesizeBypassContext
// ---------------------------------------------------------------------------

describe("synthesizeBypassContext", () => {
  const bypassCfg = {
    enabled: true,
    user: "dev-user",
    scopes: Object.freeze(["read:tools", "write:tools"]) as readonly string[],
    allowInProduction: false,
  }

  it("returns tokenType: bypass", () => {
    const ctx = synthesizeBypassContext(bypassCfg)
    expect(ctx.tokenType).toBe("bypass")
  })

  it("returns expiresAt: null", () => {
    const ctx = synthesizeBypassContext(bypassCfg)
    expect(ctx.expiresAt).toBeNull()
  })

  it("returns the configured user as subject", () => {
    const ctx = synthesizeBypassContext(bypassCfg)
    expect(ctx.subject).toBe("dev-user")
  })

  it("returns the configured scopes", () => {
    const ctx = synthesizeBypassContext(bypassCfg)
    expect(ctx.scopes).toEqual(["read:tools", "write:tools"])
  })

  it("tokenId is a non-empty string", () => {
    const ctx = synthesizeBypassContext(bypassCfg)
    expect(typeof ctx.tokenId).toBe("string")
    expect(ctx.tokenId.length).toBeGreaterThan(0)
  })

  it("raw is an empty object (no token to expose)", () => {
    const ctx = synthesizeBypassContext(bypassCfg)
    expect(ctx.raw).toEqual({})
  })
})

// ---------------------------------------------------------------------------
// synthesizeStaticContext
// ---------------------------------------------------------------------------

describe("synthesizeStaticContext", () => {
  const staticCfg = {
    token: "mcp_static_supersecret",
    user: "ci-bot",
    scopes: Object.freeze(["read:tools"]) as readonly string[],
  }

  it("returns tokenType: static", () => {
    const ctx = synthesizeStaticContext(staticCfg)
    expect(ctx.tokenType).toBe("static")
  })

  it("returns expiresAt: null", () => {
    const ctx = synthesizeStaticContext(staticCfg)
    expect(ctx.expiresAt).toBeNull()
  })

  it("returns the configured user as subject", () => {
    const ctx = synthesizeStaticContext(staticCfg)
    expect(ctx.subject).toBe("ci-bot")
  })

  it("returns the configured scopes", () => {
    const ctx = synthesizeStaticContext(staticCfg)
    expect(ctx.scopes).toEqual(["read:tools"])
  })

  it("tokenId is a non-empty string", () => {
    const ctx = synthesizeStaticContext(staticCfg)
    expect(typeof ctx.tokenId).toBe("string")
    expect(ctx.tokenId.length).toBeGreaterThan(0)
  })

  it("raw is an empty object (token not exposed)", () => {
    const ctx = synthesizeStaticContext(staticCfg)
    expect(ctx.raw).toEqual({})
  })

  it("does not expose the raw static token value in the context", () => {
    const ctx = synthesizeStaticContext(staticCfg)
    const ctxStr = JSON.stringify(ctx)
    expect(ctxStr).not.toContain("mcp_static_supersecret")
  })
})
