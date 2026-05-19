import { memoryTokenStore } from "mcp-authkit-store-memory"
import { describe, expect, it } from "vitest"
import { redactConfigForLog } from "./redact.js"
import type { AuthKitConfig } from "./types.js"

function fullConfig(): AuthKitConfig {
  return {
    resourceIndicator: "https://mcp.example.test/",
    auth: {
      authorizationServer: {
        issuer: "https://as.example.test/",
        jwksUri: "https://as.example.test/.well-known/jwks.json",
        introspectionEndpoint: "https://as.example.test/introspect",
      },
      tokenStore: memoryTokenStore(),
      pat: { enabled: true, prefix: "mcp_pat_SECRET_PREFIX_" },
      bypass: {
        enabled: true,
        user: "secret-user@example.test",
        scopes: ["all"],
        allowInProduction: true,
      },
      staticToken: {
        token: "extremely-secret-static-token",
        user: "ci@example.test",
        scopes: ["files:read"],
      },
    },
    scopes: {
      vocabulary: {
        "files:read": { description: "A description that mentions internal-only stuff" },
        "files:write": { description: "Another sensitive description" },
      },
      customMatchers: [() => true],
    },
    resolveUserScopes: async () => [],
    http: { allowedHosts: ["mcp.example.test"] },
  }
}

describe("redactConfigForLog", () => {
  it("produces a safe object with no secrets", () => {
    const cfg = fullConfig()
    const redacted = redactConfigForLog(cfg)
    const serialized = JSON.stringify(redacted)

    expect(serialized).not.toContain("extremely-secret-static-token")
    expect(serialized).not.toContain("mcp_pat_SECRET_PREFIX_")
    expect(serialized).not.toContain("secret-user@example.test")
    expect(serialized).not.toContain("internal-only stuff")
    expect(serialized).not.toContain("sensitive description")
    // The introspection endpoint URL (which may carry credentials) must not
    // leak. The key name itself can stay; we only forbid the URL value.
    expect(serialized).not.toContain("as.example.test/introspect")
  })

  it("keeps non-secret identifying fields", () => {
    const cfg = fullConfig()
    const redacted = redactConfigForLog(cfg)
    expect(redacted.resourceIndicator).toBe("https://mcp.example.test/")
    const auth = redacted.auth as Record<string, unknown>
    const as = auth.authorizationServer as Record<string, unknown>
    expect(as.issuer).toBe("https://as.example.test/")
    expect(as.jwksUri).toBe("https://as.example.test/.well-known/jwks.json")
    expect(auth.tokenStore).toBe("object")
    const scopes = redacted.scopes as Record<string, unknown>
    expect(scopes.vocabulary).toEqual(["files:read", "files:write"])
    expect(scopes.customMatchers).toBe(1)
  })

  it("marks secret-shaped fields as <redacted>", () => {
    const cfg = fullConfig()
    const redacted = redactConfigForLog(cfg)
    const auth = redacted.auth as Record<string, unknown>
    const pat = auth.pat as Record<string, unknown>
    expect(pat.enabled).toBe(true)
    expect(pat.prefix).toBe("<redacted>")
    expect(auth.staticToken).toBe("<redacted>")
    const bypass = auth.bypass as Record<string, unknown>
    expect(bypass).toEqual({ enabled: true })
    const as = auth.authorizationServer as Record<string, unknown>
    expect(as.introspectionEndpoint).toBe("<redacted>")
  })

  it("omits optional sections when not configured", () => {
    const cfg: AuthKitConfig = {
      resourceIndicator: "https://mcp.example.test/",
      auth: {
        tokenStore: memoryTokenStore(),
        pat: { enabled: false },
      },
      scopes: { vocabulary: {} },
      resolveUserScopes: async () => [],
    }
    const redacted = redactConfigForLog(cfg)
    const auth = redacted.auth as Record<string, unknown>
    expect(auth.authorizationServer).toBeUndefined()
    expect(auth.bypass).toBeUndefined()
    expect(auth.staticToken).toBeUndefined()
    expect(redacted.http).toBeUndefined()
  })

  it("uses the constructor name for class-based stores", () => {
    class MyDatabaseStore {
      createPat = async () => {
        throw new Error("not impl")
      }
    }
    const cfg: AuthKitConfig = {
      resourceIndicator: "https://mcp.example.test/",
      auth: {
        // biome-ignore lint/suspicious/noExplicitAny: structural test, real shape not relevant
        tokenStore: new MyDatabaseStore() as any,
        pat: { enabled: false },
      },
      scopes: { vocabulary: {} },
      resolveUserScopes: async () => [],
    }
    const redacted = redactConfigForLog(cfg)
    const auth = redacted.auth as Record<string, unknown>
    expect(auth.tokenStore).toBe("MyDatabaseStore")
  })
})
