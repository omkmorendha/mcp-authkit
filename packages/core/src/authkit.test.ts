import { memoryTokenStore } from "mcp-authkit-store-memory"
import { afterAll, beforeAll, describe, expect, it } from "vitest"
import {
  createAuthKit,
  extractBearer,
  looksLikeJwt,
  runPipeline,
  timingSafeStringEqual,
} from "./authkit.js"
import { createPat } from "./pats/lifecycle.js"
import { startTestAS, type TestAS } from "./test/fixtures/as.js"
import type { AuthKitConfig } from "./types.js"

const AUDIENCE = "https://mcp.example.test/"
const ISSUER_PLACEHOLDER = "https://as.example.test"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeConfig(overrides: Partial<AuthKitConfig> = {}): AuthKitConfig {
  return {
    resourceIndicator: AUDIENCE,
    auth: {
      authorizationServer: {
        issuer: ISSUER_PLACEHOLDER,
        jwksUri: `${ISSUER_PLACEHOLDER}/.well-known/jwks.json`,
      },
      tokenStore: memoryTokenStore(),
      pat: { enabled: true, prefix: "mcp_pat_" },
    },
    scopes: { vocabulary: {} },
    resolveUserScopes: async () => ["read:data", "write:data"],
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// Unit: extractBearer
// ---------------------------------------------------------------------------

describe("extractBearer", () => {
  it("returns token from valid Bearer header", () => {
    expect(extractBearer("Bearer abc123")).toBe("abc123")
  })
  it("is case-insensitive", () => {
    expect(extractBearer("bearer abc123")).toBe("abc123")
  })
  it("returns null for missing header", () => {
    expect(extractBearer(undefined)).toBeNull()
  })
  it("returns null for non-Bearer scheme", () => {
    expect(extractBearer("Basic abc123")).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Unit: looksLikeJwt
// ---------------------------------------------------------------------------

describe("looksLikeJwt", () => {
  it("returns true for three-part token", () => {
    expect(looksLikeJwt("aaa.bbb.ccc")).toBe(true)
  })
  it("returns false for two-part token", () => {
    expect(looksLikeJwt("aaa.bbb")).toBe(false)
  })
  it("returns false for opaque token", () => {
    expect(looksLikeJwt("mcp_pat_abc123")).toBe(false)
  })
  it("returns false for empty segments", () => {
    expect(looksLikeJwt("aaa..ccc")).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Unit: timingSafeStringEqual
// ---------------------------------------------------------------------------

describe("timingSafeStringEqual", () => {
  it("returns true for equal strings", () => {
    expect(timingSafeStringEqual("secret", "secret")).toBe(true)
  })
  it("returns false for different strings of same length", () => {
    expect(timingSafeStringEqual("secret1", "secret2")).toBe(false)
  })
  it("returns false for different lengths", () => {
    expect(timingSafeStringEqual("short", "longer-string")).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Pipeline: step 1 — bypass mode
// ---------------------------------------------------------------------------

describe("runPipeline: bypass mode (step 1)", () => {
  it("returns bypass AuthContext when bypass enabled", async () => {
    const config = makeConfig({
      auth: {
        ...makeConfig().auth,
        bypass: { enabled: true, user: "dev", scopes: ["read:data"] },
      },
    })
    const result = await runPipeline(config, null)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.auth.tokenType).toBe("bypass")
    expect(result.auth.subject).toBe("dev")
    expect(result.auth.expiresAt).toBeNull()
  })

  it("skips bypass when not enabled", async () => {
    const config = makeConfig({
      auth: { ...makeConfig().auth, bypass: { enabled: false, user: "dev", scopes: [] } },
    })
    const result = await runPipeline(config, null)
    expect(result.ok).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Pipeline: step 2 — static token
// ---------------------------------------------------------------------------

describe("runPipeline: static token (step 2)", () => {
  it("accepts matching static token", async () => {
    const config = makeConfig({
      auth: {
        ...makeConfig().auth,
        staticToken: { token: "super-secret", user: "ci-bot", scopes: ["read:data"] },
      },
    })
    const result = await runPipeline(config, "super-secret")
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.auth.tokenType).toBe("static")
    expect(result.auth.subject).toBe("ci-bot")
  })

  it("rejects wrong static token", async () => {
    const config = makeConfig({
      auth: {
        ...makeConfig().auth,
        staticToken: { token: "super-secret", user: "ci-bot", scopes: [] },
      },
    })
    const result = await runPipeline(config, "wrong-token")
    expect(result.ok).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Pipeline: step 3 — PAT
// ---------------------------------------------------------------------------

describe("runPipeline: PAT (step 3)", () => {
  it("accepts a valid minted PAT and intersects scopes", async () => {
    const store = memoryTokenStore()
    const config = makeConfig({
      auth: { ...makeConfig().auth, tokenStore: store, pat: { enabled: true, prefix: "mcp_pat_" } },
      resolveUserScopes: async () => ["read:data"], // restricts to read only
    })
    const patConfig = {
      prefix: "mcp_pat_",
      defaultExpiryDays: 90,
      maxExpiryDays: 365,
      rotationGraceSeconds: 0,
    }
    const result = await createPat(store, patConfig, {
      userIdentifier: "u1",
      name: "test",
      scopes: ["read:data", "write:data"],
      expiresInDays: 1,
    })
    const pipelineResult = await runPipeline(config, result.token)
    expect(pipelineResult.ok).toBe(true)
    if (!pipelineResult.ok) return
    expect(pipelineResult.auth.tokenType).toBe("pat")
    expect(pipelineResult.auth.subject).toBe("u1")
    // Scope intersection: PAT has write:data but user only has read:data
    expect(pipelineResult.auth.scopes).toEqual(["read:data"])
  })

  it("rejects unknown PAT-prefixed token", async () => {
    const config = makeConfig()
    const result = await runPipeline(config, "mcp_pat_unknowntoken_XXXXXX")
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toContain("pat-not-found")
  })
})

// ---------------------------------------------------------------------------
// Pipeline: step 4 — JWT (integration with fixture AS)
// ---------------------------------------------------------------------------

describe("runPipeline: JWT (step 4)", () => {
  let as: TestAS

  beforeAll(async () => {
    as = await startTestAS()
  })

  afterAll(async () => {
    await as.close()
  })

  function jwtConfig(): AuthKitConfig {
    return makeConfig({
      auth: {
        ...makeConfig().auth,
        authorizationServer: { issuer: as.issuer, jwksUri: as.jwksUri },
      },
    })
  }

  it("accepts valid JWT with correct aud", async () => {
    const token = await as.signToken({ sub: "user-1", aud: AUDIENCE, scope: "read:data" })
    const result = await runPipeline(jwtConfig(), token)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.auth.tokenType).toBe("oauth")
    expect(result.auth.subject).toBe("user-1")
  })

  it("rejects JWT with wrong aud (spec §14)", async () => {
    const token = await as.signToken({ sub: "user-1", aud: "https://wrong.example.com/" })
    const result = await runPipeline(jwtConfig(), token)
    expect(result.ok).toBe(false)
  })

  it("rejects JWT with missing aud (spec §14)", async () => {
    const token = await as.signToken({ sub: "user-1" })
    const result = await runPipeline(jwtConfig(), token)
    expect(result.ok).toBe(false)
  })

  it("rejects expired JWT", async () => {
    const token = await as.signToken({
      sub: "user-1",
      aud: AUDIENCE,
      exp: Math.floor(Date.now() / 1000) - 60,
    })
    const result = await runPipeline(jwtConfig(), token)
    expect(result.ok).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Pipeline: step 6 — no match → 401
// ---------------------------------------------------------------------------

describe("runPipeline: no match (step 6)", () => {
  it("returns not-ok with no bearer token and no bypass", async () => {
    const result = await runPipeline(makeConfig(), null)
    expect(result.ok).toBe(false)
  })

  it("returns not-ok for opaque token without introspection endpoint", async () => {
    const result = await runPipeline(makeConfig(), "opaque-random-token")
    expect(result.ok).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// createAuthKit: startup validation
// ---------------------------------------------------------------------------

describe("createAuthKit", () => {
  it("throws BypassProductionError in production with bypass enabled", () => {
    const origEnv = process.env["NODE_ENV"]
    process.env["NODE_ENV"] = "production"
    try {
      expect(() =>
        createAuthKit(
          makeConfig({
            auth: {
              ...makeConfig().auth,
              bypass: { enabled: true, user: "dev", scopes: [] },
            },
          }),
        ),
      ).toThrow()
    } finally {
      process.env["NODE_ENV"] = origEnv
    }
  })

  it("allows bypass in production with allowInProduction: true", () => {
    const origEnv = process.env["NODE_ENV"]
    process.env["NODE_ENV"] = "production"
    try {
      expect(() =>
        createAuthKit(
          makeConfig({
            auth: {
              ...makeConfig().auth,
              bypass: { enabled: true, user: "dev", scopes: [], allowInProduction: true },
            },
          }),
        ),
      ).not.toThrow()
    } finally {
      process.env["NODE_ENV"] = origEnv
    }
  })
})

// ---------------------------------------------------------------------------
// Audit events
// ---------------------------------------------------------------------------

describe("runPipeline: audit events", () => {
  it("fires oauth.validate on successful JWT", async () => {
    const as2 = await startTestAS()
    try {
      const events: string[] = []
      const config: AuthKitConfig = {
        resourceIndicator: AUDIENCE,
        auth: {
          authorizationServer: { issuer: as2.issuer, jwksUri: as2.jwksUri },
          tokenStore: memoryTokenStore(),
          pat: { enabled: false },
        },
        scopes: { vocabulary: {} },
        resolveUserScopes: async () => [],
        audit: {
          onEvent: (e) => {
            events.push(e.type)
          },
        },
      }
      const token = await as2.signToken({ sub: "u1", aud: AUDIENCE, scope: "read:data" })
      await runPipeline(config, token, config.audit?.onEvent)
      expect(events).toContain("oauth.validate")
    } finally {
      await as2.close()
    }
  })

  it("fires oauth.reject on failed JWT", async () => {
    const as2 = await startTestAS()
    try {
      const events: string[] = []
      const config: AuthKitConfig = {
        resourceIndicator: AUDIENCE,
        auth: {
          authorizationServer: { issuer: as2.issuer, jwksUri: as2.jwksUri },
          tokenStore: memoryTokenStore(),
          pat: { enabled: false },
        },
        scopes: { vocabulary: {} },
        resolveUserScopes: async () => [],
        audit: {
          onEvent: (e) => {
            events.push(e.type)
          },
        },
      }
      const token = await as2.signToken({ sub: "u1", aud: "wrong-aud" })
      await runPipeline(config, token, config.audit?.onEvent)
      expect(events).toContain("oauth.reject")
    } finally {
      await as2.close()
    }
  })

  it("fires pat.use on valid PAT", async () => {
    const store = memoryTokenStore()
    const events: string[] = []
    const config = makeConfig({
      auth: { ...makeConfig().auth, tokenStore: store, pat: { enabled: true, prefix: "mcp_pat_" } },
      audit: {
        onEvent: (e) => {
          events.push(e.type)
        },
      },
    })
    const patConfig = {
      prefix: "mcp_pat_",
      defaultExpiryDays: 90,
      maxExpiryDays: 365,
      rotationGraceSeconds: 0,
    }
    const result = await createPat(store, patConfig, {
      userIdentifier: "u1",
      name: "t",
      scopes: ["read:data"],
      expiresInDays: 1,
    })
    await runPipeline(config, result.token, config.audit?.onEvent)
    expect(events).toContain("pat.use")
  })
})
