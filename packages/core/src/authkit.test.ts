import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { memoryTokenStore } from "mcp-authkit-store-memory"
import { afterAll, beforeAll, describe, expect, it } from "vitest"
import { z } from "zod"
import {
  createAuthKit,
  extractBearer,
  looksLikeJwt,
  runPipeline,
  timingSafeStringEqual,
} from "./authkit.js"
import { createPat, revokePat } from "./pats/lifecycle.js"
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
    const origEnv = process.env.NODE_ENV
    process.env.NODE_ENV = "production"
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
      process.env.NODE_ENV = origEnv
    }
  })

  it("throws when resourceIndicator cannot derive a host and http.allowedHosts is unset (spec §14)", () => {
    expect(() => createAuthKit(makeConfig({ resourceIndicator: "not a url" }))).toThrow(
      /allowlist/i,
    )
  })

  it("accepts unparseable resourceIndicator when http.allowedHosts is provided explicitly", () => {
    expect(() =>
      createAuthKit(makeConfig({ resourceIndicator: "not a url", http: { allowedHosts: [] } })),
    ).not.toThrow()
  })

  it("allows bypass in production with allowInProduction: true", () => {
    const origEnv = process.env.NODE_ENV
    process.env.NODE_ENV = "production"
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
      process.env.NODE_ENV = origEnv
    }
  })

  it("throws when bypass is enabled alongside signed stdio (spec v0.2 §11)", () => {
    expect(() =>
      createAuthKit(
        makeConfig({
          auth: {
            ...makeConfig().auth,
            bypass: { enabled: true, user: "dev", scopes: [] },
            stdio: { mode: "signed", hmacKey: "k".repeat(32) },
          },
        }),
      ),
    ).toThrow(/signed stdio/i)
  })

  it("accepts signed stdio when bypass is absent", () => {
    expect(() =>
      createAuthKit(
        makeConfig({
          auth: {
            ...makeConfig().auth,
            stdio: { mode: "signed", hmacKey: "k".repeat(32) },
          },
        }),
      ),
    ).not.toThrow()
  })

  it("upstreamFor is available when authorizationServer is in function form (#107)", () => {
    // Function-form AS: issuer is resolved per call from auth.raw.iss.
    // The helper must construct without throwing and must return a fetcher
    // closure for any non-empty audience.
    const authkit = createAuthKit(
      makeConfig({
        auth: {
          ...makeConfig().auth,
          authorizationServer: async () => ({
            issuer: ISSUER_PLACEHOLDER,
            jwksUri: `${ISSUER_PLACEHOLDER}/.well-known/jwks.json`,
          }),
        },
      }),
    )
    const fetcher = authkit.upstreamFor("https://upstream.example.test/")
    expect(typeof fetcher).toBe("function")
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

// ---------------------------------------------------------------------------
// Security tests (spec §14)
// ---------------------------------------------------------------------------

describe("security: revoked PAT is rejected", () => {
  it("rejects a PAT that has been revoked", async () => {
    const store = memoryTokenStore()
    const config = makeConfig({
      auth: { ...makeConfig().auth, tokenStore: store, pat: { enabled: true, prefix: "mcp_pat_" } },
    })
    const patConfig = {
      prefix: "mcp_pat_",
      defaultExpiryDays: 90,
      maxExpiryDays: 365,
      rotationGraceSeconds: 0,
    }
    const { token, stored } = await createPat(store, patConfig, {
      userIdentifier: "u1",
      name: "test-revoke",
      scopes: ["read:data"],
      expiresInDays: 1,
    })
    await revokePat(store, stored.id, "u1")
    const result = await runPipeline(config, token)
    expect(result.ok).toBe(false)
  })
})

describe("security: PAT scope escalation is prevented (spec §14)", () => {
  it("clamps effective scopes to resolveUserScopes — PAT cannot escalate", async () => {
    const store = memoryTokenStore()
    const config = makeConfig({
      auth: { ...makeConfig().auth, tokenStore: store, pat: { enabled: true, prefix: "mcp_pat_" } },
      // User has only read:data; PAT stamps write:data in addition
      resolveUserScopes: async () => ["read:data"],
    })
    const patConfig = {
      prefix: "mcp_pat_",
      defaultExpiryDays: 90,
      maxExpiryDays: 365,
      rotationGraceSeconds: 0,
    }
    const { token } = await createPat(store, patConfig, {
      userIdentifier: "u1",
      name: "escalation-attempt",
      scopes: ["read:data", "write:data", "admin:all"],
      expiresInDays: 1,
    })
    const result = await runPipeline(config, token)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    // Effective scopes must not include write:data or admin:all
    expect(result.auth.scopes).toEqual(["read:data"])
    expect(result.auth.scopes).not.toContain("write:data")
    expect(result.auth.scopes).not.toContain("admin:all")
  })
})

describe("security: static token with insufficient scopes is denied at the tool gate", () => {
  it("registerTool emits scope.deny when static token lacks required scope", async () => {
    const deniedScopes: string[] = []
    const config = makeConfig({
      auth: {
        ...makeConfig().auth,
        staticToken: { token: "ci-token", user: "ci-bot", scopes: ["read:data"] },
      },
      audit: {
        onEvent: (e) => {
          if (e.type === "scope.deny" && "required" in e.detail) {
            deniedScopes.push(e.detail.required as string)
          }
        },
      },
    })
    const kit = createAuthKit(config)
    const mcp = new McpServer({ name: "test", version: "0.0.1" })

    kit.registerTool(mcp, {
      name: "privileged-tool",
      description: "needs admin",
      inputSchema: {},
      requireScopes: ["admin:all"],
      handler: async () => ({ content: [{ type: "text" as const, text: "ok" }] }),
    })

    // biome-ignore lint/suspicious/noExplicitAny: accessing internal MCP SDK object for test purposes
    const tools = (mcp as any)._registeredTools as Record<
      string,
      {
        handler: (
          input: Record<string, unknown>,
          extra: Record<string, unknown>,
        ) => Promise<unknown>
      }
    >
    const toolResult = (await tools["privileged-tool"]?.handler(
      {},
      { authInfo: { token: "ci-token" } },
    )) as { content: Array<{ type: string; text: string }>; isError?: boolean }

    expect(toolResult?.isError).toBe(true)
    expect(deniedScopes).toContain("admin:all")
  })
})

// ---------------------------------------------------------------------------
// registerTool: scope gate (scope.allow / scope.deny)
// ---------------------------------------------------------------------------

// Helper: get a registered tool's handler from McpServer internals.
function getToolHandler(
  mcp: McpServer,
  name: string,
):
  | ((input: Record<string, unknown>, extra: Record<string, unknown>) => Promise<unknown>)
  | undefined {
  // biome-ignore lint/suspicious/noExplicitAny: accessing internal MCP SDK object for test purposes
  const tools = (mcp as any)._registeredTools as Record<
    string,
    {
      handler: (input: Record<string, unknown>, extra: Record<string, unknown>) => Promise<unknown>
    }
  >
  return tools[name]?.handler
}

describe("registerTool: scope gate", () => {
  it("invokes handler when required scopes are satisfied", async () => {
    const config = makeConfig({
      auth: {
        ...makeConfig().auth,
        bypass: { enabled: true, user: "dev", scopes: ["read:data", "write:data"] },
      },
    })
    const kit = createAuthKit(config)
    const mcp = new McpServer({ name: "test", version: "0.0.1" })

    kit.registerTool(mcp, {
      name: "echo",
      description: "echo tool",
      inputSchema: { message: z.string() },
      requireScopes: ["read:data"],
      handler: async ({ input }) => ({
        content: [{ type: "text" as const, text: input.message }],
      }),
    })

    const handler = getToolHandler(mcp, "echo")
    expect(handler).toBeDefined()
    const result = (await handler?.({ message: "hello" }, {})) as {
      content: Array<{ type: string; text: string }>
      isError?: boolean
    }
    expect(result.isError).toBeFalsy()
    expect(result.content[0]?.text).toBe("hello")
  })

  it("returns Forbidden when required scope is missing", async () => {
    const config = makeConfig({
      auth: {
        ...makeConfig().auth,
        bypass: { enabled: true, user: "dev", scopes: ["read:data"] },
      },
    })
    const kit = createAuthKit(config)
    const mcp = new McpServer({ name: "test", version: "0.0.1" })

    kit.registerTool(mcp, {
      name: "admin-tool",
      description: "needs admin",
      inputSchema: {},
      requireScopes: ["admin:all"],
      handler: async () => ({ content: [{ type: "text" as const, text: "should not reach" }] }),
    })

    const handler = getToolHandler(mcp, "admin-tool")
    const result = (await handler?.({}, {})) as {
      content: Array<{ type: string; text: string }>
      isError?: boolean
    }
    expect(result?.isError).toBe(true)
    expect(result?.content[0]?.text).toContain("Forbidden")
  })

  it("emits scope.allow and scope.deny audit events", async () => {
    const events: Array<{ type: string; detail: Record<string, unknown> }> = []
    const config: AuthKitConfig = {
      ...makeConfig(),
      auth: {
        ...makeConfig().auth,
        bypass: { enabled: true, user: "dev", scopes: ["read:data"] },
      },
      audit: {
        onEvent: (e) => {
          events.push({ type: e.type, detail: e.detail as Record<string, unknown> })
        },
      },
    }
    const kit = createAuthKit(config)
    const mcp = new McpServer({ name: "test", version: "0.0.1" })

    kit.registerTool(mcp, {
      name: "allowed-tool",
      description: "allowed",
      inputSchema: {},
      requireScopes: ["read:data"],
      handler: async () => ({ content: [{ type: "text" as const, text: "ok" }] }),
    })
    kit.registerTool(mcp, {
      name: "denied-tool",
      description: "denied",
      inputSchema: {},
      requireScopes: ["admin:all"],
      handler: async () => ({ content: [{ type: "text" as const, text: "nope" }] }),
    })

    await getToolHandler(mcp, "allowed-tool")?.({}, {})
    await getToolHandler(mcp, "denied-tool")?.({}, {})

    expect(events.some((e) => e.type === "scope.allow")).toBe(true)
    expect(events.some((e) => e.type === "scope.deny")).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Audit hook rejection (spec §12: "an exception aborts the triggering op")
// ---------------------------------------------------------------------------

describe("audit hook rejection propagates from runPipeline", () => {
  it("propagates from oauth.validate (JWT happy path)", async () => {
    const as2 = await startTestAS()
    try {
      const boom = new Error("audit refused validate")
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
          onEvent: () => {
            throw boom
          },
        },
      }
      const token = await as2.signToken({ sub: "u1", aud: AUDIENCE })
      await expect(runPipeline(config, token, config.audit?.onEvent)).rejects.toBe(boom)
    } finally {
      await as2.close()
    }
  })

  it("propagates from oauth.reject (JWT failure path)", async () => {
    const as2 = await startTestAS()
    try {
      const boom = new Error("audit refused reject")
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
          onEvent: () => {
            throw boom
          },
        },
      }
      const token = await as2.signToken({ sub: "u1", aud: "wrong-aud" })
      await expect(runPipeline(config, token, config.audit?.onEvent)).rejects.toBe(boom)
    } finally {
      await as2.close()
    }
  })

  it("propagates from pat.use (valid PAT)", async () => {
    const store = memoryTokenStore()
    const boom = new Error("audit refused pat.use")
    const config = makeConfig({
      auth: { ...makeConfig().auth, tokenStore: store, pat: { enabled: true, prefix: "mcp_pat_" } },
      audit: {
        onEvent: (e) => {
          if (e.type === "pat.use") throw boom
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
    await expect(runPipeline(config, result.token, config.audit?.onEvent)).rejects.toBe(boom)
  })

  it("propagates from oauth.reject (PAT-not-found)", async () => {
    const boom = new Error("audit refused pat-reject")
    const config = makeConfig({
      auth: {
        ...makeConfig().auth,
        tokenStore: memoryTokenStore(),
        pat: { enabled: true, prefix: "mcp_pat_" },
      },
      audit: {
        onEvent: () => {
          throw boom
        },
      },
    })
    await expect(runPipeline(config, "mcp_pat_unknown_token", config.audit?.onEvent)).rejects.toBe(
      boom,
    )
  })
})

describe("audit hook rejection propagates from registerTool scope gate", () => {
  it("propagates from scope.allow", async () => {
    const boom = new Error("audit refused allow")
    const config: AuthKitConfig = {
      ...makeConfig(),
      auth: {
        ...makeConfig().auth,
        bypass: { enabled: true, user: "dev", scopes: ["read:data"] },
      },
      audit: {
        onEvent: (e) => {
          if (e.type === "scope.allow") throw boom
        },
      },
    }
    const kit = createAuthKit(config)
    const mcp = new McpServer({ name: "test", version: "0.0.1" })
    kit.registerTool(mcp, {
      name: "ok-tool",
      description: "ok",
      inputSchema: {},
      requireScopes: ["read:data"],
      handler: async () => ({ content: [{ type: "text" as const, text: "ok" }] }),
    })
    await expect(getToolHandler(mcp, "ok-tool")?.({}, {})).rejects.toBe(boom)
  })

  it("propagates from scope.deny", async () => {
    const boom = new Error("audit refused deny")
    const config: AuthKitConfig = {
      ...makeConfig(),
      auth: {
        ...makeConfig().auth,
        bypass: { enabled: true, user: "dev", scopes: ["read:data"] },
      },
      audit: {
        onEvent: (e) => {
          if (e.type === "scope.deny") throw boom
        },
      },
    }
    const kit = createAuthKit(config)
    const mcp = new McpServer({ name: "test", version: "0.0.1" })
    kit.registerTool(mcp, {
      name: "denied",
      description: "denied",
      inputSchema: {},
      requireScopes: ["admin:all"],
      handler: async () => ({ content: [{ type: "text" as const, text: "nope" }] }),
    })
    await expect(getToolHandler(mcp, "denied")?.({}, {})).rejects.toBe(boom)
  })
})

// ---------------------------------------------------------------------------
// upstreamFor: function-form authorizationServer (#91)
// ---------------------------------------------------------------------------

describe("upstreamFor with function-form authorizationServer", () => {
  it("constructs without reading .issuer off the resolver function", () => {
    // Regression: pre-fix the wiring read `as.issuer` directly even when the
    // AS was the function form, which type-failed at build time (spec v0.2
    // §5.1 introduced the union).
    const config = makeConfig({
      auth: {
        ...makeConfig().auth,
        authorizationServer: async () => ({
          issuer: ISSUER_PLACEHOLDER,
          jwksUri: `${ISSUER_PLACEHOLDER}/.well-known/jwks.json`,
        }),
      },
    })
    expect(() => createAuthKit(config)).not.toThrow()
  })

  it("mints an upstream credential for an OAuth auth context (#107)", async () => {
    // Function-form AS resolves the issuer per call from auth.raw.iss.
    // We stub fetch on the token endpoint to keep the test hermetic.
    const config = makeConfig({
      auth: {
        ...makeConfig().auth,
        authorizationServer: async () => ({
          issuer: "https://tenant-a.example.test",
          jwksUri: "https://tenant-a.example.test/.well-known/jwks.json",
        }),
      },
    })
    const kit = createAuthKit(config)

    // The default exchange path will try RFC 8414 discovery + token endpoint.
    // Stub fetch to return a discovery doc + a minted token; spec compliance
    // of the exchange itself is covered by token-exchange's own tests.
    const origFetch = globalThis.fetch
    const fetchCalls: string[] = []
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const u = typeof input === "string" ? input : input.toString()
      fetchCalls.push(u)
      if (u.endsWith("/.well-known/oauth-authorization-server")) {
        return new Response(
          JSON.stringify({
            issuer: "https://tenant-a.example.test",
            token_endpoint: "https://tenant-a.example.test/token",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        )
      }
      if (u === "https://tenant-a.example.test/token") {
        // JWT-shaped minted token with aud == requested audience. The
        // exchange validator decodes it locally and checks aud (spec §8);
        // an opaque token would require an introspection endpoint.
        const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString(
          "base64url",
        )
        const payload = Buffer.from(
          JSON.stringify({ aud: "https://upstream.example.test/", sub: "u1" }),
        ).toString("base64url")
        // Three non-empty segments (compact JWS shape); decode-only validator
        // doesn't verify the signature.
        const minted = `${header}.${payload}.sig`
        return new Response(
          JSON.stringify({
            access_token: minted,
            token_type: "Bearer",
            issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
            expires_in: 60,
            scope: "upstream:read",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        )
      }
      throw new Error(`unexpected fetch: ${u}`)
    }) as typeof globalThis.fetch

    try {
      const out = await kit.upstreamFor("https://upstream.example.test/")({
        auth: {
          subject: "u1",
          tokenType: "oauth",
          tokenId: "jti",
          scopes: ["upstream:read"],
          expiresAt: new Date(Date.now() + 60_000),
          // Subject token must be JWT-shaped with aud == resourceIndicator
          // (AUDIENCE) — spec v0.2 §8 enforces this locally before any AS
          // call (PR #110).
          raw: {
            access_token: (() => {
              const h = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString(
                "base64url",
              )
              const p = Buffer.from(JSON.stringify({ aud: AUDIENCE, sub: "u1" })).toString(
                "base64url",
              )
              return `${h}.${p}.sig`
            })(),
            iss: "https://tenant-a.example.test",
            sub: "u1",
          },
        },
        scopes: ["upstream:read"],
      })
      expect(out.token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/)
      // Discovery + token endpoint were both hit.
      expect(fetchCalls.some((u) => u.endsWith("/.well-known/oauth-authorization-server"))).toBe(
        true,
      )
      expect(fetchCalls).toContain("https://tenant-a.example.test/token")
    } finally {
      globalThis.fetch = origFetch
    }
  })

  it("refuses with a clear error when auth.raw.iss is missing (#107)", async () => {
    const kit = createAuthKit(
      makeConfig({
        auth: {
          ...makeConfig().auth,
          authorizationServer: async () => ({
            issuer: ISSUER_PLACEHOLDER,
            jwksUri: `${ISSUER_PLACEHOLDER}/.well-known/jwks.json`,
          }),
        },
      }),
    )
    await expect(
      kit.upstreamFor("https://upstream.example.test/")({
        auth: {
          subject: "u1",
          tokenType: "oauth",
          tokenId: "jti",
          scopes: [],
          expiresAt: new Date(Date.now() + 60_000),
          raw: { access_token: "subj", sub: "u1" }, // no `iss`
        },
        scopes: [],
      }),
    ).rejects.toThrow(/auth\.raw\.iss/)
  })

  it("refuses PAT tokenType in function-form deployments with a clear error (#107)", async () => {
    const kit = createAuthKit(
      makeConfig({
        auth: {
          ...makeConfig().auth,
          authorizationServer: async () => ({
            issuer: ISSUER_PLACEHOLDER,
            jwksUri: `${ISSUER_PLACEHOLDER}/.well-known/jwks.json`,
          }),
        },
      }),
    )
    await expect(
      kit.upstreamFor("https://upstream.example.test/")({
        auth: {
          subject: "u1",
          tokenType: "pat",
          tokenId: "pat-1",
          scopes: [],
          expiresAt: null,
          raw: {},
        },
        scopes: [],
      }),
    ).rejects.toThrow(/tokenType=pat/)
  })
})
