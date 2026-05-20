/**
 * End-to-end tests for the function-form `authorizationServer` resolver
 * wired through `createAuthKit` + `handlers.mcp` (spec v0.2 §5.1, §7).
 *
 * Covers:
 *   - Two-tenant: token minted by tenant A is rejected when request resolves
 *     to tenant B's AS (signature / audience mismatch path → 401).
 *   - Resolver throw → 503 with `WWW-Authenticate: error="server_error"`,
 *     NOT 401.
 *   - JWKS cache isolation per resolved issuer.
 *   - Memoization: resolver invoked at most once per request even though
 *     the pipeline may peek at the AS multiple times.
 *   - Static object form remains source-compatible.
 */
import {
  createServer,
  request as httpRequest,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http"
import type { AddressInfo } from "node:net"
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { memoryTokenStore } from "mcp-authkit-store-memory"
import { afterEach, describe, expect, it, vi } from "vitest"
import { createAuthKit } from "../authkit.js"
import { startTestAS, type TestAS } from "../test/fixtures/as.js"
import type {
  AuthKitConfig,
  AuthorizationServerConfig,
  AuthorizationServerResolver,
} from "../types.js"

const AUDIENCE = "https://mcp.example.test/"

interface Rig {
  url: string
  close: () => Promise<void>
}

async function startRig(config: AuthKitConfig): Promise<Rig> {
  const authkit = createAuthKit(config)
  const mcp = new McpServer({ name: "test", version: "0.0.1" })
  const h = authkit.handlers(mcp)
  const server: Server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    try {
      const url = req.url ?? "/"
      if (url.startsWith("/mcp")) {
        await h.mcp(req, res)
        return
      }
      res.writeHead(404)
      res.end()
    } catch {
      if (!res.headersSent) {
        res.writeHead(500)
        res.end()
      }
    }
  })
  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve())
  })
  const { port } = server.address() as AddressInfo
  return {
    url: `http://127.0.0.1:${port}`,
    close: async () =>
      new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      ),
  }
}

function baseConfig(
  authzServer: AuthKitConfig["auth"]["authorizationServer"],
  overrides?: Partial<AuthKitConfig>,
): AuthKitConfig {
  return {
    resourceIndicator: AUDIENCE,
    auth: {
      ...(authzServer !== undefined ? { authorizationServer: authzServer } : {}),
      tokenStore: memoryTokenStore(),
      pat: { enabled: false },
    },
    scopes: { vocabulary: {} },
    resolveUserScopes: async () => [],
    http: { allowedHosts: [] },
    ...overrides,
  }
}

interface RawResponse {
  status: number
  wwwAuthenticate: string | null
  body: string
}

/**
 * Plain HTTP request that allows overriding the Host header. `globalThis.fetch`
 * silently ignores `Host`, so multi-tenant routing by Host can't be exercised
 * through it.
 */
async function rawPost(
  rigUrl: string,
  path: string,
  hostHeader: string,
  token: string,
): Promise<RawResponse> {
  const url = new URL(rigUrl)
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "1.0",
      capabilities: {},
      clientInfo: { name: "t", version: "0" },
    },
  })
  return await new Promise<RawResponse>((resolve, reject) => {
    const req = httpRequest(
      {
        method: "POST",
        host: url.hostname,
        port: url.port,
        path,
        headers: {
          Host: hostHeader,
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
          Accept: "application/json, text/event-stream",
          "Content-Length": Buffer.byteLength(body),
        },
      },
      (res) => {
        const chunks: Buffer[] = []
        res.on("data", (c: Buffer) => chunks.push(c))
        res.on("end", () => {
          const wwwHeader = res.headers["www-authenticate"]
          resolve({
            status: res.statusCode ?? 0,
            wwwAuthenticate: Array.isArray(wwwHeader)
              ? (wwwHeader[0] ?? null)
              : (wwwHeader ?? null),
            body: Buffer.concat(chunks).toString("utf8"),
          })
        })
      },
    )
    req.on("error", reject)
    req.write(body)
    req.end()
  })
}

async function postMcp(rigUrl: string, token: string): Promise<RawResponse> {
  // Default host: use rigUrl's hostname so the resolver sees a meaningful
  // tenantId or null, depending on the rig's address.
  const url = new URL(rigUrl)
  return rawPost(rigUrl, "/mcp", `${url.hostname}:${url.port}`, token)
}

// ---------------------------------------------------------------------------
// Two-tenant: cross-tenant token is rejected
// ---------------------------------------------------------------------------

describe("multi-tenant authorizationServer: two-tenant rejection", () => {
  let asA: TestAS
  let asB: TestAS
  let rig: Rig
  afterEach(async () => {
    await rig?.close()
    await asA?.close()
    await asB?.close()
  })

  it("rejects a tenant-A token presented to a tenant-B request", async () => {
    asA = await startTestAS()
    asB = await startTestAS()

    // Resolver routes by tenantId derived from Host header.
    const resolver: AuthorizationServerResolver = async (sel) => {
      if (sel.tenantId === "a") return { issuer: asA.issuer, jwksUri: asA.jwksUri }
      if (sel.tenantId === "b") return { issuer: asB.issuer, jwksUri: asB.jwksUri }
      throw new Error(`unknown tenant: ${sel.tenantId}`)
    }
    rig = await startRig(baseConfig(resolver))

    // Token minted by tenant A (signed with A's key, claims A's iss).
    const tokenFromA = await asA.signToken({ sub: "u1", aud: AUDIENCE, scope: "read:data" })

    // Same token presented to tenant B's endpoint. Tenant B's pipeline
    // expects iss == asB.issuer and the JWT to be signed by B's key, so
    // it must reject — either issuer mismatch or signature mismatch.
    const r = await rawPost(rig.url, "/mcp", "b.example.test", tokenFromA)
    expect(r.status).toBe(401)
    expect(r.wwwAuthenticate).toContain("Bearer")
  })

  it("accepts a tenant-A token presented to tenant A", async () => {
    asA = await startTestAS()
    asB = await startTestAS()
    const resolver: AuthorizationServerResolver = async (sel) => {
      if (sel.tenantId === "a") return { issuer: asA.issuer, jwksUri: asA.jwksUri }
      if (sel.tenantId === "b") return { issuer: asB.issuer, jwksUri: asB.jwksUri }
      throw new Error("unknown tenant")
    }
    rig = await startRig(baseConfig(resolver))

    const token = await asA.signToken({ sub: "u1", aud: AUDIENCE })
    const r = await rawPost(rig.url, "/mcp", "a.example.test", token)
    // 200 or 202 — any non-401/503 means the pipeline accepted the token.
    expect([200, 202]).toContain(r.status)
  })
})

// ---------------------------------------------------------------------------
// Resolver throw → 503 (NOT 401)
// ---------------------------------------------------------------------------

describe("multi-tenant authorizationServer: resolver failure → 503", () => {
  let rig: Rig
  afterEach(async () => {
    await rig?.close()
  })

  it('returns 503 with `WWW-Authenticate: error="server_error"` when the resolver throws', async () => {
    const resolver: AuthorizationServerResolver = async () => {
      throw new Error("AS lookup failed: DB down")
    }
    rig = await startRig(baseConfig(resolver))

    const r = await postMcp(rig.url, "any-token")
    expect(r.status).toBe(503)
    expect(r.wwwAuthenticate).toBeTruthy()
    expect(r.wwwAuthenticate).toMatch(/error="server_error"/)
  })

  it("returns 503 when the resolver returns a malformed config", async () => {
    const resolver: AuthorizationServerResolver = (async () => ({
      jwksUri: "https://x",
    })) as unknown as AuthorizationServerResolver
    rig = await startRig(baseConfig(resolver))
    const r = await postMcp(rig.url, "any-token")
    expect(r.status).toBe(503)
    expect(r.wwwAuthenticate).toMatch(/error="server_error"/)
  })
})

// ---------------------------------------------------------------------------
// JWKS cache isolation per issuer
// ---------------------------------------------------------------------------

describe("multi-tenant authorizationServer: JWKS cache isolation", () => {
  let asA: TestAS
  let asB: TestAS
  let rig: Rig
  afterEach(async () => {
    await rig?.close()
    await asA?.close()
    await asB?.close()
  })

  it("fetches and caches JWKS separately per resolved issuer", async () => {
    asA = await startTestAS()
    asB = await startTestAS()

    // Wrap each AS to count JWKS fetches.
    const fetches = new Map<string, number>()
    const origFetch = globalThis.fetch
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const u = typeof input === "string" ? input : input.toString()
      if (u.includes("/.well-known/jwks.json")) {
        fetches.set(u, (fetches.get(u) ?? 0) + 1)
      }
      return origFetch(input as Parameters<typeof origFetch>[0], init)
    }) as typeof globalThis.fetch

    try {
      const resolver: AuthorizationServerResolver = async (sel) => {
        if (sel.tenantId === "a") return { issuer: asA.issuer, jwksUri: asA.jwksUri }
        return { issuer: asB.issuer, jwksUri: asB.jwksUri }
      }
      rig = await startRig(baseConfig(resolver))

      const tokenA = await asA.signToken({ sub: "u1", aud: AUDIENCE })
      const tokenB = await asB.signToken({ sub: "u1", aud: AUDIENCE })

      // Two requests to tenant A, two to tenant B — each AS must be hit at
      // least once, and the two URLs must be distinct keys.
      await rawPost(rig.url, "/mcp", "a.example.test", tokenA)
      await rawPost(rig.url, "/mcp", "a.example.test", tokenA)
      await rawPost(rig.url, "/mcp", "b.example.test", tokenB)
      await rawPost(rig.url, "/mcp", "b.example.test", tokenB)

      const keys = Array.from(fetches.keys())
      expect(keys.some((k) => k === asA.jwksUri)).toBe(true)
      expect(keys.some((k) => k === asB.jwksUri)).toBe(true)
      expect(asA.jwksUri).not.toBe(asB.jwksUri)
    } finally {
      globalThis.fetch = origFetch
    }
  })
})

// ---------------------------------------------------------------------------
// Memoization: resolver invoked once per request
// ---------------------------------------------------------------------------

describe("multi-tenant authorizationServer: per-request memoization", () => {
  let as: TestAS
  let rig: Rig
  afterEach(async () => {
    await rig?.close()
    await as?.close()
  })

  it("invokes the resolver at most once per HTTP request", async () => {
    as = await startTestAS()
    const resolver = vi.fn<AuthorizationServerResolver>(async () => ({
      issuer: as.issuer,
      jwksUri: as.jwksUri,
    }))
    rig = await startRig(baseConfig(resolver))

    const token = await as.signToken({ sub: "u1", aud: AUDIENCE })
    await postMcp(rig.url, token)
    // Exactly one invocation for the single request even though the pipeline
    // peeks at the AS (JWT-step, possibly introspection-step).
    expect(resolver).toHaveBeenCalledTimes(1)

    // Second request: resolver invoked again (memoization is per request).
    await postMcp(rig.url, token)
    expect(resolver).toHaveBeenCalledTimes(2)
  })
})

// ---------------------------------------------------------------------------
// Static object form is unchanged
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// upstreamFor with function-form AS (#107)
// ---------------------------------------------------------------------------

describe("multi-tenant authorizationServer: upstreamFor (#107)", () => {
  function mintedJwt(
    audience: string,
    sub: string,
    extra: Record<string, unknown> = {},
  ): string {
    const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url")
    const payload = Buffer.from(JSON.stringify({ aud: audience, sub, ...extra })).toString(
      "base64url",
    )
    return `${header}.${payload}.sig`
  }

  function stubFetch(
    issuersToTokenEndpoints: Record<string, string>,
    onTokenExchange: (issuer: string, body: string) => string,
  ): { restore: () => void; calls: { issuer: string; body: string }[] } {
    const calls: { issuer: string; body: string }[] = []
    const origFetch = globalThis.fetch
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const u = typeof input === "string" ? input : input.toString()
      for (const [issuer, tokenEndpoint] of Object.entries(issuersToTokenEndpoints)) {
        if (u === `${issuer}/.well-known/oauth-authorization-server`) {
          return new Response(JSON.stringify({ issuer, token_endpoint: tokenEndpoint }), {
            status: 200,
            headers: { "content-type": "application/json" },
          })
        }
        if (u === tokenEndpoint) {
          const body = typeof init?.body === "string" ? init.body : ""
          calls.push({ issuer, body })
          return new Response(onTokenExchange(issuer, body), {
            status: 200,
            headers: { "content-type": "application/json" },
          })
        }
      }
      throw new Error(`unexpected fetch: ${u}`)
    }) as typeof globalThis.fetch
    return {
      restore: () => {
        globalThis.fetch = origFetch
      },
      calls,
    }
  }

  it("isolates upstream cache by resolved issuer (no cross-tenant collision)", async () => {
    const ISS_A = "https://tenant-a.example.test"
    const ISS_B = "https://tenant-b.example.test"
    const UPSTREAM = "https://upstream.example.test/"

    const stub = stubFetch(
      {
        [ISS_A]: `${ISS_A}/token`,
        [ISS_B]: `${ISS_B}/token`,
      },
      (issuer) =>
        JSON.stringify({
          access_token: mintedJwt(UPSTREAM, `sub-via-${issuer}`),
          token_type: "Bearer",
          issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
          expires_in: 60,
        }),
    )

    try {
      const resolver: AuthorizationServerResolver = async (sel) => {
        if (sel.tenantId === "a") return { issuer: ISS_A, jwksUri: `${ISS_A}/jwks` }
        return { issuer: ISS_B, jwksUri: `${ISS_B}/jwks` }
      }
      const kit = createAuthKit(baseConfig(resolver))
      const fetcher = kit.upstreamFor(UPSTREAM)

      // Subject tokens must be JWT-shaped with aud == resourceIndicator
      // because spec v0.2 §8 (PR #110) audience-validates the subject token
      // locally BEFORE any AS request.
      const subjA = mintedJwt(AUDIENCE, "u1", { iss: ISS_A })
      const subjB = mintedJwt(AUDIENCE, "u1", { iss: ISS_B })
      const authA = {
        subject: "u1",
        tokenType: "oauth" as const,
        tokenId: "jti-a",
        scopes: ["read"] as readonly string[],
        expiresAt: new Date(Date.now() + 60_000),
        raw: { access_token: subjA, iss: ISS_A, sub: "u1" },
      }
      const authB = {
        subject: "u1",
        tokenType: "oauth" as const,
        tokenId: "jti-b",
        scopes: ["read"] as readonly string[],
        expiresAt: new Date(Date.now() + 60_000),
        raw: { access_token: subjB, iss: ISS_B, sub: "u1" },
      }

      const a1 = await fetcher({ auth: authA, scopes: ["read"] })
      const b1 = await fetcher({ auth: authB, scopes: ["read"] })
      const a2 = await fetcher({ auth: authA, scopes: ["read"] })
      const b2 = await fetcher({ auth: authB, scopes: ["read"] })

      // Two distinct token exchanges (one per tenant), then both cached.
      expect(stub.calls.length).toBe(2)
      const seenIssuers = new Set(stub.calls.map((c) => c.issuer))
      expect(seenIssuers).toEqual(new Set([ISS_A, ISS_B]))

      // Tenant A's cached entry stays bound to tenant A's minted token, and
      // likewise for B — no cross-tenant cache poisoning.
      expect(a2.token).toBe(a1.token)
      expect(b2.token).toBe(b1.token)
      expect(a1.token).not.toBe(b1.token)
    } finally {
      stub.restore()
    }
  })

  it("refuses upstreamFor with a clear error for PAT tokenType", async () => {
    const resolver: AuthorizationServerResolver = async () => ({
      issuer: "https://tenant.example.test",
      jwksUri: "https://tenant.example.test/jwks",
    })
    const kit = createAuthKit(baseConfig(resolver))
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

  it("refuses upstreamFor when auth.raw.iss is absent (e.g. introspection without iss)", async () => {
    const resolver: AuthorizationServerResolver = async () => ({
      issuer: "https://tenant.example.test",
      jwksUri: "https://tenant.example.test/jwks",
    })
    const kit = createAuthKit(baseConfig(resolver))
    await expect(
      kit.upstreamFor("https://upstream.example.test/")({
        auth: {
          subject: "u1",
          tokenType: "oauth",
          tokenId: "jti",
          scopes: [],
          expiresAt: new Date(Date.now() + 60_000),
          raw: { access_token: "subj", sub: "u1" }, // RFC 7662 leaves iss optional
        },
        scopes: [],
      }),
    ).rejects.toThrow(/auth\.raw\.iss/)
  })
})

describe("multi-tenant authorizationServer: static object form unchanged", () => {
  let as: TestAS
  let rig: Rig
  afterEach(async () => {
    await rig?.close()
    await as?.close()
  })

  it("accepts a valid JWT via the static-object configuration (no resolver)", async () => {
    as = await startTestAS()
    const staticAs: AuthorizationServerConfig = { issuer: as.issuer, jwksUri: as.jwksUri }
    rig = await startRig(baseConfig(staticAs))

    const token = await as.signToken({ sub: "u1", aud: AUDIENCE })
    const r = await postMcp(rig.url, token)
    expect([200, 202]).toContain(r.status)
  })
})
