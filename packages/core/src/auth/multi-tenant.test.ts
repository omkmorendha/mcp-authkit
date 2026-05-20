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
