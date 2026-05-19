/**
 * Integration tests for framework-agnostic HTTP handlers.
 *
 * Spins a real `http.createServer`, mounts `mcp`, `metadata`, `pats` from
 * `authkit.handlers(mcp)`, and exercises every documented route including
 * the §8.6 (PAT/static cannot manage PATs) gate and DNS-rebinding checks.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http"
import type { AddressInfo } from "node:net"
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { memoryTokenStore } from "mcp-authkit-store-memory"
import { afterAll, beforeAll, describe, expect, it } from "vitest"
import { createAuthKit } from "../authkit.js"
import { startTestAS, type TestAS } from "../test/fixtures/as.js"
import type { AuthKitConfig } from "../types.js"

// ---------------------------------------------------------------------------
// Test rig
// ---------------------------------------------------------------------------

interface Rig {
  url: string
  close: () => Promise<void>
}

interface RigOptions {
  readonly config: AuthKitConfig
  readonly registerEcho?: boolean
}

async function startRig(opts: RigOptions): Promise<Rig> {
  const authkit = createAuthKit(opts.config)
  const mcp = new McpServer({ name: "test", version: "0.0.1" })

  if (opts.registerEcho !== false) {
    authkit.registerTool(mcp, {
      name: "whoami",
      description: "returns auth.subject",
      inputSchema: {},
      requireScopes: ["read:data"],
      handler: async ({ auth }) => ({
        content: [{ type: "text" as const, text: auth.subject }],
      }),
    })
  }

  const h = authkit.handlers(mcp)

  const server: Server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    try {
      const url = req.url ?? "/"
      if (url.startsWith("/.well-known/oauth-protected-resource")) {
        await h.metadata(req, res)
        return
      }
      if (url.startsWith("/pats")) {
        // Strip the mount prefix so the handler sees relative URLs.
        const stripped = url.slice("/pats".length) || "/"
        req.url = stripped
        await h.pats(req, res)
        return
      }
      if (url.startsWith("/mcp")) {
        await h.mcp(req, res)
        return
      }
      res.writeHead(404)
      res.end()
    } catch (err) {
      if (!res.headersSent) {
        res.writeHead(500)
        res.end(String(err))
      }
    }
  })

  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve())
  })
  const { port } = server.address() as AddressInfo
  const url = `http://127.0.0.1:${port}`
  return {
    url,
    close: async () =>
      new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      ),
  }
}

// Tiny JSON fetch helper that returns status + headers + body.
async function http(
  method: string,
  url: string,
  init: { body?: unknown; headers?: Record<string, string> } = {},
): Promise<{ status: number; headers: Headers; body: string }> {
  const headers: Record<string, string> = { ...(init.headers ?? {}) }
  let body: string | undefined
  if (init.body !== undefined) {
    body = JSON.stringify(init.body)
    headers["Content-Type"] = headers["Content-Type"] ?? "application/json"
  }
  const res = await fetch(url, { method, headers, body })
  return { status: res.status, headers: res.headers, body: await res.text() }
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

const AUDIENCE = "https://mcp.example.test/"

describe("handlers integration", () => {
  let as: TestAS
  beforeAll(async () => {
    as = await startTestAS()
  })
  afterAll(async () => {
    await as.close()
  })

  function baseConfig(overrides: Partial<AuthKitConfig> = {}): AuthKitConfig {
    return {
      resourceIndicator: AUDIENCE,
      auth: {
        authorizationServer: { issuer: as.issuer, jwksUri: as.jwksUri },
        tokenStore: memoryTokenStore(),
        pat: { enabled: true, prefix: "mcp_pat_" },
      },
      scopes: { vocabulary: { "read:data": { description: "Read" } } },
      resolveUserScopes: async () => ["read:data"],
      // Disable host validation in tests; covered by a dedicated case below.
      http: { allowedHosts: [] },
      ...overrides,
    }
  }

  it("metadata: serves RFC 9728 document on GET", async () => {
    const rig = await startRig({ config: baseConfig() })
    try {
      const r = await http("GET", `${rig.url}/.well-known/oauth-protected-resource`)
      expect(r.status).toBe(200)
      const doc = JSON.parse(r.body)
      expect(doc.resource).toBe(AUDIENCE)
      expect(doc.bearer_methods_supported).toEqual(["header"])
      expect(doc.scopes_supported).toContain("read:data")
      expect(doc.authorization_servers).toEqual([as.issuer])
    } finally {
      await rig.close()
    }
  })

  it("mcp: 401 with WWW-Authenticate when no token", async () => {
    const rig = await startRig({ config: baseConfig() })
    try {
      const r = await http("POST", `${rig.url}/mcp`, { body: { jsonrpc: "2.0" } })
      expect(r.status).toBe(401)
      const challenge = r.headers.get("www-authenticate") ?? ""
      expect(challenge).toMatch(/^Bearer /)
      expect(challenge).toContain('resource_metadata="')
      expect(challenge).toContain(".well-known/oauth-protected-resource")
    } finally {
      await rig.close()
    }
  })

  it("mcp: 401 with error=invalid_token when bearer is present but bad", async () => {
    const rig = await startRig({ config: baseConfig() })
    try {
      const r = await http("POST", `${rig.url}/mcp`, {
        body: { jsonrpc: "2.0" },
        headers: { authorization: "Bearer not-a-real-token" },
      })
      expect(r.status).toBe(401)
      expect(r.headers.get("www-authenticate") ?? "").toContain('error="invalid_token"')
    } finally {
      await rig.close()
    }
  })

  it("mcp: forged Host returns 403 (DNS rebinding mitigation)", async () => {
    const rig = await startRig({
      config: baseConfig({ http: { allowedHosts: ["api.example.com"] } }),
    })
    try {
      // Real connection goes to 127.0.0.1; the SDK fetch sends Host=127.0.0.1:port.
      const r = await http("POST", `${rig.url}/mcp`, { body: { jsonrpc: "2.0" } })
      expect(r.status).toBe(403)
    } finally {
      await rig.close()
    }
  })

  // -------------------------------------------------------------------------
  // PAT lifecycle over HTTP with JWT-authenticated caller
  // -------------------------------------------------------------------------

  it("pats: full mint → list → rotate → revoke lifecycle with JWT auth", async () => {
    const store = memoryTokenStore()
    const rig = await startRig({
      config: baseConfig({
        auth: {
          authorizationServer: { issuer: as.issuer, jwksUri: as.jwksUri },
          tokenStore: store,
          pat: { enabled: true, prefix: "mcp_pat_" },
        },
      }),
    })
    try {
      const jwt = await as.signToken({ sub: "alice", aud: AUDIENCE, scope: "read:data" })
      const authH = { authorization: `Bearer ${jwt}` }

      // POST /pats → 201 with token + pat
      const mint = await http("POST", `${rig.url}/pats`, {
        headers: authH,
        body: { name: "my-token", scopes: ["read:data"], expiresInDays: 30 },
      })
      expect(mint.status).toBe(201)
      const mintBody = JSON.parse(mint.body)
      expect(typeof mintBody.token).toBe("string")
      expect(mintBody.token).toMatch(/^mcp_pat_/)
      expect(mintBody.pat.id).toBeDefined()
      const patId = mintBody.pat.id

      // GET /pats → 200 with list containing the new pat
      const list = await http("GET", `${rig.url}/pats`, { headers: authH })
      expect(list.status).toBe(200)
      const listBody = JSON.parse(list.body)
      expect(listBody.pats.some((p: { id: string }) => p.id === patId)).toBe(true)

      // POST /pats/:id/rotate → new token
      const rot = await http("POST", `${rig.url}/pats/${patId}/rotate`, { headers: authH })
      expect(rot.status).toBe(200)
      const rotBody = JSON.parse(rot.body)
      expect(rotBody.token).not.toBe(mintBody.token)

      // DELETE /pats/:id (the rotated-out one is gone; revoke the new one)
      const newId = rotBody.pat.id
      const del = await http("DELETE", `${rig.url}/pats/${newId}`, { headers: authH })
      expect(del.status).toBe(204)
    } finally {
      await rig.close()
    }
  })

  it("pats POST: rejects malformed body with 400", async () => {
    const rig = await startRig({ config: baseConfig() })
    try {
      const jwt = await as.signToken({ sub: "alice", aud: AUDIENCE })
      const r = await http("POST", `${rig.url}/pats`, {
        headers: { authorization: `Bearer ${jwt}` },
        body: { name: "" }, // missing scopes
      })
      expect(r.status).toBe(400)
    } finally {
      await rig.close()
    }
  })

  it("pats POST: rejects out-of-range expiresInDays with 400", async () => {
    const rig = await startRig({ config: baseConfig() })
    try {
      const jwt = await as.signToken({ sub: "alice", aud: AUDIENCE })
      const r = await http("POST", `${rig.url}/pats`, {
        headers: { authorization: `Bearer ${jwt}` },
        body: { name: "t", scopes: ["read:data"], expiresInDays: 999999 },
      })
      expect(r.status).toBe(400)
      expect(JSON.parse(r.body).error).toBe("expiry_out_of_range")
    } finally {
      await rig.close()
    }
  })

  it("pats DELETE: cross-user returns 404 (no leak)", async () => {
    const store = memoryTokenStore()
    const rig = await startRig({
      config: baseConfig({
        auth: {
          authorizationServer: { issuer: as.issuer, jwksUri: as.jwksUri },
          tokenStore: store,
          pat: { enabled: true, prefix: "mcp_pat_" },
        },
      }),
    })
    try {
      // Alice mints a PAT
      const aliceJwt = await as.signToken({ sub: "alice", aud: AUDIENCE })
      const mint = await http("POST", `${rig.url}/pats`, {
        headers: { authorization: `Bearer ${aliceJwt}` },
        body: { name: "t", scopes: ["read:data"], expiresInDays: 30 },
      })
      const patId = JSON.parse(mint.body).pat.id

      // Bob tries to delete it
      const bobJwt = await as.signToken({ sub: "bob", aud: AUDIENCE })
      const del = await http("DELETE", `${rig.url}/pats/${patId}`, {
        headers: { authorization: `Bearer ${bobJwt}` },
      })
      expect(del.status).toBe(404)
    } finally {
      await rig.close()
    }
  })

  // -------------------------------------------------------------------------
  // Security: §8.6 PAT cannot manage PATs
  // -------------------------------------------------------------------------

  it("pats: PAT-authenticated request returns 403 (§8.6)", async () => {
    const store = memoryTokenStore()
    const rig = await startRig({
      config: baseConfig({
        auth: {
          authorizationServer: { issuer: as.issuer, jwksUri: as.jwksUri },
          tokenStore: store,
          pat: { enabled: true, prefix: "mcp_pat_" },
        },
      }),
    })
    try {
      const jwt = await as.signToken({ sub: "alice", aud: AUDIENCE })
      const mint = await http("POST", `${rig.url}/pats`, {
        headers: { authorization: `Bearer ${jwt}` },
        body: { name: "t", scopes: ["read:data"], expiresInDays: 30 },
      })
      const patToken = JSON.parse(mint.body).token as string

      // Use the PAT to attempt list /pats
      const listAttempt = await http("GET", `${rig.url}/pats`, {
        headers: { authorization: `Bearer ${patToken}` },
      })
      expect(listAttempt.status).toBe(403)
      expect(JSON.parse(listAttempt.body).error).toBe("forbidden")

      // Also mint attempt
      const mintAttempt = await http("POST", `${rig.url}/pats`, {
        headers: { authorization: `Bearer ${patToken}` },
        body: { name: "sibling", scopes: ["read:data"] },
      })
      expect(mintAttempt.status).toBe(403)
    } finally {
      await rig.close()
    }
  })

  it("pats: static-token-authenticated request returns 403 (§8.6)", async () => {
    const rig = await startRig({
      config: baseConfig({
        auth: {
          authorizationServer: { issuer: as.issuer, jwksUri: as.jwksUri },
          tokenStore: memoryTokenStore(),
          pat: { enabled: true, prefix: "mcp_pat_" },
          staticToken: { token: "ci-secret", user: "ci-bot", scopes: ["read:data"] },
        },
      }),
    })
    try {
      const r = await http("GET", `${rig.url}/pats`, {
        headers: { authorization: "Bearer ci-secret" },
      })
      expect(r.status).toBe(403)
    } finally {
      await rig.close()
    }
  })

  // -------------------------------------------------------------------------
  // Method routing
  // -------------------------------------------------------------------------

  it("pats: unknown method on collection returns 405", async () => {
    const rig = await startRig({ config: baseConfig() })
    try {
      const jwt = await as.signToken({ sub: "alice", aud: AUDIENCE })
      const r = await http("PUT", `${rig.url}/pats`, {
        headers: { authorization: `Bearer ${jwt}` },
      })
      expect(r.status).toBe(405)
      expect(r.headers.get("allow")).toBeTruthy()
    } finally {
      await rig.close()
    }
  })

  // -------------------------------------------------------------------------
  // mcp: auth context flows into tool handler
  // -------------------------------------------------------------------------

  it("mcp: auth context from JWT is reachable inside tool handler", async () => {
    const rig = await startRig({ config: baseConfig() })
    try {
      const jwt = await as.signToken({ sub: "carol", aud: AUDIENCE, scope: "read:data" })

      // 1) initialize
      const init = await http("POST", `${rig.url}/mcp`, {
        headers: {
          authorization: `Bearer ${jwt}`,
          accept: "application/json, text/event-stream",
        },
        body: {
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: "2025-06-18",
            capabilities: {},
            clientInfo: { name: "test", version: "0" },
          },
        },
      })
      expect(init.status).toBe(200)
      const sessionId = init.headers.get("mcp-session-id")
      expect(sessionId).toBeTruthy()
      const sessionHeaders = {
        authorization: `Bearer ${jwt}`,
        accept: "application/json, text/event-stream",
        "mcp-session-id": sessionId ?? "",
      }

      // notifications/initialized — required between initialize and any further calls
      await http("POST", `${rig.url}/mcp`, {
        headers: sessionHeaders,
        body: { jsonrpc: "2.0", method: "notifications/initialized" },
      })

      // 2) call the whoami tool
      const call = await http("POST", `${rig.url}/mcp`, {
        headers: sessionHeaders,
        body: {
          jsonrpc: "2.0",
          id: 2,
          method: "tools/call",
          params: { name: "whoami", arguments: {} },
        },
      })
      expect(call.status).toBe(200)
      // Body is either JSON or SSE; both contain the subject.
      expect(call.body).toContain("carol")
    } finally {
      await rig.close()
    }
  })
})
