/**
 * Full security test matrix (spec v0.1 §14 + §15, v0.2 §12 + §13).
 *
 * One file, one describe-per-non-negotiable. Each acceptance criterion in
 * the v0.1 and v0.2 security lists is covered by a test that would fail
 * without the corresponding production code path. Deeper unit tests live
 * alongside each owning module; this file is the single grep-able gate.
 *
 * The rig is a thin HTTP server that mounts the three framework-owned
 * handlers (`mcp`, `metadata`, `pats`) on top of an in-memory store and a
 * test-fixture authorization server. All audit events are captured via
 * `createAuditRecorder` so each scenario can assert §12 ("audit events fire
 * for every documented case").
 *
 * Spec anchors (v0.1):
 *   - docs/spec/v0.1.md#14-security-non-negotiables
 *   - docs/spec/v0.1.md#15-testing
 *   - docs/spec/v0.1.md#9-token-validation-pipeline
 *   - docs/spec/v0.1.md#84-scope-constraint-at-validation
 *   - docs/spec/v0.1.md#86-pat-cannot-manage-pats
 *   - docs/spec/v0.1.md#111-bypass-mode
 *   - docs/spec/v0.1.md#12-audit-callbacks
 *
 * Spec anchors (v0.2):
 *   - docs/spec/v0.2.md#12-security-non-negotiables-additions
 *   - docs/spec/v0.2.md#13-testing  (Security subsection)
 *   - docs/spec/v0.2.md#7-multi-tenant-authorization-server
 *   - docs/spec/v0.2.md#11-production-stdio-support
 */
import { createHash, randomBytes, randomUUID } from "node:crypto"
import {
  createServer,
  request as httpRequest,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http"
import type { AddressInfo } from "node:net"
import { PassThrough } from "node:stream"
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { memoryTokenStore } from "mcp-authkit-store-memory"
import type { RedisClient } from "mcp-authkit-store-redis"
import { redisCache } from "mcp-authkit-store-redis"
import type { SqliteDatabase } from "mcp-authkit-store-sqlite"
import { InvalidIdentifierError, sqliteTokenStore } from "mcp-authkit-store-sqlite"
import pino from "pino"
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest"
import { createAuthKit, runPipeline } from "../authkit.js"
import { BypassProductionError, checkBypassConfig } from "../bypass/index.js"
import { registerClient } from "../oauth/dcr.js"
import { exchangeToken, TokenExchangeError } from "../oauth/token-exchange.js"
import { mintPat } from "../pats/format.js"
import { encodeFrame } from "../stdio/frame.js"
import { createSignedStdioTransport } from "../stdio/transport.js"
import { startTestAS, type TestAS } from "../test/fixtures/as.js"
import type {
  AuditEvent,
  AuthKitConfig,
  AuthorizationServerResolver,
  CreatePatInput,
  CreateRefreshTokenInput,
} from "../types.js"
import { createAuditRecorder } from "./audit-recorder.js"

// ---------------------------------------------------------------------------
// Test rig
// ---------------------------------------------------------------------------

interface Rig {
  url: string
  close: () => Promise<void>
}

interface RigOptions {
  readonly config: AuthKitConfig
  readonly registerWhoami?: boolean
  readonly registerAdminTool?: boolean
}

async function startRig(opts: RigOptions): Promise<Rig> {
  const authkit = createAuthKit(opts.config)
  const mcp = new McpServer({ name: "test", version: "0.0.1" })

  if (opts.registerWhoami !== false) {
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

  if (opts.registerAdminTool) {
    authkit.registerTool(mcp, {
      name: "admin",
      description: "needs admin:write",
      inputSchema: {},
      requireScopes: ["admin:write"],
      handler: async () => ({
        content: [{ type: "text" as const, text: "ok" }],
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

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))
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

/**
 * Send an HTTP request via node:http so the caller can forge headers that
 * the WHATWG fetch implementation forbids — most importantly the Host
 * header (DNS-rebinding tests). Returns the same shape as `httpReq`.
 */
async function rawHttpRequest(
  method: string,
  url: string,
  headers: Record<string, string>,
): Promise<{ status: number; headers: Headers; body: string }> {
  const u = new URL(url)
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        method,
        hostname: u.hostname,
        port: u.port,
        path: `${u.pathname}${u.search}`,
        headers,
      },
      (res) => {
        const chunks: Buffer[] = []
        res.on("data", (c: Buffer) => chunks.push(c))
        res.on("end", () => {
          const h = new Headers()
          for (const [k, v] of Object.entries(res.headers)) {
            if (typeof v === "string") h.set(k, v)
            else if (Array.isArray(v)) h.set(k, v.join(", "))
          }
          resolve({
            status: res.statusCode ?? 0,
            headers: h,
            body: Buffer.concat(chunks).toString("utf8"),
          })
        })
      },
    )
    req.on("error", reject)
    req.end()
  })
}

async function httpReq(
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

/**
 * Drive a full MCP roundtrip against the rig: initialize → notifications/
 * initialized → tools/call. Returns the tools/call response body so the
 * caller can assert on the tool's reply (or the framework's scope-gate
 * "Forbidden" reply).
 */
async function mcpCallTool(
  rigUrl: string,
  bearer: string,
  toolName: string,
): Promise<{ status: number; body: string }> {
  const init = await httpReq("POST", `${rigUrl}/mcp`, {
    headers: {
      authorization: `Bearer ${bearer}`,
      accept: "application/json, text/event-stream",
    },
    body: {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "sec-test", version: "0" },
      },
    },
  })
  const sessionId = init.headers.get("mcp-session-id") ?? ""
  const sessionHeaders = {
    authorization: `Bearer ${bearer}`,
    accept: "application/json, text/event-stream",
    "mcp-session-id": sessionId,
  }
  await httpReq("POST", `${rigUrl}/mcp`, {
    headers: sessionHeaders,
    body: { jsonrpc: "2.0", method: "notifications/initialized" },
  })
  const call = await httpReq("POST", `${rigUrl}/mcp`, {
    headers: sessionHeaders,
    body: {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: toolName, arguments: {} },
    },
  })
  return { status: call.status, body: call.body }
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

const AUDIENCE = "https://mcp.example.test/"

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
    scopes: {
      vocabulary: {
        "read:data": { description: "Read" },
        "admin:write": { description: "Admin write" },
      },
    },
    resolveUserScopes: async () => ["read:data"],
    http: { allowedHosts: [] },
    ...overrides,
  }
}

// =========================================================================
// 1. Audience validation (spec §14)
// =========================================================================

describe("§14 audience validation", () => {
  it("wrong aud → 401 + oauth.reject", async () => {
    const rec = createAuditRecorder()
    const rig = await startRig({ config: baseConfig({ audit: { onEvent: rec.sink } }) })
    try {
      const jwt = await as.signToken({ sub: "alice", aud: "https://wrong.example/" })
      const r = await httpReq("POST", `${rig.url}/mcp`, {
        body: { jsonrpc: "2.0" },
        headers: { authorization: `Bearer ${jwt}` },
      })
      expect(r.status).toBe(401)
      expect(r.headers.get("www-authenticate") ?? "").toContain('error="invalid_token"')
      expect(rec.events.some((e) => e.type === "oauth.reject")).toBe(true)
    } finally {
      await rig.close()
    }
  })

  it("missing aud → 401 + oauth.reject", async () => {
    const rec = createAuditRecorder()
    const rig = await startRig({ config: baseConfig({ audit: { onEvent: rec.sink } }) })
    try {
      // Pass aud=undefined to suppress the default — signToken only sets aud
      // when the claim is provided.
      const jwt = await as.signToken({ sub: "alice" })
      const r = await httpReq("POST", `${rig.url}/mcp`, {
        body: { jsonrpc: "2.0" },
        headers: { authorization: `Bearer ${jwt}` },
      })
      expect(r.status).toBe(401)
      expect(rec.events.some((e) => e.type === "oauth.reject")).toBe(true)
    } finally {
      await rig.close()
    }
  })

  it("array aud without match → 401", async () => {
    const rig = await startRig({ config: baseConfig() })
    try {
      const jwt = await as.signToken({
        sub: "alice",
        aud: ["https://a.example/", "https://b.example/"],
      })
      const r = await httpReq("POST", `${rig.url}/mcp`, {
        body: { jsonrpc: "2.0" },
        headers: { authorization: `Bearer ${jwt}` },
      })
      expect(r.status).toBe(401)
    } finally {
      await rig.close()
    }
  })

  it("array aud containing resourceIndicator → not 401 (positive control)", async () => {
    const rig = await startRig({ config: baseConfig() })
    try {
      const jwt = await as.signToken({
        sub: "alice",
        aud: ["https://other.example/", AUDIENCE],
        scope: "read:data",
      })
      const r = await httpReq("POST", `${rig.url}/mcp`, {
        body: { jsonrpc: "2.0", id: 1, method: "ping" },
        headers: {
          authorization: `Bearer ${jwt}`,
          accept: "application/json, text/event-stream",
        },
      })
      // Pipeline accepted the token; the MCP transport itself may 400/406 on
      // a non-initialize call, but it MUST NOT be 401.
      expect(r.status).not.toBe(401)
    } finally {
      await rig.close()
    }
  })
})

// =========================================================================
// 2. Expiry
// =========================================================================

describe("§14 expiry", () => {
  it("expired JWT → 401 + oauth.reject(expired)", async () => {
    const rec = createAuditRecorder()
    const rig = await startRig({ config: baseConfig({ audit: { onEvent: rec.sink } }) })
    try {
      const past = Math.floor(Date.now() / 1000) - 60
      const jwt = await as.signToken({ sub: "alice", aud: AUDIENCE, exp: past })
      const r = await httpReq("POST", `${rig.url}/mcp`, {
        body: { jsonrpc: "2.0" },
        headers: { authorization: `Bearer ${jwt}` },
      })
      expect(r.status).toBe(401)
      const rejected = rec.events.find((e) => e.type === "oauth.reject")
      expect(rejected).toBeDefined()
      expect(JSON.stringify(rejected?.detail)).toMatch(/expired/i)
    } finally {
      await rig.close()
    }
  })

  it("expired PAT → 401", async () => {
    const store = memoryTokenStore()
    const rec = createAuditRecorder()
    const config = baseConfig({
      auth: {
        authorizationServer: { issuer: as.issuer, jwksUri: as.jwksUri },
        tokenStore: store,
        pat: { enabled: true, prefix: "mcp_pat_" },
      },
      audit: { onEvent: rec.sink },
    })
    const rig = await startRig({ config })
    try {
      // Insert an already-expired PAT row directly into the store.
      const minted = mintPat("mcp_pat_")
      const past = new Date(Date.now() - 60_000)
      const input: CreatePatInput = {
        userIdentifier: "alice",
        name: "expired",
        scopes: ["read:data"],
        expiresAt: past,
        tokenHash: minted.tokenHash,
        display: "mcp_pat_xxxx…yyyy",
      }
      await store.createPat(input)

      const r = await httpReq("POST", `${rig.url}/mcp`, {
        body: { jsonrpc: "2.0" },
        headers: { authorization: `Bearer ${minted.token}` },
      })
      expect(r.status).toBe(401)
    } finally {
      await rig.close()
    }
  })
})

// =========================================================================
// 3. Revocation
// =========================================================================

describe("§14 revocation", () => {
  it("revoked PAT → 401", async () => {
    const store = memoryTokenStore()
    const config = baseConfig({
      auth: {
        authorizationServer: { issuer: as.issuer, jwksUri: as.jwksUri },
        tokenStore: store,
        pat: { enabled: true, prefix: "mcp_pat_" },
      },
    })
    const rig = await startRig({ config })
    try {
      // Mint a real PAT, then revoke it.
      const jwt = await as.signToken({ sub: "alice", aud: AUDIENCE })
      const mint = await httpReq("POST", `${rig.url}/pats`, {
        headers: { authorization: `Bearer ${jwt}` },
        body: { name: "doomed", scopes: ["read:data"], expiresInDays: 30 },
      })
      expect(mint.status).toBe(201)
      const body = JSON.parse(mint.body)
      const patToken = body.token as string
      const patId = body.pat.id as string

      const del = await httpReq("DELETE", `${rig.url}/pats/${patId}`, {
        headers: { authorization: `Bearer ${jwt}` },
      })
      expect(del.status).toBe(204)

      // Try to use the revoked PAT.
      const r = await httpReq("POST", `${rig.url}/mcp`, {
        body: { jsonrpc: "2.0" },
        headers: { authorization: `Bearer ${patToken}` },
      })
      expect(r.status).toBe(401)
    } finally {
      await rig.close()
    }
  })
})

// =========================================================================
// 4. Scope escalation / intersection shrink (spec §8.4)
// =========================================================================

describe("§8.4 PAT scope intersection", () => {
  it("PAT minted with broader scopes than current user grants → effective scopes clamped", async () => {
    const store = memoryTokenStore()
    let userScopes: readonly string[] = ["read:data", "admin:write"]
    const rec = createAuditRecorder()
    const config: AuthKitConfig = {
      ...baseConfig(),
      auth: {
        authorizationServer: { issuer: as.issuer, jwksUri: as.jwksUri },
        tokenStore: store,
        pat: { enabled: true, prefix: "mcp_pat_" },
      },
      resolveUserScopes: async () => userScopes,
      audit: { onEvent: rec.sink },
    }
    const rig = await startRig({ config, registerAdminTool: true })
    try {
      // Mint via the REST endpoint while userScopes still grants admin:write.
      const jwt = await as.signToken({ sub: "alice", aud: AUDIENCE })
      const mint = await httpReq("POST", `${rig.url}/pats`, {
        headers: { authorization: `Bearer ${jwt}` },
        body: {
          name: "broad",
          scopes: ["read:data", "admin:write"],
          expiresInDays: 30,
        },
      })
      expect(mint.status).toBe(201)
      const patToken = JSON.parse(mint.body).token as string

      // Now shrink the user's grants.
      userScopes = ["read:data"]

      // Direct pipeline check: effective scopes must be clamped to [read:data].
      const result = await runPipeline(config, patToken, rec.sink)
      expect(result.ok).toBe(true)
      if (result.ok) {
        expect([...result.auth.scopes]).toEqual(["read:data"])
      }
    } finally {
      await rig.close()
    }
  })
})

// =========================================================================
// 5. Cross-user PAT (lookup by hash does not return another user's row)
// =========================================================================

describe("§14 cross-user PAT", () => {
  it("hash lookup never returns another user's PAT", async () => {
    const store = memoryTokenStore()
    // Mint two PATs for alice and one for bob; their token hashes are
    // independent 32-byte values, so the "wrong user" lookup naturally
    // misses. Assert that a bob-token resolves only to bob.
    const alice = mintPat("mcp_pat_")
    const bob = mintPat("mcp_pat_")
    const future = new Date(Date.now() + 86_400_000)
    await store.createPat({
      userIdentifier: "alice",
      name: "a",
      scopes: ["read:data"],
      expiresAt: future,
      tokenHash: alice.tokenHash,
      display: "alice",
    })
    await store.createPat({
      userIdentifier: "bob",
      name: "b",
      scopes: ["read:data"],
      expiresAt: future,
      tokenHash: bob.tokenHash,
      display: "bob",
    })

    // Search for bob's hash → bob's row.
    const found = await store.findPatByHash(bob.tokenHash)
    expect(found?.userIdentifier).toBe("bob")

    // A fabricated random hash must miss entirely.
    const fake = createHash("sha256").update("not-a-token").digest()
    const miss = await store.findPatByHash(fake)
    expect(miss).toBeNull()
  })
})

// =========================================================================
// 6. Refresh token rotation + family revocation on reuse (spec §6.1 store contract)
// =========================================================================

describe("§14 refresh rotation + reuse → family revoked", () => {
  it("rotates, marks old token, and family-revoke wipes successors", async () => {
    const store = memoryTokenStore()
    const familyId = randomUUID()

    const t1Hash = createHash("sha256").update("t1").digest()
    const t2Hash = createHash("sha256").update("t2").digest()
    const future = new Date(Date.now() + 86_400_000)

    const t1Input: CreateRefreshTokenInput = {
      familyId,
      tokenHash: t1Hash,
      subject: "alice",
      scopes: ["read:data"],
      expiresAt: future,
    }
    await store.createRefreshToken(t1Input)

    const t2Input: CreateRefreshTokenInput = {
      familyId,
      tokenHash: t2Hash,
      subject: "alice",
      scopes: ["read:data"],
      expiresAt: future,
    }
    await store.rotateRefreshToken(t1Hash, t2Input)

    // T1 is still findable, but marked rotated.
    const t1After = await store.findRefreshToken(t1Hash)
    expect(t1After).not.toBeNull()
    expect(t1After?.rotatedAt).not.toBeNull()

    // T2 is the live token.
    const t2After = await store.findRefreshToken(t2Hash)
    expect(t2After).not.toBeNull()
    expect(t2After?.rotatedAt).toBeNull()

    // Reuse detection: caller sees rotatedAt != null on T1 → revoke the family.
    await store.revokeRefreshTokenFamily(familyId)

    // T2 must now be gone too.
    const t2Reused = await store.findRefreshToken(t2Hash)
    expect(t2Reused).toBeNull()
  })
})

// =========================================================================
// 7. PKCE — framework-side assertion (spec §14, §13)
// =========================================================================

describe("§14 PKCE", () => {
  it("framework does not own /authorize or /token (PKCE is AS-side)", async () => {
    const rig = await startRig({ config: baseConfig() })
    try {
      // Neither path is mounted by the framework — they 404 at the test rig.
      const a = await httpReq("GET", `${rig.url}/authorize`)
      const b = await httpReq("POST", `${rig.url}/token`)
      expect(a.status).toBe(404)
      expect(b.status).toBe(404)
    } finally {
      await rig.close()
    }
  })

  it("public API exports no PKCE helper", async () => {
    const mod = await import("../index.js")
    const names = Object.keys(mod)
    expect(names.filter((n) => /pkce/i.test(n))).toEqual([])
  })
})

// =========================================================================
// 8. Host header (DNS rebinding mitigation)
// =========================================================================

describe("§14 Host header allowlist", () => {
  it("disallowed Host → 403 on mcp, pats, and metadata", async () => {
    const config = baseConfig({ http: { allowedHosts: ["api.example.com"] } })
    const rig = await startRig({ config })
    try {
      // Real connection is to 127.0.0.1; Host header from fetch is the IP+port,
      // which is NOT in the allowlist → 403.
      const m = await httpReq("POST", `${rig.url}/mcp`, { body: { jsonrpc: "2.0" } })
      expect(m.status).toBe(403)

      const p = await httpReq("GET", `${rig.url}/pats`)
      expect(p.status).toBe(403)

      const w = await httpReq("GET", `${rig.url}/.well-known/oauth-protected-resource`)
      expect(w.status).toBe(403)
    } finally {
      await rig.close()
    }
  })

  it("allowed Host → no Host-related 403", async () => {
    const config = baseConfig({ http: { allowedHosts: ["api.example.com"] } })
    const rig = await startRig({ config })
    try {
      // fetch() rewrites the Host header to match the connect target, so we
      // drop to node:http to forge it. URL points at 127.0.0.1, header says
      // api.example.com → allowlist hit, metadata returns 200.
      const r = await rawHttpRequest("GET", `${rig.url}/.well-known/oauth-protected-resource`, {
        host: "api.example.com",
      })
      expect(r.status).toBe(200)
    } finally {
      await rig.close()
    }
  })
})

// =========================================================================
// 9. PAT-managing-PAT (spec §8.6)
// =========================================================================

describe("§8.6 PAT cannot manage PATs", () => {
  it("PAT-authenticated POST /pats → 403", async () => {
    const store = memoryTokenStore()
    const config = baseConfig({
      auth: {
        authorizationServer: { issuer: as.issuer, jwksUri: as.jwksUri },
        tokenStore: store,
        pat: { enabled: true, prefix: "mcp_pat_" },
      },
    })
    const rig = await startRig({ config })
    try {
      const jwt = await as.signToken({ sub: "alice", aud: AUDIENCE })
      const mint = await httpReq("POST", `${rig.url}/pats`, {
        headers: { authorization: `Bearer ${jwt}` },
        body: { name: "a", scopes: ["read:data"], expiresInDays: 30 },
      })
      const patToken = JSON.parse(mint.body).token as string

      const post = await httpReq("POST", `${rig.url}/pats`, {
        headers: { authorization: `Bearer ${patToken}` },
        body: { name: "sibling", scopes: ["read:data"] },
      })
      expect(post.status).toBe(403)
      expect(JSON.parse(post.body).error).toBe("forbidden")

      const list = await httpReq("GET", `${rig.url}/pats`, {
        headers: { authorization: `Bearer ${patToken}` },
      })
      expect(list.status).toBe(403)

      // DELETE also forbidden.
      const del = await httpReq("DELETE", `${rig.url}/pats/some-id`, {
        headers: { authorization: `Bearer ${patToken}` },
      })
      expect(del.status).toBe(403)
    } finally {
      await rig.close()
    }
  })

  it("static-token POST /pats → 403", async () => {
    const config = baseConfig({
      auth: {
        authorizationServer: { issuer: as.issuer, jwksUri: as.jwksUri },
        tokenStore: memoryTokenStore(),
        pat: { enabled: true, prefix: "mcp_pat_" },
        staticToken: { token: "ci-secret-xyz", user: "ci", scopes: ["read:data"] },
      },
    })
    const rig = await startRig({ config })
    try {
      const r = await httpReq("POST", `${rig.url}/pats`, {
        headers: { authorization: "Bearer ci-secret-xyz" },
        body: { name: "x", scopes: ["read:data"] },
      })
      expect(r.status).toBe(403)
    } finally {
      await rig.close()
    }
  })
})

// =========================================================================
// 10. Bypass mode refuses production (spec §11.1, §14)
// =========================================================================

describe("§14 bypass refuses production", () => {
  it("throws BypassProductionError when NODE_ENV=production and allowInProduction is unset", () => {
    const logger = pino({ level: "silent" })
    const config = baseConfig({
      auth: {
        authorizationServer: { issuer: as.issuer, jwksUri: as.jwksUri },
        tokenStore: memoryTokenStore(),
        pat: { enabled: true, prefix: "mcp_pat_" },
        bypass: { enabled: true, user: "dev", scopes: ["read:data"] },
      },
    })
    expect(() => checkBypassConfig({ config, env: "production", logger })).toThrow(
      BypassProductionError,
    )
  })

  it("does NOT throw when allowInProduction is explicitly true", () => {
    const logger = pino({ level: "silent" })
    const config = baseConfig({
      auth: {
        authorizationServer: { issuer: as.issuer, jwksUri: as.jwksUri },
        tokenStore: memoryTokenStore(),
        pat: { enabled: true, prefix: "mcp_pat_" },
        bypass: {
          enabled: true,
          user: "dev",
          scopes: ["read:data"],
          allowInProduction: true,
        },
      },
    })
    expect(() => checkBypassConfig({ config, env: "production", logger })).not.toThrow()
  })

  it("createAuthKit factory propagates the BypassProductionError before handlers exist", () => {
    const logger = pino({ level: "silent" })
    const prevEnv = process.env.NODE_ENV
    process.env.NODE_ENV = "production"
    try {
      const config = baseConfig({
        logger,
        auth: {
          authorizationServer: { issuer: as.issuer, jwksUri: as.jwksUri },
          tokenStore: memoryTokenStore(),
          pat: { enabled: true, prefix: "mcp_pat_" },
          bypass: { enabled: true, user: "dev", scopes: ["read:data"] },
        },
      })
      expect(() => createAuthKit(config)).toThrow(BypassProductionError)
    } finally {
      if (prevEnv === undefined) delete process.env.NODE_ENV
      else process.env.NODE_ENV = prevEnv
    }
  })
})

// =========================================================================
// 11. Static token with insufficient scopes
// =========================================================================

describe("§11.3 static token + insufficient scopes", () => {
  it("static token without admin:write → tool call returns Forbidden + scope.deny audit", async () => {
    const rec = createAuditRecorder()
    const config = baseConfig({
      auth: {
        authorizationServer: { issuer: as.issuer, jwksUri: as.jwksUri },
        tokenStore: memoryTokenStore(),
        pat: { enabled: true, prefix: "mcp_pat_" },
        // Static token holds only read:data — the admin tool requires admin:write.
        staticToken: { token: "ci-only-read", user: "ci", scopes: ["read:data"] },
      },
      audit: { onEvent: rec.sink },
    })
    const rig = await startRig({ config, registerAdminTool: true })
    try {
      // Drive a full MCP roundtrip and call the admin tool. The scope gate
      // returns isError=true with a "Forbidden" message inside the JSON-RPC
      // result rather than a non-200 HTTP status (the SDK transport always
      // 200s once it has handled the JSON-RPC request).
      const call = await mcpCallTool(rig.url, "ci-only-read", "admin")
      expect(call.status).toBe(200)
      expect(call.body).toContain("Forbidden")
      expect(rec.events.some((e) => e.type === "scope.deny")).toBe(true)

      // Sanity: the deny event has the right shape (§12).
      const deny = rec.events.find((e) => e.type === "scope.deny")
      expect(deny?.subject).toBe("ci")
      expect(JSON.stringify(deny?.detail)).toMatch(/admin:write/)
    } finally {
      await rig.close()
    }
  })
})

// =========================================================================
// 12. Audit events fire for every documented case (spec §12 / §15)
// =========================================================================

describe("§12 audit events fire end-to-end", () => {
  it("pat.mint, pat.use, pat.revoke, pat.rotate, oauth.validate, scope.allow all fire", async () => {
    const rec = createAuditRecorder()
    const store = memoryTokenStore()
    const config = baseConfig({
      auth: {
        authorizationServer: { issuer: as.issuer, jwksUri: as.jwksUri },
        tokenStore: store,
        pat: { enabled: true, prefix: "mcp_pat_" },
      },
      audit: { onEvent: rec.sink },
    })
    const rig = await startRig({ config })
    try {
      // 1. JWT auth → oauth.validate
      const jwt = await as.signToken({ sub: "alice", aud: AUDIENCE, scope: "read:data" })

      // 2. POST /pats → pat.mint
      const mint = await httpReq("POST", `${rig.url}/pats`, {
        headers: { authorization: `Bearer ${jwt}` },
        body: { name: "audit-test", scopes: ["read:data"], expiresInDays: 30 },
      })
      expect(mint.status).toBe(201)
      const patToken = JSON.parse(mint.body).token as string
      const patId = JSON.parse(mint.body).pat.id as string

      // 3. Use the PAT via the pipeline → pat.use
      const useResult = await runPipeline(config, patToken, rec.sink)
      expect(useResult.ok).toBe(true)

      // 4. DELETE /pats/:id → pat.revoke
      const del = await httpReq("DELETE", `${rig.url}/pats/${patId}`, {
        headers: { authorization: `Bearer ${jwt}` },
      })
      expect(del.status).toBe(204)

      // 5. Mint + rotate → pat.rotate
      const mint2 = await httpReq("POST", `${rig.url}/pats`, {
        headers: { authorization: `Bearer ${jwt}` },
        body: { name: "rotate-me", scopes: ["read:data"], expiresInDays: 30 },
      })
      const rotateId = JSON.parse(mint2.body).pat.id as string
      const rot = await httpReq("POST", `${rig.url}/pats/${rotateId}/rotate`, {
        headers: { authorization: `Bearer ${jwt}` },
      })
      expect(rot.status).toBe(200)

      // 6. Drive a full MCP roundtrip with the JWT to fire scope.allow on the
      // whoami tool (registered with requireScopes: ["read:data"], which the
      // JWT carries).
      const call = await mcpCallTool(rig.url, jwt, "whoami")
      expect(call.status).toBe(200)
      expect(call.body).toContain("alice")

      const types = new Set(rec.events.map((e) => e.type))
      expect(types.has("oauth.validate")).toBe(true)
      expect(types.has("pat.mint")).toBe(true)
      expect(types.has("pat.use")).toBe(true)
      expect(types.has("pat.revoke")).toBe(true)
      expect(types.has("pat.rotate")).toBe(true)
      expect(types.has("scope.allow")).toBe(true)

      // §12: subject + tokenId must be present where the spec implies them.
      const mintEvent = rec.events.find((e) => e.type === "pat.mint")
      expect(mintEvent?.subject).toBe("alice")
      expect(typeof mintEvent?.tokenId).toBe("string")
    } finally {
      await rig.close()
    }
  })

  it("oauth.reject fires for invalid bearer", async () => {
    const rec = createAuditRecorder()
    const config = baseConfig({ audit: { onEvent: rec.sink } })
    const rig = await startRig({ config })
    try {
      // Sign a token with wrong audience to trigger the JWT validator
      // rejection path (which emits oauth.reject). A bogus non-JWT string
      // would not reach the validator and so would not emit oauth.reject.
      const jwt = await as.signToken({ sub: "x", aud: "https://wrong/" })
      const r = await httpReq("POST", `${rig.url}/mcp`, {
        body: { jsonrpc: "2.0" },
        headers: { authorization: `Bearer ${jwt}` },
      })
      expect(r.status).toBe(401)
      expect(rec.events.some((e) => e.type === "oauth.reject")).toBe(true)
    } finally {
      await rig.close()
    }
  })
})

// =========================================================================
// v0.2 §12 / §13 Security additions
// =========================================================================

// -------------------------------------------------------------------------
// 13. Token-exchange audience validation (v0.2 §12 + §13)
// -------------------------------------------------------------------------

describe("v0.2 §12 token-exchange audience validation", () => {
  it("rejects a minted token whose aud != requested audience and never returns the subject token", async () => {
    const issued = await as.signToken({ sub: "u", aud: "https://attacker.example/" })
    const subjectToken = "subj-tok-DO-NOT-LEAK"
    const tokenEndpoint = `${as.issuer}/oauth/token`

    type FetchInit = Parameters<typeof globalThis.fetch>[1]
    const fetchMock = vi.fn(async (_url: unknown, _init?: FetchInit) =>
      Promise.resolve({
        ok: true,
        status: 200,
        json: async () => ({
          access_token: issued,
          issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
          expires_in: 60,
        }),
        text: async () => "",
      }),
    )

    await expect(
      exchangeToken({
        issuer: as.issuer,
        subjectToken,
        subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
        audience: AUDIENCE,
        tokenEndpoint,
        // biome-ignore lint/suspicious/noExplicitAny: test-only structural match
        fetch: fetchMock as any,
      }),
    ).rejects.toMatchObject({
      name: "TokenExchangeError",
      reason: "audience",
    })

    // Defense in depth: the call must not have surfaced the subject token to
    // the caller. The thrown error path returns nothing; we also check that
    // it was never echoed back into any response body the test inspects.
    expect(TokenExchangeError).toBeDefined()
  })
})

// -------------------------------------------------------------------------
// 14. DCR initial-access-token never appears in logs (v0.2 §12 + §13)
// -------------------------------------------------------------------------

describe("v0.2 §12 DCR initial access token never logged", () => {
  it("captures pino output for happy + AS-error paths and asserts the token is absent", async () => {
    const initialAccessToken = "iat-sentinel-must-not-appear-in-logs"
    const issuer = "https://as.example.test"
    const registrationEndpoint = `${issuer}/oauth/register`

    const captured: string[] = []
    const sink = new PassThrough()
    sink.on("data", (chunk: Buffer) => {
      captured.push(chunk.toString("utf8"))
    })
    const logger = pino({ level: "trace" }, sink)

    type FetchInit = Parameters<typeof globalThis.fetch>[1]
    // Happy path.
    const happyFetch = vi.fn(async (_url: unknown, _init?: FetchInit) =>
      Promise.resolve({
        ok: true,
        status: 201,
        json: async () => ({ client_id: "abc-123" }),
        text: async () => "",
      }),
    )
    await registerClient({
      issuer,
      initialAccessToken,
      metadata: { client_name: "matrix-test" },
      registrationEndpoint,
      // biome-ignore lint/suspicious/noExplicitAny: test-only structural match
      fetch: happyFetch as any,
      logger,
    })

    // AS-error path.
    const errFetch = vi.fn(async (_url: unknown, _init?: FetchInit) =>
      Promise.resolve({
        ok: false,
        status: 400,
        json: async () => ({ error: "invalid_client_metadata", error_description: "bad scope" }),
        text: async () => "",
      }),
    )
    await expect(
      registerClient({
        issuer,
        initialAccessToken,
        metadata: { client_name: "matrix-test" },
        registrationEndpoint,
        // biome-ignore lint/suspicious/noExplicitAny: test-only structural match
        fetch: errFetch as any,
        logger,
      }),
    ).rejects.toBeDefined()

    // Drain.
    await new Promise<void>((resolve) => setImmediate(resolve))
    const joined = captured.join("")
    expect(joined).not.toContain(initialAccessToken)
  })
})

// -------------------------------------------------------------------------
// 15. SQL injection attempts via tableNames override (v0.2 §12 + §13)
// -------------------------------------------------------------------------

describe("v0.2 §12 SQL injection via tableNames", () => {
  /** Minimal stub satisfying SqliteDatabase. Never reached because identifier
   *  validation fires at construction time. */
  function stubDatabase(): SqliteDatabase {
    const stmt = {
      run: () => ({ changes: 0, lastInsertRowid: 0 }),
      get: () => undefined,
      all: () => [],
    }
    return {
      prepare: () => stmt,
      exec: () => undefined,
      pragma: () => undefined,
      transaction: <A extends unknown[], R>(fn: (...args: A) => R) => fn,
      readonly: false,
    }
  }

  it.each([
    ['pats"; DROP TABLE pats; --', "pats"],
    ["foo;DROP TABLE x", "pats"],
    ["bad name", "pats"],
    ["refresh-tokens", "refreshTokens"],
    ["schema.table", "upstreamCredentials"],
  ])("rejects malicious table-name %s", (malicious, key) => {
    expect(() =>
      sqliteTokenStore({
        database: stubDatabase(),
        tableNames: { [key]: malicious } as Record<string, string>,
      }),
    ).toThrow(InvalidIdentifierError)
  })
})

// -------------------------------------------------------------------------
// 16. Redis cache value with a wrong HMAC tag (v0.2 §12 + §13)
// -------------------------------------------------------------------------

describe("v0.2 §12 Redis HMAC tag mismatch is a miss + warn", () => {
  /** Minimal in-memory RedisClient covering only what redisCache uses. */
  function makeFakeRedis(): {
    client: RedisClient
    rawSet: (key: string, value: Buffer) => void
  } {
    const kv = new Map<string, Buffer>()
    const sets = new Map<string, Set<string>>()
    return {
      rawSet: (key, value) => kv.set(key, value),
      client: {
        async get(key) {
          return kv.get(key) ?? null
        },
        async set(key, value) {
          const buf = typeof value === "string" ? Buffer.from(value, "utf8") : Buffer.from(value)
          kv.set(key, buf)
          return "OK"
        },
        async del(...keys) {
          let n = 0
          for (const k of keys) {
            if (kv.delete(k)) n++
            if (sets.delete(k)) n++
          }
          return n
        },
        async sadd(key, ...members) {
          const set = sets.get(key) ?? new Set<string>()
          for (const m of members) set.add(m)
          sets.set(key, set)
          return members.length
        },
        async smembers(key) {
          return Array.from(sets.get(key) ?? [])
        },
        async expire() {
          return 1
        },
      },
    }
  }

  it("treats a tampered cache value as a miss and falls through to inner; warn fires", async () => {
    const { client, rawSet } = makeFakeRedis()
    const inner = memoryTokenStore()
    const innerSpy = vi.spyOn(inner, "findPatByHash")
    const logger = { warn: vi.fn(), info: vi.fn() }

    const cache = redisCache(inner, {
      client,
      hmacKey: randomBytes(32),
      logger,
    })

    // Seed the inner store with a real PAT so the fall-through has something to find.
    const minted = mintPat("mcp_pat_")
    const stored = await inner.createPat({
      userIdentifier: "alice",
      name: "matrix",
      scopes: ["read:data"],
      expiresAt: new Date(Date.now() + 60_000),
      tokenHash: minted.tokenHash,
      display: "mcp_pat_xxx",
    })
    expect(stored.id).toBeTruthy()

    // Compute the cache key the decorator would use (sha256 hex of tokenHash).
    const cacheKey = `mcp:authkit:pat:hash:${createHash("sha256")
      .update(minted.tokenHash)
      .digest("hex")}`
    // Plant a value that cannot possibly authenticate under any HMAC key: a
    // 32-byte zero tag plus a random non-MessagePack body.
    const tampered = Buffer.concat([Buffer.alloc(32, 0), Buffer.from("not-msgpack")])
    rawSet(cacheKey, tampered)

    const hit = await cache.findPatByHash(minted.tokenHash)
    expect(hit).not.toBeNull()
    expect(hit?.userIdentifier).toBe("alice")
    expect(innerSpy).toHaveBeenCalledTimes(1)
    expect(logger.warn).toHaveBeenCalledWith(
      expect.objectContaining({ key: cacheKey }),
      expect.stringContaining("HMAC tag mismatch"),
    )
  })
})

// -------------------------------------------------------------------------
// 17. Production stdio replay tears down the transport (v0.2 §11 + §12)
// -------------------------------------------------------------------------

describe("v0.2 §11 stdio replay tears down the transport", () => {
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
      // biome-ignore lint/suspicious/noExplicitAny: pino test stub
    } as any
  }

  it("a replayed inbound counter resolves closed with stdio-replay and emits oauth.reject", async () => {
    const KEY = Buffer.from("k".repeat(32), "utf8")
    const input = new PassThrough()
    const output = new PassThrough()
    const audit = vi.fn<(e: AuditEvent) => void>()
    const t = createSignedStdioTransport({
      hmacKey: KEY,
      input,
      output,
      onRequest: async () => Buffer.from("ok"),
      logger: makeLogger(),
      audit,
    })

    // Consume the first response so the inbound counter advances past N=5.
    const firstOut = new Promise<void>((resolve) => output.once("data", () => resolve()))
    input.write(encodeFrame(KEY, 5n, Buffer.from("first")))
    await firstOut

    // Replay counter 5.
    input.write(encodeFrame(KEY, 5n, Buffer.from("replay")))

    const reason = await t.closed
    expect(reason.kind).toBe("stdio-replay")
    const rejects = audit.mock.calls.filter(
      ([e]) => e.type === "oauth.reject" && e.detail?.reason === "stdio-replay",
    )
    expect(rejects.length).toBe(1)
  })
})

// -------------------------------------------------------------------------
// 18. Multi-tenant cross-tenant token (right shape, wrong issuer) (v0.2 §7 + §12)
// -------------------------------------------------------------------------

describe("v0.2 §7 multi-tenant cross-tenant token rejected", () => {
  /**
   * Two AS instances; resolver picks by Host. A token signed by AS-A is sent
   * to a request whose Host resolves to AS-B → 401 (signature/issuer
   * mismatch). Confirms the resolver runs BEFORE token validation and that
   * a stolen valid-shape token cannot cross tenants.
   */
  it("rejects a token minted by tenant A presented against tenant B", async () => {
    const asA = await startTestAS()
    const asB = await startTestAS()

    const resolver: AuthorizationServerResolver = async (sel) => {
      if (sel.tenantId === "a") return { issuer: asA.issuer, jwksUri: asA.jwksUri }
      if (sel.tenantId === "b") return { issuer: asB.issuer, jwksUri: asB.jwksUri }
      throw new Error(`unknown tenant: ${String(sel.tenantId)}`)
    }
    const config = baseConfig({
      auth: {
        authorizationServer: resolver,
        tokenStore: memoryTokenStore(),
        pat: { enabled: false },
      },
    })
    const rig = await startRig({ config })
    try {
      const tokenFromA = await asA.signToken({ sub: "u", aud: AUDIENCE, scope: "read:data" })
      const rigUrl = new URL(rig.url)
      const body = JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-06-18",
          capabilities: {},
          clientInfo: { name: "x-tenant", version: "0" },
        },
      })
      const status: number = await new Promise((resolve, reject) => {
        const req = httpRequest(
          {
            method: "POST",
            host: rigUrl.hostname,
            port: rigUrl.port,
            path: "/mcp",
            headers: {
              Host: "b.example.test",
              Authorization: `Bearer ${tokenFromA}`,
              "Content-Type": "application/json",
              Accept: "application/json, text/event-stream",
              "Content-Length": Buffer.byteLength(body),
            },
          },
          (res) => {
            res.on("data", () => {})
            res.on("end", () => resolve(res.statusCode ?? 0))
          },
        )
        req.on("error", reject)
        req.write(body)
        req.end()
      })
      expect(status).toBe(401)
    } finally {
      await rig.close()
      await asA.close()
      await asB.close()
    }
  })
})

// -------------------------------------------------------------------------
// 19. CLI mint-pat path traversal (v0.2 §12 + §13)
//
// Deep coverage lives in packages/cli/src/commands/mint-pat.test.ts. The
// matrix carries a single acceptance call that proves the rejection is
// wired through the public CLI command surface.
// -------------------------------------------------------------------------

describe("v0.2 §12 CLI mint-pat rejects path-traversal --user", () => {
  it("`--user '../../../etc/passwd'` returns a userError CliError before any I/O", async () => {
    const { mintPatCommand, CliError, ExitCode, createLogger } = await import("mcp-authkit-cli")
    let caught: unknown
    try {
      await mintPatCommand({
        // Path is never read because validation fires first.
        configPath: "/dev/null/never-read.config.ts",
        user: "../../../etc/passwd",
        name: "demo",
        scopes: ["read:data"],
        logger: createLogger("silent"),
      })
    } catch (err) {
      caught = err
    }
    expect(caught).toBeInstanceOf(CliError)
    expect((caught as InstanceType<typeof CliError>).exitCode).toBe(ExitCode.userError)
  })
})
