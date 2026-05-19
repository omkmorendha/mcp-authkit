/**
 * Hono adapter integration tests.
 *
 * Drives the real `createAuthKit` pipeline through a real Hono app
 * served by `@hono/node-server`, using `fetch` for the client side.
 *
 * Covers the matrix called out in the issue:
 *   - mcp: 401 challenge on no-bearer
 *   - mcp: 401 challenge with `error="invalid_token"` on bad-bearer
 *   - mcp: forged Host → 403 (DNS rebinding mitigation, spec §14)
 *   - metadata: RFC 9728 document on GET
 *   - pats: 401 challenge on unauthenticated access
 *   - streaming: response body is delivered incrementally
 *
 * Full lifecycle (mint/list/rotate/revoke with real JWT auth) is
 * covered against the framework-agnostic handlers in
 * `packages/core/src/handlers/integration.test.ts`; replicating that
 * here would duplicate the test AS fixture without exercising any
 * additional Hono code path.
 */
import type { AddressInfo } from "node:net"
import { serve } from "@hono/node-server"
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { memoryTokenStore } from "mcp-authkit-store-memory"
import { afterAll, beforeAll, describe, expect, it } from "vitest"
// Test-only import via relative path. The adapter package does NOT
// depend on `mcp-authkit` at the package.json level (workspace cycle),
// so we cannot use the published import path here. The relative path
// is fine because tests run inside the monorepo and never ship.
import { createAuthKit } from "../../core/src/authkit.js"
import type { AuthKitConfig } from "../../core/src/types.js"

import { honoMiddleware } from "./index.js"

const AUDIENCE = "http://api.example.test/"

interface Rig {
  url: string
  hostHeaderHostname: string
  port: number
  close: () => Promise<void>
}

async function startRig(opts: { config: AuthKitConfig }): Promise<Rig> {
  const authkit = createAuthKit(opts.config)
  const mcp = new McpServer({ name: "test", version: "0.0.0" })
  const app = honoMiddleware(authkit, mcp)

  // `serve` returns synchronously but the underlying server is not yet
  // listening — `address()` is null until the `listening` event fires.
  // The `listeningListener` callback receives the bound `AddressInfo`.
  const { server, address } = await new Promise<{
    server: ReturnType<typeof serve>
    address: AddressInfo
  }>((resolve) => {
    const s = serve({ fetch: app.fetch, port: 0, hostname: "127.0.0.1" }, (info) => {
      resolve({ server: s, address: info })
    })
  })
  const port = address.port
  return {
    url: `http://127.0.0.1:${port}`,
    hostHeaderHostname: "127.0.0.1",
    port,
    close: () =>
      new Promise<void>((resolve, reject) => {
        ;(server as unknown as { close: (cb: (err?: Error) => void) => void }).close((err) =>
          err ? reject(err) : resolve(),
        )
      }),
  }
}

function baseConfig(overrides: Partial<AuthKitConfig> = {}): AuthKitConfig {
  return {
    resourceIndicator: AUDIENCE,
    auth: {
      authorizationServer: {
        // Dummy issuer — we never present a token in these tests so the AS
        // is never contacted. The mcp handler 401s before touching JWKS.
        issuer: "https://as.example.test",
        jwksUri: "https://as.example.test/.well-known/jwks.json",
      },
      tokenStore: memoryTokenStore(),
      pat: { enabled: true, prefix: "mcp_pat_" },
    },
    scopes: { vocabulary: { "read:data": { description: "Read" } } },
    resolveUserScopes: async () => ["read:data"],
    // Default to disabled host validation; specific tests enable it.
    http: { allowedHosts: [] },
    ...overrides,
  }
}

describe("Hono adapter integration", () => {
  describe("metadata", () => {
    let rig: Rig
    beforeAll(async () => {
      rig = await startRig({ config: baseConfig() })
    })
    afterAll(async () => {
      await rig.close()
    })

    it("serves the RFC 9728 protected resource metadata document", async () => {
      const r = await fetch(`${rig.url}/.well-known/oauth-protected-resource`)
      expect(r.status).toBe(200)
      const doc = (await r.json()) as Record<string, unknown>
      expect(doc.resource).toBe(AUDIENCE)
      expect(doc.bearer_methods_supported).toEqual(["header"])
      expect(doc.scopes_supported).toContain("read:data")
    })
  })

  describe("mcp 401 challenge", () => {
    let rig: Rig
    beforeAll(async () => {
      rig = await startRig({ config: baseConfig() })
    })
    afterAll(async () => {
      await rig.close()
    })

    it("returns 401 with a Bearer challenge when no token is present", async () => {
      const r = await fetch(`${rig.url}/mcp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0" }),
      })
      expect(r.status).toBe(401)
      const challenge = r.headers.get("www-authenticate") ?? ""
      expect(challenge).toMatch(/^Bearer /)
      expect(challenge).toContain('resource_metadata="')
      expect(challenge).toContain(".well-known/oauth-protected-resource")
    })

    it("returns 401 with error=invalid_token when bearer is present but invalid", async () => {
      const r = await fetch(`${rig.url}/mcp`, {
        method: "POST",
        headers: { "Content-Type": "application/json", authorization: "Bearer junk" },
        body: JSON.stringify({ jsonrpc: "2.0" }),
      })
      expect(r.status).toBe(401)
      expect(r.headers.get("www-authenticate") ?? "").toContain('error="invalid_token"')
    })
  })

  describe("pats 401 challenge", () => {
    let rig: Rig
    beforeAll(async () => {
      rig = await startRig({ config: baseConfig() })
    })
    afterAll(async () => {
      await rig.close()
    })

    it("returns 401 with a Bearer challenge on unauthenticated GET /pats", async () => {
      const r = await fetch(`${rig.url}/pats`)
      expect(r.status).toBe(401)
      expect(r.headers.get("www-authenticate") ?? "").toMatch(/^Bearer /)
    })
  })

  describe("host header validation (spec §14)", () => {
    it("rejects requests with a forged Host header with 403", async () => {
      // Allowlist only `api.example.com`; the real fetch will send Host:
      // 127.0.0.1:<port>, which is not on the allowlist.
      const rig = await startRig({
        config: baseConfig({ http: { allowedHosts: ["api.example.com"] } }),
      })
      try {
        const r = await fetch(`${rig.url}/mcp`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0" }),
        })
        expect(r.status).toBe(403)
      } finally {
        await rig.close()
      }
    })

    it("accepts requests whose Host matches the allowlist (host-only entry, any port)", async () => {
      const rig = await startRig({
        config: baseConfig({ http: { allowedHosts: ["127.0.0.1"] } }),
      })
      try {
        const r = await fetch(`${rig.url}/mcp`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0" }),
        })
        // Host check passes; we still 401 because no bearer was sent.
        expect(r.status).toBe(401)
      } finally {
        await rig.close()
      }
    })
  })

  describe("streaming", () => {
    it("ships the response body incrementally over HTTP (not buffered)", async () => {
      // Build a fake authkit whose `mcp` handler writes a chunk,
      // pauses on a promise the test only resolves AFTER reading the
      // chunk, then writes the rest. A buffered implementation would
      // deadlock — the reader couldn't see the first chunk until the
      // handler called `end()`, and the handler couldn't call `end()`
      // until the gate resolves. The gate only resolves AFTER the
      // reader sees the first chunk, proving streaming.
      const gate = Promise.withResolvers<void>()
      let receivedFirstChunk: ((value: string) => void) | null = null
      const firstChunkSeen = new Promise<string>((resolve) => {
        receivedFirstChunk = resolve
      })

      const fakeAuthKit = {
        handlers: () => ({
          mcp: async (
            _req: import("node:http").IncomingMessage,
            res: import("node:http").ServerResponse,
          ): Promise<void> => {
            res.statusCode = 200
            res.setHeader("Content-Type", "text/plain")
            res.write("first-chunk;")
            await gate.promise
            res.write("second-chunk")
            res.end()
          },
          metadata: async () => undefined,
          pats: async () => undefined,
          challenge: () => undefined,
        }),
      }
      // Same `honoMiddleware` we publish; ensures the public API supports streaming.
      const mcp = new McpServer({ name: "fake", version: "0.0.0" })
      const app = honoMiddleware(
        // The structural-typed `AuthKitLike` accepts the fake. Cast through
        // the public surface so this test exercises the same code path as
        // the production wiring.
        fakeAuthKit as unknown as Parameters<typeof honoMiddleware>[0],
        mcp,
      )
      const { server, port } = await new Promise<{
        server: ReturnType<typeof serve>
        port: number
      }>((resolve) => {
        const s = serve({ fetch: app.fetch, port: 0, hostname: "127.0.0.1" }, (info) => {
          resolve({ server: s, port: info.port })
        })
      })
      try {
        const r = await fetch(`http://127.0.0.1:${port}/mcp`, { method: "POST" })
        expect(r.status).toBe(200)
        expect(r.body).not.toBeNull()
        const reader = (r.body as ReadableStream<Uint8Array>).getReader()
        const decoder = new TextDecoder()

        // Read until we have the first chunk.
        let accumulated = ""
        while (!accumulated.includes(";")) {
          const piece = await reader.read()
          if (piece.done) break
          accumulated += decoder.decode(piece.value, { stream: true })
        }
        expect(accumulated.startsWith("first-chunk;")).toBe(true)
        receivedFirstChunk?.(accumulated)
        gate.resolve()

        while (true) {
          const piece = await reader.read()
          if (piece.done) break
          accumulated += decoder.decode(piece.value, { stream: true })
        }
        accumulated += decoder.decode()
        expect(accumulated).toBe("first-chunk;second-chunk")
        await firstChunkSeen
      } finally {
        await new Promise<void>((resolve, reject) =>
          (server as unknown as { close: (cb: (err?: Error) => void) => void }).close((err) =>
            err ? reject(err) : resolve(),
          ),
        )
      }
    })
  })
})
