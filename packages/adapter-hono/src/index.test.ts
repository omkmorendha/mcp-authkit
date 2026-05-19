/**
 * Tests for the Hono adapter.
 *
 * Unit (this file): forwarding semantics, streaming-response behaviour,
 * and the per-route helper matrix. These use a fake `AuthKit` (structural)
 * so we don't drag the full pipeline into adapter tests.
 *
 * Integration tests live in core (`handlers/integration.test.ts`) and
 * cover the real pipeline against `http.createServer`. The
 * Hono-specific end-to-end (real `Hono` + real `createAuthKit` + real
 * JWT) tests live in `integration.test.ts` next to this file.
 */
import type { IncomingMessage, ServerResponse } from "node:http"
import type { Readable } from "node:stream"
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { Hono } from "hono"
import { describe, expect, it, vi } from "vitest"

import { type AuthKitLike, honoHandlers, honoMiddleware, type RawHandlers } from "./index.js"

interface Fake {
  authkit: AuthKitLike
  mcp: McpServer
  handlers: {
    mcp: ReturnType<typeof vi.fn>
    metadata: ReturnType<typeof vi.fn>
    pats: ReturnType<typeof vi.fn>
    challenge: ReturnType<typeof vi.fn>
  }
}

function fakeAuthKit(overrides?: Partial<RawHandlers>): Fake {
  const defaults: RawHandlers = {
    mcp: async (_req: IncomingMessage, res: ServerResponse) => {
      res.statusCode = 200
      res.setHeader("Content-Type", "text/plain")
      res.end("mcp")
    },
    metadata: async (_req: IncomingMessage, res: ServerResponse) => {
      res.statusCode = 200
      res.setHeader("Content-Type", "application/json")
      res.end('{"ok":true}')
    },
    pats: async (_req: IncomingMessage, res: ServerResponse) => {
      res.statusCode = 200
      res.setHeader("Content-Type", "text/plain")
      res.end("pats")
    },
    challenge: (res: ServerResponse) => {
      res.statusCode = 401
      res.setHeader("WWW-Authenticate", 'Bearer resource_metadata="https://e.test/m"')
      res.end()
    },
  }
  const merged: RawHandlers = { ...defaults, ...overrides }
  const handlers = {
    mcp: vi.fn(merged.mcp),
    metadata: vi.fn(merged.metadata),
    pats: vi.fn(merged.pats),
    challenge: vi.fn(merged.challenge),
  }
  const authkit: AuthKitLike = {
    handlers: (_mcp: McpServer): RawHandlers => handlers,
  }
  return { authkit, mcp: new McpServer({ name: "fake", version: "0.0.0" }), handlers }
}

describe("honoHandlers (unit)", () => {
  it("forwards a Hono request to the raw mcp handler and returns the body", async () => {
    const fake = fakeAuthKit()
    const h = honoHandlers(fake.authkit, fake.mcp)
    const app = new Hono().all("/mcp", h.mcp)

    const res = await app.request("/mcp", { method: "POST", body: "x" })
    expect(res.status).toBe(200)
    expect(await res.text()).toBe("mcp")
    expect(fake.handlers.mcp).toHaveBeenCalledTimes(1)
    const call = fake.handlers.mcp.mock.calls[0]
    expect(call?.[0]).toBeDefined()
    expect(call?.[1]).toBeDefined()
  })

  it("propagates raw-handler rejection before commit as a thrown error", async () => {
    const boom = new Error("kaboom")
    const fake = fakeAuthKit({
      mcp: async () => {
        throw boom
      },
    })
    // Hono converts uncaught middleware errors to 500 by default.
    const app = new Hono().all("/mcp", honoHandlers(fake.authkit, fake.mcp).mcp)
    const seen: unknown[] = []
    app.onError((err) => {
      seen.push(err)
      return new Response("server error", { status: 500 })
    })

    const res = await app.request("/mcp", { method: "POST" })
    expect(res.status).toBe(500)
    expect(seen).toEqual([boom])
  })

  it("passes the underlying Web Request through so Host header survives", async () => {
    const captured: { host?: string | undefined } = {}
    const fake = fakeAuthKit({
      mcp: async (req, res) => {
        captured.host = req.headers.host
        res.statusCode = 200
        res.end("ok")
      },
    })
    const app = new Hono().all("/mcp", honoHandlers(fake.authkit, fake.mcp).mcp)

    await app.request("http://api.example.com/mcp", { method: "POST" })
    expect(captured.host).toBe("api.example.com")
  })

  it("forwards method and url path", async () => {
    const captured: { method?: string; url?: string | undefined } = {}
    const fake = fakeAuthKit({
      mcp: async (req, res) => {
        captured.method = req.method
        captured.url = req.url
        res.statusCode = 200
        res.end("ok")
      },
    })
    const app = new Hono().all("/mcp/*", honoHandlers(fake.authkit, fake.mcp).mcp)

    await app.request("http://api.example.com/mcp/sub?x=1", { method: "POST" })
    expect(captured.method).toBe("POST")
    expect(captured.url).toBe("/mcp/sub?x=1")
  })

  it("metadata + pats helpers forward correctly", async () => {
    const fake = fakeAuthKit()
    const h = honoHandlers(fake.authkit, fake.mcp)
    const app = new Hono()
    app.get("/.well-known/oauth-protected-resource", h.metadata)
    app.all("/pats/*", h.pats)
    app.all("/pats", h.pats)

    const m = await app.request("/.well-known/oauth-protected-resource")
    expect(m.status).toBe(200)
    expect(await m.text()).toBe('{"ok":true}')

    const p = await app.request("/pats", { method: "GET" })
    expect(p.status).toBe(200)
    expect(await p.text()).toBe("pats")

    expect(fake.handlers.metadata).toHaveBeenCalledTimes(1)
    expect(fake.handlers.pats).toHaveBeenCalledTimes(1)
  })

  it("propagates response headers from the raw handler (Content-Type, WWW-Authenticate)", async () => {
    const fake = fakeAuthKit({
      mcp: async (_req, res) => {
        res.statusCode = 401
        res.setHeader("WWW-Authenticate", 'Bearer error="invalid_token"')
        res.setHeader("Cache-Control", "no-store")
        res.end()
      },
    })
    const app = new Hono().all("/mcp", honoHandlers(fake.authkit, fake.mcp).mcp)
    const res = await app.request("/mcp", { method: "POST" })
    expect(res.status).toBe(401)
    expect(res.headers.get("www-authenticate")).toBe('Bearer error="invalid_token"')
    expect(res.headers.get("cache-control")).toBe("no-store")
  })

  it("challenge() helper returns a 401 Response with WWW-Authenticate (with and without reason)", async () => {
    const fake = fakeAuthKit()
    const h = honoHandlers(fake.authkit, fake.mcp)
    // Build a minimal Hono Context shim — `challenge` only uses the
    // returned Response, never reading from `c`.
    const c = {} as never

    const r1 = await h.challenge(c)
    expect(r1.status).toBe(401)
    expect(r1.headers.get("www-authenticate")).toMatch(/^Bearer /)

    const r2 = await h.challenge(c, "expired")
    expect(r2.status).toBe(401)

    expect(fake.handlers.challenge).toHaveBeenNthCalledWith(1, expect.anything())
    expect(fake.handlers.challenge).toHaveBeenNthCalledWith(2, expect.anything(), "expired")
  })
})

describe("honoMiddleware (unit)", () => {
  it("mounts /mcp, /pats, /.well-known/... on a sub-app", async () => {
    const fake = fakeAuthKit()
    const sub = honoMiddleware(fake.authkit, fake.mcp)
    const app = new Hono().route("/", sub)

    expect((await app.request("/mcp", { method: "POST" })).status).toBe(200)
    expect((await app.request("/.well-known/oauth-protected-resource")).status).toBe(200)
    expect((await app.request("/pats", { method: "GET" })).status).toBe(200)
    expect((await app.request("/pats/abc/rotate", { method: "POST" })).status).toBe(200)

    expect(fake.handlers.mcp).toHaveBeenCalledTimes(1)
    expect(fake.handlers.metadata).toHaveBeenCalledTimes(1)
    expect(fake.handlers.pats).toHaveBeenCalledTimes(2)
  })
})

describe("streaming response (Hono-specific)", () => {
  it("does not buffer: chunks written by the raw handler are visible to the reader before end()", async () => {
    // Sequence:
    //   1. handler writes chunk A
    //   2. handler waits on a promise the test resolves only after reading A
    //   3. handler writes chunk B and ends
    // If the body were buffered, step (2) would deadlock — the reader
    // couldn't see A until end(), and the test couldn't resolve the
    // gate. Streaming makes A visible immediately.
    const gate = Promise.withResolvers<void>()
    const fake = fakeAuthKit({
      mcp: async (_req, res) => {
        res.statusCode = 200
        res.setHeader("Content-Type", "text/plain")
        res.write("A")
        await gate.promise
        res.write("B")
        res.end()
      },
    })
    const app = new Hono().all("/mcp", honoHandlers(fake.authkit, fake.mcp).mcp)

    const httpRes = await app.request("/mcp", { method: "POST" })
    expect(httpRes.status).toBe(200)
    expect(httpRes.body).not.toBeNull()
    const reader = (httpRes.body as ReadableStream<Uint8Array>).getReader()
    const decoder = new TextDecoder()

    const first = await reader.read()
    expect(first.done).toBe(false)
    expect(decoder.decode(first.value, { stream: true })).toBe("A")

    // The handler is blocked on `gate`. If the response were buffered we
    // would never have received "A". Release the gate so the rest can
    // come through.
    gate.resolve()

    let rest = ""
    while (true) {
      const r = await reader.read()
      if (r.done) break
      rest += decoder.decode(r.value, { stream: true })
    }
    rest += decoder.decode()
    expect(rest).toBe("B")
  })

  it("forwards the request body to the raw handler as a readable stream", async () => {
    let received = ""
    const fake = fakeAuthKit({
      mcp: async (req, res) => {
        for await (const chunk of req as unknown as Readable) {
          received += Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk)
        }
        res.statusCode = 200
        res.end("ok")
      },
    })
    const app = new Hono().all("/mcp", honoHandlers(fake.authkit, fake.mcp).mcp)
    const res = await app.request("/mcp", { method: "POST", body: "payload-123" })
    expect(res.status).toBe(200)
    expect(received).toBe("payload-123")
  })
})
