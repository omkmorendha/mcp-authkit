/**
 * Tests for the Express adapter.
 *
 * Unit: forwarding semantics and `next(err)` on rejection. These use a fake
 * `AuthKit` (structural) so we don't drag the full pipeline into adapter
 * tests.
 *
 * Integration: the real `createAuthKit` + a real `express()` app + supertest
 * lives in core's `handlers/integration.test.ts` (cross-package integration
 * via supertest from this package would re-pull express into core's test
 * graph). The unit tests below cover every adapter-owned behaviour stated
 * in the issue.
 */
import type { IncomingMessage, ServerResponse } from "node:http"
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import express, { type NextFunction, type Request, type Response } from "express"
import request from "supertest"
import { describe, expect, it, vi } from "vitest"

import { type AuthKitLike, expressHandlers, type RawHandlers } from "./index.js"

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
      res.end("mcp")
    },
    metadata: async (_req: IncomingMessage, res: ServerResponse) => {
      res.statusCode = 200
      res.setHeader("Content-Type", "application/json")
      res.end('{"ok":true}')
    },
    pats: async (_req: IncomingMessage, res: ServerResponse) => {
      res.statusCode = 200
      res.end("pats")
    },
    challenge: (res: ServerResponse) => {
      res.statusCode = 401
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

describe("expressHandlers (unit)", () => {
  it("forwards req and res to the underlying raw mcp handler exactly once", async () => {
    const fake = fakeAuthKit()
    const h = expressHandlers(fake.authkit, fake.mcp)
    const app = express().use(h.mcp)

    await request(app).get("/").expect(200)
    expect(fake.handlers.mcp).toHaveBeenCalledTimes(1)
    const call = fake.handlers.mcp.mock.calls[0]
    expect(call?.[0]).toBeDefined()
    expect(call?.[1]).toBeDefined()
  })

  it("forwards rejections from the raw handler to Express next(err)", async () => {
    const boom = new Error("kaboom")
    const fake = fakeAuthKit({
      mcp: async () => {
        throw boom
      },
    })
    const seen: unknown[] = []
    const app = express()
      .use(expressHandlers(fake.authkit, fake.mcp).mcp)
      .use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
        seen.push(err)
        res.status(500).end("server error")
      })

    await request(app).get("/").expect(500)
    expect(seen).toEqual([boom])
  })

  it("does not call next when the raw handler resolves cleanly", async () => {
    const fake = fakeAuthKit()
    const nextSpy = vi.fn()
    const middleware = expressHandlers(fake.authkit, fake.mcp).mcp
    const app = express().use((req, res, next) => {
      const wrappedNext = ((...args: unknown[]) => {
        nextSpy(...args)
        next(...(args as [unknown?]))
      }) as NextFunction
      middleware(req, res, wrappedNext)
    })

    await request(app).get("/").expect(200)
    expect(nextSpy).not.toHaveBeenCalled()
  })

  it("challenge delegates to the underlying handler with and without reason", () => {
    const fake = fakeAuthKit()
    const h = expressHandlers(fake.authkit, fake.mcp)
    const fakeRes = {
      statusCode: 0,
      end: () => undefined,
    } as unknown as Response

    h.challenge(fakeRes)
    h.challenge(fakeRes, "expired")

    expect(fake.handlers.challenge).toHaveBeenNthCalledWith(1, fakeRes)
    expect(fake.handlers.challenge).toHaveBeenNthCalledWith(2, fakeRes, "expired")
  })

  it("each raw handler is wrapped (metadata + pats forward correctly)", async () => {
    const fake = fakeAuthKit()
    const h = expressHandlers(fake.authkit, fake.mcp)
    const app = express()
    app.use("/.well-known/oauth-protected-resource", h.metadata)
    app.use("/pats", h.pats)

    await request(app).get("/.well-known/oauth-protected-resource").expect(200)
    await request(app).get("/pats").expect(200)
    expect(fake.handlers.metadata).toHaveBeenCalledTimes(1)
    expect(fake.handlers.pats).toHaveBeenCalledTimes(1)
  })
})
