/**
 * Unit tests for createMcpHandler — connect retry semantics and the
 * top-level try/catch that prevents unhandled rejections from crashing the
 * server process.
 */
import { AsyncLocalStorage } from "node:async_hooks"
import type { IncomingMessage, ServerResponse } from "node:http"
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { describe, expect, it, vi } from "vitest"
import type { PipelineResult } from "../authkit.js"
import type { AuthContext } from "../types.js"
import { createMcpHandler } from "./mcp.js"

function mockRes(): {
  res: ServerResponse
  get: () => { status: number; body: string; headersSent: boolean; ended: boolean }
} {
  let status = 0
  let body = ""
  let ended = false
  const res = {
    writeHead(s: number) {
      status = s
    },
    setHeader() {},
    end(b?: string) {
      if (b) body = b
      ended = true
    },
    get headersSent() {
      return status !== 0
    },
    get writableEnded() {
      return ended
    },
  } as unknown as ServerResponse
  return {
    res,
    get: () => ({ status, body, headersSent: status !== 0, ended }),
  }
}

function mockReq(): IncomingMessage {
  return {
    method: "POST",
    url: "/",
    headers: { host: "api.example.test", authorization: "Bearer good" },
  } as unknown as IncomingMessage
}

const okAuth: AuthContext = {
  subject: "u1",
  tokenType: "jwt",
  tokenId: "tok",
  scopes: ["read:data"],
  expiresAt: new Date(Date.now() + 60_000),
  raw: {},
}

describe("createMcpHandler", () => {
  it("retries mcp.connect after a transient failure", async () => {
    let calls = 0
    const connect = vi.fn(async () => {
      calls += 1
      if (calls === 1) throw new Error("transient")
    })
    const mcp = { connect } as unknown as McpServer
    const runPipeline = async (
      _req: IncomingMessage,
      _bearer: string | null,
    ): Promise<PipelineResult> => ({ ok: true, auth: okAuth })
    const handler = createMcpHandler({
      mcp,
      resourceIndicator: "https://api.example.test/",
      host: { allowedHosts: [] },
      runPipeline,
      authContextStorage: new AsyncLocalStorage<AuthContext>(),
    })

    // First request: connect rejects, handler should not crash; emits 500.
    const r1 = mockRes()
    await handler(mockReq(), r1.res)
    expect(r1.get().status).toBe(500)

    // Second request: connect resolves; handler proceeds and delegates to
    // the SDK transport (which throws on a non-real request — caught by the
    // top-level guard and surfaced as 500 too). The key assertion is that
    // `connect` was called *again*, proving the retry semantics.
    const r2 = mockRes()
    await handler(mockReq(), r2.res)
    expect(connect).toHaveBeenCalledTimes(2)
  })

  it("does not crash and emits 500 when the pipeline throws", async () => {
    const mcp = { connect: vi.fn(async () => {}) } as unknown as McpServer
    const handler = createMcpHandler({
      mcp,
      resourceIndicator: "https://api.example.test/",
      host: { allowedHosts: [] },
      runPipeline: async (_req: IncomingMessage, _bearer: string | null) => {
        throw new Error("pipeline boom")
      },
      authContextStorage: new AsyncLocalStorage<AuthContext>(),
    })

    const { res, get } = mockRes()
    await expect(handler(mockReq(), res)).resolves.toBeUndefined()
    expect(get().status).toBe(500)
  })
})
