import { Readable } from "node:stream"
import { describe, expect, it } from "vitest"
import { readJsonBody, requestPath } from "./http-utils.js"

function mockReq(body: string): import("node:http").IncomingMessage {
  return Readable.from(Buffer.from(body, "utf8")) as unknown as import("node:http").IncomingMessage
}

describe("readJsonBody", () => {
  it("parses valid JSON", async () => {
    const r = await readJsonBody<{ a: number }>(mockReq('{"a":1}'))
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.value).toEqual({ a: 1 })
  })

  it("rejects invalid JSON", async () => {
    const r = await readJsonBody(mockReq("not json"))
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.reason).toBe("invalid_json")
  })

  it("rejects empty body", async () => {
    const r = await readJsonBody(mockReq(""))
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.reason).toBe("empty")
  })

  it("rejects bodies above maxBytes", async () => {
    const big = "x".repeat(2048)
    const r = await readJsonBody(mockReq(`"${big}"`), 1024)
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.reason).toBe("too_large")
  })
})

describe("requestPath", () => {
  it("strips query string", () => {
    const req = { url: "/foo?bar=1" } as import("node:http").IncomingMessage
    expect(requestPath(req)).toBe("/foo")
  })
  it("defaults to /", () => {
    const req = {} as import("node:http").IncomingMessage
    expect(requestPath(req)).toBe("/")
  })
})
