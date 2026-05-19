import { describe, expect, it } from "vitest"
import { buildMetadataDocument, createMetadataHandler } from "./metadata.js"

const RESOURCE = "https://api.example.com/mcp"

describe("buildMetadataDocument", () => {
  it("includes resource, bearer_methods_supported, scopes_supported", () => {
    const doc = buildMetadataDocument({
      resourceIndicator: RESOURCE,
      vocabulary: { "echo:say": { description: "echo" }, "db:read": { description: "db" } },
    })
    expect(doc.resource).toBe(RESOURCE)
    expect(doc.bearer_methods_supported).toEqual(["header"])
    expect(doc.scopes_supported).toEqual(["db:read", "echo:say"]) // sorted
    expect(doc.authorization_servers).toBeUndefined()
  })

  it("includes authorization_servers when issuer is configured", () => {
    const doc = buildMetadataDocument({
      resourceIndicator: RESOURCE,
      authorizationServerIssuer: "https://as.example.com",
      vocabulary: {},
    })
    expect(doc.authorization_servers).toEqual(["https://as.example.com"])
  })
})

describe("createMetadataHandler", () => {
  function mockRes() {
    let status = 0
    const headers: Record<string, string> = {}
    let body = ""
    const res = {
      writeHead(s: number, h?: Record<string, unknown>) {
        status = s
        if (h) for (const [k, v] of Object.entries(h)) headers[k] = String(v)
      },
      setHeader(k: string, v: string | number) {
        headers[k] = String(v)
      },
      end(b?: string) {
        if (b) body = b
      },
      get headersSent() {
        return status !== 0
      },
    }
    return {
      res: res as unknown as import("node:http").ServerResponse,
      get: () => ({ status, headers, body }),
    }
  }

  it("serves 200 GET", async () => {
    const handler = createMetadataHandler({
      resourceIndicator: RESOURCE,
      vocabulary: { "echo:say": { description: "echo" } },
      host: { allowedHosts: [] },
    })
    const { res, get } = mockRes()
    await handler(
      {
        method: "GET",
        headers: { host: "api.example.com" },
        url: "/.well-known/oauth-protected-resource",
      } as import("node:http").IncomingMessage,
      res,
    )
    const out = get()
    expect(out.status).toBe(200)
    expect(JSON.parse(out.body).resource).toBe(RESOURCE)
  })

  it("rejects non-GET with 405", async () => {
    const handler = createMetadataHandler({
      resourceIndicator: RESOURCE,
      vocabulary: {},
      host: { allowedHosts: [] },
    })
    const { res, get } = mockRes()
    await handler(
      {
        method: "POST",
        headers: { host: "api.example.com" },
        url: "/x",
      } as import("node:http").IncomingMessage,
      res,
    )
    expect(get().status).toBe(405)
  })

  it("serves 200 HEAD without body", async () => {
    const handler = createMetadataHandler({
      resourceIndicator: RESOURCE,
      vocabulary: { "echo:say": { description: "echo" } },
      host: { allowedHosts: [] },
    })
    const { res, get } = mockRes()
    await handler(
      {
        method: "HEAD",
        headers: { host: "api.example.com" },
        url: "/.well-known/oauth-protected-resource",
      } as import("node:http").IncomingMessage,
      res,
    )
    const out = get()
    expect(out.status).toBe(200)
  })

  it("rejects forged Host with 403", async () => {
    const handler = createMetadataHandler({
      resourceIndicator: RESOURCE,
      vocabulary: {},
      host: { allowedHosts: ["api.example.com"] },
    })
    const { res, get } = mockRes()
    await handler(
      {
        method: "GET",
        headers: { host: "evil.com" },
        url: "/x",
      } as import("node:http").IncomingMessage,
      res,
    )
    expect(get().status).toBe(403)
  })
})
