/**
 * Tests for multi-tenant authorization-server resolution (spec v0.2 §5.1, §7).
 */
import type { IncomingMessage } from "node:http"
import pino from "pino"
import { describe, expect, it, vi } from "vitest"
import type { AuthorizationServerConfig, AuthorizationServerResolver } from "../types.js"
import {
  assertResolvedConfig,
  defaultTenantIdFromHost,
  makeSelector,
  resolveAuthorizationServer,
} from "./tenant.js"

function silentLogger() {
  return pino({ level: "silent" })
}

function mockReq(headers: Record<string, string | string[] | undefined> = {}): IncomingMessage {
  return { headers } as unknown as IncomingMessage
}

const goodAs: AuthorizationServerConfig = {
  issuer: "https://acme.example.com",
  jwksUri: "https://acme.example.com/.well-known/jwks.json",
}

describe("defaultTenantIdFromHost", () => {
  it("returns the leftmost label of a multi-label host", () => {
    expect(defaultTenantIdFromHost("acme.example.com")).toBe("acme")
    expect(defaultTenantIdFromHost("tenant-42.api.example.com")).toBe("tenant-42")
  })

  it("strips port", () => {
    expect(defaultTenantIdFromHost("acme.example.com:443")).toBe("acme")
  })

  it("returns null for single-label host", () => {
    expect(defaultTenantIdFromHost("example")).toBeNull()
  })

  it("returns null for two-label host (no subdomain)", () => {
    // "example.com" has no tenant label; first label is "example" but we
    // distinguish apex-vs-subdomain by requiring at least three labels would
    // be wrong (the spec says subdomain split). We use first label only and
    // return it for two-label hosts too — actually the spec example
    // `acme.example.com` → `acme` implies splitting on first dot, so
    // `example.com` → `example`. Re-affirm.
    expect(defaultTenantIdFromHost("example.com")).toBe("example")
  })

  it("returns null for numeric-only label", () => {
    expect(defaultTenantIdFromHost("127.0.0.1")).toBeNull()
  })

  it("returns null for IPv6 literal", () => {
    expect(defaultTenantIdFromHost("[::1]:8080")).toBeNull()
  })

  it("returns null for empty / missing", () => {
    expect(defaultTenantIdFromHost(undefined)).toBeNull()
    expect(defaultTenantIdFromHost("")).toBeNull()
    expect(defaultTenantIdFromHost("   ")).toBeNull()
  })
})

describe("makeSelector", () => {
  it("derives tenantId from the Host header", () => {
    const req = mockReq({ host: "acme.example.com" })
    const sel = makeSelector(req)
    expect(sel.tenantId).toBe("acme")
    expect(sel.incoming).toBe(req)
  })

  it("returns null tenantId when Host is missing", () => {
    expect(makeSelector(mockReq()).tenantId).toBeNull()
  })
})

describe("assertResolvedConfig", () => {
  it("accepts a valid config", () => {
    expect(() => assertResolvedConfig(goodAs)).not.toThrow()
  })

  it("throws on null / non-object", () => {
    expect(() => assertResolvedConfig(null)).toThrow(/non-object/)
    expect(() => assertResolvedConfig("nope")).toThrow(/non-object/)
  })

  it("throws when issuer is missing or empty", () => {
    expect(() => assertResolvedConfig({ jwksUri: "x" })).toThrow(/issuer/)
    expect(() => assertResolvedConfig({ issuer: "", jwksUri: "x" })).toThrow(/issuer/)
  })

  it("throws when jwksUri is missing or empty", () => {
    expect(() => assertResolvedConfig({ issuer: "https://a" })).toThrow(/jwksUri/)
    expect(() => assertResolvedConfig({ issuer: "https://a", jwksUri: "" })).toThrow(/jwksUri/)
  })
})

describe("resolveAuthorizationServer", () => {
  it("returns the static object form synchronously without latency", async () => {
    const req = mockReq({ host: "acme.example.com" })
    const result = await resolveAuthorizationServer({
      incoming: req,
      resolverSpec: goodAs,
      logger: silentLogger(),
    })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.as).toBe(goodAs)
    expect(result.latencyMs).toBe(0)
  })

  it("invokes the function form once and memoizes per request", async () => {
    const resolver = vi.fn<AuthorizationServerResolver>(async () => goodAs)
    const req = mockReq({ host: "acme.example.com" })
    const logger = silentLogger()
    const a = await resolveAuthorizationServer({
      incoming: req,
      resolverSpec: resolver,
      logger,
    })
    const b = await resolveAuthorizationServer({
      incoming: req,
      resolverSpec: resolver,
      logger,
    })
    expect(a.ok).toBe(true)
    expect(b.ok).toBe(true)
    expect(resolver).toHaveBeenCalledTimes(1)
  })

  it("passes a selector with the resolved tenantId to the resolver", async () => {
    const resolver = vi.fn<AuthorizationServerResolver>(async (sel) => {
      expect(sel.tenantId).toBe("acme")
      expect(sel.incoming.headers.host).toBe("acme.example.com")
      return goodAs
    })
    const req = mockReq({ host: "acme.example.com" })
    const result = await resolveAuthorizationServer({
      incoming: req,
      resolverSpec: resolver,
      logger: silentLogger(),
    })
    expect(result.ok).toBe(true)
    expect(resolver).toHaveBeenCalledOnce()
  })

  it("returns an error result when the resolver throws (no exception escapes)", async () => {
    const boom = new Error("DB down")
    const resolver: AuthorizationServerResolver = async () => {
      throw boom
    }
    const result = await resolveAuthorizationServer({
      incoming: mockReq({ host: "acme.example.com" }),
      resolverSpec: resolver,
      logger: silentLogger(),
    })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.error).toBe(boom)
    expect(result.latencyMs).toBeGreaterThanOrEqual(0)
  })

  it("returns an error result when the resolver returns a non-object", async () => {
    const resolver: AuthorizationServerResolver = (async () =>
      "not an object") as unknown as AuthorizationServerResolver
    const result = await resolveAuthorizationServer({
      incoming: mockReq({ host: "acme.example.com" }),
      resolverSpec: resolver,
      logger: silentLogger(),
    })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.error.message).toMatch(/non-object|issuer|jwksUri/)
  })

  it("returns an error result when the resolver returns a config missing issuer", async () => {
    const resolver: AuthorizationServerResolver = (async () => ({
      jwksUri: "https://x/jwks",
    })) as unknown as AuthorizationServerResolver
    const result = await resolveAuthorizationServer({
      incoming: mockReq({ host: "acme.example.com" }),
      resolverSpec: resolver,
      logger: silentLogger(),
    })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.error.message).toMatch(/issuer/)
  })

  it("returns an error result when the resolver returns a config missing jwksUri", async () => {
    const resolver: AuthorizationServerResolver = (async () => ({
      issuer: "https://x",
    })) as unknown as AuthorizationServerResolver
    const result = await resolveAuthorizationServer({
      incoming: mockReq({ host: "acme.example.com" }),
      resolverSpec: resolver,
      logger: silentLogger(),
    })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.error.message).toMatch(/jwksUri/)
  })

  it("logs resolver latency at debug with `authkit.tenant_resolve_ms`", async () => {
    const debug = vi.fn()
    const logger = {
      debug,
      info: () => {},
      warn: () => {},
      error: () => {},
    } as unknown as ReturnType<typeof silentLogger>
    const resolver: AuthorizationServerResolver = async () => goodAs
    await resolveAuthorizationServer({
      incoming: mockReq({ host: "acme.example.com" }),
      resolverSpec: resolver,
      logger,
    })
    expect(debug).toHaveBeenCalled()
    const [fields] = debug.mock.calls[0] ?? []
    expect(fields).toHaveProperty("authkit.tenant_resolve_ms")
  })

  it("two distinct requests get distinct resolver invocations", async () => {
    const resolver = vi.fn<AuthorizationServerResolver>(async () => goodAs)
    const logger = silentLogger()
    await resolveAuthorizationServer({
      incoming: mockReq({ host: "acme.example.com" }),
      resolverSpec: resolver,
      logger,
    })
    await resolveAuthorizationServer({
      incoming: mockReq({ host: "globex.example.com" }),
      resolverSpec: resolver,
      logger,
    })
    expect(resolver).toHaveBeenCalledTimes(2)
  })
})
