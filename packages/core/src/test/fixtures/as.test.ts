import { createRemoteJWKSet, jwtVerify } from "jose"
import { afterEach, beforeEach, describe, expect, it } from "vitest"
import type { TestAS } from "./as.js"
import { startTestAS } from "./as.js"

describe("startTestAS", () => {
  let as: TestAS

  beforeEach(async () => {
    as = await startTestAS()
  })

  afterEach(async () => {
    await as.close()
  })

  it("serves a valid JWKS at the jwksUri", async () => {
    const res = await fetch(as.jwksUri)
    expect(res.ok).toBe(true)
    const body = (await res.json()) as { keys: unknown[] }
    expect(body.keys).toHaveLength(1)
  })

  it("issuer and jwksUri are on the same ephemeral host", () => {
    expect(as.jwksUri).toBe(`${as.issuer}/.well-known/jwks.json`)
  })

  it("signs a token that can be verified against the served JWKS", async () => {
    const token = await as.signToken({ sub: "user-1", aud: "https://api.example.com" })
    const JWKS = createRemoteJWKSet(new URL(as.jwksUri))
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: as.issuer,
      audience: "https://api.example.com",
    })
    expect(payload.sub).toBe("user-1")
    expect(payload.iss).toBe(as.issuer)
  })

  it("allows overriding the issuer claim (for security tests crafting bad tokens)", async () => {
    const token = await as.signToken({ sub: "user-1", iss: "https://evil.example.com" })
    const JWKS = createRemoteJWKSet(new URL(as.jwksUri))
    await expect(jwtVerify(token, JWKS, { issuer: as.issuer })).rejects.toThrow()
  })

  it("allows overriding exp to create expired tokens (for security tests)", async () => {
    const pastExp = Math.floor(Date.now() / 1000) - 3600
    const token = await as.signToken({ sub: "user-1", exp: pastExp })
    const JWKS = createRemoteJWKSet(new URL(as.jwksUri))
    await expect(jwtVerify(token, JWKS, { issuer: as.issuer })).rejects.toThrow()
  })

  it("close() stops the HTTP server (no lingering handles)", async () => {
    await as.close()
    // Verify the server is no longer accepting connections
    await expect(fetch(as.jwksUri)).rejects.toThrow()
    // Prevent afterEach from calling close() again on an already-closed server
    as = await startTestAS()
  })

  it("works with RS256 algorithm", async () => {
    const rsAs = await startTestAS({ alg: "RS256" })
    try {
      const token = await rsAs.signToken({ sub: "user-rs", aud: "https://api.example.com" })
      const JWKS = createRemoteJWKSet(new URL(rsAs.jwksUri))
      const { payload } = await jwtVerify(token, JWKS, {
        issuer: rsAs.issuer,
        audience: "https://api.example.com",
      })
      expect(payload.sub).toBe("user-rs")
    } finally {
      await rsAs.close()
    }
  })

  it("includes custom claims in the signed token", async () => {
    const token = await as.signToken({ sub: "user-1", scope: "read write" })
    const JWKS = createRemoteJWKSet(new URL(as.jwksUri))
    const { payload } = await jwtVerify(token, JWKS, { issuer: as.issuer })
    expect(payload.scope).toBe("read write")
  })
})
