import { afterAll, beforeAll, describe, expect, it } from "vitest"
import { startTestAS, type TestAS } from "../test/fixtures/as.js"
import { createJwtValidator, type JwtValidator } from "./jwt.js"

const AUDIENCE = "https://mcp.example.test/"

describe("createJwtValidator", () => {
  let as: TestAS
  let validator: JwtValidator

  beforeAll(async () => {
    as = await startTestAS()
    validator = createJwtValidator({
      issuer: as.issuer,
      audience: AUDIENCE,
      jwksUri: as.jwksUri,
    })
  })

  afterAll(async () => {
    await as.close()
  })

  describe("happy path", () => {
    it("accepts a correctly signed token and populates AuthContext", async () => {
      const token = await as.signToken({
        sub: "user-123",
        aud: AUDIENCE,
        jti: "jti-abc",
        scope: "read:profile  write:posts",
      })

      const result = await validator.validate(token)
      expect(result.ok).toBe(true)
      if (!result.ok) return
      expect(result.auth.subject).toBe("user-123")
      expect(result.auth.tokenType).toBe("oauth")
      expect(result.auth.tokenId).toBe("jti-abc")
      expect(result.auth.scopes).toEqual(["read:profile", "write:posts"])
      expect(result.auth.expiresAt).toBeInstanceOf(Date)
      expect(result.auth.raw.sub).toBe("user-123")
    })

    it("accepts array `aud` when one entry matches", async () => {
      const token = await as.signToken({
        sub: "u",
        aud: ["other", AUDIENCE, "another"],
      })
      const result = await validator.validate(token)
      expect(result.ok).toBe(true)
    })

    it("falls back to a 64-char hex tokenId when jti is absent", async () => {
      const token = await as.signToken({ sub: "u", aud: AUDIENCE })
      const result = await validator.validate(token)
      expect(result.ok).toBe(true)
      if (!result.ok) return
      expect(result.auth.tokenId).toMatch(/^[0-9a-f]{64}$/)
    })

    it("returns empty scopes when `scope` claim is missing", async () => {
      const token = await as.signToken({ sub: "u", aud: AUDIENCE })
      const result = await validator.validate(token)
      expect(result.ok).toBe(true)
      if (!result.ok) return
      expect(result.auth.scopes).toEqual([])
    })

    it("returns empty scopes when `scope` claim is whitespace only", async () => {
      const token = await as.signToken({
        sub: "u",
        aud: AUDIENCE,
        scope: "   ",
      })
      const result = await validator.validate(token)
      expect(result.ok).toBe(true)
      if (!result.ok) return
      expect(result.auth.scopes).toEqual([])
    })

    it("verifies multiple tokens through the same cached JWKS", async () => {
      const t1 = await as.signToken({ sub: "a", aud: AUDIENCE })
      const t2 = await as.signToken({ sub: "b", aud: AUDIENCE })
      const r1 = await validator.validate(t1)
      const r2 = await validator.validate(t2)
      expect(r1.ok && r2.ok).toBe(true)
    })
  })

  describe("security (spec §14)", () => {
    it("rejects wrong audience", async () => {
      const token = await as.signToken({
        sub: "u",
        aud: "https://attacker.example/",
      })
      const result = await validator.validate(token)
      expect(result.ok).toBe(false)
      if (result.ok) return
      expect(result.reason).toBe("audience")
    })

    it("rejects missing audience", async () => {
      const token = await as.signToken({ sub: "u" })
      const result = await validator.validate(token)
      expect(result.ok).toBe(false)
      if (result.ok) return
      expect(result.reason).toBe("audience")
    })

    it("rejects array audience with no matching entry", async () => {
      const token = await as.signToken({
        sub: "u",
        aud: ["https://a.example/", "https://b.example/"],
      })
      const result = await validator.validate(token)
      expect(result.ok).toBe(false)
      if (result.ok) return
      expect(result.reason).toBe("audience")
    })

    it("rejects unknown issuer", async () => {
      const token = await as.signToken({
        sub: "u",
        aud: AUDIENCE,
        iss: "https://other-issuer.example/",
      })
      const result = await validator.validate(token)
      expect(result.ok).toBe(false)
      if (result.ok) return
      expect(result.reason).toBe("issuer")
    })

    it("rejects expired token", async () => {
      const now = Math.floor(Date.now() / 1000)
      const token = await as.signToken({
        sub: "u",
        aud: AUDIENCE,
        exp: now - 60,
      })
      const result = await validator.validate(token)
      expect(result.ok).toBe(false)
      if (result.ok) return
      expect(result.reason).toBe("expired")
    })

    it("rejects token whose nbf is in the future", async () => {
      const now = Math.floor(Date.now() / 1000)
      const token = await as.signToken({
        sub: "u",
        aud: AUDIENCE,
        nbf: now + 600,
      })
      const result = await validator.validate(token)
      expect(result.ok).toBe(false)
      if (result.ok) return
      expect(result.reason).toBe("not-yet-valid")
    })

    it("rejects a token signed by a different key", async () => {
      const otherAS = await startTestAS()
      try {
        const token = await otherAS.signToken({ sub: "u", aud: AUDIENCE })
        // Tell the second AS to sign with our validator's expected issuer
        // so issuer check passes and we hit signature verification.
        const tokenWithIss = await otherAS.signToken({
          sub: "u",
          aud: AUDIENCE,
          iss: as.issuer,
        })
        void token
        const result = await validator.validate(tokenWithIss)
        expect(result.ok).toBe(false)
        if (result.ok) return
        // JWKS lookup by kid will fail (other AS uses the same static kid
        // "test-key-1" but with a different key) — jose surfaces this as
        // JWSSignatureVerificationFailed in v6.
        expect(["signature", "jwks"]).toContain(result.reason)
      } finally {
        await otherAS.close()
      }
    })

    it("rejects a malformed token string", async () => {
      const result = await validator.validate("not.a.jwt")
      expect(result.ok).toBe(false)
      if (result.ok) return
      expect(result.reason).toBe("malformed")
    })

    it("rejects an empty token string", async () => {
      const result = await validator.validate("")
      expect(result.ok).toBe(false)
      if (result.ok) return
      expect(result.reason).toBe("malformed")
    })
  })
})
