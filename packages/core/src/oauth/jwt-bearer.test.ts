import { decodeJwt, decodeProtectedHeader, exportJWK, generateKeyPair, jwtVerify } from "jose"
import { describe, expect, it, vi } from "vitest"
import { type FetchLike, JwtBearerError, requestTokenWithAssertion } from "./jwt-bearer.js"

const ISSUER = "https://as.example.test"
const TOKEN_ENDPOINT = "https://as.example.test/oauth/token"
const AUDIENCE = TOKEN_ENDPOINT

interface MockJsonResponseInit {
  status?: number
  body?: unknown
  throwOnJson?: boolean
}

function mockJsonResponse(init: MockJsonResponseInit = {}) {
  const status = init.status ?? 200
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() {
      if (init.throwOnJson) throw new Error("invalid json")
      return init.body
    },
    async text() {
      return ""
    },
  }
}

type Captured = { url: string; body: string; headers?: Record<string, string> }

function fetchStub(
  responses: { match: (url: string) => boolean; respond: MockJsonResponseInit }[],
  capture: Captured[] = [],
): FetchLike {
  return vi.fn<FetchLike>(async (input, init) => {
    const url = typeof input === "string" ? input : input.toString()
    capture.push({
      url,
      body: typeof init?.body === "string" ? init.body : "",
      ...(init?.headers !== undefined ? { headers: init.headers } : {}),
    })
    const match = responses.find((r) => r.match(url))
    if (!match) throw new Error(`unexpected fetch: ${url}`)
    return mockJsonResponse(match.respond)
  })
}

describe("requestTokenWithAssertion", () => {
  describe("assertion JWT structure (RFC 7523 §3)", () => {
    it("builds a JWT with iss, sub, aud, exp, iat, jti and posts to the token endpoint", async () => {
      const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true })
      const jwk = await exportJWK(privateKey)
      jwk.alg = "ES256"

      const captured: Captured[] = []
      const fetch = fetchStub(
        [
          {
            match: (u) => u === TOKEN_ENDPOINT,
            respond: { body: { access_token: "at-1", token_type: "Bearer", expires_in: 3600 } },
          },
        ],
        captured,
      )

      const before = Math.floor(Date.now() / 1000)
      const result = await requestTokenWithAssertion({
        issuer: ISSUER,
        audience: AUDIENCE,
        signingKey: jwk,
        scopes: ["upstream:read", "upstream:write"],
        tokenEndpoint: TOKEN_ENDPOINT,
        fetch,
      })
      const after = Math.floor(Date.now() / 1000)

      expect(result.accessToken).toBe("at-1")
      expect(result.scopes).toEqual(["upstream:read", "upstream:write"])
      expect(result.expiresAt).toBeInstanceOf(Date)

      expect(captured).toHaveLength(1)
      const form = new URLSearchParams(captured[0]?.body ?? "")
      expect(form.get("grant_type")).toBe("urn:ietf:params:oauth:grant-type:jwt-bearer")
      expect(form.get("scope")).toBe("upstream:read upstream:write")
      expect(captured[0]?.headers?.["Content-Type"]).toBe("application/x-www-form-urlencoded")

      const assertion = form.get("assertion")
      expect(assertion).toBeTruthy()
      const header = decodeProtectedHeader(assertion as string)
      expect(header.alg).toBe("ES256")
      expect(header.typ).toBe("JWT")

      const verified = await jwtVerify(assertion as string, publicKey, {
        issuer: ISSUER,
        audience: AUDIENCE,
      })
      const claims = verified.payload
      expect(claims.iss).toBe(ISSUER)
      expect(claims.aud).toBe(AUDIENCE)
      expect(typeof claims.jti).toBe("string")
      expect((claims.jti as string).length).toBeGreaterThan(0)
      expect(claims.scope).toBe("upstream:read upstream:write")

      const iat = claims.iat as number
      const exp = claims.exp as number
      expect(iat).toBeGreaterThanOrEqual(before)
      expect(iat).toBeLessThanOrEqual(after)
      expect(exp).toBeGreaterThan(iat)
      // default TTL is 60s
      expect(exp - iat).toBe(60)
    })

    it("act-as-client: sub defaults to issuer when subject is omitted", async () => {
      const { privateKey } = await generateKeyPair("ES256", { extractable: true })
      const jwk = await exportJWK(privateKey)
      jwk.alg = "ES256"

      const captured: Captured[] = []
      const fetch = fetchStub(
        [
          {
            match: (u) => u === TOKEN_ENDPOINT,
            respond: { body: { access_token: "x" } },
          },
        ],
        captured,
      )

      await requestTokenWithAssertion({
        issuer: ISSUER,
        audience: AUDIENCE,
        signingKey: jwk,
        tokenEndpoint: TOKEN_ENDPOINT,
        fetch,
      })

      const form = new URLSearchParams(captured[0]?.body ?? "")
      const claims = decodeJwt(form.get("assertion") as string)
      expect(claims.sub).toBe(ISSUER)
      expect(claims.iss).toBe(ISSUER)
    })

    it("act-as-user: sub is set to the supplied subject", async () => {
      const { privateKey } = await generateKeyPair("ES256", { extractable: true })
      const jwk = await exportJWK(privateKey)
      jwk.alg = "ES256"

      const captured: Captured[] = []
      const fetch = fetchStub(
        [
          {
            match: (u) => u === TOKEN_ENDPOINT,
            respond: { body: { access_token: "x" } },
          },
        ],
        captured,
      )

      await requestTokenWithAssertion({
        issuer: ISSUER,
        audience: AUDIENCE,
        signingKey: jwk,
        subject: "user-42",
        tokenEndpoint: TOKEN_ENDPOINT,
        fetch,
      })

      const form = new URLSearchParams(captured[0]?.body ?? "")
      const claims = decodeJwt(form.get("assertion") as string)
      expect(claims.sub).toBe("user-42")
      expect(claims.iss).toBe(ISSUER)
    })

    it("respects custom jti and assertionTtlSeconds", async () => {
      const { privateKey } = await generateKeyPair("ES256", { extractable: true })
      const jwk = await exportJWK(privateKey)
      jwk.alg = "ES256"

      const captured: Captured[] = []
      const fetch = fetchStub(
        [
          {
            match: (u) => u === TOKEN_ENDPOINT,
            respond: { body: { access_token: "x" } },
          },
        ],
        captured,
      )

      await requestTokenWithAssertion({
        issuer: ISSUER,
        audience: AUDIENCE,
        signingKey: jwk,
        jti: "fixed-jti",
        assertionTtlSeconds: 30,
        tokenEndpoint: TOKEN_ENDPOINT,
        fetch,
      })

      const form = new URLSearchParams(captured[0]?.body ?? "")
      const claims = decodeJwt(form.get("assertion") as string)
      expect(claims.jti).toBe("fixed-jti")
      expect((claims.exp as number) - (claims.iat as number)).toBe(30)
    })

    it("omits scope claim and form parameter when scopes are not provided", async () => {
      const { privateKey } = await generateKeyPair("ES256", { extractable: true })
      const jwk = await exportJWK(privateKey)
      jwk.alg = "ES256"

      const captured: Captured[] = []
      const fetch = fetchStub(
        [
          {
            match: (u) => u === TOKEN_ENDPOINT,
            respond: { body: { access_token: "x" } },
          },
        ],
        captured,
      )

      await requestTokenWithAssertion({
        issuer: ISSUER,
        audience: AUDIENCE,
        signingKey: jwk,
        tokenEndpoint: TOKEN_ENDPOINT,
        fetch,
      })

      const form = new URLSearchParams(captured[0]?.body ?? "")
      expect(form.has("scope")).toBe(false)
      const claims = decodeJwt(form.get("assertion") as string)
      expect(claims.scope).toBeUndefined()
    })
  })

  describe("signing key types", () => {
    it("accepts a JWK", async () => {
      const { privateKey } = await generateKeyPair("ES256", { extractable: true })
      const jwk = await exportJWK(privateKey)

      const fetch = fetchStub([
        {
          match: (u) => u === TOKEN_ENDPOINT,
          respond: { body: { access_token: "ok-jwk" } },
        },
      ])

      const result = await requestTokenWithAssertion({
        issuer: ISSUER,
        audience: AUDIENCE,
        signingKey: jwk,
        tokenEndpoint: TOKEN_ENDPOINT,
        fetch,
      })
      expect(result.accessToken).toBe("ok-jwk")
    })

    it("accepts a CryptoKey/KeyObject when alg is provided", async () => {
      const { privateKey } = await generateKeyPair("ES256", { extractable: true })

      const fetch = fetchStub([
        {
          match: (u) => u === TOKEN_ENDPOINT,
          respond: { body: { access_token: "ok-key" } },
        },
      ])

      const result = await requestTokenWithAssertion({
        issuer: ISSUER,
        audience: AUDIENCE,
        signingKey: privateKey,
        alg: "ES256",
        tokenEndpoint: TOKEN_ENDPOINT,
        fetch,
      })
      expect(result.accessToken).toBe("ok-key")
    })

    it("rejects a CryptoKey/KeyObject without an alg", async () => {
      const { privateKey } = await generateKeyPair("ES256", { extractable: true })
      const fetch = fetchStub([{ match: () => true, respond: { body: { access_token: "x" } } }])

      await expect(
        requestTokenWithAssertion({
          issuer: ISSUER,
          audience: AUDIENCE,
          signingKey: privateKey,
          tokenEndpoint: TOKEN_ENDPOINT,
          fetch,
        }),
      ).rejects.toMatchObject({ name: "JwtBearerError", reason: "key" })
    })

    it("accepts a Uint8Array (HS256 default)", async () => {
      const captured: Captured[] = []
      const fetch = fetchStub(
        [
          {
            match: (u) => u === TOKEN_ENDPOINT,
            respond: { body: { access_token: "ok-oct" } },
          },
        ],
        captured,
      )

      const secret = new Uint8Array(32).fill(7)
      const result = await requestTokenWithAssertion({
        issuer: ISSUER,
        audience: AUDIENCE,
        signingKey: secret,
        tokenEndpoint: TOKEN_ENDPOINT,
        fetch,
      })
      expect(result.accessToken).toBe("ok-oct")

      const form = new URLSearchParams(captured[0]?.body ?? "")
      const header = decodeProtectedHeader(form.get("assertion") as string)
      expect(header.alg).toBe("HS256")
    })

    it("derives alg from JWK.alg when present", async () => {
      const { privateKey } = await generateKeyPair("ES256", { extractable: true })
      const jwk = await exportJWK(privateKey)
      jwk.alg = "ES256"

      const captured: Captured[] = []
      const fetch = fetchStub(
        [
          {
            match: (u) => u === TOKEN_ENDPOINT,
            respond: { body: { access_token: "x" } },
          },
        ],
        captured,
      )

      await requestTokenWithAssertion({
        issuer: ISSUER,
        audience: AUDIENCE,
        signingKey: jwk,
        tokenEndpoint: TOKEN_ENDPOINT,
        fetch,
      })
      const form = new URLSearchParams(captured[0]?.body ?? "")
      const header = decodeProtectedHeader(form.get("assertion") as string)
      expect(header.alg).toBe("ES256")
    })

    it("infers alg from JWK kty/crv when alg is absent (RSA → RS256)", async () => {
      const { privateKey } = await generateKeyPair("RS256", { extractable: true })
      const jwk = await exportJWK(privateKey)
      // intentionally omit jwk.alg
      jwk.alg = undefined as unknown as string

      const captured: Captured[] = []
      const fetch = fetchStub(
        [
          {
            match: (u) => u === TOKEN_ENDPOINT,
            respond: { body: { access_token: "x" } },
          },
        ],
        captured,
      )

      await requestTokenWithAssertion({
        issuer: ISSUER,
        audience: AUDIENCE,
        signingKey: jwk,
        tokenEndpoint: TOKEN_ENDPOINT,
        fetch,
      })
      const form = new URLSearchParams(captured[0]?.body ?? "")
      const header = decodeProtectedHeader(form.get("assertion") as string)
      expect(header.alg).toBe("RS256")
    })
  })

  describe("RFC 8414 discovery", () => {
    it("discovers the token endpoint via oauth-authorization-server", async () => {
      const { privateKey } = await generateKeyPair("ES256", { extractable: true })
      const jwk = await exportJWK(privateKey)
      jwk.alg = "ES256"

      const captured: Captured[] = []
      const fetch = fetchStub(
        [
          {
            match: (u) => u === `${ISSUER}/.well-known/oauth-authorization-server`,
            respond: { body: { token_endpoint: TOKEN_ENDPOINT } },
          },
          {
            match: (u) => u === TOKEN_ENDPOINT,
            respond: { body: { access_token: "discovered" } },
          },
        ],
        captured,
      )

      const result = await requestTokenWithAssertion({
        issuer: ISSUER,
        audience: AUDIENCE,
        signingKey: jwk,
        fetch,
      })
      expect(result.accessToken).toBe("discovered")
      expect(captured[0]?.url).toBe(`${ISSUER}/.well-known/oauth-authorization-server`)
      expect(captured[1]?.url).toBe(TOKEN_ENDPOINT)
    })

    it("falls back to openid-configuration when oauth-authorization-server fails", async () => {
      const { privateKey } = await generateKeyPair("ES256", { extractable: true })
      const jwk = await exportJWK(privateKey)
      jwk.alg = "ES256"

      const fetch = fetchStub([
        {
          match: (u) => u === `${ISSUER}/.well-known/oauth-authorization-server`,
          respond: { status: 404, body: {} },
        },
        {
          match: (u) => u === `${ISSUER}/.well-known/openid-configuration`,
          respond: { body: { token_endpoint: TOKEN_ENDPOINT } },
        },
        {
          match: (u) => u === TOKEN_ENDPOINT,
          respond: { body: { access_token: "fallback" } },
        },
      ])

      const result = await requestTokenWithAssertion({
        issuer: ISSUER,
        audience: AUDIENCE,
        signingKey: jwk,
        fetch,
      })
      expect(result.accessToken).toBe("fallback")
    })

    it("throws JwtBearerError(reason=discovery) when both metadata URLs fail", async () => {
      const { privateKey } = await generateKeyPair("ES256", { extractable: true })
      const jwk = await exportJWK(privateKey)
      jwk.alg = "ES256"

      const fetch = fetchStub([
        {
          match: () => true,
          respond: { status: 404, body: {} },
        },
      ])

      await expect(
        requestTokenWithAssertion({
          issuer: ISSUER,
          audience: AUDIENCE,
          signingKey: jwk,
          fetch,
        }),
      ).rejects.toMatchObject({ name: "JwtBearerError", reason: "discovery" })
    })

    it("trims a trailing slash on the issuer when composing well-known URLs", async () => {
      const { privateKey } = await generateKeyPair("ES256", { extractable: true })
      const jwk = await exportJWK(privateKey)
      jwk.alg = "ES256"

      const captured: Captured[] = []
      const fetch = fetchStub(
        [
          {
            match: (u) => u === `${ISSUER}/.well-known/oauth-authorization-server`,
            respond: { body: { token_endpoint: TOKEN_ENDPOINT } },
          },
          {
            match: (u) => u === TOKEN_ENDPOINT,
            respond: { body: { access_token: "ok" } },
          },
        ],
        captured,
      )

      await requestTokenWithAssertion({
        issuer: `${ISSUER}/`,
        audience: AUDIENCE,
        signingKey: jwk,
        fetch,
      })
      expect(captured[0]?.url).toBe(`${ISSUER}/.well-known/oauth-authorization-server`)
    })
  })

  describe("token endpoint response handling", () => {
    it("surfaces AS error JSON as a typed JwtBearerError(reason=as-error)", async () => {
      const { privateKey } = await generateKeyPair("ES256", { extractable: true })
      const jwk = await exportJWK(privateKey)
      jwk.alg = "ES256"

      const fetch = fetchStub([
        {
          match: (u) => u === TOKEN_ENDPOINT,
          respond: {
            status: 400,
            body: { error: "invalid_grant", error_description: "assertion expired" },
          },
        },
      ])

      let caught: unknown
      try {
        await requestTokenWithAssertion({
          issuer: ISSUER,
          audience: AUDIENCE,
          signingKey: jwk,
          tokenEndpoint: TOKEN_ENDPOINT,
          fetch,
        })
      } catch (err) {
        caught = err
      }
      expect(caught).toBeInstanceOf(JwtBearerError)
      const err = caught as JwtBearerError
      expect(err.reason).toBe("as-error")
      expect(err.oauthError).toBe("invalid_grant")
      expect(err.oauthErrorDescription).toBe("assertion expired")
      expect(err.httpStatus).toBe(400)
    })

    it("throws invalid-response when access_token is missing", async () => {
      const { privateKey } = await generateKeyPair("ES256", { extractable: true })
      const jwk = await exportJWK(privateKey)
      jwk.alg = "ES256"

      const fetch = fetchStub([
        {
          match: (u) => u === TOKEN_ENDPOINT,
          respond: { body: { token_type: "Bearer" } },
        },
      ])

      await expect(
        requestTokenWithAssertion({
          issuer: ISSUER,
          audience: AUDIENCE,
          signingKey: jwk,
          tokenEndpoint: TOKEN_ENDPOINT,
          fetch,
        }),
      ).rejects.toMatchObject({ name: "JwtBearerError", reason: "invalid-response" })
    })

    it("uses scope from the AS response when present", async () => {
      const { privateKey } = await generateKeyPair("ES256", { extractable: true })
      const jwk = await exportJWK(privateKey)
      jwk.alg = "ES256"

      const fetch = fetchStub([
        {
          match: (u) => u === TOKEN_ENDPOINT,
          respond: { body: { access_token: "x", scope: "granted:a granted:b" } },
        },
      ])

      const result = await requestTokenWithAssertion({
        issuer: ISSUER,
        audience: AUDIENCE,
        signingKey: jwk,
        scopes: ["asked:a", "asked:b"],
        tokenEndpoint: TOKEN_ENDPOINT,
        fetch,
      })
      expect(result.scopes).toEqual(["granted:a", "granted:b"])
    })

    it("returns expiresAt=null when expires_in is omitted", async () => {
      const { privateKey } = await generateKeyPair("ES256", { extractable: true })
      const jwk = await exportJWK(privateKey)
      jwk.alg = "ES256"

      const fetch = fetchStub([
        {
          match: (u) => u === TOKEN_ENDPOINT,
          respond: { body: { access_token: "x" } },
        },
      ])

      const result = await requestTokenWithAssertion({
        issuer: ISSUER,
        audience: AUDIENCE,
        signingKey: jwk,
        tokenEndpoint: TOKEN_ENDPOINT,
        fetch,
      })
      expect(result.expiresAt).toBeNull()
    })

    it("wraps transport errors with reason=transport", async () => {
      const { privateKey } = await generateKeyPair("ES256", { extractable: true })
      const jwk = await exportJWK(privateKey)
      jwk.alg = "ES256"

      const fetch: FetchLike = vi.fn(async () => {
        throw new Error("connection refused")
      })

      let caught: unknown
      try {
        await requestTokenWithAssertion({
          issuer: ISSUER,
          audience: AUDIENCE,
          signingKey: jwk,
          tokenEndpoint: TOKEN_ENDPOINT,
          fetch,
        })
      } catch (err) {
        caught = err
      }
      expect(caught).toBeInstanceOf(JwtBearerError)
      expect((caught as JwtBearerError).reason).toBe("transport")
    })
  })
})
