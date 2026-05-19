import { createHash } from "node:crypto"
import { describe, expect, it, vi } from "vitest"
import {
  createIntrospectionValidator,
  type FetchLike,
  type IntrospectionValidator,
} from "./introspection.js"

const ENDPOINT = "https://as.example.test/oauth/introspect"
const AUDIENCE = "https://mcp.example.test/"

interface MockResponseInit {
  status?: number
  body?: unknown
  bodyText?: string
  throwOnJson?: boolean
}

function mockResponse(init: MockResponseInit = {}) {
  const status = init.status ?? 200
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() {
      if (init.throwOnJson) throw new Error("invalid json")
      return init.body
    },
    async text() {
      return init.bodyText ?? ""
    },
  }
}

function makeValidator(fetchImpl: FetchLike): IntrospectionValidator {
  return createIntrospectionValidator({
    introspectionEndpoint: ENDPOINT,
    audience: AUDIENCE,
    fetch: fetchImpl,
  })
}

const farFuture = () => Math.floor(Date.now() / 1000) + 3600
const farPast = () => Math.floor(Date.now() / 1000) - 3600

describe("createIntrospectionValidator", () => {
  describe("happy path", () => {
    it("accepts an active response and populates AuthContext", async () => {
      const fetchMock = vi.fn<FetchLike>().mockResolvedValue(
        mockResponse({
          body: {
            active: true,
            sub: "user-123",
            aud: AUDIENCE,
            scope: "read:profile  write:posts",
            jti: "jti-abc",
            exp: farFuture(),
          },
        }),
      )
      const validator = makeValidator(fetchMock)

      const result = await validator.validate("opaque-token-value")
      expect(result.ok).toBe(true)
      if (!result.ok) return
      expect(result.auth.subject).toBe("user-123")
      expect(result.auth.tokenType).toBe("oauth")
      expect(result.auth.tokenId).toBe("jti-abc")
      expect(result.auth.scopes).toEqual(["read:profile", "write:posts"])
      expect(result.auth.expiresAt).toBeInstanceOf(Date)
      expect(result.auth.raw.sub).toBe("user-123")
    })

    it("POSTs token as application/x-www-form-urlencoded with Accept JSON", async () => {
      const fetchMock = vi
        .fn<FetchLike>()
        .mockResolvedValue(mockResponse({ body: { active: true, sub: "u", aud: AUDIENCE } }))
      const validator = makeValidator(fetchMock)
      await validator.validate("tok en+/=")

      expect(fetchMock).toHaveBeenCalledTimes(1)
      const [url, init] = fetchMock.mock.calls[0] ?? []
      expect(url).toBe(ENDPOINT)
      expect(init?.method).toBe("POST")
      expect(init?.headers?.["Content-Type"]).toBe("application/x-www-form-urlencoded")
      expect(init?.headers?.Accept).toBe("application/json")
      expect(init?.body).toBe(`token=${encodeURIComponent("tok en+/=")}`)
    })

    it("accepts array aud when one entry matches", async () => {
      const fetchMock = vi.fn<FetchLike>().mockResolvedValue(
        mockResponse({
          body: { active: true, sub: "u", aud: ["other", AUDIENCE, "another"] },
        }),
      )
      const result = await makeValidator(fetchMock).validate("t")
      expect(result.ok).toBe(true)
    })

    it("falls back to SHA-256 token id when jti is missing", async () => {
      const fetchMock = vi
        .fn<FetchLike>()
        .mockResolvedValue(mockResponse({ body: { active: true, sub: "u", aud: AUDIENCE } }))
      const token = "raw-token-xyz"
      const result = await makeValidator(fetchMock).validate(token)
      expect(result.ok).toBe(true)
      if (!result.ok) return
      const expected = createHash("sha256").update(token).digest("hex")
      expect(result.auth.tokenId).toBe(expected)
    })

    it("expiresAt is null when exp is absent", async () => {
      const fetchMock = vi
        .fn<FetchLike>()
        .mockResolvedValue(mockResponse({ body: { active: true, sub: "u", aud: AUDIENCE } }))
      const result = await makeValidator(fetchMock).validate("t")
      expect(result.ok).toBe(true)
      if (!result.ok) return
      expect(result.auth.expiresAt).toBeNull()
    })
  })

  describe("rejections", () => {
    it("rejects empty token before calling fetch", async () => {
      const fetchMock = vi.fn<FetchLike>()
      const result = await makeValidator(fetchMock).validate("")
      expect(result.ok).toBe(false)
      if (result.ok) return
      expect(result.reason).toBe("malformed")
      expect(fetchMock).not.toHaveBeenCalled()
    })

    it("rejects when active is false", async () => {
      const fetchMock = vi
        .fn<FetchLike>()
        .mockResolvedValue(mockResponse({ body: { active: false } }))
      const result = await makeValidator(fetchMock).validate("t")
      expect(result.ok).toBe(false)
      if (result.ok) return
      expect(result.reason).toBe("inactive")
    })

    it("rejects when active is missing", async () => {
      const fetchMock = vi
        .fn<FetchLike>()
        .mockResolvedValue(mockResponse({ body: { sub: "u", aud: AUDIENCE } }))
      const result = await makeValidator(fetchMock).validate("t")
      expect(result.ok).toBe(false)
      if (result.ok) return
      expect(result.reason).toBe("inactive")
    })

    it("rejects when active is truthy but not the boolean true", async () => {
      const fetchMock = vi
        .fn<FetchLike>()
        .mockResolvedValue(mockResponse({ body: { active: "true", sub: "u", aud: AUDIENCE } }))
      const result = await makeValidator(fetchMock).validate("t")
      expect(result.ok).toBe(false)
      if (result.ok) return
      expect(result.reason).toBe("inactive")
    })

    it("rejects wrong audience (string form)", async () => {
      const fetchMock = vi
        .fn<FetchLike>()
        .mockResolvedValue(mockResponse({ body: { active: true, sub: "u", aud: "https://evil/" } }))
      const result = await makeValidator(fetchMock).validate("t")
      expect(result.ok).toBe(false)
      if (result.ok) return
      expect(result.reason).toBe("audience")
    })

    it("rejects wrong audience (array form, no match)", async () => {
      const fetchMock = vi
        .fn<FetchLike>()
        .mockResolvedValue(mockResponse({ body: { active: true, sub: "u", aud: ["a", "b"] } }))
      const result = await makeValidator(fetchMock).validate("t")
      expect(result.ok).toBe(false)
      if (result.ok) return
      expect(result.reason).toBe("audience")
    })

    it("rejects missing audience", async () => {
      const fetchMock = vi
        .fn<FetchLike>()
        .mockResolvedValue(mockResponse({ body: { active: true, sub: "u" } }))
      const result = await makeValidator(fetchMock).validate("t")
      expect(result.ok).toBe(false)
      if (result.ok) return
      expect(result.reason).toBe("audience")
    })

    it("rejects expired token (exp in the past)", async () => {
      const fetchMock = vi.fn<FetchLike>().mockResolvedValue(
        mockResponse({
          body: { active: true, sub: "u", aud: AUDIENCE, exp: farPast() },
        }),
      )
      const result = await makeValidator(fetchMock).validate("t")
      expect(result.ok).toBe(false)
      if (result.ok) return
      expect(result.reason).toBe("expired")
    })

    it("rejects not-yet-valid token (nbf in the future)", async () => {
      const fetchMock = vi.fn<FetchLike>().mockResolvedValue(
        mockResponse({
          body: { active: true, sub: "u", aud: AUDIENCE, nbf: farFuture() },
        }),
      )
      const result = await makeValidator(fetchMock).validate("t")
      expect(result.ok).toBe(false)
      if (result.ok) return
      expect(result.reason).toBe("not-yet-valid")
    })

    it("rejects when sub is missing", async () => {
      const fetchMock = vi
        .fn<FetchLike>()
        .mockResolvedValue(mockResponse({ body: { active: true, aud: AUDIENCE } }))
      const result = await makeValidator(fetchMock).validate("t")
      expect(result.ok).toBe(false)
      if (result.ok) return
      expect(result.reason).toBe("claims")
    })

    it("treats network errors as transport rejections (no throw)", async () => {
      const fetchMock = vi.fn<FetchLike>().mockRejectedValue(new Error("ECONNREFUSED"))
      const result = await makeValidator(fetchMock).validate("t")
      expect(result.ok).toBe(false)
      if (result.ok) return
      expect(result.reason).toBe("transport")
    })

    it("treats non-2xx responses as transport rejections", async () => {
      const fetchMock = vi
        .fn<FetchLike>()
        .mockResolvedValue(mockResponse({ status: 500, bodyText: "boom" }))
      const result = await makeValidator(fetchMock).validate("t")
      expect(result.ok).toBe(false)
      if (result.ok) return
      expect(result.reason).toBe("transport")
    })

    it("treats 401 from the AS as transport rejection (no retry, no fallback)", async () => {
      const fetchMock = vi.fn<FetchLike>().mockResolvedValue(mockResponse({ status: 401 }))
      const result = await makeValidator(fetchMock).validate("t")
      expect(result.ok).toBe(false)
      if (result.ok) return
      expect(result.reason).toBe("transport")
      expect(fetchMock).toHaveBeenCalledTimes(1)
    })

    it("treats invalid JSON as transport rejection", async () => {
      const fetchMock = vi.fn<FetchLike>().mockResolvedValue(mockResponse({ throwOnJson: true }))
      const result = await makeValidator(fetchMock).validate("t")
      expect(result.ok).toBe(false)
      if (result.ok) return
      expect(result.reason).toBe("transport")
    })

    it("treats non-object response body as transport rejection", async () => {
      const fetchMock = vi
        .fn<FetchLike>()
        .mockResolvedValue(mockResponse({ body: ["not", "an", "object"] }))
      const result = await makeValidator(fetchMock).validate("t")
      expect(result.ok).toBe(false)
      if (result.ok) return
      expect(result.reason).toBe("transport")
    })
  })

  describe("security (spec §14)", () => {
    it("does not echo the presented token in error messages", async () => {
      const secret = "super-secret-token-DO-NOT-LEAK"
      const fetchMock = vi
        .fn<FetchLike>()
        .mockResolvedValue(mockResponse({ body: { active: true, sub: "u", aud: "wrong" } }))
      const result = await makeValidator(fetchMock).validate(secret)
      expect(result.ok).toBe(false)
      if (result.ok) return
      expect(result.message).not.toContain(secret)
    })

    it("never accepts a response whose aud doesn't match resourceIndicator", async () => {
      // Belt-and-suspenders for spec §14: confirm audience check fires even
      // when every other field is plausible.
      const fetchMock = vi.fn<FetchLike>().mockResolvedValue(
        mockResponse({
          body: {
            active: true,
            sub: "u",
            aud: "https://other-resource.example/",
            scope: "admin",
            exp: farFuture(),
          },
        }),
      )
      const result = await makeValidator(fetchMock).validate("t")
      expect(result.ok).toBe(false)
      if (result.ok) return
      expect(result.reason).toBe("audience")
    })
  })
})
