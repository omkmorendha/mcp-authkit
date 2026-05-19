/**
 * Tests for RFC 7591 Dynamic Client Registration consumer.
 *
 * Spec: docs/spec/v0.2.md#52-dynamic-client-registration-rfc-7591 and §12.
 */
import { Writable } from "node:stream"
import pino from "pino"
import { afterEach, describe, expect, it, vi } from "vitest"
import { _clearMetadataCache, type FetchLike, OAuthError, registerClient } from "./dcr.js"

const ISSUER = "https://as.example.test"
const METADATA_URL = `${ISSUER}/.well-known/oauth-authorization-server`
const REGISTRATION_URL = "https://as.example.test/oauth/register"

interface MockInit {
  status?: number
  body?: unknown
  throwOnJson?: boolean
}

function mockResponse(init: MockInit = {}) {
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

function metadataResponse(extra: Record<string, unknown> = {}) {
  return mockResponse({
    body: {
      issuer: ISSUER,
      registration_endpoint: REGISTRATION_URL,
      ...extra,
    },
  })
}

afterEach(() => {
  _clearMetadataCache()
  vi.restoreAllMocks()
})

describe("registerClient", () => {
  describe("happy path", () => {
    it("registers without an initial access token", async () => {
      const fetchMock = vi
        .fn<FetchLike>()
        .mockResolvedValueOnce(metadataResponse())
        .mockResolvedValueOnce(
          mockResponse({
            body: {
              client_id: "client-abc",
              client_secret: "secret-xyz",
              client_id_issued_at: 1_700_000_000,
            },
          }),
        )

      const result = await registerClient({
        issuer: ISSUER,
        metadata: { client_name: "my-app", redirect_uris: ["https://app.example/cb"] },
        fetch: fetchMock,
      })

      expect(result.client_id).toBe("client-abc")
      expect(result.client_secret).toBe("secret-xyz")
      expect(result.client_id_issued_at).toBe(1_700_000_000)

      expect(fetchMock).toHaveBeenCalledTimes(2)
      const [metadataCall, registerCall] = fetchMock.mock.calls
      expect(metadataCall?.[0]).toBe(METADATA_URL)
      expect(metadataCall?.[1]?.method).toBe("GET")

      expect(registerCall?.[0]).toBe(REGISTRATION_URL)
      expect(registerCall?.[1]?.method).toBe("POST")
      expect(registerCall?.[1]?.headers?.["Content-Type"]).toBe("application/json")
      expect(registerCall?.[1]?.headers?.Accept).toBe("application/json")
      // No Authorization header when initialAccessToken is omitted.
      expect(registerCall?.[1]?.headers?.Authorization).toBeUndefined()

      const sentBody = JSON.parse(registerCall?.[1]?.body ?? "{}") as Record<string, unknown>
      expect(sentBody.client_name).toBe("my-app")
      expect(sentBody.redirect_uris).toEqual(["https://app.example/cb"])
    })

    it("sends initial access token as a Bearer credential", async () => {
      const fetchMock = vi
        .fn<FetchLike>()
        .mockResolvedValueOnce(metadataResponse())
        .mockResolvedValueOnce(mockResponse({ body: { client_id: "c1" } }))

      await registerClient({
        issuer: ISSUER,
        initialAccessToken: "iat-secret-value",
        metadata: { client_name: "n" },
        fetch: fetchMock,
      })

      const registerCall = fetchMock.mock.calls[1]
      expect(registerCall?.[1]?.headers?.Authorization).toBe("Bearer iat-secret-value")
    })

    it("trims trailing slashes from issuer when building the metadata URL", async () => {
      const fetchMock = vi
        .fn<FetchLike>()
        .mockResolvedValueOnce(metadataResponse())
        .mockResolvedValueOnce(mockResponse({ body: { client_id: "c" } }))

      await registerClient({
        issuer: `${ISSUER}//`,
        metadata: { client_name: "n" },
        fetch: fetchMock,
      })

      const metadataCall = fetchMock.mock.calls[0]
      expect(metadataCall?.[0]).toBe(METADATA_URL)
    })

    it("caches AS metadata per issuer across calls", async () => {
      const fetchMock = vi
        .fn<FetchLike>()
        .mockResolvedValueOnce(metadataResponse())
        .mockResolvedValueOnce(mockResponse({ body: { client_id: "c1" } }))
        .mockResolvedValueOnce(mockResponse({ body: { client_id: "c2" } }))

      await registerClient({ issuer: ISSUER, metadata: {}, fetch: fetchMock })
      await registerClient({ issuer: ISSUER, metadata: {}, fetch: fetchMock })

      // metadata fetched once, register fetched twice
      expect(fetchMock).toHaveBeenCalledTimes(3)
      expect(fetchMock.mock.calls[0]?.[0]).toBe(METADATA_URL)
      expect(fetchMock.mock.calls[1]?.[0]).toBe(REGISTRATION_URL)
      expect(fetchMock.mock.calls[2]?.[0]).toBe(REGISTRATION_URL)
    })

    it("passes an AbortSignal with the configured timeout", async () => {
      const fetchMock = vi
        .fn<FetchLike>()
        .mockResolvedValueOnce(metadataResponse())
        .mockResolvedValueOnce(mockResponse({ body: { client_id: "c" } }))

      await registerClient({
        issuer: ISSUER,
        metadata: {},
        timeoutMs: 5_000,
        fetch: fetchMock,
      })

      for (const call of fetchMock.mock.calls) {
        expect(call?.[1]?.signal).toBeInstanceOf(AbortSignal)
      }
    })
  })

  describe("AS error responses", () => {
    it("throws an OAuthError with kind=as_error on a structured 400 error", async () => {
      const fetchMock = vi
        .fn<FetchLike>()
        .mockResolvedValueOnce(metadataResponse())
        .mockResolvedValueOnce(
          mockResponse({
            status: 400,
            body: {
              error: "invalid_redirect_uri",
              error_description: "redirect_uri must use https",
            },
          }),
        )

      await expect(
        registerClient({ issuer: ISSUER, metadata: {}, fetch: fetchMock }),
      ).rejects.toMatchObject({
        name: "OAuthError",
        kind: "as_error",
        error: "invalid_redirect_uri",
        errorDescription: "redirect_uri must use https",
        status: 400,
      })
    })

    it("falls back to error code when error_description is missing", async () => {
      const fetchMock = vi
        .fn<FetchLike>()
        .mockResolvedValueOnce(metadataResponse())
        .mockResolvedValueOnce(
          mockResponse({ status: 400, body: { error: "invalid_client_metadata" } }),
        )

      const err = await registerClient({
        issuer: ISSUER,
        metadata: {},
        fetch: fetchMock,
      }).catch((e) => e)

      expect(err).toBeInstanceOf(OAuthError)
      expect((err as OAuthError).kind).toBe("as_error")
      expect((err as OAuthError).error).toBe("invalid_client_metadata")
      expect((err as OAuthError).message).toBe("invalid_client_metadata")
      expect((err as OAuthError).errorDescription).toBeUndefined()
    })

    it("treats an unstructured 5xx body as a transport error", async () => {
      const fetchMock = vi
        .fn<FetchLike>()
        .mockResolvedValueOnce(metadataResponse())
        .mockResolvedValueOnce(mockResponse({ status: 502, throwOnJson: true }))

      await expect(
        registerClient({ issuer: ISSUER, metadata: {}, fetch: fetchMock }),
      ).rejects.toMatchObject({
        name: "OAuthError",
        kind: "transport",
        status: 502,
      })
    })

    it("treats network failures during registration as transport errors", async () => {
      const fetchMock = vi
        .fn<FetchLike>()
        .mockResolvedValueOnce(metadataResponse())
        .mockRejectedValueOnce(new Error("ECONNRESET"))

      await expect(
        registerClient({ issuer: ISSUER, metadata: {}, fetch: fetchMock }),
      ).rejects.toMatchObject({
        name: "OAuthError",
        kind: "transport",
      })
    })
  })

  describe("invalid responses", () => {
    it("throws when the response is missing client_id", async () => {
      const fetchMock = vi
        .fn<FetchLike>()
        .mockResolvedValueOnce(metadataResponse())
        .mockResolvedValueOnce(mockResponse({ body: { client_secret: "secret-only" } }))

      await expect(
        registerClient({ issuer: ISSUER, metadata: {}, fetch: fetchMock }),
      ).rejects.toMatchObject({
        kind: "invalid_response",
        message: expect.stringContaining("client_id"),
      })
    })

    it("throws when the response body is not a JSON object", async () => {
      const fetchMock = vi
        .fn<FetchLike>()
        .mockResolvedValueOnce(metadataResponse())
        .mockResolvedValueOnce(mockResponse({ body: ["unexpected", "array"] }))

      await expect(
        registerClient({ issuer: ISSUER, metadata: {}, fetch: fetchMock }),
      ).rejects.toMatchObject({ kind: "invalid_response" })
    })

    it("throws when the response body is not valid JSON", async () => {
      const fetchMock = vi
        .fn<FetchLike>()
        .mockResolvedValueOnce(metadataResponse())
        .mockResolvedValueOnce(mockResponse({ throwOnJson: true }))

      await expect(
        registerClient({ issuer: ISSUER, metadata: {}, fetch: fetchMock }),
      ).rejects.toMatchObject({ kind: "invalid_response" })
    })
  })

  describe("discovery errors", () => {
    it("throws kind=discovery when metadata fetch returns non-2xx", async () => {
      const fetchMock = vi.fn<FetchLike>().mockResolvedValueOnce(mockResponse({ status: 404 }))

      await expect(
        registerClient({ issuer: ISSUER, metadata: {}, fetch: fetchMock }),
      ).rejects.toMatchObject({ kind: "discovery", status: 404 })
    })

    it("throws kind=discovery when metadata lacks registration_endpoint", async () => {
      const fetchMock = vi
        .fn<FetchLike>()
        .mockResolvedValueOnce(mockResponse({ body: { issuer: ISSUER } }))

      await expect(
        registerClient({ issuer: ISSUER, metadata: {}, fetch: fetchMock }),
      ).rejects.toMatchObject({ kind: "discovery" })
    })

    it("throws kind=discovery on network failure during discovery", async () => {
      const fetchMock = vi.fn<FetchLike>().mockRejectedValueOnce(new Error("ENOTFOUND"))

      await expect(
        registerClient({ issuer: ISSUER, metadata: {}, fetch: fetchMock }),
      ).rejects.toMatchObject({ kind: "discovery" })
    })

    it("evicts the cache after a failed discovery so the next call retries", async () => {
      const fetchMock = vi
        .fn<FetchLike>()
        .mockResolvedValueOnce(mockResponse({ status: 503 }))
        .mockResolvedValueOnce(metadataResponse())
        .mockResolvedValueOnce(mockResponse({ body: { client_id: "c" } }))

      await expect(
        registerClient({ issuer: ISSUER, metadata: {}, fetch: fetchMock }),
      ).rejects.toMatchObject({ kind: "discovery" })

      const result = await registerClient({ issuer: ISSUER, metadata: {}, fetch: fetchMock })
      expect(result.client_id).toBe("c")
      expect(fetchMock).toHaveBeenCalledTimes(3)
    })
  })

  describe("security (spec §12)", () => {
    it("never logs the initial access token at any pino level", async () => {
      const captured: string[] = []
      const sink = new Writable({
        write(chunk: Buffer | string, _enc, cb) {
          captured.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"))
          cb()
        },
      })
      const logger = pino({ level: "trace" }, sink)

      const secret = "INITIAL-ACCESS-TOKEN-do-not-leak-1234"

      // Surround the registration with logger calls at every level. If
      // dcr.ts ever wrote the token to a shared logger this test would
      // observe it on `captured`.
      logger.trace({ event: "before-register" }, "starting registration")
      const fetchMock = vi
        .fn<FetchLike>()
        .mockResolvedValueOnce(metadataResponse())
        .mockResolvedValueOnce(mockResponse({ body: { client_id: "c1" } }))

      await registerClient({
        issuer: ISSUER,
        initialAccessToken: secret,
        metadata: { client_name: "n" },
        fetch: fetchMock,
      })

      logger.info({ event: "after-register" }, "done")
      logger.flush()
      await new Promise<void>((r) => setImmediate(r))

      const allOutput = captured.join("")
      expect(allOutput).not.toContain(secret)
    })

    it("does not embed the initial access token in OAuthError fields it constructs", async () => {
      const secret = "another-leak-canary-XYZ"
      const fetchMock = vi
        .fn<FetchLike>()
        .mockResolvedValueOnce(metadataResponse())
        .mockResolvedValueOnce(
          mockResponse({
            status: 400,
            body: { error: "invalid_client_metadata", error_description: "bad redirect" },
          }),
        )

      const err = await registerClient({
        issuer: ISSUER,
        initialAccessToken: secret,
        metadata: {},
        fetch: fetchMock,
      }).catch((e) => e as OAuthError)

      expect(err).toBeInstanceOf(OAuthError)
      expect(err.kind).toBe("as_error")
      expect(err.message).not.toContain(secret)
      expect(err.error ?? "").not.toContain(secret)
      expect(err.errorDescription ?? "").not.toContain(secret)
      expect(JSON.stringify(err)).not.toContain(secret)
    })

    it("sends the initial access token only via the Authorization header", async () => {
      const fetchMock = vi
        .fn<FetchLike>()
        .mockResolvedValueOnce(metadataResponse())
        .mockResolvedValueOnce(mockResponse({ body: { client_id: "c" } }))

      const secret = "leak-canary-abc-XYZ"
      await registerClient({
        issuer: ISSUER,
        initialAccessToken: secret,
        metadata: { client_name: "n" },
        fetch: fetchMock,
      })

      const registerCall = fetchMock.mock.calls[1]
      // Authorization is the only place the token appears in the request init.
      expect(registerCall?.[1]?.headers?.Authorization).toBe(`Bearer ${secret}`)
      expect(registerCall?.[1]?.body ?? "").not.toContain(secret)
      const metadataCall = fetchMock.mock.calls[0]
      expect(metadataCall?.[1]?.headers?.Authorization).toBeUndefined()
    })
  })
})
