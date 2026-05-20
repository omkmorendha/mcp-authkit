/**
 * Tests for `registerClient` (RFC 7591 Dynamic Client Registration).
 *
 * Spec: docs/spec/v0.2.md#52-dynamic-client-registration-rfc-7591 and
 * docs/spec/v0.2.md#12-security-non-negotiables-additions
 * ("DCR initial-access-token handling").
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import {
  __clearDcrMetadataCache,
  DCR_LOG_REDACT_PATHS,
  DcrError,
  type DcrLogger,
  type FetchLike,
  type RegisteredClient,
  registerClient,
} from "./dcr.js"

const ISSUER = "https://as.example.test"
const METADATA_URL = `${ISSUER}/.well-known/oauth-authorization-server`
const REGISTRATION_URL = `${ISSUER}/oauth/register`
const INITIAL_ACCESS_TOKEN = "iat-supersecret-do-not-log-me-XYZ"
const REGISTRATION_ACCESS_TOKEN = "rat-supersecret-do-not-log-me-ABC"

interface MockResponseInit {
  status?: number
  body?: unknown
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
      return ""
    },
  }
}

interface RecordedCall {
  url: string
  method?: string
  headers?: Record<string, string>
  body?: string
  signal?: AbortSignal
}

function recordingFetch(routes: Record<string, () => ReturnType<FetchLike>>): {
  fetch: FetchLike
  calls: RecordedCall[]
} {
  const calls: RecordedCall[] = []
  const fetch: FetchLike = vi.fn(async (url, init) => {
    const key = String(url)
    const headers = init?.headers
    const headersCopy = headers !== undefined ? { ...headers } : undefined
    calls.push({
      url: key,
      ...(init?.method !== undefined ? { method: init.method } : {}),
      ...(headersCopy !== undefined ? { headers: headersCopy } : {}),
      ...(init?.body !== undefined ? { body: init.body } : {}),
      ...(init?.signal !== undefined ? { signal: init.signal } : {}),
    })
    for (const [needle, handler] of Object.entries(routes)) {
      if (key.includes(needle)) return handler()
    }
    throw new Error(`unexpected url: ${key}`)
  })
  return { fetch, calls }
}

const VALID_METADATA = Object.freeze({
  client_name: "test-mcp",
  redirect_uris: Object.freeze(["https://app.example.test/callback"]),
  grant_types: Object.freeze(["authorization_code"]),
})

const SUCCESS_BODY: RegisteredClient = {
  client_id: "c-12345",
  client_secret: "s-shhh",
  client_id_issued_at: 1_700_000_000,
  registration_access_token: REGISTRATION_ACCESS_TOKEN,
  registration_client_uri: `${ISSUER}/oauth/register/c-12345`,
}

beforeEach(() => {
  __clearDcrMetadataCache()
})

describe("registerClient — happy path", () => {
  it("discovers registration_endpoint and POSTs metadata as JSON", async () => {
    const { fetch, calls } = recordingFetch({
      "/.well-known/oauth-authorization-server": () =>
        Promise.resolve(mockResponse({ body: { registration_endpoint: REGISTRATION_URL } })),
      "/oauth/register": () => Promise.resolve(mockResponse({ status: 201, body: SUCCESS_BODY })),
    })

    const result = await registerClient({
      issuer: ISSUER,
      metadata: VALID_METADATA,
      fetch,
    })

    expect(result.client_id).toBe("c-12345")
    expect(result.client_secret).toBe("s-shhh")
    expect(result.registration_access_token).toBe(REGISTRATION_ACCESS_TOKEN)

    const discovery = calls.find((c) => c.url === METADATA_URL)
    const register = calls.find((c) => c.url === REGISTRATION_URL)
    expect(discovery?.method ?? "GET").toBe("GET")
    expect(register?.method).toBe("POST")
    expect(register?.headers?.["Content-Type"]).toBe("application/json")
    expect(register?.headers?.Accept).toBe("application/json")
    // No Authorization header when initialAccessToken is not supplied.
    expect(register?.headers?.Authorization).toBeUndefined()

    expect(register?.body).toBeDefined()
    const parsedBody = JSON.parse(register?.body ?? "{}") as Record<string, unknown>
    expect(parsedBody.client_name).toBe("test-mcp")
    expect(parsedBody.redirect_uris).toEqual(["https://app.example.test/callback"])
    expect(parsedBody.grant_types).toEqual(["authorization_code"])
  })

  it("sends Authorization: Bearer when initialAccessToken is supplied", async () => {
    const { fetch, calls } = recordingFetch({
      "/.well-known/oauth-authorization-server": () =>
        Promise.resolve(mockResponse({ body: { registration_endpoint: REGISTRATION_URL } })),
      "/oauth/register": () => Promise.resolve(mockResponse({ status: 201, body: SUCCESS_BODY })),
    })

    await registerClient({
      issuer: ISSUER,
      initialAccessToken: INITIAL_ACCESS_TOKEN,
      metadata: VALID_METADATA,
      fetch,
    })

    const register = calls.find((c) => c.url === REGISTRATION_URL)
    expect(register?.headers?.Authorization).toBe(`Bearer ${INITIAL_ACCESS_TOKEN}`)
  })

  it("skips discovery when registrationEndpoint is provided", async () => {
    const { fetch, calls } = recordingFetch({
      "/oauth/register": () => Promise.resolve(mockResponse({ status: 201, body: SUCCESS_BODY })),
    })

    const result = await registerClient({
      issuer: ISSUER,
      metadata: VALID_METADATA,
      registrationEndpoint: REGISTRATION_URL,
      fetch,
    })

    expect(result.client_id).toBe("c-12345")
    // No discovery call.
    expect(calls.find((c) => c.url.includes(".well-known"))).toBeUndefined()
    expect(calls).toHaveLength(1)
  })

  it("caches discovery results per-issuer (single GET across two calls)", async () => {
    const { fetch, calls } = recordingFetch({
      "/.well-known/oauth-authorization-server": () =>
        Promise.resolve(mockResponse({ body: { registration_endpoint: REGISTRATION_URL } })),
      "/oauth/register": () => Promise.resolve(mockResponse({ status: 201, body: SUCCESS_BODY })),
    })

    await registerClient({ issuer: ISSUER, metadata: VALID_METADATA, fetch })
    await registerClient({ issuer: ISSUER, metadata: VALID_METADATA, fetch })

    const discoveries = calls.filter((c) => c.url === METADATA_URL)
    const registrations = calls.filter((c) => c.url === REGISTRATION_URL)
    expect(discoveries).toHaveLength(1)
    expect(registrations).toHaveLength(2)
  })

  it("noCache: true forces a fresh discovery", async () => {
    const { fetch, calls } = recordingFetch({
      "/.well-known/oauth-authorization-server": () =>
        Promise.resolve(mockResponse({ body: { registration_endpoint: REGISTRATION_URL } })),
      "/oauth/register": () => Promise.resolve(mockResponse({ status: 201, body: SUCCESS_BODY })),
    })

    await registerClient({ issuer: ISSUER, metadata: VALID_METADATA, fetch })
    await registerClient({ issuer: ISSUER, metadata: VALID_METADATA, fetch, noCache: true })

    const discoveries = calls.filter((c) => c.url === METADATA_URL)
    expect(discoveries).toHaveLength(2)
  })

  it("forwards an AbortSignal derived from timeoutMs", async () => {
    const { fetch, calls } = recordingFetch({
      "/.well-known/oauth-authorization-server": () =>
        Promise.resolve(mockResponse({ body: { registration_endpoint: REGISTRATION_URL } })),
      "/oauth/register": () => Promise.resolve(mockResponse({ status: 201, body: SUCCESS_BODY })),
    })

    await registerClient({ issuer: ISSUER, metadata: VALID_METADATA, fetch, timeoutMs: 5_000 })

    for (const call of calls) {
      expect(call.signal).toBeInstanceOf(AbortSignal)
    }
  })
})

describe("registerClient — error paths", () => {
  it("maps RFC 7591 §3.2.2 error responses to DcrError reason=as-error", async () => {
    const { fetch } = recordingFetch({
      "/.well-known/oauth-authorization-server": () =>
        Promise.resolve(mockResponse({ body: { registration_endpoint: REGISTRATION_URL } })),
      "/oauth/register": () =>
        Promise.resolve(
          mockResponse({
            status: 400,
            body: {
              error: "invalid_redirect_uri",
              error_description: "redirect_uri must be HTTPS",
            },
          }),
        ),
    })

    await expect(
      registerClient({ issuer: ISSUER, metadata: VALID_METADATA, fetch }),
    ).rejects.toMatchObject({
      name: "DcrError",
      reason: "as-error",
      oauthError: "invalid_redirect_uri",
      oauthErrorDescription: "redirect_uri must be HTTPS",
      status: 400,
    })
  })

  it("non-JSON body from registration endpoint surfaces as transport", async () => {
    const { fetch } = recordingFetch({
      "/.well-known/oauth-authorization-server": () =>
        Promise.resolve(mockResponse({ body: { registration_endpoint: REGISTRATION_URL } })),
      "/oauth/register": () => Promise.resolve(mockResponse({ status: 500, throwOnJson: true })),
    })

    await expect(
      registerClient({ issuer: ISSUER, metadata: VALID_METADATA, fetch }),
    ).rejects.toMatchObject({ name: "DcrError", reason: "transport" })
  })

  it("non-object body from registration endpoint surfaces as malformed-response", async () => {
    const { fetch } = recordingFetch({
      "/.well-known/oauth-authorization-server": () =>
        Promise.resolve(mockResponse({ body: { registration_endpoint: REGISTRATION_URL } })),
      "/oauth/register": () => Promise.resolve(mockResponse({ status: 201, body: "nope" })),
    })

    await expect(
      registerClient({ issuer: ISSUER, metadata: VALID_METADATA, fetch }),
    ).rejects.toMatchObject({ name: "DcrError", reason: "malformed-response" })
  })

  it("missing client_id in success response surfaces as malformed-response", async () => {
    const { fetch } = recordingFetch({
      "/.well-known/oauth-authorization-server": () =>
        Promise.resolve(mockResponse({ body: { registration_endpoint: REGISTRATION_URL } })),
      "/oauth/register": () =>
        Promise.resolve(mockResponse({ status: 201, body: { client_secret: "s" } })),
    })

    await expect(
      registerClient({ issuer: ISSUER, metadata: VALID_METADATA, fetch }),
    ).rejects.toMatchObject({
      name: "DcrError",
      reason: "malformed-response",
    })
  })

  it("missing registration_endpoint in discovery surfaces as discovery", async () => {
    const { fetch } = recordingFetch({
      "/.well-known/oauth-authorization-server": () =>
        Promise.resolve(mockResponse({ body: { token_endpoint: `${ISSUER}/token` } })),
    })

    await expect(
      registerClient({ issuer: ISSUER, metadata: VALID_METADATA, fetch }),
    ).rejects.toMatchObject({ name: "DcrError", reason: "discovery" })
  })

  it("discovery HTTP failure surfaces as discovery with status", async () => {
    const { fetch } = recordingFetch({
      "/.well-known/oauth-authorization-server": () =>
        Promise.resolve(mockResponse({ status: 503, body: {} })),
    })

    await expect(
      registerClient({ issuer: ISSUER, metadata: VALID_METADATA, fetch }),
    ).rejects.toMatchObject({ name: "DcrError", reason: "discovery", status: 503 })
  })

  it("network error during registration surfaces as transport", async () => {
    const fetch: FetchLike = vi.fn(async (url) => {
      if (String(url).includes(".well-known")) {
        return mockResponse({ body: { registration_endpoint: REGISTRATION_URL } })
      }
      throw new Error("ECONNRESET")
    })

    await expect(
      registerClient({ issuer: ISSUER, metadata: VALID_METADATA, fetch }),
    ).rejects.toMatchObject({ name: "DcrError", reason: "transport" })
  })

  it("rejects missing issuer with reason=input", async () => {
    await expect(
      // @ts-expect-error — exercising runtime validation
      registerClient({ metadata: VALID_METADATA }),
    ).rejects.toMatchObject({ name: "DcrError", reason: "input" })
  })

  it("rejects non-URL issuer with reason=input", async () => {
    await expect(
      registerClient({ issuer: "not-a-url", metadata: VALID_METADATA }),
    ).rejects.toMatchObject({ name: "DcrError", reason: "input" })
  })

  it("rejects non-http(s) issuer with reason=input", async () => {
    await expect(
      registerClient({ issuer: "ftp://as.example.test", metadata: VALID_METADATA }),
    ).rejects.toMatchObject({ name: "DcrError", reason: "input" })
  })

  it("rejects empty metadata-missing argument with reason=input", async () => {
    await expect(
      // @ts-expect-error — exercising runtime validation
      registerClient({ issuer: ISSUER }),
    ).rejects.toMatchObject({ name: "DcrError", reason: "input" })
  })

  it("rejects metadata that is not a plain object", async () => {
    await expect(
      // @ts-expect-error — exercising runtime validation
      registerClient({ issuer: ISSUER, metadata: [] }),
    ).rejects.toMatchObject({ name: "DcrError", reason: "input" })
  })

  it("rejects empty-string initialAccessToken with reason=input", async () => {
    await expect(
      registerClient({
        issuer: ISSUER,
        initialAccessToken: "",
        metadata: VALID_METADATA,
      }),
    ).rejects.toMatchObject({ name: "DcrError", reason: "input" })
  })
})

describe("registerClient — security (spec v0.2 §12)", () => {
  let logger: DcrLogger
  let logSink: Array<{
    level: "debug" | "warn" | "error"
    obj: Record<string, unknown>
    msg?: string
  }>

  beforeEach(() => {
    logSink = []
    logger = {
      debug: (obj, msg) =>
        logSink.push(msg !== undefined ? { level: "debug", obj, msg } : { level: "debug", obj }),
      warn: (obj, msg) =>
        logSink.push(msg !== undefined ? { level: "warn", obj, msg } : { level: "warn", obj }),
      error: (obj, msg) =>
        logSink.push(msg !== undefined ? { level: "error", obj, msg } : { level: "error", obj }),
    }
  })

  afterEach(() => {
    logSink.length = 0
  })

  it("never logs the initialAccessToken (happy path)", async () => {
    const { fetch } = recordingFetch({
      "/.well-known/oauth-authorization-server": () =>
        Promise.resolve(mockResponse({ body: { registration_endpoint: REGISTRATION_URL } })),
      "/oauth/register": () => Promise.resolve(mockResponse({ status: 201, body: SUCCESS_BODY })),
    })

    await registerClient({
      issuer: ISSUER,
      initialAccessToken: INITIAL_ACCESS_TOKEN,
      metadata: VALID_METADATA,
      fetch,
      logger,
    })

    const serialized = JSON.stringify(logSink)
    expect(serialized).not.toContain(INITIAL_ACCESS_TOKEN)
  })

  it("never logs the initialAccessToken (error path)", async () => {
    const { fetch } = recordingFetch({
      "/.well-known/oauth-authorization-server": () =>
        Promise.resolve(mockResponse({ body: { registration_endpoint: REGISTRATION_URL } })),
      "/oauth/register": () =>
        Promise.resolve(
          mockResponse({
            status: 400,
            body: { error: "invalid_client_metadata", error_description: "bad scope" },
          }),
        ),
    })

    await expect(
      registerClient({
        issuer: ISSUER,
        initialAccessToken: INITIAL_ACCESS_TOKEN,
        metadata: VALID_METADATA,
        fetch,
        logger,
      }),
    ).rejects.toBeInstanceOf(DcrError)

    const serialized = JSON.stringify(logSink)
    expect(serialized).not.toContain(INITIAL_ACCESS_TOKEN)
  })

  it("never logs the registration_access_token returned by the AS", async () => {
    const { fetch } = recordingFetch({
      "/.well-known/oauth-authorization-server": () =>
        Promise.resolve(mockResponse({ body: { registration_endpoint: REGISTRATION_URL } })),
      "/oauth/register": () => Promise.resolve(mockResponse({ status: 201, body: SUCCESS_BODY })),
    })

    await registerClient({
      issuer: ISSUER,
      metadata: VALID_METADATA,
      fetch,
      logger,
    })

    const serialized = JSON.stringify(logSink)
    expect(serialized).not.toContain(REGISTRATION_ACCESS_TOKEN)
    // Sanity: we did emit at least one log entry on the happy path.
    expect(logSink.length).toBeGreaterThan(0)
  })

  it("exports redaction paths covering known secret fields", () => {
    expect(DCR_LOG_REDACT_PATHS).toContain("initialAccessToken")
    expect(DCR_LOG_REDACT_PATHS).toContain("registration_access_token")
    expect(DCR_LOG_REDACT_PATHS).toContain("client_secret")
  })
})
