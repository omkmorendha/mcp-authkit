/**
 * Tests for `requestClientCredentialsToken`.
 *
 * Spec: docs/spec/v0.2.md#54-client-credentials-rfc-6749-44 and
 * docs/spec/v0.2.md#12-security-non-negotiables-additions.
 */
import { generateKeyPair, jwtVerify } from "jose"
import { describe, expect, it } from "vitest"
import {
  ClientCredentialsError,
  type FetchLike,
  requestClientCredentialsToken,
} from "./client-credentials.js"

const ISSUER = "https://auth.example.com"
const TOKEN_ENDPOINT = "https://auth.example.com/oauth/token"
const AUDIENCE = "https://upstream.example.com"
const CLIENT_ID = "test-client"
const CLIENT_SECRET = "s3cret!"

interface FetchCall {
  url: string
  method?: string
  headers?: Record<string, string>
  body?: string
}

interface FakeResponse {
  ok: boolean
  status: number
  bodyJson?: unknown
  /** Override JSON parsing failure. */
  jsonThrows?: boolean
  /** Override fetch rejection. */
  rejectWith?: Error
}

/**
 * Build a stub `fetch` that returns predetermined responses keyed by URL
 * substring. Records every call for assertion.
 */
function buildFetch(responses: Array<{ match: string; response: FakeResponse }>): {
  fetch: FetchLike
  calls: FetchCall[]
} {
  const calls: FetchCall[] = []
  const fetch: FetchLike = async (input, init) => {
    const url = typeof input === "string" ? input : input.toString()
    calls.push({
      url,
      method: init?.method,
      ...(init?.headers !== undefined ? { headers: init.headers } : {}),
      ...(init?.body !== undefined ? { body: init.body } : {}),
    })
    const match = responses.find((r) => url.includes(r.match))
    if (match === undefined) {
      throw new Error(`unexpected fetch URL: ${url}`)
    }
    const r = match.response
    if (r.rejectWith !== undefined) throw r.rejectWith
    return {
      ok: r.ok,
      status: r.status,
      async json() {
        if (r.jsonThrows === true) throw new Error("invalid json")
        return r.bodyJson
      },
      async text() {
        return JSON.stringify(r.bodyJson ?? "")
      },
    }
  }
  return { fetch, calls }
}

function discoveryResponse(): { match: string; response: FakeResponse } {
  return {
    match: "/.well-known/oauth-authorization-server",
    response: {
      ok: true,
      status: 200,
      bodyJson: { issuer: ISSUER, token_endpoint: TOKEN_ENDPOINT },
    },
  }
}

function tokenResponse(body: unknown, status = 200, ok = true) {
  return {
    match: "/oauth/token",
    response: { ok, status, bodyJson: body },
  }
}

describe("requestClientCredentialsToken — config validation", () => {
  it("rejects when audience is missing", async () => {
    const { fetch } = buildFetch([])
    await expect(
      requestClientCredentialsToken({
        issuer: ISSUER,
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        scopes: [],
        // @ts-expect-error intentional missing audience for runtime test
        audience: undefined,
        fetch,
      }),
    ).rejects.toMatchObject({
      name: "ClientCredentialsError",
      code: "invalid-config",
    })
  })

  it("rejects when audience is not a URL", async () => {
    const { fetch } = buildFetch([])
    await expect(
      requestClientCredentialsToken({
        issuer: ISSUER,
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        scopes: [],
        audience: "not-a-url",
        fetch,
      }),
    ).rejects.toMatchObject({ code: "invalid-config" })
  })

  it("rejects when both clientSecret and signingKey are supplied", async () => {
    const { privateKey } = await generateKeyPair("ES256", { extractable: true })
    const { fetch } = buildFetch([])
    await expect(
      requestClientCredentialsToken({
        issuer: ISSUER,
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        signingKey: privateKey,
        scopes: [],
        audience: AUDIENCE,
        fetch,
      }),
    ).rejects.toMatchObject({
      code: "invalid-config",
      message: expect.stringContaining("mutually exclusive"),
    })
  })

  it("rejects when neither clientSecret nor signingKey is supplied", async () => {
    const { fetch } = buildFetch([])
    await expect(
      requestClientCredentialsToken({
        issuer: ISSUER,
        clientId: CLIENT_ID,
        scopes: [],
        audience: AUDIENCE,
        fetch,
      }),
    ).rejects.toMatchObject({ code: "invalid-config" })
  })

  it("rejects when issuer is not http(s)", async () => {
    const { fetch } = buildFetch([])
    await expect(
      requestClientCredentialsToken({
        issuer: "ftp://example.com",
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        scopes: [],
        audience: AUDIENCE,
        fetch,
      }),
    ).rejects.toMatchObject({ code: "invalid-config" })
  })

  it("rejects when clientSecret is the empty string", async () => {
    const { fetch } = buildFetch([])
    await expect(
      requestClientCredentialsToken({
        issuer: ISSUER,
        clientId: CLIENT_ID,
        clientSecret: "",
        scopes: [],
        audience: AUDIENCE,
        fetch,
      }),
    ).rejects.toMatchObject({ code: "invalid-config" })
  })
})

describe("requestClientCredentialsToken — client_secret_basic mode", () => {
  it("posts grant_type, scope, resource with HTTP Basic auth", async () => {
    const { fetch, calls } = buildFetch([
      discoveryResponse(),
      tokenResponse({
        access_token: "at-1",
        token_type: "Bearer",
        expires_in: 3600,
        scope: "service:read service:write",
      }),
    ])

    const before = Date.now()
    const token = await requestClientCredentialsToken({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      scopes: ["service:read", "service:write"],
      audience: AUDIENCE,
      fetch,
    })
    const after = Date.now()

    expect(token.accessToken).toBe("at-1")
    expect(token.scopes).toEqual(["service:read", "service:write"])
    expect(token.expiresAt.getTime()).toBeGreaterThanOrEqual(before + 3600 * 1000)
    expect(token.expiresAt.getTime()).toBeLessThanOrEqual(after + 3600 * 1000)

    expect(calls).toHaveLength(2)
    expect(calls[0]?.url).toContain("/.well-known/oauth-authorization-server")
    const tokenCall = calls[1]
    expect(tokenCall?.url).toBe(TOKEN_ENDPOINT)
    expect(tokenCall?.method).toBe("POST")
    expect(tokenCall?.headers?.["Content-Type"]).toBe("application/x-www-form-urlencoded")
    const authHeader = tokenCall?.headers?.Authorization
    expect(authHeader).toBeDefined()
    expect(authHeader?.startsWith("Basic ")).toBe(true)
    const decoded = Buffer.from(authHeader?.slice("Basic ".length) ?? "", "base64").toString("utf8")
    expect(decoded).toBe(`${encodeURIComponent(CLIENT_ID)}:${encodeURIComponent(CLIENT_SECRET)}`)

    const params = new URLSearchParams(tokenCall?.body ?? "")
    expect(params.get("grant_type")).toBe("client_credentials")
    expect(params.get("resource")).toBe(AUDIENCE)
    expect(params.get("scope")).toBe("service:read service:write")
    expect(params.has("client_id")).toBe(false)
    expect(params.has("client_assertion")).toBe(false)
  })

  it("omits scope param when no scopes requested but returns AS scopes", async () => {
    const { fetch, calls } = buildFetch([
      discoveryResponse(),
      tokenResponse({
        access_token: "at-2",
        token_type: "Bearer",
        expires_in: 60,
        scope: "service:default",
      }),
    ])
    const token = await requestClientCredentialsToken({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      scopes: [],
      audience: AUDIENCE,
      fetch,
    })
    expect(token.scopes).toEqual(["service:default"])
    const params = new URLSearchParams(calls[1]?.body ?? "")
    expect(params.has("scope")).toBe(false)
  })

  it("falls back to requested scopes when response omits scope", async () => {
    const { fetch } = buildFetch([
      discoveryResponse(),
      tokenResponse({ access_token: "at-3", token_type: "Bearer", expires_in: 60 }),
    ])
    const token = await requestClientCredentialsToken({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      scopes: ["a", "b"],
      audience: AUDIENCE,
      fetch,
    })
    expect(token.scopes).toEqual(["a", "b"])
  })

  it("percent-encodes client_id and secret containing special characters", async () => {
    const weirdId = "client:with spaces"
    const weirdSecret = "p@ss:word/+="
    const { fetch, calls } = buildFetch([
      discoveryResponse(),
      tokenResponse({ access_token: "at-4", token_type: "Bearer", expires_in: 60 }),
    ])
    await requestClientCredentialsToken({
      issuer: ISSUER,
      clientId: weirdId,
      clientSecret: weirdSecret,
      scopes: [],
      audience: AUDIENCE,
      fetch,
    })
    const authHeader = calls[1]?.headers?.Authorization ?? ""
    const decoded = Buffer.from(authHeader.slice("Basic ".length), "base64").toString("utf8")
    expect(decoded).toBe(`${encodeURIComponent(weirdId)}:${encodeURIComponent(weirdSecret)}`)
  })
})

describe("requestClientCredentialsToken — private_key_jwt mode", () => {
  it("builds a client_assertion JWT (iss=sub=clientId, aud=token_endpoint)", async () => {
    const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true })
    const { fetch, calls } = buildFetch([
      discoveryResponse(),
      tokenResponse({ access_token: "at-jwt", token_type: "Bearer", expires_in: 60 }),
    ])

    await requestClientCredentialsToken({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      signingKey: privateKey,
      scopes: ["x"],
      audience: AUDIENCE,
      fetch,
    })

    const tokenCall = calls[1]
    expect(tokenCall?.headers?.Authorization).toBeUndefined()
    const params = new URLSearchParams(tokenCall?.body ?? "")
    expect(params.get("grant_type")).toBe("client_credentials")
    expect(params.get("resource")).toBe(AUDIENCE)
    expect(params.get("scope")).toBe("x")
    expect(params.get("client_id")).toBe(CLIENT_ID)
    expect(params.get("client_assertion_type")).toBe(
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    )
    const assertion = params.get("client_assertion")
    expect(typeof assertion).toBe("string")

    const verified = await jwtVerify(assertion as string, publicKey, {
      audience: TOKEN_ENDPOINT,
      issuer: CLIENT_ID,
    })
    expect(verified.payload.iss).toBe(CLIENT_ID)
    expect(verified.payload.sub).toBe(CLIENT_ID)
    expect(verified.payload.aud).toBe(TOKEN_ENDPOINT)
    expect(typeof verified.payload.jti).toBe("string")
    expect(typeof verified.payload.exp).toBe("number")
    expect(typeof verified.payload.iat).toBe("number")
    expect(verified.protectedHeader.alg).toBe("ES256")
    expect(verified.protectedHeader.typ).toBe("JWT")
  })

  it("works with an RSA key (RS256)", async () => {
    const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true })
    const { fetch, calls } = buildFetch([
      discoveryResponse(),
      tokenResponse({ access_token: "at-rsa", token_type: "Bearer", expires_in: 60 }),
    ])
    await requestClientCredentialsToken({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      signingKey: privateKey,
      scopes: [],
      audience: AUDIENCE,
      fetch,
    })
    const params = new URLSearchParams(calls[1]?.body ?? "")
    const assertion = params.get("client_assertion") as string
    const verified = await jwtVerify(assertion, publicKey)
    expect(verified.protectedHeader.alg).toBe("RS256")
  })
})

describe("requestClientCredentialsToken — error mapping", () => {
  it("surfaces RFC 6749 §5.2 error responses as typed errors", async () => {
    const { fetch } = buildFetch([
      discoveryResponse(),
      tokenResponse({ error: "invalid_client", error_description: "auth failed" }, 401, false),
    ])
    let caught: unknown
    try {
      await requestClientCredentialsToken({
        issuer: ISSUER,
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        scopes: [],
        audience: AUDIENCE,
        fetch,
      })
    } catch (err) {
      caught = err
    }
    expect(caught).toBeInstanceOf(ClientCredentialsError)
    const err = caught as ClientCredentialsError
    expect(err.code).toBe("oauth-error")
    expect(err.oauthError).toBe("invalid_client")
    expect(err.oauthErrorDescription).toBe("auth failed")
    expect(err.status).toBe(401)
    expect(err.message).toContain("invalid_client")
  })

  it("maps an HTTP error without an `error` field to oauth-error", async () => {
    const { fetch } = buildFetch([
      discoveryResponse(),
      tokenResponse({ message: "boom" }, 500, false),
    ])
    await expect(
      requestClientCredentialsToken({
        issuer: ISSUER,
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        scopes: [],
        audience: AUDIENCE,
        fetch,
      }),
    ).rejects.toMatchObject({ code: "oauth-error", status: 500 })
  })

  it("rejects when token response is missing access_token", async () => {
    const { fetch } = buildFetch([
      discoveryResponse(),
      tokenResponse({ token_type: "Bearer", expires_in: 60 }),
    ])
    await expect(
      requestClientCredentialsToken({
        issuer: ISSUER,
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        scopes: [],
        audience: AUDIENCE,
        fetch,
      }),
    ).rejects.toMatchObject({ code: "invalid-response" })
  })

  it("rejects when token response is missing expires_in", async () => {
    const { fetch } = buildFetch([
      discoveryResponse(),
      tokenResponse({ access_token: "x", token_type: "Bearer" }),
    ])
    await expect(
      requestClientCredentialsToken({
        issuer: ISSUER,
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        scopes: [],
        audience: AUDIENCE,
        fetch,
      }),
    ).rejects.toMatchObject({ code: "invalid-response" })
  })

  it("maps non-JSON token response to transport error", async () => {
    const { fetch } = buildFetch([
      discoveryResponse(),
      { match: "/oauth/token", response: { ok: true, status: 200, jsonThrows: true } },
    ])
    await expect(
      requestClientCredentialsToken({
        issuer: ISSUER,
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        scopes: [],
        audience: AUDIENCE,
        fetch,
      }),
    ).rejects.toMatchObject({ code: "transport" })
  })

  it("maps fetch failure on token endpoint to transport error", async () => {
    const { fetch } = buildFetch([
      discoveryResponse(),
      {
        match: "/oauth/token",
        response: { ok: false, status: 0, rejectWith: new Error("ECONNRESET") },
      },
    ])
    await expect(
      requestClientCredentialsToken({
        issuer: ISSUER,
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        scopes: [],
        audience: AUDIENCE,
        fetch,
      }),
    ).rejects.toMatchObject({ code: "transport" })
  })
})

describe("requestClientCredentialsToken — discovery", () => {
  it("fails when discovery returns non-2xx", async () => {
    const { fetch } = buildFetch([
      {
        match: "/.well-known/oauth-authorization-server",
        response: { ok: false, status: 404 },
      },
    ])
    await expect(
      requestClientCredentialsToken({
        issuer: ISSUER,
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        scopes: [],
        audience: AUDIENCE,
        fetch,
      }),
    ).rejects.toMatchObject({ code: "discovery-failed", status: 404 })
  })

  it("fails when metadata is missing token_endpoint", async () => {
    const { fetch } = buildFetch([
      {
        match: "/.well-known/oauth-authorization-server",
        response: { ok: true, status: 200, bodyJson: { issuer: ISSUER } },
      },
    ])
    await expect(
      requestClientCredentialsToken({
        issuer: ISSUER,
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        scopes: [],
        audience: AUDIENCE,
        fetch,
      }),
    ).rejects.toMatchObject({ code: "discovery-failed" })
  })

  it("builds well-known URL correctly for issuers with a path component", async () => {
    const pathIssuer = "https://auth.example.com/tenants/t1"
    const { fetch, calls } = buildFetch([
      {
        match: "/.well-known/oauth-authorization-server/tenants/t1",
        response: {
          ok: true,
          status: 200,
          bodyJson: { issuer: pathIssuer, token_endpoint: TOKEN_ENDPOINT },
        },
      },
      tokenResponse({ access_token: "at-tenant", token_type: "Bearer", expires_in: 60 }),
    ])
    await requestClientCredentialsToken({
      issuer: pathIssuer,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      scopes: [],
      audience: AUDIENCE,
      fetch,
    })
    expect(calls[0]?.url).toBe(
      "https://auth.example.com/.well-known/oauth-authorization-server/tenants/t1",
    )
  })
})
