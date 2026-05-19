import { describe, expect, it, vi } from "vitest"
import { startTestAS } from "../test/fixtures/as.js"
import {
  exchangeToken,
  type FetchLike,
  TOKEN_EXCHANGE_BODY_LIMIT_BYTES,
  TOKEN_EXCHANGE_GRANT_TYPE,
  TokenExchangeError,
} from "./token-exchange.js"

const AUDIENCE = "https://upstream.example.test/"
const ISSUER = "https://as.example.test"
const METADATA_URL = `${ISSUER}/.well-known/oauth-authorization-server`
const TOKEN_URL = `${ISSUER}/oauth/token`
const INTROSPECTION_URL = `${ISSUER}/oauth/introspect`

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

/**
 * Build a fetch mock that dispatches by URL substring so individual tests
 * don't need to know the call order.
 */
function routedFetch(routes: Record<string, () => ReturnType<FetchLike>>): FetchLike {
  return vi.fn<FetchLike>((url) => {
    const key = String(url)
    for (const [needle, handler] of Object.entries(routes)) {
      if (key.includes(needle)) return handler()
    }
    return Promise.reject(new Error(`unexpected url: ${key}`))
  })
}

describe("exchangeToken", () => {
  describe("happy path", () => {
    it("returns minted token, expiresAt, scopes, tokenType against a real signing AS", async () => {
      const as = await startTestAS()
      try {
        const issuer = as.issuer
        const issuedToken = await as.signToken({
          sub: "user-123",
          aud: AUDIENCE,
          scope: "upstream:write",
        })

        const fetchMock = vi.fn<FetchLike>(async (url) => {
          const u = String(url)
          if (u.endsWith("/.well-known/oauth-authorization-server")) {
            return mockResponse({
              body: {
                issuer,
                token_endpoint: `${issuer}/token`,
                introspection_endpoint: `${issuer}/introspect`,
              },
            })
          }
          if (u.endsWith("/token")) {
            return mockResponse({
              body: {
                access_token: issuedToken,
                issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
                token_type: "Bearer",
                expires_in: 3600,
                scope: "upstream:write",
              },
            })
          }
          throw new Error(`unexpected url: ${u}`)
        })

        const result = await exchangeToken({
          issuer,
          subjectToken: "subject-token-value",
          subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
          audience: AUDIENCE,
          scopes: ["upstream:write"],
          fetch: fetchMock,
        })

        expect(result.accessToken).toBe(issuedToken)
        expect(result.scopes).toEqual(["upstream:write"])
        expect(result.tokenType).toBe("urn:ietf:params:oauth:token-type:access_token")
        expect(result.expiresAt).toBeInstanceOf(Date)
      } finally {
        await as.close()
      }
    })

    it("sends grant_type, subject_token, audience, resource, scope on the wire", async () => {
      const as = await startTestAS()
      try {
        const issuedToken = await as.signToken({ sub: "u", aud: AUDIENCE })
        const calls: Array<{ url: string; body?: string; method?: string }> = []
        const fetchMock: FetchLike = vi.fn(async (url, init) => {
          calls.push({ url: String(url), body: init?.body, method: init?.method })
          if (String(url).endsWith("/.well-known/oauth-authorization-server")) {
            return mockResponse({ body: { token_endpoint: TOKEN_URL } })
          }
          return mockResponse({
            body: {
              access_token: issuedToken,
              issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
              expires_in: 60,
            },
          })
        })

        await exchangeToken({
          issuer: ISSUER,
          subjectToken: "subj",
          subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
          audience: AUDIENCE,
          scopes: ["a", "b"],
          fetch: fetchMock,
        })

        const tokenCall = calls.find((c) => c.url === TOKEN_URL)
        if (tokenCall === undefined) throw new Error("token endpoint was not called")
        const params = new URLSearchParams(tokenCall.body ?? "")
        expect(params.get("grant_type")).toBe(TOKEN_EXCHANGE_GRANT_TYPE)
        expect(params.get("subject_token")).toBe("subj")
        expect(params.get("subject_token_type")).toBe(
          "urn:ietf:params:oauth:token-type:access_token",
        )
        expect(params.get("audience")).toBe(AUDIENCE)
        expect(params.get("resource")).toBe(AUDIENCE)
        expect(params.get("scope")).toBe("a b")
        expect(params.get("actor_token")).toBeNull()
      } finally {
        await as.close()
      }
    })

    it("forwards actor_token and actor_token_type when supplied", async () => {
      const as = await startTestAS()
      try {
        const issued = await as.signToken({ sub: "u", aud: AUDIENCE })
        const calls: Array<{ body?: string }> = []
        const fetchMock: FetchLike = vi.fn(async (url, init) => {
          if (String(url).endsWith("/.well-known/oauth-authorization-server")) {
            return mockResponse({ body: { token_endpoint: TOKEN_URL } })
          }
          calls.push({ body: init?.body })
          return mockResponse({
            body: {
              access_token: issued,
              issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
              expires_in: 60,
            },
          })
        })
        await exchangeToken({
          issuer: ISSUER,
          subjectToken: "subj",
          subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
          audience: AUDIENCE,
          actorToken: "actor-tok",
          actorTokenType: "urn:ietf:params:oauth:token-type:jwt",
          fetch: fetchMock,
        })
        const params = new URLSearchParams(calls[0]?.body ?? "")
        expect(params.get("actor_token")).toBe("actor-tok")
        expect(params.get("actor_token_type")).toBe("urn:ietf:params:oauth:token-type:jwt")
      } finally {
        await as.close()
      }
    })

    it("accepts opaque minted tokens validated via introspection", async () => {
      const fetchMock = routedFetch({
        "/.well-known/oauth-authorization-server": () =>
          Promise.resolve(
            mockResponse({
              body: {
                token_endpoint: TOKEN_URL,
                introspection_endpoint: INTROSPECTION_URL,
              },
            }),
          ),
        "/oauth/token": () =>
          Promise.resolve(
            mockResponse({
              body: {
                access_token: "opaque-minted",
                issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
                expires_in: 120,
              },
            }),
          ),
        "/oauth/introspect": () =>
          Promise.resolve(
            mockResponse({
              body: {
                active: true,
                sub: "u",
                aud: AUDIENCE,
                exp: Math.floor(Date.now() / 1000) + 600,
              },
            }),
          ),
      })

      const result = await exchangeToken({
        issuer: ISSUER,
        subjectToken: "subj",
        subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
        audience: AUDIENCE,
        fetch: fetchMock,
      })
      expect(result.accessToken).toBe("opaque-minted")
    })

    it("skips discovery when tokenEndpoint is provided", async () => {
      const as = await startTestAS()
      try {
        const issued = await as.signToken({ sub: "u", aud: AUDIENCE })
        const fetchMock: FetchLike = vi.fn(async (url) => {
          if (String(url).endsWith("/.well-known/oauth-authorization-server")) {
            throw new Error("discovery should be skipped")
          }
          return mockResponse({
            body: {
              access_token: issued,
              issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
              expires_in: 60,
            },
          })
        })
        const result = await exchangeToken({
          issuer: ISSUER,
          subjectToken: "subj",
          subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
          audience: AUDIENCE,
          tokenEndpoint: TOKEN_URL,
          fetch: fetchMock,
        })
        expect(result.accessToken).toBe(issued)
      } finally {
        await as.close()
      }
    })
  })

  describe("security (spec v0.2 §8/§12)", () => {
    it("rejects a minted token whose aud does not match requested audience (fail-closed)", async () => {
      const as = await startTestAS()
      try {
        const issued = await as.signToken({ sub: "u", aud: "https://attacker.example/" })
        const fetchMock = routedFetch({
          "/.well-known/oauth-authorization-server": () =>
            Promise.resolve(mockResponse({ body: { token_endpoint: TOKEN_URL } })),
          "/oauth/token": () =>
            Promise.resolve(
              mockResponse({
                body: {
                  access_token: issued,
                  issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
                  expires_in: 60,
                },
              }),
            ),
        })

        await expect(
          exchangeToken({
            issuer: ISSUER,
            subjectToken: "subj",
            subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
            audience: AUDIENCE,
            fetch: fetchMock,
          }),
        ).rejects.toMatchObject({
          name: "TokenExchangeError",
          reason: "audience",
        })
      } finally {
        await as.close()
      }
    })

    it("does not fall back to the subject token on audience mismatch (return value never includes subjectToken)", async () => {
      // Belt-and-suspenders: even with a minted token whose aud is wrong,
      // there must be NO code path that resolves with the subject token.
      const as = await startTestAS()
      try {
        const minted = await as.signToken({ sub: "u", aud: "https://wrong/" })
        const subjectToken = "the-subject-token-MUST-NOT-LEAK"
        const fetchMock = routedFetch({
          "/.well-known/oauth-authorization-server": () =>
            Promise.resolve(mockResponse({ body: { token_endpoint: TOKEN_URL } })),
          "/oauth/token": () =>
            Promise.resolve(
              mockResponse({
                body: {
                  access_token: minted,
                  issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
                  expires_in: 60,
                },
              }),
            ),
        })

        let caught: unknown
        try {
          await exchangeToken({
            issuer: ISSUER,
            subjectToken,
            subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
            audience: AUDIENCE,
            fetch: fetchMock,
          })
        } catch (err) {
          caught = err
        }
        expect(caught).toBeInstanceOf(TokenExchangeError)
        expect((caught as TokenExchangeError).message).not.toContain(subjectToken)
      } finally {
        await as.close()
      }
    })

    it("rejects subject tokens larger than 64 KB BEFORE any network call", async () => {
      const fetchMock = vi.fn<FetchLike>()
      const tooLong = "x".repeat(TOKEN_EXCHANGE_BODY_LIMIT_BYTES + 1)
      await expect(
        exchangeToken({
          issuer: ISSUER,
          subjectToken: tooLong,
          subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
          audience: AUDIENCE,
          tokenEndpoint: TOKEN_URL,
          fetch: fetchMock,
        }),
      ).rejects.toMatchObject({
        name: "TokenExchangeError",
        reason: "request-too-large",
      })
      expect(fetchMock).not.toHaveBeenCalled()
    })

    it("never logs the minted token at any level", async () => {
      const as = await startTestAS()
      try {
        const minted = await as.signToken({ sub: "u", aud: AUDIENCE })
        const fetchMock = routedFetch({
          "/.well-known/oauth-authorization-server": () =>
            Promise.resolve(mockResponse({ body: { token_endpoint: TOKEN_URL } })),
          "/oauth/token": () =>
            Promise.resolve(
              mockResponse({
                body: {
                  access_token: minted,
                  issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
                  expires_in: 60,
                },
              }),
            ),
        })

        const logged: string[] = []
        const captureLogger = {
          debug(obj: Record<string, unknown>, msg?: string) {
            logged.push(JSON.stringify(obj))
            if (msg !== undefined) logged.push(msg)
          },
          warn(obj: Record<string, unknown>, msg?: string) {
            logged.push(JSON.stringify(obj))
            if (msg !== undefined) logged.push(msg)
          },
          error(obj: Record<string, unknown>, msg?: string) {
            logged.push(JSON.stringify(obj))
            if (msg !== undefined) logged.push(msg)
          },
        }

        const result = await exchangeToken({
          issuer: ISSUER,
          subjectToken: "subj",
          subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
          audience: AUDIENCE,
          fetch: fetchMock,
          logger: captureLogger,
        })

        // Sanity: we got the minted token back so the test isn't vacuous.
        expect(result.accessToken).toBe(minted)
        // The minted token MUST NOT appear anywhere in captured log output.
        for (const entry of logged) {
          expect(entry).not.toContain(minted)
        }
      } finally {
        await as.close()
      }
    })

    it("never logs the subject token at any level", async () => {
      const as = await startTestAS()
      try {
        const minted = await as.signToken({ sub: "u", aud: AUDIENCE })
        const fetchMock = routedFetch({
          "/.well-known/oauth-authorization-server": () =>
            Promise.resolve(mockResponse({ body: { token_endpoint: TOKEN_URL } })),
          "/oauth/token": () =>
            Promise.resolve(
              mockResponse({
                body: {
                  access_token: minted,
                  issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
                  expires_in: 60,
                },
              }),
            ),
        })

        const logged: string[] = []
        const captureLogger = {
          debug(obj: Record<string, unknown>, msg?: string) {
            logged.push(JSON.stringify(obj))
            if (msg !== undefined) logged.push(msg)
          },
          warn(obj: Record<string, unknown>, msg?: string) {
            logged.push(JSON.stringify(obj))
            if (msg !== undefined) logged.push(msg)
          },
          error(obj: Record<string, unknown>, msg?: string) {
            logged.push(JSON.stringify(obj))
            if (msg !== undefined) logged.push(msg)
          },
        }

        const SUBJECT = "subject-token-MUST-NOT-LEAK"
        await exchangeToken({
          issuer: ISSUER,
          subjectToken: SUBJECT,
          subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
          audience: AUDIENCE,
          fetch: fetchMock,
          logger: captureLogger,
        })
        for (const entry of logged) {
          expect(entry).not.toContain(SUBJECT)
        }
      } finally {
        await as.close()
      }
    })
  })

  describe("error mapping", () => {
    it("maps AS error responses to TokenExchangeError(as-error) with oauthError", async () => {
      const fetchMock = routedFetch({
        "/.well-known/oauth-authorization-server": () =>
          Promise.resolve(mockResponse({ body: { token_endpoint: TOKEN_URL } })),
        "/oauth/token": () =>
          Promise.resolve(
            mockResponse({
              status: 400,
              body: {
                error: "invalid_grant",
                error_description: "subject token expired",
              },
            }),
          ),
      })

      const err = await exchangeToken({
        issuer: ISSUER,
        subjectToken: "subj",
        subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
        audience: AUDIENCE,
        fetch: fetchMock,
      }).then(
        () => null,
        (e: unknown) => e,
      )
      expect(err).toBeInstanceOf(TokenExchangeError)
      const tee = err as TokenExchangeError
      expect(tee.reason).toBe("as-error")
      expect(tee.oauthError).toBe("invalid_grant")
      expect(tee.oauthErrorDescription).toBe("subject token expired")
    })

    it("maps a non-JSON AS response to TokenExchangeError(malformed-response)", async () => {
      const fetchMock = routedFetch({
        "/.well-known/oauth-authorization-server": () =>
          Promise.resolve(mockResponse({ body: { token_endpoint: TOKEN_URL } })),
        "/oauth/token": () => Promise.resolve(mockResponse({ throwOnJson: true })),
      })
      await expect(
        exchangeToken({
          issuer: ISSUER,
          subjectToken: "subj",
          subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
          audience: AUDIENCE,
          fetch: fetchMock,
        }),
      ).rejects.toMatchObject({ name: "TokenExchangeError", reason: "malformed-response" })
    })

    it("maps network failures during discovery to TokenExchangeError(discovery)", async () => {
      const fetchMock: FetchLike = vi.fn(async () => {
        throw new Error("ECONNREFUSED")
      })
      await expect(
        exchangeToken({
          issuer: ISSUER,
          subjectToken: "subj",
          subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
          audience: AUDIENCE,
          fetch: fetchMock,
        }),
      ).rejects.toMatchObject({ name: "TokenExchangeError", reason: "discovery" })
    })

    it("maps network failures during token request to TokenExchangeError(transport)", async () => {
      let firstCall = true
      const fetchMock: FetchLike = vi.fn(async (url) => {
        if (firstCall) {
          firstCall = false
          // Discovery succeeds.
          if (String(url).includes("/.well-known/")) {
            return mockResponse({ body: { token_endpoint: TOKEN_URL } })
          }
        }
        throw new Error("ECONNREFUSED")
      })
      await expect(
        exchangeToken({
          issuer: ISSUER,
          subjectToken: "subj",
          subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
          audience: AUDIENCE,
          fetch: fetchMock,
        }),
      ).rejects.toMatchObject({ name: "TokenExchangeError", reason: "transport" })
    })

    it("rejects AS responses missing access_token", async () => {
      const fetchMock = routedFetch({
        "/.well-known/oauth-authorization-server": () =>
          Promise.resolve(mockResponse({ body: { token_endpoint: TOKEN_URL } })),
        "/oauth/token": () =>
          Promise.resolve(
            mockResponse({
              body: { issued_token_type: "urn:ietf:params:oauth:token-type:access_token" },
            }),
          ),
      })
      await expect(
        exchangeToken({
          issuer: ISSUER,
          subjectToken: "subj",
          subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
          audience: AUDIENCE,
          fetch: fetchMock,
        }),
      ).rejects.toMatchObject({ name: "TokenExchangeError", reason: "malformed-response" })
    })

    it("rejects AS responses missing issued_token_type", async () => {
      const as = await startTestAS()
      try {
        const minted = await as.signToken({ sub: "u", aud: AUDIENCE })
        const fetchMock = routedFetch({
          "/.well-known/oauth-authorization-server": () =>
            Promise.resolve(mockResponse({ body: { token_endpoint: TOKEN_URL } })),
          "/oauth/token": () => Promise.resolve(mockResponse({ body: { access_token: minted } })),
        })
        await expect(
          exchangeToken({
            issuer: ISSUER,
            subjectToken: "subj",
            subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
            audience: AUDIENCE,
            fetch: fetchMock,
          }),
        ).rejects.toMatchObject({ name: "TokenExchangeError", reason: "malformed-response" })
      } finally {
        await as.close()
      }
    })

    it("rejects opaque tokens when no introspection endpoint is available", async () => {
      const fetchMock = routedFetch({
        "/.well-known/oauth-authorization-server": () =>
          Promise.resolve(mockResponse({ body: { token_endpoint: TOKEN_URL } })),
        "/oauth/token": () =>
          Promise.resolve(
            mockResponse({
              body: {
                access_token: "opaque",
                issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
                expires_in: 60,
              },
            }),
          ),
      })
      await expect(
        exchangeToken({
          issuer: ISSUER,
          subjectToken: "subj",
          subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
          audience: AUDIENCE,
          fetch: fetchMock,
        }),
      ).rejects.toMatchObject({ name: "TokenExchangeError", reason: "introspection" })
    })

    it("rejects opaque tokens when introspection reports inactive", async () => {
      const fetchMock = routedFetch({
        "/.well-known/oauth-authorization-server": () =>
          Promise.resolve(
            mockResponse({
              body: {
                token_endpoint: TOKEN_URL,
                introspection_endpoint: INTROSPECTION_URL,
              },
            }),
          ),
        "/oauth/token": () =>
          Promise.resolve(
            mockResponse({
              body: {
                access_token: "opaque",
                issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
                expires_in: 60,
              },
            }),
          ),
        "/oauth/introspect": () => Promise.resolve(mockResponse({ body: { active: false } })),
      })
      await expect(
        exchangeToken({
          issuer: ISSUER,
          subjectToken: "subj",
          subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
          audience: AUDIENCE,
          fetch: fetchMock,
        }),
      ).rejects.toMatchObject({ name: "TokenExchangeError", reason: "inactive" })
    })

    it("rejects discovery responses missing token_endpoint", async () => {
      const fetchMock = routedFetch({
        "/.well-known/oauth-authorization-server": () =>
          Promise.resolve(mockResponse({ body: { issuer: ISSUER } })),
      })
      await expect(
        exchangeToken({
          issuer: ISSUER,
          subjectToken: "subj",
          subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
          audience: AUDIENCE,
          fetch: fetchMock,
        }),
      ).rejects.toMatchObject({ name: "TokenExchangeError", reason: "discovery" })
    })
  })

  describe("input validation", () => {
    it("requires issuer", async () => {
      await expect(
        exchangeToken({
          issuer: "",
          subjectToken: "x",
          subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
          audience: AUDIENCE,
        }),
      ).rejects.toMatchObject({ name: "TokenExchangeError", reason: "input" })
    })

    it("requires audience", async () => {
      await expect(
        exchangeToken({
          issuer: ISSUER,
          subjectToken: "x",
          subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
          audience: "",
        }),
      ).rejects.toMatchObject({ name: "TokenExchangeError", reason: "input" })
    })

    it("requires actorTokenType when actorToken is provided", async () => {
      await expect(
        exchangeToken({
          issuer: ISSUER,
          subjectToken: "x",
          subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
          audience: AUDIENCE,
          actorToken: "a",
        } as Parameters<typeof exchangeToken>[0]),
      ).rejects.toMatchObject({ name: "TokenExchangeError", reason: "input" })
    })
  })

  describe("constants", () => {
    it("metadata URL is built from the issuer with a trailing slash gracefully stripped", async () => {
      // We don't export metadataUrl directly; instead, observe the call.
      const seen: string[] = []
      const fetchMock: FetchLike = vi.fn(async (url) => {
        seen.push(String(url))
        return mockResponse({ status: 500 })
      })
      const err = await exchangeToken({
        issuer: "https://issuer.example/",
        subjectToken: "x",
        subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
        audience: AUDIENCE,
        fetch: fetchMock,
      }).then(
        () => null,
        (e: unknown) => e,
      )
      expect(err).toBeInstanceOf(TokenExchangeError)
      expect(seen[0]).toBe("https://issuer.example/.well-known/oauth-authorization-server")
    })
    it("uses constant URN as the metadata endpoint name", () => {
      expect(METADATA_URL).toBe(`${ISSUER}/.well-known/oauth-authorization-server`)
    })
  })
})
