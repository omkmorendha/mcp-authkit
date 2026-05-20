import { describe, expect, it, vi } from "vitest"
import { TokenExchangeError } from "../oauth/token-exchange.js"
import type { AuditEvent, AuthContext, TokenStore } from "../types.js"
import {
  createUpstreamFor,
  onBehalfOf,
  UPSTREAM_CACHE_TTL_CEILING_SECONDS,
  UPSTREAM_CACHE_TTL_HEADROOM_SECONDS,
  UPSTREAM_LRU_CAPACITY,
} from "./index.js"

const AUDIENCE = "https://upstream.example.test/"
const ISSUER = "https://as.example.test/"
const RESOURCE_INDICATOR = "https://mcp.example.test/"

function buildAuth(overrides: Partial<AuthContext> = {}): AuthContext {
  return {
    subject: "user-42",
    tokenType: "oauth",
    tokenId: "jti-abc",
    scopes: ["mcp:read"],
    expiresAt: new Date(Date.now() + 60_000),
    raw: { access_token: "subject-token-xyz", sub: "user-42" },
    ...overrides,
  }
}

interface FakeStoreOptions {
  withCacheMethods: boolean
}

interface CacheRow {
  token: string
  expiresAt: Date
}

function buildFakeStore(opts: FakeStoreOptions): {
  store: TokenStore
  cache: Map<string, CacheRow>
  cacheSpy: ReturnType<typeof vi.fn>
  findSpy: ReturnType<typeof vi.fn>
} {
  const cache = new Map<string, CacheRow>()
  const cacheSpy = vi.fn(async (input: { cacheKey: string; token: string; expiresAt: Date }) => {
    cache.set(input.cacheKey, { token: input.token, expiresAt: input.expiresAt })
  })
  const findSpy = vi.fn(async (cacheKey: string): Promise<CacheRow | null> => {
    const hit = cache.get(cacheKey)
    if (hit === undefined) return null
    if (hit.expiresAt.getTime() <= Date.now()) {
      cache.delete(cacheKey)
      return null
    }
    return hit
  })

  const base = {
    async createPat() {
      throw new Error("not implemented")
    },
    async findPatByHash() {
      return null
    },
    async listPatsByUser() {
      return []
    },
    async revokePat() {},
    async rotatePat() {
      throw new Error("not implemented")
    },
    async updatePatLastUsed() {},
    async createRefreshToken() {},
    async findRefreshToken() {
      return null
    },
    async rotateRefreshToken() {},
    async revokeRefreshTokenFamily() {},
  } satisfies Partial<TokenStore>

  const store: TokenStore = opts.withCacheMethods
    ? {
        ...(base as TokenStore),
        cacheUpstreamCredential: cacheSpy,
        findUpstreamCredential: findSpy,
      }
    : (base as TokenStore)

  return { store, cache, cacheSpy, findSpy }
}

function mockedExchange(
  impl?: (input: { audience: string; scopes?: readonly string[]; subjectToken: string }) => {
    accessToken: string
    expiresAt: Date | null
    scopes?: readonly string[]
  },
) {
  return vi.fn(async (input) => {
    const result = impl
      ? impl(input)
      : {
          accessToken: `minted-for-${input.audience}`,
          expiresAt: new Date(Date.now() + 60_000),
          scopes: input.scopes ?? [],
        }
    return {
      accessToken: result.accessToken,
      expiresAt: result.expiresAt,
      scopes: Object.freeze([...(result.scopes ?? input.scopes ?? [])]),
      tokenType: "urn:ietf:params:oauth:token-type:access_token",
    }
  })
}

describe("createUpstreamFor", () => {
  describe("happy path with store cache", () => {
    it("calls exchangeToken, caches the result, returns the minted token", async () => {
      const { store, cacheSpy } = buildFakeStore({ withCacheMethods: true })
      const exchange = mockedExchange()
      const audit = vi.fn<(event: AuditEvent) => Promise<void>>(async () => {})
      const factory = createUpstreamFor({
        issuer: ISSUER,
        resourceIndicator: RESOURCE_INDICATOR,
        tokenStore: store,
        audit,
        exchange,
      })
      const fetcher = factory(AUDIENCE)

      const out = await fetcher({ auth: buildAuth(), scopes: ["upstream:write", "upstream:read"] })

      expect(out.token).toBe(`minted-for-${AUDIENCE}`)
      expect(out.expiresAt).toBeInstanceOf(Date)
      expect(exchange).toHaveBeenCalledTimes(1)
      expect(cacheSpy).toHaveBeenCalledTimes(1)

      const call = exchange.mock.calls[0]?.[0]
      expect(call).toBeDefined()
      expect(call?.issuer).toBe(ISSUER)
      expect(call?.audience).toBe(AUDIENCE)
      expect(call?.subjectToken).toBe("subject-token-xyz")
      expect(call?.subjectTokenType).toBe("urn:ietf:params:oauth:token-type:access_token")
      // scopes must be sorted before being sent to the AS (cache-key stability).
      expect(call?.scopes).toEqual(["upstream:read", "upstream:write"])

      expect(audit).toHaveBeenCalledTimes(1)
      const event = audit.mock.calls[0]?.[0]
      expect(event).toBeDefined()
      expect(event?.type).toBe("upstream.exchange")
      expect(event?.subject).toBe("user-42")
      expect(event?.tokenId).toBe("jti-abc")
      expect(event?.detail.audience).toBe(AUDIENCE)
      expect(event?.detail.scopes).toEqual(["upstream:read", "upstream:write"])
      // Token boundary: the audit payload MUST NOT carry any token material.
      expect(event?.detail).not.toHaveProperty("token")
      expect(event?.detail).not.toHaveProperty("access_token")
      expect(event?.detail).not.toHaveProperty("accessToken")
      expect(event?.detail).not.toHaveProperty("subject_token")
      expect(event?.detail).not.toHaveProperty("subjectToken")
    })
  })

  describe("cache semantics", () => {
    it("returns cached value on second call within TTL without re-exchanging", async () => {
      const { store } = buildFakeStore({ withCacheMethods: true })
      const exchange = mockedExchange()
      const fetcher = createUpstreamFor({
        issuer: ISSUER,
        resourceIndicator: RESOURCE_INDICATOR,
        tokenStore: store,
        exchange,
      })(AUDIENCE)

      const auth = buildAuth()
      const first = await fetcher({ auth, scopes: ["upstream:read"] })
      const second = await fetcher({ auth, scopes: ["upstream:read"] })

      expect(second.token).toBe(first.token)
      expect(exchange).toHaveBeenCalledTimes(1)
    })

    it("re-exchanges after the cached entry expires", async () => {
      // Mint a token whose AS-issued TTL puts the cache window below the
      // 30 s headroom (so the helper skips the cache write), and then a
      // second mint with a longer TTL. Two calls => two exchanges.
      const { store } = buildFakeStore({ withCacheMethods: true })
      let n = 0
      const exchange = mockedExchange((input) => {
        n += 1
        return {
          accessToken: `minted-${n}-for-${input.audience}`,
          // First mint: expires in 5 s — below the 30 s headroom => not cached.
          // Second mint: expires in 60 s — cached normally.
          expiresAt: new Date(Date.now() + (n === 1 ? 5_000 : 60_000)),
          scopes: input.scopes ?? [],
        }
      })
      const fetcher = createUpstreamFor({
        issuer: ISSUER,
        resourceIndicator: RESOURCE_INDICATOR,
        tokenStore: store,
        exchange,
      })(AUDIENCE)

      const a = await fetcher({ auth: buildAuth(), scopes: ["upstream:read"] })
      const b = await fetcher({ auth: buildAuth(), scopes: ["upstream:read"] })

      expect(a.token).toBe(`minted-1-for-${AUDIENCE}`)
      expect(b.token).toBe(`minted-2-for-${AUDIENCE}`)
      expect(exchange).toHaveBeenCalledTimes(2)
    })

    it("respects the 5 min / −30 s cache TTL trim", async () => {
      const { cache, store } = buildFakeStore({ withCacheMethods: true })
      // AS-issued lifetime far exceeds the 5 min ceiling.
      const exchange = mockedExchange(() => ({
        accessToken: "long-lived",
        expiresAt: new Date(Date.now() + 60 * 60 * 1000),
        scopes: [],
      }))
      const fetcher = createUpstreamFor({
        issuer: ISSUER,
        resourceIndicator: RESOURCE_INDICATOR,
        tokenStore: store,
        exchange,
      })(AUDIENCE)

      const now = Date.now()
      await fetcher({ auth: buildAuth(), scopes: [] })

      expect(cache.size).toBe(1)
      const stored = [...cache.values()][0]
      expect(stored).toBeDefined()
      const expectedMs =
        now + UPSTREAM_CACHE_TTL_CEILING_SECONDS * 1000 - UPSTREAM_CACHE_TTL_HEADROOM_SECONDS * 1000
      expect(Math.abs((stored?.expiresAt.getTime() ?? 0) - expectedMs)).toBeLessThan(1_000)
    })

    it("isolates cache by (subject, audience, scopes)", async () => {
      const { store } = buildFakeStore({ withCacheMethods: true })
      const exchange = mockedExchange()
      const fetcher = createUpstreamFor({
        issuer: ISSUER,
        resourceIndicator: RESOURCE_INDICATOR,
        tokenStore: store,
        exchange,
      })(AUDIENCE)

      await fetcher({ auth: buildAuth({ subject: "alice" }), scopes: ["read"] })
      await fetcher({ auth: buildAuth({ subject: "bob" }), scopes: ["read"] })
      await fetcher({ auth: buildAuth({ subject: "alice" }), scopes: ["write"] })
      await fetcher({ auth: buildAuth({ subject: "alice" }), scopes: ["read"] })

      // alice/read is reused on the 4th call; the other three are unique keys.
      expect(exchange).toHaveBeenCalledTimes(3)
    })
  })

  describe("LRU fallback", () => {
    it("warns on first use when the store omits the cache methods", async () => {
      const { store } = buildFakeStore({ withCacheMethods: false })
      const logger = { warn: vi.fn() }
      const fetcher = createUpstreamFor({
        issuer: ISSUER,
        resourceIndicator: RESOURCE_INDICATOR,
        tokenStore: store,
        logger,
        exchange: mockedExchange(),
      })(AUDIENCE)
      // Construction itself stays quiet — startup logs are precious in
      // production stdio mode and we don't want a fallback notice on every
      // server that never calls upstreamFor.
      expect(logger.warn).not.toHaveBeenCalled()
      await fetcher({ auth: buildAuth(), scopes: ["read"] })
      expect(logger.warn).toHaveBeenCalledTimes(1)
      const call = logger.warn.mock.calls[0]?.[0]
      expect(call).toBeDefined()
      expect(call?.capacity).toBe(UPSTREAM_LRU_CAPACITY)
      // And only once: subsequent calls don't re-warn.
      await fetcher({ auth: buildAuth({ subject: "other" }), scopes: ["read"] })
      expect(logger.warn).toHaveBeenCalledTimes(1)
    })

    it("caches and serves from the in-process LRU when the store lacks methods", async () => {
      const { store } = buildFakeStore({ withCacheMethods: false })
      const logger = { warn: vi.fn() }
      const exchange = mockedExchange()
      const fetcher = createUpstreamFor({
        issuer: ISSUER,
        resourceIndicator: RESOURCE_INDICATOR,
        tokenStore: store,
        logger,
        exchange,
      })(AUDIENCE)

      const first = await fetcher({ auth: buildAuth(), scopes: ["read"] })
      const second = await fetcher({ auth: buildAuth(), scopes: ["read"] })

      expect(second.token).toBe(first.token)
      expect(exchange).toHaveBeenCalledTimes(1)
    })

    it("does not warn when the store provides both cache methods", async () => {
      const { store } = buildFakeStore({ withCacheMethods: true })
      const logger = { warn: vi.fn() }
      const fetcher = createUpstreamFor({
        issuer: ISSUER,
        resourceIndicator: RESOURCE_INDICATOR,
        tokenStore: store,
        logger,
        exchange: mockedExchange(),
      })(AUDIENCE)
      await fetcher({ auth: buildAuth(), scopes: ["read"] })
      expect(logger.warn).not.toHaveBeenCalled()
    })
  })

  describe("error paths", () => {
    it("throws clearly when auth.raw.access_token is missing", async () => {
      const { store } = buildFakeStore({ withCacheMethods: true })
      const exchange = mockedExchange()
      const fetcher = createUpstreamFor({
        issuer: ISSUER,
        resourceIndicator: RESOURCE_INDICATOR,
        tokenStore: store,
        exchange,
      })(AUDIENCE)

      await expect(
        fetcher({
          auth: buildAuth({ raw: { sub: "user-42" } }),
          scopes: ["read"],
        }),
      ).rejects.toThrow(/auth\.raw\.access_token/)
      expect(exchange).not.toHaveBeenCalled()
    })

    it("throws when auth.raw.access_token is the empty string", async () => {
      const { store } = buildFakeStore({ withCacheMethods: true })
      const exchange = mockedExchange()
      const fetcher = createUpstreamFor({
        issuer: ISSUER,
        resourceIndicator: RESOURCE_INDICATOR,
        tokenStore: store,
        exchange,
      })(AUDIENCE)

      await expect(
        fetcher({
          auth: buildAuth({ raw: { access_token: "" } }),
          scopes: ["read"],
        }),
      ).rejects.toThrow(/auth\.raw\.access_token/)
      expect(exchange).not.toHaveBeenCalled()
    })

    it("fires upstream.exchange_reject and rethrows on exchange failure", async () => {
      const { store } = buildFakeStore({ withCacheMethods: true })
      const exchange = vi.fn(async () => {
        throw new TokenExchangeError("as-error", "AS rejected token exchange (HTTP 400)", {
          oauthError: "invalid_grant",
        })
      })
      const audit = vi.fn<(event: AuditEvent) => Promise<void>>(async () => {})
      const fetcher = createUpstreamFor({
        issuer: ISSUER,
        resourceIndicator: RESOURCE_INDICATOR,
        tokenStore: store,
        audit,
        exchange,
      })(AUDIENCE)

      await expect(fetcher({ auth: buildAuth(), scopes: ["read"] })).rejects.toBeInstanceOf(
        TokenExchangeError,
      )

      expect(audit).toHaveBeenCalledTimes(1)
      const event = audit.mock.calls[0]?.[0]
      expect(event).toBeDefined()
      expect(event?.type).toBe("upstream.exchange_reject")
      expect(event?.detail.audience).toBe(AUDIENCE)
      expect(event?.detail.scopes).toEqual(["read"])
      expect(event?.detail.reason).toBe("token-exchange:as-error")
      // The reject audit MUST NOT leak the subject token either.
      expect(event?.detail).not.toHaveProperty("token")
      expect(event?.detail).not.toHaveProperty("subject_token")
      expect(event?.detail).not.toHaveProperty("subjectToken")
      expect(event?.detail).not.toHaveProperty("access_token")
    })

    it("never returns the subject token when exchange fails", async () => {
      const { store } = buildFakeStore({ withCacheMethods: true })
      const exchange = vi.fn(async () => {
        throw new Error("boom")
      })
      const fetcher = createUpstreamFor({
        issuer: ISSUER,
        resourceIndicator: RESOURCE_INDICATOR,
        tokenStore: store,
        exchange,
      })(AUDIENCE)

      const result = await fetcher({ auth: buildAuth(), scopes: ["read"] }).then(
        (ok) => ({ ok }),
        (err: unknown) => ({ err }),
      )
      expect("err" in result).toBe(true)
      if ("err" in result) {
        expect(result.err).toBeInstanceOf(Error)
        expect((result.err as Error).message).toBe("boom")
        // Sanity: the thrown error does not carry the subject token by accident.
        expect(JSON.stringify(result.err)).not.toContain("subject-token-xyz")
      }
    })

    it("rejects PAT tokenType with a clear message naming the tokenType (#107)", async () => {
      const { store } = buildFakeStore({ withCacheMethods: true })
      const exchange = mockedExchange()
      const fetcher = createUpstreamFor({
        issuer: ISSUER,
        resourceIndicator: RESOURCE_INDICATOR,
        tokenStore: store,
        exchange,
      })(AUDIENCE)
      await expect(
        fetcher({
          auth: buildAuth({ tokenType: "pat", raw: { access_token: "x" } }),
          scopes: ["read"],
        }),
      ).rejects.toThrow(/tokenType=pat/)
      expect(exchange).not.toHaveBeenCalled()
    })

    it("rejects static tokenType with a clear message (#107)", async () => {
      const { store } = buildFakeStore({ withCacheMethods: true })
      const exchange = mockedExchange()
      const fetcher = createUpstreamFor({
        issuer: ISSUER,
        resourceIndicator: RESOURCE_INDICATOR,
        tokenStore: store,
        exchange,
      })(AUDIENCE)
      await expect(
        fetcher({
          auth: buildAuth({ tokenType: "static", raw: { access_token: "x" } }),
          scopes: ["read"],
        }),
      ).rejects.toThrow(/tokenType=static/)
    })

    it("rejects empty-string audiences eagerly", () => {
      const { store } = buildFakeStore({ withCacheMethods: true })
      const factory = createUpstreamFor({
        issuer: ISSUER,
        resourceIndicator: RESOURCE_INDICATOR,
        tokenStore: store,
        exchange: mockedExchange(),
      })
      expect(() => factory("")).toThrow(/audience/)
    })
  })
})

describe("createUpstreamFor — subject-audience enforcement (spec v0.2 §8)", () => {
  it("passes resourceIndicator as expectedSubjectAudience on every exchange call", async () => {
    const { store } = buildFakeStore({ withCacheMethods: true })
    const exchange = mockedExchange()
    const fetcher = createUpstreamFor({
      issuer: ISSUER,
      resourceIndicator: RESOURCE_INDICATOR,
      tokenStore: store,
      exchange,
    })(AUDIENCE)

    await fetcher({ auth: buildAuth(), scopes: ["read"] })

    expect(exchange).toHaveBeenCalledTimes(1)
    const call = exchange.mock.calls[0]?.[0]
    expect(call).toBeDefined()
    expect(call?.expectedSubjectAudience).toBe(RESOURCE_INDICATOR)
  })

  it("propagates a subject-audience TokenExchangeError and audits the rejection", async () => {
    const { store } = buildFakeStore({ withCacheMethods: true })
    const exchange = vi.fn(async () => {
      throw new TokenExchangeError(
        "subject-audience",
        "subject token audience does not match expected resource indicator",
      )
    })
    const audit = vi.fn<(event: AuditEvent) => Promise<void>>(async () => {})
    const fetcher = createUpstreamFor({
      issuer: ISSUER,
      resourceIndicator: RESOURCE_INDICATOR,
      tokenStore: store,
      audit,
      exchange,
    })(AUDIENCE)

    await expect(fetcher({ auth: buildAuth(), scopes: ["read"] })).rejects.toMatchObject({
      name: "TokenExchangeError",
      reason: "subject-audience",
    })

    expect(audit).toHaveBeenCalledTimes(1)
    const event = audit.mock.calls[0]?.[0]
    expect(event?.type).toBe("upstream.exchange_reject")
    expect(event?.detail.reason).toBe("token-exchange:subject-audience")
  })
})

describe("createUpstreamFor: function-form issuer resolver (#107)", () => {
  it("forwards the resolver-returned issuer to exchangeToken", async () => {
    const { store } = buildFakeStore({ withCacheMethods: true })
    const exchange = mockedExchange()
    const resolver = vi.fn((auth: AuthContext) => `${ISSUER}#${auth.subject}`)
    const fetcher = createUpstreamFor({
      issuer: resolver,
      resourceIndicator: RESOURCE_INDICATOR,
      tokenStore: store,
      exchange,
    })(AUDIENCE)

    await fetcher({ auth: buildAuth({ subject: "alice" }), scopes: ["read"] })

    expect(resolver).toHaveBeenCalledTimes(1)
    const call = exchange.mock.calls[0]?.[0]
    expect(call?.issuer).toBe(`${ISSUER}#alice`)
  })

  it("isolates the cache by resolved issuer (no cross-tenant collision)", async () => {
    // Two AuthContexts with identical subject/audience/scopes but DIFFERENT
    // resolved issuers must produce two distinct cache entries — otherwise
    // tenant A could be handed tenant B's minted token.
    const { store } = buildFakeStore({ withCacheMethods: true })
    const exchange = mockedExchange((input) => ({
      accessToken: `minted-for-${input.subjectToken}-via-${input.audience}`,
      expiresAt: new Date(Date.now() + 60_000),
      scopes: input.scopes ?? [],
    }))
    const resolver = (auth: AuthContext) => {
      const raw = auth.raw as { iss?: string }
      return raw.iss ?? ""
    }
    const fetcher = createUpstreamFor({
      issuer: resolver,
      resourceIndicator: RESOURCE_INDICATOR,
      tokenStore: store,
      exchange,
    })(AUDIENCE)

    const authA = buildAuth({
      raw: { access_token: "subj", iss: "https://tenant-a.example.test" },
    })
    const authB = buildAuth({
      raw: { access_token: "subj", iss: "https://tenant-b.example.test" },
    })

    await fetcher({ auth: authA, scopes: ["read"] })
    await fetcher({ auth: authB, scopes: ["read"] })
    await fetcher({ auth: authA, scopes: ["read"] }) // hits cache
    await fetcher({ auth: authB, scopes: ["read"] }) // hits cache

    // Two distinct issuers + identical (subject, audience, scopes) =>
    // two exchange calls, then both calls served from cache.
    expect(exchange).toHaveBeenCalledTimes(2)
    const issuers = exchange.mock.calls.map((c) => c[0].issuer)
    expect(new Set(issuers)).toEqual(
      new Set(["https://tenant-a.example.test", "https://tenant-b.example.test"]),
    )
  })

  it("surfaces a typed error when the resolver throws", async () => {
    const { store } = buildFakeStore({ withCacheMethods: true })
    const exchange = mockedExchange()
    const resolver = () => {
      throw new Error("tenant lookup down")
    }
    const fetcher = createUpstreamFor({
      issuer: resolver,
      resourceIndicator: RESOURCE_INDICATOR,
      tokenStore: store,
      exchange,
    })(AUDIENCE)

    await expect(fetcher({ auth: buildAuth(), scopes: ["read"] })).rejects.toThrow(
      /issuer resolver threw: tenant lookup down/,
    )
    expect(exchange).not.toHaveBeenCalled()
  })

  it("surfaces a typed error when the resolver returns an empty string", async () => {
    const { store } = buildFakeStore({ withCacheMethods: true })
    const exchange = mockedExchange()
    const fetcher = createUpstreamFor({
      issuer: () => "",
      resourceIndicator: RESOURCE_INDICATOR,
      tokenStore: store,
      exchange,
    })(AUDIENCE)

    await expect(fetcher({ auth: buildAuth(), scopes: ["read"] })).rejects.toThrow(
      /empty\/invalid issuer/,
    )
    expect(exchange).not.toHaveBeenCalled()
  })
})

describe("onBehalfOf", () => {
  it("delegates to authkit.upstreamFor(audience)", async () => {
    const auth = buildAuth()
    const credential = { token: "minted", expiresAt: new Date(Date.now() + 60_000) }
    const fetcher = vi.fn(async () => credential)
    const upstreamFor = vi.fn((aud: string) => {
      expect(aud).toBe(AUDIENCE)
      return fetcher
    })

    const result = await onBehalfOf({
      authkit: {
        registerTool: () => {},
        handlers: () => {
          throw new Error("not used")
        },
        upstreamFor,
      },
      auth,
      audience: AUDIENCE,
      scopes: ["read"],
    })

    expect(result).toBe(credential)
    expect(upstreamFor).toHaveBeenCalledWith(AUDIENCE)
    expect(fetcher).toHaveBeenCalledWith({ auth, scopes: ["read"] })
  })
})
