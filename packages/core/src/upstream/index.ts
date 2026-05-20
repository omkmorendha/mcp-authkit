/**
 * Upstream credential helper (spec v0.2 §5.6, §8.1, §8.2).
 *
 * Built on top of {@link exchangeToken} (RFC 8693). Tool handlers call
 * `authkit.upstreamFor(audience)({ auth, scopes })` (or the standalone
 * convenience wrapper {@link onBehalfOf}) to obtain an audience-bound
 * upstream credential. The framework MINTS a new token via token exchange;
 * the caller's subject token is never returned (v0.1 §14, v0.2 §8).
 *
 * Cache key: SHA-256 of `<subject>\n<audience>\n<sorted-scopes>`. TTL is
 * `min(token.expiresIn, 5 min) − 30 s` so a cached credential always has
 * ≥30 s of useful life when handed out. Cache writes prefer the token
 * store's optional methods (§6.2); otherwise an in-process LRU (cap 100)
 * is used and `logger.warn` fires once at construction time.
 *
 * @module
 */
import { createHash } from "node:crypto"
import type { AuditSink } from "../audit/index.js"
import { dispatchAudit } from "../audit/index.js"
import {
  type ExchangeTokenInput,
  exchangeToken,
  TokenExchangeError,
} from "../oauth/token-exchange.js"
import type {
  AuthContext,
  AuthKit,
  CachedUpstreamCredential,
  TokenStore,
  UpstreamCredential,
  UpstreamForArgs,
} from "../types.js"

/** Maximum cached credentials in the in-process LRU fallback (spec §5.6). */
export const UPSTREAM_LRU_CAPACITY = 100

/** Hard upper-bound on the cache TTL regardless of the AS-issued lifetime. */
export const UPSTREAM_CACHE_TTL_CEILING_SECONDS = 5 * 60

/** Cushion subtracted from the TTL so a cached entry is never on the edge of
 *  expiry when returned to a caller. */
export const UPSTREAM_CACHE_TTL_HEADROOM_SECONDS = 30

/** Minimal logger surface used by the helper. Mirrors pino's level methods. */
export interface UpstreamLogger {
  warn(obj: Record<string, unknown>, msg?: string): void
}

/**
 * Subset of the `exchangeToken` input the helper synthesizes per call.
 * Everything else (issuer + endpoints + transport hooks) is fixed at
 * construction time via {@link UpstreamHelperConfig}.
 */
type CallSpecificExchangeInput = Pick<
  ExchangeTokenInput,
  "subjectToken" | "subjectTokenType" | "audience" | "scopes"
>

/**
 * Wiring required to mint upstream credentials. Constructed by `createAuthKit`
 * from the consumer's `AuthKitConfig`; not part of the public API.
 */
export interface UpstreamHelperConfig {
  /** Issuer used for RFC 8414 discovery when minting tokens. */
  issuer: string
  tokenStore: TokenStore
  audit?: AuditSink
  logger?: UpstreamLogger
  /** Optional override of `exchangeToken` (used in tests). */
  exchange?: (input: ExchangeTokenInput) => Promise<{
    accessToken: string
    expiresAt: Date | null
    scopes: readonly string[]
    tokenType: string
  }>
}

/** Public arguments for {@link onBehalfOf}. */
export interface OnBehalfOfArgs {
  authkit: AuthKit
  auth: AuthContext
  audience: string
  scopes: readonly string[]
}

/**
 * Convenience wrapper around `authkit.upstreamFor(audience)({ auth, scopes })`.
 * Identical semantics, ergonomic name (spec §8.1).
 */
export async function onBehalfOf(args: OnBehalfOfArgs): Promise<UpstreamCredential> {
  return args.authkit.upstreamFor(args.audience)({ auth: args.auth, scopes: args.scopes })
}

/**
 * Build the `upstreamFor` implementation that `createAuthKit` exposes on the
 * `AuthKit` instance. Captures the helper config once so per-call invocation
 * is cheap.
 *
 * Emits a single `logger.warn` at construction time if the token store does
 * not implement the optional cache methods — operators should know an
 * in-process LRU is in play (multi-process deployments will re-exchange on
 * cache misses).
 */
export function createUpstreamFor(
  helperConfig: UpstreamHelperConfig,
): (audience: string) => (args: UpstreamForArgs) => Promise<UpstreamCredential> {
  const storeHasCache =
    typeof helperConfig.tokenStore.cacheUpstreamCredential === "function" &&
    typeof helperConfig.tokenStore.findUpstreamCredential === "function"

  const fallbackCache: LruCache | null = storeHasCache ? null : new LruCache(UPSTREAM_LRU_CAPACITY)
  let fallbackWarned = false
  const warnFallbackOnce = (): void => {
    if (fallbackWarned || fallbackCache === null) return
    fallbackWarned = true
    helperConfig.logger?.warn(
      { capacity: UPSTREAM_LRU_CAPACITY },
      "upstream-credentials: token store does not implement cacheUpstreamCredential/findUpstreamCredential; falling back to in-process LRU",
    )
  }

  const doExchange = helperConfig.exchange ?? exchangeToken

  return (audience: string) => {
    if (typeof audience !== "string" || audience.length === 0) {
      throw new Error("upstreamFor: audience must be a non-empty string")
    }
    return async (args: UpstreamForArgs): Promise<UpstreamCredential> => {
      warnFallbackOnce()
      const { auth, scopes } = args
      const subjectToken = extractSubjectToken(auth)
      const sortedScopes = [...scopes].sort()
      const cacheKey = computeCacheKey(auth.subject, audience, sortedScopes)
      const now = Date.now()

      const cached = await readCache({
        store: helperConfig.tokenStore,
        fallback: fallbackCache,
        cacheKey,
        nowMs: now,
      })
      if (cached !== null) {
        return { token: cached.token, expiresAt: cached.expiresAt }
      }

      const exchangeInput: CallSpecificExchangeInput & Pick<ExchangeTokenInput, "issuer"> = {
        issuer: helperConfig.issuer,
        subjectToken,
        subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
        audience,
        scopes: sortedScopes,
      }

      let minted: Awaited<ReturnType<typeof doExchange>>
      try {
        minted = await doExchange(exchangeInput)
      } catch (err) {
        await dispatchAudit(helperConfig.audit, {
          type: "upstream.exchange_reject",
          at: new Date(now),
          subject: auth.subject,
          tokenId: auth.tokenId,
          detail: {
            audience,
            scopes: sortedScopes,
            reason: reasonOf(err),
            errorClass: err instanceof Error ? err.name : typeof err,
          },
        })
        throw err
      }

      const expiresAt =
        minted.expiresAt ?? new Date(now + UPSTREAM_CACHE_TTL_CEILING_SECONDS * 1000)
      const cacheExpiresAt = computeCacheExpiry(now, minted.expiresAt)

      // Only cache when the trimmed TTL leaves a positive useful window. A
      // negative window means the AS issued a token with ≤30 s of life; we
      // still hand the caller the live token but skip the cache to avoid
      // immediate-stale reads.
      if (cacheExpiresAt.getTime() > now) {
        await writeCache({
          store: helperConfig.tokenStore,
          fallback: fallbackCache,
          cacheKey,
          token: minted.accessToken,
          expiresAt: cacheExpiresAt,
        })
      }

      await dispatchAudit(helperConfig.audit, {
        type: "upstream.exchange",
        at: new Date(now),
        subject: auth.subject,
        tokenId: auth.tokenId,
        detail: {
          audience,
          scopes: minted.scopes,
          expiresAt,
        },
      })

      return { token: minted.accessToken, expiresAt }
    }
  }
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

function extractSubjectToken(auth: AuthContext): string {
  const raw = auth.raw as Record<string, unknown> | undefined
  const candidate = raw?.access_token
  if (typeof candidate !== "string" || candidate.length === 0) {
    throw new Error(
      "upstreamFor: auth.raw.access_token is required for token exchange; the AuthContext does not carry a usable subject token (token-type=" +
        auth.tokenType +
        ")",
    )
  }
  return candidate
}

function computeCacheKey(
  subject: string,
  audience: string,
  sortedScopes: readonly string[],
): string {
  const hash = createHash("sha256")
  hash.update(subject)
  hash.update("\n")
  hash.update(audience)
  hash.update("\n")
  hash.update(sortedScopes.join(" "))
  return hash.digest("hex")
}

function computeCacheExpiry(nowMs: number, mintedExpiresAt: Date | null): Date {
  const ceilingMs = UPSTREAM_CACHE_TTL_CEILING_SECONDS * 1000
  const headroomMs = UPSTREAM_CACHE_TTL_HEADROOM_SECONDS * 1000
  const mintedMs = mintedExpiresAt === null ? Number.POSITIVE_INFINITY : mintedExpiresAt.getTime()
  const cappedMs = Math.min(mintedMs, nowMs + ceilingMs)
  return new Date(cappedMs - headroomMs)
}

function reasonOf(err: unknown): string {
  if (err instanceof TokenExchangeError) return `token-exchange:${err.reason}`
  if (err instanceof Error) return err.name
  return "unknown"
}

interface ReadCacheArgs {
  store: TokenStore
  fallback: LruCache | null
  cacheKey: string
  nowMs: number
}

async function readCache(args: ReadCacheArgs): Promise<CachedUpstreamCredential | null> {
  if (args.fallback !== null) {
    const hit = args.fallback.get(args.cacheKey)
    if (hit === undefined) return null
    if (hit.expiresAt.getTime() <= args.nowMs) {
      args.fallback.delete(args.cacheKey)
      return null
    }
    return { token: hit.token, expiresAt: hit.expiresAt }
  }
  const find = args.store.findUpstreamCredential
  if (find === undefined) return null
  const hit = await find.call(args.store, args.cacheKey)
  if (hit === null) return null
  if (hit.expiresAt.getTime() <= args.nowMs) return null
  return hit
}

interface WriteCacheArgs {
  store: TokenStore
  fallback: LruCache | null
  cacheKey: string
  token: string
  expiresAt: Date
}

async function writeCache(args: WriteCacheArgs): Promise<void> {
  if (args.fallback !== null) {
    args.fallback.set(args.cacheKey, { token: args.token, expiresAt: args.expiresAt })
    return
  }
  const cache = args.store.cacheUpstreamCredential
  if (cache === undefined) return
  await cache.call(args.store, {
    cacheKey: args.cacheKey,
    token: args.token,
    expiresAt: args.expiresAt,
  })
}

/**
 * Tiny LRU used when the token store does not implement the cache methods.
 * Insertion-order semantics of `Map` give us O(1) recency tracking — touch
 * by delete+set on read so the most-recently-used entry is always the tail.
 */
class LruCache {
  readonly #capacity: number
  readonly #entries = new Map<string, CachedUpstreamCredential>()

  constructor(capacity: number) {
    this.#capacity = capacity
  }

  get(key: string): CachedUpstreamCredential | undefined {
    const value = this.#entries.get(key)
    if (value === undefined) return undefined
    // Re-insert to move to the tail (most recently used).
    this.#entries.delete(key)
    this.#entries.set(key, value)
    return value
  }

  set(key: string, value: CachedUpstreamCredential): void {
    if (this.#entries.has(key)) this.#entries.delete(key)
    this.#entries.set(key, value)
    while (this.#entries.size > this.#capacity) {
      const oldest = this.#entries.keys().next()
      if (oldest.done === true) break
      this.#entries.delete(oldest.value)
    }
  }

  delete(key: string): void {
    this.#entries.delete(key)
  }

  get size(): number {
    return this.#entries.size
  }
}
