/**
 * RFC 8693 OAuth 2.0 Token Exchange client.
 *
 * Spec: docs/spec/v0.2.md#55-token-exchange-rfc-8693 and §8 (hard rules).
 *
 * Mints a downstream/upstream access token from an authorization server
 * that supports RFC 8693. The minted token is audience-bound to the
 * caller-supplied `audience` and validated before being returned.
 *
 * Security non-negotiables (v0.2 §8, §12):
 * - The returned token's `aud` MUST equal the requested audience.
 * - On any failure the function throws — it MUST NOT fall back to the
 *   subject token. The subject token is never returned to the caller.
 * - The minted token is never logged at any level. Pino redaction paths
 *   are declared so a consumer-attached logger cannot accidentally print
 *   it either.
 * - The HTTP request body is capped at 64 KB; oversize subject tokens
 *   are rejected client-side before any network call.
 *
 * @module
 */
import { decodeJwt } from "jose"

/** RFC 8693 grant type. */
export const TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"

/** RFC 8693 token-type URIs commonly used in `subject_token_type`. */
export type SubjectTokenType =
  | "urn:ietf:params:oauth:token-type:access_token"
  | "urn:ietf:params:oauth:token-type:refresh_token"
  | "urn:ietf:params:oauth:token-type:id_token"
  | "urn:ietf:params:oauth:token-type:jwt"
  | "urn:ietf:params:oauth:token-type:saml1"
  | "urn:ietf:params:oauth:token-type:saml2"

/** RFC 8693 token-type URIs commonly used in `actor_token_type`. */
export type ActorTokenType = SubjectTokenType

/**
 * Spec §12: HTTP request body cap. Applied to the encoded form body that
 * goes on the wire, with a client-side guard on the raw `subject_token`
 * (and `actor_token`) length before encoding.
 */
export const TOKEN_EXCHANGE_BODY_LIMIT_BYTES = 64 * 1024

/** Pino redaction paths so consumers' loggers cannot accidentally print
 *  a minted token. Re-export for inclusion in a project-level pino setup.
 *  Used internally by the typed `Logger` argument as well.
 */
export const TOKEN_EXCHANGE_LOG_REDACT_PATHS: readonly string[] = Object.freeze([
  "accessToken",
  "*.accessToken",
  "token",
  "*.token",
  "subjectToken",
  "*.subjectToken",
  "actorToken",
  "*.actorToken",
  "response.access_token",
  "response.refresh_token",
])

/**
 * Minimal `fetch` surface this module depends on. Mirrors the shape used
 * by `auth/introspection.ts` so consumers can pass the same stub.
 */
export type FetchLike = (
  input: string | URL,
  init?: {
    method?: string
    headers?: Record<string, string>
    body?: string
    signal?: AbortSignal
  },
) => Promise<{
  ok: boolean
  status: number
  json(): Promise<unknown>
  text(): Promise<string>
}>

/**
 * Minimal logger surface. Compatible with pino's `Logger` shape (only the
 * level methods we actually call). The minted token is never passed to any
 * of these methods, but the shape is kept narrow so the public surface
 * never accepts `any`.
 */
export interface TokenExchangeLogger {
  debug(obj: Record<string, unknown>, msg?: string): void
  warn(obj: Record<string, unknown>, msg?: string): void
  error(obj: Record<string, unknown>, msg?: string): void
}

export interface ExchangeTokenInput {
  /** Issuer URL of the authorization server (RFC 8414 base for discovery). */
  issuer: string
  /** The subject token to exchange. */
  subjectToken: string
  /** RFC 8693 `subject_token_type`. */
  subjectTokenType: SubjectTokenType
  /** Resource the minted token will address. Used for both `audience` and `resource` (RFC 8707). */
  audience: string
  /** Optional requested scopes. */
  scopes?: readonly string[]
  /** Optional actor token (RFC 8693 §2.1). */
  actorToken?: string
  /** Required when `actorToken` is provided. */
  actorTokenType?: ActorTokenType
  /**
   * Optional pre-discovered `token_endpoint` URL. Skips RFC 8414 discovery.
   * Useful in tests and for ASes that do not publish metadata at the
   * standard location.
   */
  tokenEndpoint?: string
  /**
   * Optional pre-discovered `introspection_endpoint`. Used to validate the
   * minted token when the AS issues an opaque (non-JWT) `access_token`.
   * If absent, RFC 8414 discovery is attempted; if discovery also lacks
   * an introspection endpoint and the minted token is not a JWT, the
   * exchange fails closed.
   */
  introspectionEndpoint?: string
  /** Network timeout for each HTTP call. Defaults to 5 000 ms. */
  timeoutMs?: number
  /** Override of `globalThis.fetch`. */
  fetch?: FetchLike
  /** Optional structured logger. The minted token is never logged. */
  logger?: TokenExchangeLogger
}

export interface ExchangedToken {
  accessToken: string
  expiresAt: Date | null
  scopes: readonly string[]
  /** RFC 8693 `issued_token_type` returned by the AS. */
  tokenType: string
}

/** Discriminator for the typed error subclasses below. */
export type TokenExchangeErrorReason =
  | "input"
  | "request-too-large"
  | "discovery"
  | "transport"
  | "as-error"
  | "malformed-response"
  | "audience"
  | "introspection"
  | "inactive"

/**
 * Base error class for `exchangeToken`. Concrete reasons live on the
 * `reason` discriminator so callers can branch with full type narrowing
 * without instanceof spelunking.
 */
export class TokenExchangeError extends Error {
  readonly reason: TokenExchangeErrorReason
  /** AS-supplied `error` field (RFC 6749 §5.2) when reason === "as-error". */
  readonly oauthError?: string
  /** AS-supplied `error_description` when reason === "as-error". */
  readonly oauthErrorDescription?: string

  constructor(
    reason: TokenExchangeErrorReason,
    message: string,
    extras?: { oauthError?: string; oauthErrorDescription?: string },
  ) {
    super(message)
    this.name = "TokenExchangeError"
    this.reason = reason
    if (extras?.oauthError !== undefined) this.oauthError = extras.oauthError
    if (extras?.oauthErrorDescription !== undefined) {
      this.oauthErrorDescription = extras.oauthErrorDescription
    }
  }
}

interface AsMetadata {
  tokenEndpoint: string
  introspectionEndpoint: string | null
}

/**
 * Exchange a subject token for an audience-bound minted token (RFC 8693).
 *
 * Fail-closed: every error path throws {@link TokenExchangeError}. There
 * is no fallback to the subject token.
 */
export async function exchangeToken(input: ExchangeTokenInput): Promise<ExchangedToken> {
  validateInput(input)

  const doFetch: FetchLike = input.fetch ?? (globalThis.fetch as FetchLike)
  const timeoutMs = input.timeoutMs ?? 5_000

  const params = buildRequestParams(input)
  const body = params.toString()
  if (Buffer.byteLength(body, "utf8") > TOKEN_EXCHANGE_BODY_LIMIT_BYTES) {
    // Re-check the encoded form size after URL-encoding; the per-token
    // pre-check in validateInput catches the common case but encoding
    // expansion (e.g. many `+`/`/` characters) can push a borderline
    // payload over the wire limit.
    throw new TokenExchangeError(
      "request-too-large",
      `encoded token-exchange body exceeds ${TOKEN_EXCHANGE_BODY_LIMIT_BYTES} bytes`,
    )
  }

  const metadata = await resolveMetadata(input, doFetch, timeoutMs)

  const tokenResponse = await postTokenRequest(metadata.tokenEndpoint, body, doFetch, timeoutMs)

  const accessToken = readString(tokenResponse, "access_token")
  if (accessToken === null || accessToken.length === 0) {
    throw new TokenExchangeError("malformed-response", "AS response missing access_token")
  }
  const issuedTokenType = readString(tokenResponse, "issued_token_type")
  if (issuedTokenType === null || issuedTokenType.length === 0) {
    throw new TokenExchangeError("malformed-response", "AS response missing issued_token_type")
  }

  const expiresIn = readNumber(tokenResponse, "expires_in")
  const expiresAt = expiresIn === null ? null : new Date(Date.now() + expiresIn * 1000)

  // Scopes returned by the AS take precedence over requested scopes; some
  // ASes downscope. Falls back to the requested list when the AS is silent.
  const scopeString = readString(tokenResponse, "scope")
  const scopes =
    scopeString !== null ? parseScopeString(scopeString) : Object.freeze([...(input.scopes ?? [])])

  await validateAudience({
    accessToken,
    expectedAudience: input.audience,
    introspectionEndpoint: metadata.introspectionEndpoint,
    doFetch,
    timeoutMs,
  })

  input.logger?.debug(
    {
      audience: input.audience,
      issuer: input.issuer,
      scopes,
      issuedTokenType,
      expiresAt,
    },
    "token exchange succeeded",
  )

  return {
    accessToken,
    expiresAt,
    scopes,
    tokenType: issuedTokenType,
  }
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

function validateInput(input: ExchangeTokenInput): void {
  if (typeof input.issuer !== "string" || input.issuer.length === 0) {
    throw new TokenExchangeError("input", "issuer is required")
  }
  if (typeof input.audience !== "string" || input.audience.length === 0) {
    throw new TokenExchangeError("input", "audience is required")
  }
  if (typeof input.subjectToken !== "string" || input.subjectToken.length === 0) {
    throw new TokenExchangeError("input", "subjectToken is required")
  }
  if (typeof input.subjectTokenType !== "string" || input.subjectTokenType.length === 0) {
    throw new TokenExchangeError("input", "subjectTokenType is required")
  }
  if (input.actorToken !== undefined) {
    if (typeof input.actorToken !== "string" || input.actorToken.length === 0) {
      throw new TokenExchangeError("input", "actorToken, if provided, must be a non-empty string")
    }
    if (typeof input.actorTokenType !== "string" || input.actorTokenType.length === 0) {
      throw new TokenExchangeError("input", "actorTokenType is required when actorToken is set")
    }
  }

  // Spec §12: request body capped at 64 KB. We enforce a sub-cap on the
  // raw subject token (plus actor token when present) so the rejection
  // fires BEFORE any HTTP call.
  const subjectLen = Buffer.byteLength(input.subjectToken, "utf8")
  const actorLen = input.actorToken !== undefined ? Buffer.byteLength(input.actorToken, "utf8") : 0
  if (subjectLen + actorLen > TOKEN_EXCHANGE_BODY_LIMIT_BYTES) {
    throw new TokenExchangeError(
      "request-too-large",
      `subject token exceeds ${TOKEN_EXCHANGE_BODY_LIMIT_BYTES}-byte request-body limit`,
    )
  }
}

function buildRequestParams(input: ExchangeTokenInput): URLSearchParams {
  const params = new URLSearchParams()
  params.set("grant_type", TOKEN_EXCHANGE_GRANT_TYPE)
  params.set("subject_token", input.subjectToken)
  params.set("subject_token_type", input.subjectTokenType)
  params.set("audience", input.audience)
  // RFC 8707: bind the minted token to the upstream resource. The spec
  // requires `resource` to equal `audience` for our use; that is enforced
  // here, not optional.
  params.set("resource", input.audience)
  if (input.scopes !== undefined && input.scopes.length > 0) {
    params.set("scope", input.scopes.join(" "))
  }
  if (input.actorToken !== undefined && input.actorTokenType !== undefined) {
    params.set("actor_token", input.actorToken)
    params.set("actor_token_type", input.actorTokenType)
  }
  return params
}

async function resolveMetadata(
  input: ExchangeTokenInput,
  doFetch: FetchLike,
  timeoutMs: number,
): Promise<AsMetadata> {
  // Caller can short-circuit discovery entirely.
  if (input.tokenEndpoint !== undefined) {
    return {
      tokenEndpoint: input.tokenEndpoint,
      introspectionEndpoint: input.introspectionEndpoint ?? null,
    }
  }

  const url = metadataUrl(input.issuer)

  let response: Awaited<ReturnType<FetchLike>>
  try {
    response = await doFetch(url, {
      method: "GET",
      headers: { Accept: "application/json" },
      signal: timeoutSignal(timeoutMs),
    })
  } catch (err) {
    const message = err instanceof Error ? err.message : "fetch failed"
    throw new TokenExchangeError("discovery", `AS metadata discovery failed: ${message}`)
  }

  if (!response.ok) {
    throw new TokenExchangeError(
      "discovery",
      `AS metadata discovery returned HTTP ${response.status}`,
    )
  }

  let body: unknown
  try {
    body = await response.json()
  } catch (err) {
    const message = err instanceof Error ? err.message : "invalid json"
    throw new TokenExchangeError("discovery", `AS metadata is not valid JSON: ${message}`)
  }
  if (!isRecord(body)) {
    throw new TokenExchangeError("discovery", "AS metadata is not a JSON object")
  }
  const tokenEndpoint = readString(body, "token_endpoint")
  if (tokenEndpoint === null || tokenEndpoint.length === 0) {
    throw new TokenExchangeError("discovery", "AS metadata missing token_endpoint")
  }
  const introspectionEndpoint = readString(body, "introspection_endpoint")
  return {
    tokenEndpoint,
    introspectionEndpoint:
      input.introspectionEndpoint ??
      (introspectionEndpoint !== null && introspectionEndpoint.length > 0
        ? introspectionEndpoint
        : null),
  }
}

function metadataUrl(issuer: string): string {
  const base = issuer.endsWith("/") ? issuer.slice(0, -1) : issuer
  return `${base}/.well-known/oauth-authorization-server`
}

async function postTokenRequest(
  tokenEndpoint: string,
  body: string,
  doFetch: FetchLike,
  timeoutMs: number,
): Promise<Record<string, unknown>> {
  let response: Awaited<ReturnType<FetchLike>>
  try {
    response = await doFetch(tokenEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body,
      signal: timeoutSignal(timeoutMs),
    })
  } catch (err) {
    const message = err instanceof Error ? err.message : "fetch failed"
    throw new TokenExchangeError("transport", `token endpoint request failed: ${message}`)
  }

  let parsed: unknown
  try {
    parsed = await response.json()
  } catch (err) {
    const message = err instanceof Error ? err.message : "invalid json"
    throw new TokenExchangeError(
      "malformed-response",
      `token endpoint returned non-JSON: ${message}`,
    )
  }

  if (!isRecord(parsed)) {
    throw new TokenExchangeError("malformed-response", "token endpoint returned non-object body")
  }

  if (!response.ok) {
    // RFC 6749 §5.2: error responses are JSON with `error` and optional
    // `error_description`. Map them to typed errors; do not log token
    // material — but the body has none on the error path so we keep the
    // description.
    const oauthError = readString(parsed, "error") ?? "as_error"
    const description = readString(parsed, "error_description") ?? undefined
    throw new TokenExchangeError(
      "as-error",
      `AS rejected token exchange (HTTP ${response.status}): ${oauthError}${
        description ? ` — ${description}` : ""
      }`,
      {
        oauthError,
        ...(description !== undefined ? { oauthErrorDescription: description } : {}),
      },
    )
  }

  return parsed
}

interface ValidateAudienceArgs {
  accessToken: string
  expectedAudience: string
  introspectionEndpoint: string | null
  doFetch: FetchLike
  timeoutMs: number
}

async function validateAudience(args: ValidateAudienceArgs): Promise<void> {
  if (isLikelyJwt(args.accessToken)) {
    let payload: { aud?: unknown }
    try {
      payload = decodeJwt(args.accessToken)
    } catch (err) {
      const message = err instanceof Error ? err.message : "decode failed"
      throw new TokenExchangeError(
        "malformed-response",
        `minted token could not be decoded as JWT: ${message}`,
      )
    }
    if (!audienceMatches(payload.aud, args.expectedAudience)) {
      throw new TokenExchangeError(
        "audience",
        "minted token audience does not match requested audience",
      )
    }
    return
  }

  // Opaque token: RFC 7662 introspection.
  if (args.introspectionEndpoint === null) {
    throw new TokenExchangeError(
      "introspection",
      "minted token is opaque and no introspection_endpoint is available to validate its audience",
    )
  }

  let response: Awaited<ReturnType<FetchLike>>
  try {
    response = await args.doFetch(args.introspectionEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: `token=${encodeURIComponent(args.accessToken)}`,
      signal: timeoutSignal(args.timeoutMs),
    })
  } catch (err) {
    const message = err instanceof Error ? err.message : "fetch failed"
    throw new TokenExchangeError(
      "introspection",
      `introspection of minted token failed: ${message}`,
    )
  }
  if (!response.ok) {
    throw new TokenExchangeError(
      "introspection",
      `introspection of minted token returned HTTP ${response.status}`,
    )
  }

  let body: unknown
  try {
    body = await response.json()
  } catch (err) {
    const message = err instanceof Error ? err.message : "invalid json"
    throw new TokenExchangeError(
      "introspection",
      `introspection of minted token returned non-JSON: ${message}`,
    )
  }
  if (!isRecord(body)) {
    throw new TokenExchangeError(
      "introspection",
      "introspection of minted token returned non-object body",
    )
  }
  if (body.active !== true) {
    throw new TokenExchangeError("inactive", "minted token is not active per introspection")
  }
  if (!audienceMatches(body.aud, args.expectedAudience)) {
    throw new TokenExchangeError(
      "audience",
      "minted token audience does not match requested audience",
    )
  }
}

function isLikelyJwt(token: string): boolean {
  // A compact JWS has exactly two dots. We do not rely on the AS to tell
  // us the format — we look at the token itself and try decode-only first.
  const parts = token.split(".")
  return parts.length === 3 && parts.every((p) => p.length > 0)
}

function audienceMatches(aud: unknown, expected: string): boolean {
  if (typeof aud === "string") return aud === expected
  if (Array.isArray(aud)) return aud.some((v) => v === expected)
  return false
}

function parseScopeString(scope: string): readonly string[] {
  return Object.freeze(scope.split(/\s+/).filter((s) => s.length > 0))
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

function readString(body: Record<string, unknown>, key: string): string | null {
  const value = body[key]
  return typeof value === "string" ? value : null
}

function readNumber(body: Record<string, unknown>, key: string): number | null {
  const value = body[key]
  return typeof value === "number" && Number.isFinite(value) ? value : null
}

function timeoutSignal(ms: number): AbortSignal {
  return AbortSignal.timeout(ms)
}
