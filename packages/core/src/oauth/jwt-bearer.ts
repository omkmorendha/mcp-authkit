/**
 * RFC 7523 — JWT Bearer Token Profile for OAuth 2.0 Client Authentication
 * and Authorization Grants. v0.2 implements the *authorization grant* side:
 * a client requests an access token from the authorization server by
 * presenting a signed JWT assertion.
 *
 * Spec: docs/spec/v0.2.md#53-jwt-bearer-assertion-rfc-7523.
 *
 * The assertion JWT MUST contain `iss`, `sub`, `aud`, and `exp` per
 * RFC 7523 §3. We also set `iat` and `jti`. `aud` is the AS token
 * endpoint (discovered via RFC 8414). The grant type is the registered
 * URI `urn:ietf:params:oauth:grant-type:jwt-bearer` (RFC 7523 §2.1).
 *
 * This module does NOT cache its result. Callers cache. The
 * upstream-credentials helper (v0.2 §5.6) caches per
 * `(audience, scopes, subject)`.
 *
 * @module
 */
import { randomUUID } from "node:crypto"
import { importJWK, type JWK, SignJWT } from "jose"

/** Registered grant_type URI for RFC 7523 §2.1. */
const GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer"

/** Default assertion lifetime — 60 seconds, well under the RFC 7523 §3 SHOULD. */
const DEFAULT_ASSERTION_TTL_SECONDS = 60

/** Default HTTP timeout for token endpoint and discovery requests. */
const DEFAULT_TIMEOUT_MS = 10_000

/**
 * `KeyObject` from `node:crypto`. Imported as a type alias so we do not
 * pull a value dependency on `node:crypto` and so the public surface
 * stays clear about what is accepted.
 */
export type KeyObject = import("node:crypto").KeyObject

/**
 * Signing material accepted by {@link requestTokenWithAssertion}.
 *
 * - `JWK`: a JSON Web Key. `alg` is derived from `jwk.alg` if present,
 *   otherwise from `kty`/`crv` per RFC 7518.
 * - `CryptoKey` / `KeyObject`: pre-imported asymmetric private key. The
 *   caller MUST provide {@link RequestTokenInput.alg} since these types
 *   do not carry algorithm metadata reliably across runtimes.
 * - `Uint8Array`: HMAC shared secret. `alg` defaults to `HS256` and may
 *   be overridden to `HS384` or `HS512` via {@link RequestTokenInput.alg}.
 *   RFC 7523 §3 allows HMAC assertions but most ASs require asymmetric;
 *   we accept it for completeness and test parity.
 */
export type AssertionSigningKey = CryptoKey | KeyObject | JWK | Uint8Array

/** Minimal `fetch` surface, kept compatible with `auth/introspection`. */
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
 * Discriminator for {@link JwtBearerError}. Mirrors the
 * `{ ok: false; reason }` shape used elsewhere in the auth pipeline,
 * but surfaces as a thrown typed error because this is an outbound
 * client call — there is no inbound request to short-circuit.
 */
export type JwtBearerFailureReason =
  | "discovery"
  | "transport"
  | "as-error"
  | "invalid-response"
  | "signing"
  | "key"

/** Typed error thrown by {@link requestTokenWithAssertion}. */
export class JwtBearerError extends Error {
  readonly reason: JwtBearerFailureReason
  /** OAuth `error` code from the AS response body, when present. */
  readonly oauthError?: string
  /** OAuth `error_description` from the AS response body, when present. */
  readonly oauthErrorDescription?: string
  /** HTTP status from the AS, when the failure is HTTP-level. */
  readonly httpStatus?: number

  constructor(
    reason: JwtBearerFailureReason,
    message: string,
    extras: {
      oauthError?: string
      oauthErrorDescription?: string
      httpStatus?: number
      cause?: unknown
    } = {},
  ) {
    super(message, extras.cause === undefined ? undefined : { cause: extras.cause })
    this.name = "JwtBearerError"
    this.reason = reason
    if (extras.oauthError !== undefined) this.oauthError = extras.oauthError
    if (extras.oauthErrorDescription !== undefined)
      this.oauthErrorDescription = extras.oauthErrorDescription
    if (extras.httpStatus !== undefined) this.httpStatus = extras.httpStatus
  }
}

export interface RequestTokenInput {
  /**
   * AS issuer identifier (RFC 8414). Used to discover the token endpoint
   * and as the `iss` claim of the assertion (act-as-client). MUST be an
   * `https://` URL in production deployments; the framework does not
   * enforce that here so tests can use `http://127.0.0.1`.
   */
  issuer: string
  /**
   * Assertion `aud`. SHOULD be the AS token endpoint URL per RFC 7523
   * §3. The caller passes it explicitly rather than relying on
   * discovery so the assertion stays valid even if discovery is cached
   * or mocked.
   */
  audience: string
  /** Signing material — see {@link AssertionSigningKey}. */
  signingKey: AssertionSigningKey
  /**
   * Scopes to request. Joined with spaces and sent as both the
   * `scope` form parameter and the assertion `scope` claim (the latter
   * is informational; the AS authoritatively returns granted scopes).
   */
  scopes?: readonly string[]
  /**
   * `sub` claim of the assertion. When omitted, `sub` defaults to
   * `issuer` (act-as-client per RFC 7523 §3). When set, the assertion
   * is an act-as-user request and the AS decides whether the client
   * is authorised to assert that subject.
   */
  subject?: string
  /**
   * Override the assertion `jti`. Defaults to a random UUID per call.
   * The caller normally lets us mint one; the override exists for
   * deterministic tests.
   */
  jti?: string
  /**
   * Override the assertion lifetime in seconds. Defaults to
   * {@link DEFAULT_ASSERTION_TTL_SECONDS} (60s).
   */
  assertionTtlSeconds?: number
  /**
   * JWS `alg` override. Required for `CryptoKey`/`KeyObject` since
   * those types do not unambiguously identify their algorithm.
   * Optional for `JWK` (defaults to `jwk.alg` or an inferred value)
   * and `Uint8Array` (defaults to `HS256`).
   */
  alg?: string
  /** Per-request HTTP timeout. Defaults to {@link DEFAULT_TIMEOUT_MS}. */
  timeoutMs?: number
  /**
   * Override `globalThis.fetch`. Used in tests and for deployments
   * needing a custom HTTP client. Must be a typed function.
   */
  fetch?: FetchLike
  /**
   * Pre-resolved token endpoint URL. When provided, RFC 8414 discovery
   * is skipped. Useful when the consumer already cached metadata.
   */
  tokenEndpoint?: string
}

export interface RequestTokenResult {
  accessToken: string
  /**
   * Absolute expiry derived from the AS `expires_in` response field
   * (RFC 6749 §5.1). When the AS omits `expires_in`, this is `null`
   * — callers must treat the token as having unknown lifetime.
   */
  expiresAt: Date | null
  /**
   * Effective granted scopes. Parsed from the AS `scope` response
   * field; if absent, falls back to the requested {@link RequestTokenInput.scopes}.
   */
  scopes: readonly string[]
}

/**
 * Request an access token from the AS using a JWT bearer assertion.
 *
 * The flow:
 * 1. Discover (or use the provided) token endpoint via RFC 8414.
 * 2. Build and sign the assertion JWT per RFC 7523 §3.
 * 3. POST `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=...`
 *    to the token endpoint.
 * 4. Parse the RFC 6749 §5.1 token response.
 *
 * All failure modes throw {@link JwtBearerError} with a stable
 * {@link JwtBearerFailureReason}.
 */
export async function requestTokenWithAssertion(
  input: RequestTokenInput,
): Promise<RequestTokenResult> {
  const doFetch: FetchLike = input.fetch ?? (globalThis.fetch as FetchLike)
  const timeoutMs = input.timeoutMs ?? DEFAULT_TIMEOUT_MS

  const tokenEndpoint =
    input.tokenEndpoint ?? (await discoverTokenEndpoint(input.issuer, doFetch, timeoutMs))

  const assertion = await buildAssertion(input)

  const form = new URLSearchParams()
  form.set("grant_type", GRANT_TYPE)
  form.set("assertion", assertion)
  if (input.scopes && input.scopes.length > 0) {
    form.set("scope", input.scopes.join(" "))
  }

  const response = await fetchWithTimeout(
    doFetch,
    tokenEndpoint,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: form.toString(),
    },
    timeoutMs,
  )

  let body: unknown
  try {
    body = await response.json()
  } catch (err) {
    const message = err instanceof Error ? err.message : "invalid json"
    throw new JwtBearerError("invalid-response", message, { cause: err })
  }

  if (!response.ok) {
    if (isRecord(body)) {
      const oauthError = typeof body.error === "string" ? body.error : undefined
      const oauthErrorDescription =
        typeof body.error_description === "string" ? body.error_description : undefined
      throw new JwtBearerError(
        "as-error",
        oauthErrorDescription ?? oauthError ?? `token endpoint returned HTTP ${response.status}`,
        {
          httpStatus: response.status,
          ...(oauthError !== undefined ? { oauthError } : {}),
          ...(oauthErrorDescription !== undefined ? { oauthErrorDescription } : {}),
        },
      )
    }
    throw new JwtBearerError("as-error", `token endpoint returned HTTP ${response.status}`, {
      httpStatus: response.status,
    })
  }

  if (!isRecord(body)) {
    throw new JwtBearerError("invalid-response", "non-object token response")
  }
  if (typeof body.access_token !== "string" || body.access_token.length === 0) {
    throw new JwtBearerError("invalid-response", "missing access_token")
  }

  const expiresAt =
    typeof body.expires_in === "number" && Number.isFinite(body.expires_in)
      ? new Date(Date.now() + body.expires_in * 1000)
      : null

  const grantedScopes =
    typeof body.scope === "string"
      ? Object.freeze(body.scope.split(/\s+/).filter((s) => s.length > 0))
      : Object.freeze([...(input.scopes ?? [])])

  return {
    accessToken: body.access_token,
    expiresAt,
    scopes: grantedScopes,
  }
}

async function discoverTokenEndpoint(
  issuer: string,
  doFetch: FetchLike,
  timeoutMs: number,
): Promise<string> {
  // RFC 8414 §3: oauth-authorization-server first; fall back to
  // openid-configuration which most ASs also publish.
  const candidates = [
    joinWellKnown(issuer, "oauth-authorization-server"),
    joinWellKnown(issuer, "openid-configuration"),
  ]

  let lastErr: unknown
  for (const url of candidates) {
    try {
      const response = await fetchWithTimeout(
        doFetch,
        url,
        { method: "GET", headers: { Accept: "application/json" } },
        timeoutMs,
      )
      if (!response.ok) {
        lastErr = new Error(`HTTP ${response.status}`)
        continue
      }
      const body = await response.json()
      if (isRecord(body) && typeof body.token_endpoint === "string") {
        return body.token_endpoint
      }
      lastErr = new Error("metadata missing token_endpoint")
    } catch (err) {
      // fetchWithTimeout already wraps as JwtBearerError(transport); unwrap so
      // discovery failures carry reason=discovery, not reason=transport.
      lastErr = err instanceof JwtBearerError ? new Error(err.message) : err
    }
  }

  const message = lastErr instanceof Error ? lastErr.message : "unknown error"
  throw new JwtBearerError("discovery", `could not discover token endpoint: ${message}`, {
    cause: lastErr,
  })
}

/**
 * Compose `${issuer}/.well-known/${suffix}` while tolerating issuers
 * with a trailing slash. (Issuers with a path component are rare but
 * RFC 8414 §3.1 permits them; production deployments should pass the
 * canonical issuer string.)
 */
function joinWellKnown(issuer: string, suffix: string): string {
  const trimmed = issuer.endsWith("/") ? issuer.slice(0, -1) : issuer
  return `${trimmed}/.well-known/${suffix}`
}

async function buildAssertion(input: RequestTokenInput): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  const ttl = input.assertionTtlSeconds ?? DEFAULT_ASSERTION_TTL_SECONDS

  const sub = input.subject ?? input.issuer
  const jti = input.jti ?? randomUUID()

  const { key, alg } = await resolveSigningKey(input.signingKey, input.alg)

  const payload: Record<string, unknown> = {}
  if (input.scopes && input.scopes.length > 0) {
    payload.scope = input.scopes.join(" ")
  }

  const builder = new SignJWT(payload)
    .setProtectedHeader({ alg, typ: "JWT" })
    .setIssuer(input.issuer)
    .setSubject(sub)
    .setAudience(input.audience)
    .setIssuedAt(now)
    .setExpirationTime(now + ttl)
    .setJti(jti)

  try {
    return await builder.sign(key)
  } catch (err) {
    const message = err instanceof Error ? err.message : "sign failed"
    throw new JwtBearerError("signing", message, { cause: err })
  }
}

interface ResolvedKey {
  key: CryptoKey | KeyObject | Uint8Array
  alg: string
}

async function resolveSigningKey(
  signingKey: AssertionSigningKey,
  algOverride: string | undefined,
): Promise<ResolvedKey> {
  if (signingKey instanceof Uint8Array) {
    return { key: signingKey, alg: algOverride ?? "HS256" }
  }
  if (isJWK(signingKey)) {
    const alg = algOverride ?? signingKey.alg ?? inferAlgFromJwk(signingKey)
    if (alg === undefined) {
      throw new JwtBearerError("key", "could not infer JWS alg from JWK; pass `alg` explicitly")
    }
    let key: CryptoKey | KeyObject | Uint8Array
    try {
      key = await importJWK(signingKey, alg)
    } catch (err) {
      const message = err instanceof Error ? err.message : "JWK import failed"
      throw new JwtBearerError("key", message, { cause: err })
    }
    // jose may return Uint8Array for symmetric JWKs (kty: "oct"); pass through.
    return { key, alg }
  }
  // CryptoKey or KeyObject: alg must be supplied — neither type
  // unambiguously identifies its JWS algorithm across runtimes.
  if (algOverride === undefined) {
    throw new JwtBearerError("key", "`alg` is required when signingKey is a CryptoKey or KeyObject")
  }
  return { key: signingKey, alg: algOverride }
}

function isJWK(value: AssertionSigningKey): value is JWK {
  return (
    typeof value === "object" &&
    value !== null &&
    !(value instanceof Uint8Array) &&
    "kty" in value &&
    typeof (value as { kty: unknown }).kty === "string"
  )
}

/**
 * Pick a sane default `alg` per RFC 7518 when the JWK omits `alg`.
 * Returns `undefined` if no obvious default applies — the caller must
 * then provide `alg` explicitly.
 */
function inferAlgFromJwk(jwk: JWK): string | undefined {
  switch (jwk.kty) {
    case "RSA":
      return "RS256"
    case "EC":
      if (jwk.crv === "P-256") return "ES256"
      if (jwk.crv === "P-384") return "ES384"
      if (jwk.crv === "P-521") return "ES512"
      return undefined
    case "OKP":
      if (jwk.crv === "Ed25519" || jwk.crv === "Ed448") return "EdDSA"
      return undefined
    case "oct":
      return "HS256"
    default:
      return undefined
  }
}

async function fetchWithTimeout(
  doFetch: FetchLike,
  url: string,
  init: {
    method?: string
    headers?: Record<string, string>
    body?: string
  },
  timeoutMs: number,
): Promise<Awaited<ReturnType<FetchLike>>> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    return await doFetch(url, { ...init, signal: controller.signal })
  } catch (err) {
    const message = err instanceof Error ? err.message : "fetch failed"
    throw new JwtBearerError("transport", message, { cause: err })
  } finally {
    clearTimeout(timer)
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}
