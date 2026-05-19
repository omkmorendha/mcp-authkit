/**
 * RFC 6749 §4.4 Client Credentials grant.
 *
 * Spec: docs/spec/v0.2.md#54-client-credentials-rfc-6749-44 and
 * docs/spec/v0.2.md#12-security-non-negotiables-additions
 * ("Client Credentials audience required").
 *
 * Audience is REQUIRED and is sent as the RFC 8707 `resource` parameter.
 * The framework supports two mutually-exclusive client-authentication
 * modes:
 *
 *   - `client_secret_basic` — HTTP Basic in `Authorization` header
 *     (default when `clientSecret` is provided).
 *   - `private_key_jwt` — `client_assertion_type=urn:ietf:params:oauth:
 *     client-assertion-type:jwt-bearer` plus a signed JWT (RFC 7521 +
 *     RFC 7523) when `signingKey` is provided.
 *
 * Supplying BOTH `clientSecret` and `signingKey` is a programmer error
 * and throws immediately.
 *
 * The token endpoint is discovered via RFC 8414 OAuth authorization
 * server metadata (`/.well-known/oauth-authorization-server`) under the
 * `issuer` URL.
 *
 * @module
 */
import { type KeyObject, randomUUID } from "node:crypto"
import { type CryptoKey, type JWK, SignJWT } from "jose"

/** Default network timeout for token-endpoint / discovery requests. */
const DEFAULT_TIMEOUT_MS = 10_000

/** Lifetime of a `private_key_jwt` client assertion. RFC 7523 recommends short. */
const CLIENT_ASSERTION_LIFETIME_SEC = 60

/** RFC 7523 §2.2 client-assertion-type. */
const CLIENT_ASSERTION_TYPE_JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

/**
 * Accepted shapes for `signingKey`. Mirrors what `jose.SignJWT.sign` accepts.
 * `Uint8Array` is intentionally excluded — it implies HMAC, which is not a
 * valid `private_key_jwt` signing key (RFC 7523 §2.2 mandates asymmetric).
 */
export type SigningKey = CryptoKey | KeyObject | JWK

/**
 * Minimal `fetch` surface this module depends on. Mirrors
 * `auth/introspection.ts` so tests can inject a typed stub without `any`.
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

export interface RequestClientCredentialsTokenOptions {
  /** OAuth authorization server issuer URL. RFC 8414 metadata is fetched here. */
  issuer: string
  /** OAuth client identifier. */
  clientId: string
  /**
   * Client secret for `client_secret_basic`. Mutually exclusive with
   * `signingKey`.
   */
  clientSecret?: string
  /**
   * Asymmetric signing key for `private_key_jwt` (RFC 7523). Mutually
   * exclusive with `clientSecret`.
   *
   * The signing algorithm is inferred from the key by `jose`:
   *  - `Ed25519` → `EdDSA`
   *  - EC P-256 → `ES256` (P-384 → `ES384`, P-521 → `ES512`)
   *  - RSA → `RS256`
   *
   * Callers needing an explicit `alg` should pass a `KeyObject` /
   * `CryptoKey` whose algorithm is set, or a JWK with `alg`.
   */
  signingKey?: SigningKey
  /**
   * Requested scopes. May be empty; the AS decides the default set
   * when no scopes are requested.
   */
  scopes: readonly string[]
  /**
   * Required RFC 8707 resource indicator. The minted token's `aud` claim
   * MUST match this value when validated downstream (spec v0.1 §14,
   * v0.2 §12). Must be a valid absolute URL.
   */
  audience: string
  /** Network timeout in ms. Default {@link DEFAULT_TIMEOUT_MS}. */
  timeoutMs?: number
  /**
   * Optional `fetch` override. Defaults to `globalThis.fetch`. Useful in
   * tests and for deployments that need a custom HTTP client.
   */
  fetch?: FetchLike
}

/**
 * Successful Client Credentials token response, normalized.
 *
 * `expiresAt` is computed from `expires_in` at call time, so the caller
 * does not need to track wall-clock arithmetic.
 */
export interface ClientCredentialsToken {
  accessToken: string
  expiresAt: Date
  scopes: readonly string[]
}

/** Discriminator for `ClientCredentialsError.code`. */
export type ClientCredentialsErrorCode =
  /** Programmer-error: bad arguments before any I/O. */
  | "invalid-config"
  /** RFC 8414 discovery failed (HTTP, parsing, or missing `token_endpoint`). */
  | "discovery-failed"
  /** Token endpoint returned a non-2xx with an RFC 6749 `error` field. */
  | "oauth-error"
  /** Token endpoint returned 2xx but the body was malformed. */
  | "invalid-response"
  /** Network failure, timeout, or non-JSON body. */
  | "transport"

/**
 * Typed error surface for `requestClientCredentialsToken`. The class is
 * `unknown`-friendly: callers may narrow with `instanceof`.
 */
export class ClientCredentialsError extends Error {
  readonly code: ClientCredentialsErrorCode
  /** RFC 6749 §5.2 `error` field, when the AS supplied one. */
  readonly oauthError?: string
  /** RFC 6749 §5.2 `error_description` field, when the AS supplied one. */
  readonly oauthErrorDescription?: string
  /** HTTP status code, when the failure was an HTTP response. */
  readonly status?: number

  constructor(
    code: ClientCredentialsErrorCode,
    message: string,
    extra?: {
      oauthError?: string
      oauthErrorDescription?: string
      status?: number
      cause?: unknown
    },
  ) {
    super(message, extra?.cause !== undefined ? { cause: extra.cause } : undefined)
    this.name = "ClientCredentialsError"
    this.code = code
    if (extra?.oauthError !== undefined) this.oauthError = extra.oauthError
    if (extra?.oauthErrorDescription !== undefined) {
      this.oauthErrorDescription = extra.oauthErrorDescription
    }
    if (extra?.status !== undefined) this.status = extra.status
  }
}

/**
 * Request an access token via the RFC 6749 §4.4 Client Credentials grant.
 *
 * Discovers the token endpoint via RFC 8414, posts the form-encoded request
 * with `grant_type=client_credentials`, `scope`, and `resource` (RFC 8707),
 * and returns the normalized token. The minted token is not cached — the
 * caller decides caching.
 */
export async function requestClientCredentialsToken(
  opts: RequestClientCredentialsTokenOptions,
): Promise<ClientCredentialsToken> {
  validateConfig(opts)

  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const doFetch: FetchLike = opts.fetch ?? (globalThis.fetch as FetchLike)

  const tokenEndpoint = await discoverTokenEndpoint(opts.issuer, doFetch, timeoutMs)

  const body = new URLSearchParams()
  body.set("grant_type", "client_credentials")
  body.set("resource", opts.audience)
  if (opts.scopes.length > 0) {
    body.set("scope", opts.scopes.join(" "))
  }

  const headers: Record<string, string> = {
    "Content-Type": "application/x-www-form-urlencoded",
    Accept: "application/json",
  }

  if (opts.clientSecret !== undefined) {
    headers.Authorization = `Basic ${encodeBasicCredentials(opts.clientId, opts.clientSecret)}`
  } else {
    // `signingKey` path; validated by validateConfig.
    const assertion = await buildClientAssertion({
      clientId: opts.clientId,
      tokenEndpoint,
      signingKey: opts.signingKey as SigningKey,
    })
    body.set("client_id", opts.clientId)
    body.set("client_assertion_type", CLIENT_ASSERTION_TYPE_JWT_BEARER)
    body.set("client_assertion", assertion)
  }

  const response = await postWithTimeout(
    doFetch,
    tokenEndpoint,
    headers,
    body.toString(),
    timeoutMs,
  )

  const parsed = await readJson(response)

  if (!response.ok) {
    throw oauthErrorFrom(response.status, parsed)
  }

  if (!isRecord(parsed)) {
    throw new ClientCredentialsError("invalid-response", "token endpoint returned non-object body")
  }

  return normalizeTokenResponse(parsed, opts.scopes)
}

function validateConfig(opts: RequestClientCredentialsTokenOptions): void {
  if (typeof opts.issuer !== "string" || opts.issuer.length === 0) {
    throw new ClientCredentialsError("invalid-config", "issuer is required")
  }
  assertHttpsOrHttpUrl(opts.issuer, "issuer")

  if (typeof opts.clientId !== "string" || opts.clientId.length === 0) {
    throw new ClientCredentialsError("invalid-config", "clientId is required")
  }

  if (typeof opts.audience !== "string" || opts.audience.length === 0) {
    throw new ClientCredentialsError(
      "invalid-config",
      "audience is required (RFC 8707 resource indicator)",
    )
  }
  assertHttpsOrHttpUrl(opts.audience, "audience")

  const hasSecret = opts.clientSecret !== undefined
  const hasKey = opts.signingKey !== undefined
  if (hasSecret && hasKey) {
    throw new ClientCredentialsError(
      "invalid-config",
      "clientSecret and signingKey are mutually exclusive",
    )
  }
  if (!hasSecret && !hasKey) {
    throw new ClientCredentialsError(
      "invalid-config",
      "exactly one of clientSecret or signingKey is required",
    )
  }
  if (hasSecret && (opts.clientSecret ?? "").length === 0) {
    throw new ClientCredentialsError("invalid-config", "clientSecret must be non-empty")
  }
}

function assertHttpsOrHttpUrl(value: string, label: string): void {
  let url: URL
  try {
    url = new URL(value)
  } catch {
    throw new ClientCredentialsError("invalid-config", `${label} is not a valid URL`)
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new ClientCredentialsError("invalid-config", `${label} must be http(s)`)
  }
}

/**
 * RFC 8414 §3.1 discovery. Inserts `/.well-known/oauth-authorization-server`
 * between the host and any path component of the issuer URL.
 */
async function discoverTokenEndpoint(
  issuer: string,
  doFetch: FetchLike,
  timeoutMs: number,
): Promise<string> {
  const url = new URL(issuer)
  const path = url.pathname.replace(/\/$/, "")
  const wellKnownPath =
    path.length > 0
      ? `/.well-known/oauth-authorization-server${path}`
      : "/.well-known/oauth-authorization-server"
  const discoveryUrl = `${url.origin}${wellKnownPath}`

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  let response: Awaited<ReturnType<FetchLike>>
  try {
    response = await doFetch(discoveryUrl, {
      method: "GET",
      headers: { Accept: "application/json" },
      signal: controller.signal,
    })
  } catch (err) {
    const message = err instanceof Error ? err.message : "fetch failed"
    throw new ClientCredentialsError("discovery-failed", `discovery fetch failed: ${message}`, {
      cause: err,
    })
  } finally {
    clearTimeout(timer)
  }

  if (!response.ok) {
    throw new ClientCredentialsError(
      "discovery-failed",
      `discovery returned HTTP ${response.status}`,
      { status: response.status },
    )
  }

  let metadata: unknown
  try {
    metadata = await response.json()
  } catch (err) {
    throw new ClientCredentialsError("discovery-failed", "discovery body was not JSON", {
      cause: err,
    })
  }

  if (!isRecord(metadata)) {
    throw new ClientCredentialsError("discovery-failed", "discovery body was not an object")
  }
  const tokenEndpoint = metadata.token_endpoint
  if (typeof tokenEndpoint !== "string" || tokenEndpoint.length === 0) {
    throw new ClientCredentialsError("discovery-failed", "metadata missing token_endpoint")
  }
  try {
    // Throws if not a parseable URL.
    new URL(tokenEndpoint)
  } catch {
    throw new ClientCredentialsError("discovery-failed", "token_endpoint is not a valid URL")
  }
  return tokenEndpoint
}

async function postWithTimeout(
  doFetch: FetchLike,
  url: string,
  headers: Record<string, string>,
  body: string,
  timeoutMs: number,
): Promise<Awaited<ReturnType<FetchLike>>> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    return await doFetch(url, {
      method: "POST",
      headers,
      body,
      signal: controller.signal,
    })
  } catch (err) {
    const message = err instanceof Error ? err.message : "fetch failed"
    throw new ClientCredentialsError("transport", `token endpoint request failed: ${message}`, {
      cause: err,
    })
  } finally {
    clearTimeout(timer)
  }
}

async function readJson(response: Awaited<ReturnType<FetchLike>>): Promise<unknown> {
  try {
    return await response.json()
  } catch (err) {
    throw new ClientCredentialsError("transport", "token endpoint returned non-JSON body", {
      status: response.status,
      cause: err,
    })
  }
}

function oauthErrorFrom(status: number, body: unknown): ClientCredentialsError {
  if (isRecord(body) && typeof body.error === "string") {
    const description =
      typeof body.error_description === "string" ? body.error_description : undefined
    const message = description !== undefined ? `${body.error}: ${description}` : body.error
    return new ClientCredentialsError("oauth-error", message, {
      oauthError: body.error,
      ...(description !== undefined ? { oauthErrorDescription: description } : {}),
      status,
    })
  }
  return new ClientCredentialsError("oauth-error", `token endpoint returned HTTP ${status}`, {
    status,
  })
}

function normalizeTokenResponse(
  body: Record<string, unknown>,
  requestedScopes: readonly string[],
): ClientCredentialsToken {
  const accessToken = body.access_token
  if (typeof accessToken !== "string" || accessToken.length === 0) {
    throw new ClientCredentialsError("invalid-response", "missing access_token")
  }
  const expiresIn = body.expires_in
  if (typeof expiresIn !== "number" || !Number.isFinite(expiresIn) || expiresIn <= 0) {
    throw new ClientCredentialsError("invalid-response", "missing or invalid expires_in")
  }
  const expiresAt = new Date(Date.now() + Math.floor(expiresIn * 1000))

  let scopes: readonly string[]
  if (typeof body.scope === "string" && body.scope.length > 0) {
    scopes = Object.freeze(body.scope.split(/\s+/).filter((s) => s.length > 0))
  } else {
    // RFC 6749 §5.1: scope is OPTIONAL when identical to requested.
    scopes = Object.freeze([...requestedScopes])
  }
  return { accessToken, expiresAt, scopes }
}

/**
 * Build an RFC 7523 client assertion for `private_key_jwt`. The assertion
 * has `iss = sub = clientId`, `aud = token_endpoint`, plus `jti` and `exp`.
 */
async function buildClientAssertion(args: {
  clientId: string
  tokenEndpoint: string
  signingKey: SigningKey
}): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  const alg = inferAlg(args.signingKey)
  const jwt = new SignJWT({})
    .setProtectedHeader({ alg, typ: "JWT" })
    .setIssuer(args.clientId)
    .setSubject(args.clientId)
    .setAudience(args.tokenEndpoint)
    .setJti(randomUUID())
    .setIssuedAt(now)
    .setExpirationTime(now + CLIENT_ASSERTION_LIFETIME_SEC)

  try {
    return await jwt.sign(args.signingKey as CryptoKey | KeyObject)
  } catch (err) {
    const message = err instanceof Error ? err.message : "signing failed"
    throw new ClientCredentialsError(
      "invalid-config",
      `client assertion signing failed: ${message}`,
      { cause: err },
    )
  }
}

/**
 * Infer the JWS `alg` from the signing key.
 *
 * Order matters: JWK first (it lacks `algorithm` / `asymmetricKeyType`),
 * then KeyObject (Node has `asymmetricKeyType`), then CryptoKey (Web
 * `algorithm.name`). Predicates use plain shape checks; the resulting
 * narrow types are accessed via explicit casts to avoid the fragile
 * structural narrowing TypeScript would otherwise attempt across the
 * `CryptoKey | KeyObject | JWK` union.
 */
function inferAlg(key: SigningKey): string {
  if (looksLikeJwk(key)) {
    const jwk = key as JWK
    if (typeof jwk.alg === "string" && jwk.alg.length > 0) return jwk.alg
    if (jwk.kty === "RSA") return "RS256"
    if (jwk.kty === "EC") {
      if (jwk.crv === "P-256") return "ES256"
      if (jwk.crv === "P-384") return "ES384"
      if (jwk.crv === "P-521") return "ES512"
    }
    if (jwk.kty === "OKP") return "EdDSA"
    throw new ClientCredentialsError(
      "invalid-config",
      `unsupported JWK kty for private_key_jwt: ${String(jwk.kty)}`,
    )
  }
  if (looksLikeKeyObject(key)) {
    const ko = key as KeyObject
    const kty = ko.asymmetricKeyType
    if (kty === "rsa" || kty === "rsa-pss") return "RS256"
    if (kty === "ed25519" || kty === "ed448") return "EdDSA"
    if (kty === "ec") {
      const curve = ko.asymmetricKeyDetails?.namedCurve
      if (curve === "prime256v1" || curve === "P-256") return "ES256"
      if (curve === "secp384r1" || curve === "P-384") return "ES384"
      if (curve === "secp521r1" || curve === "P-521") return "ES512"
      return "ES256"
    }
    throw new ClientCredentialsError(
      "invalid-config",
      `unsupported KeyObject type for private_key_jwt: ${String(kty)}`,
    )
  }
  if (looksLikeCryptoKey(key)) {
    const ck = key as CryptoKey
    const algo = ck.algorithm as { name: string; namedCurve?: string; hash?: { name: string } }
    const name = algo.name
    if (name === "RSASSA-PKCS1-v1_5" || name === "RSA-PSS") return "RS256"
    if (name === "ECDSA") {
      const curve = algo.namedCurve
      if (curve === "P-256") return "ES256"
      if (curve === "P-384") return "ES384"
      if (curve === "P-521") return "ES512"
      return "ES256"
    }
    if (name === "Ed25519") return "EdDSA"
    throw new ClientCredentialsError(
      "invalid-config",
      `unsupported CryptoKey algorithm for private_key_jwt: ${name}`,
    )
  }
  throw new ClientCredentialsError("invalid-config", "signingKey is not a recognized key shape")
}

function looksLikeJwk(value: unknown): boolean {
  if (typeof value !== "object" || value === null) return false
  if (value instanceof Uint8Array) return false
  const v = value as { kty?: unknown; algorithm?: unknown; asymmetricKeyType?: unknown }
  // Distinguish from KeyObject / CryptoKey: those expose `algorithm` (Web)
  // or `asymmetricKeyType` (Node) but never `kty`.
  return typeof v.kty === "string" && v.algorithm === undefined && v.asymmetricKeyType === undefined
}

function looksLikeKeyObject(value: unknown): boolean {
  if (typeof value !== "object" || value === null) return false
  const v = value as { type?: unknown; asymmetricKeyType?: unknown }
  return typeof v.type === "string" && typeof v.asymmetricKeyType === "string"
}

function looksLikeCryptoKey(value: unknown): boolean {
  if (typeof value !== "object" || value === null) return false
  const v = value as { type?: unknown; algorithm?: unknown }
  if (typeof v.type !== "string") return false
  if (typeof v.algorithm !== "object" || v.algorithm === null) return false
  return typeof (v.algorithm as { name?: unknown }).name === "string"
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

function encodeBasicCredentials(clientId: string, clientSecret: string): string {
  // RFC 6749 §2.3.1: percent-encode the credential parts before base64.
  const encoded = `${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`
  return Buffer.from(encoded, "utf8").toString("base64")
}
