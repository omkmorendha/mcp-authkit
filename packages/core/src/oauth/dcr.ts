/**
 * RFC 7591 Dynamic Client Registration consumer.
 *
 * Spec: docs/spec/v0.2.md#52-dynamic-client-registration-rfc-7591 and
 * docs/spec/v0.2.md#12-security-non-negotiables-additions
 * ("DCR initial-access-token handling").
 *
 * Registers the MCP deployment as a client against an authorization
 * server's RFC 7591 endpoint (discovered via RFC 8414). The framework
 * NEVER persists the returned credentials — the caller decides what to
 * do with them. The `initialAccessToken`, when supplied, is sent over
 * the wire as a Bearer token and never logged at any level.
 *
 * Security non-negotiables (v0.2 §12):
 *  - `initialAccessToken` must not appear in any log line. The optional
 *    `logger` argument is the only logging surface this module touches
 *    and the token is never passed to it.
 *  - `registration_access_token` returned by the AS is treated the same
 *    way; it is returned to the caller but never logged.
 *  - Issuer and registration endpoint must be `http(s):` URLs.
 *
 * @module
 */

/** Default network timeout for discovery and registration requests. */
const DEFAULT_TIMEOUT_MS = 10_000

/** Metadata cache TTL. Discovery results are rarely volatile; ten minutes
 *  is enough to dedupe a tight loop of registrations without pinning a
 *  stale endpoint forever. */
const METADATA_CACHE_TTL_MS = 10 * 60 * 1000

/**
 * Minimal `fetch` surface this module depends on. Mirrors the shape used
 * by sibling modules so tests can inject the same stub without `any`.
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
 * Pino-shaped logger surface. The `initialAccessToken` is never passed to
 * any of these methods, but the shape is kept narrow so the public
 * surface never accepts `any`.
 */
export interface DcrLogger {
  debug(obj: Record<string, unknown>, msg?: string): void
  warn(obj: Record<string, unknown>, msg?: string): void
  error(obj: Record<string, unknown>, msg?: string): void
}

/**
 * Pino redaction paths for consumers' top-level logger configurations.
 * Including these keeps a stray `logger.info({ token })` from leaking
 * either the initial-access-token or a registration access token
 * returned by the AS.
 */
export const DCR_LOG_REDACT_PATHS: readonly string[] = Object.freeze([
  "initialAccessToken",
  "*.initialAccessToken",
  "registration_access_token",
  "*.registration_access_token",
  "client_secret",
  "*.client_secret",
])

/**
 * Subset of RFC 7591 §2 client metadata fields with their canonical types,
 * plus an index signature for AS-specific extensions. The framework does
 * not enforce required-field policy here — that is the AS's job per RFC
 * 7591 §3.2.1.
 */
export interface ClientMetadata {
  redirect_uris?: readonly string[]
  client_name?: string
  client_uri?: string
  logo_uri?: string
  scope?: string
  contacts?: readonly string[]
  tos_uri?: string
  policy_uri?: string
  jwks_uri?: string
  jwks?: Record<string, unknown>
  software_id?: string
  software_version?: string
  token_endpoint_auth_method?: string
  grant_types?: readonly string[]
  response_types?: readonly string[]
  [extra: string]: unknown
}

export interface RegisterClientInput {
  /** OAuth authorization server issuer URL. RFC 8414 metadata is fetched here. */
  issuer: string
  /**
   * Optional initial access token (RFC 7591 §3). When supplied, sent as
   * `Authorization: Bearer <tok>`. MUST be sent over TLS in production
   * (spec v0.2 §12) — the deployer is responsible for that posture.
   * Never logged at any level by this module.
   */
  initialAccessToken?: string
  /** RFC 7591 §2 metadata. Sent verbatim as the JSON request body. */
  metadata: ClientMetadata
  /**
   * Pre-discovered registration endpoint. Skips RFC 8414 discovery (and
   * the metadata cache). Useful for ASes that do not publish metadata at
   * the standard location, and for tests.
   */
  registrationEndpoint?: string
  /** Network timeout in ms for each HTTP call. Default {@link DEFAULT_TIMEOUT_MS}. */
  timeoutMs?: number
  /** Override of `globalThis.fetch`. */
  fetch?: FetchLike
  /** Optional structured logger. The initial access token is never logged. */
  logger?: DcrLogger
  /** Bypass the per-issuer metadata cache for this call. */
  noCache?: boolean
}

/**
 * RFC 7591 §3.2.1 successful registration response. Concrete RFC fields
 * are typed; AS-specific extras are surfaced via the index signature.
 * `client_id` is the only field RFC 7591 marks as REQUIRED.
 */
export interface RegisteredClient {
  client_id: string
  client_secret?: string
  client_id_issued_at?: number
  client_secret_expires_at?: number
  registration_access_token?: string
  registration_client_uri?: string
  [extra: string]: unknown
}

/** Discriminator for {@link DcrError.reason}. */
export type DcrErrorReason =
  /** Programmer-error: bad arguments before any I/O. */
  | "input"
  /** RFC 8414 discovery failed (HTTP, parsing, or missing `registration_endpoint`). */
  | "discovery"
  /** Network failure, timeout, or non-JSON body. */
  | "transport"
  /** Registration endpoint returned a non-2xx with an RFC 7591 §3.2.2 `error` field. */
  | "as-error"
  /** Registration endpoint returned 2xx but the body was malformed. */
  | "malformed-response"

/**
 * Typed error surface for {@link registerClient}. Concrete reasons live
 * on the `reason` discriminator so callers can branch with full type
 * narrowing without `instanceof` spelunking on subclasses.
 */
export class DcrError extends Error {
  readonly reason: DcrErrorReason
  /** RFC 7591 §3.2.2 `error` field, when the AS supplied one. */
  readonly oauthError?: string
  /** RFC 7591 §3.2.2 `error_description` field, when the AS supplied one. */
  readonly oauthErrorDescription?: string
  /** HTTP status code, when the failure was an HTTP response. */
  readonly status?: number

  constructor(
    reason: DcrErrorReason,
    message: string,
    extras?: {
      oauthError?: string
      oauthErrorDescription?: string
      status?: number
      cause?: unknown
    },
  ) {
    super(message, extras?.cause !== undefined ? { cause: extras.cause } : undefined)
    this.name = "DcrError"
    this.reason = reason
    if (extras?.oauthError !== undefined) this.oauthError = extras.oauthError
    if (extras?.oauthErrorDescription !== undefined) {
      this.oauthErrorDescription = extras.oauthErrorDescription
    }
    if (extras?.status !== undefined) this.status = extras.status
  }
}

interface CacheEntry {
  registrationEndpoint: string
  expiresAt: number
}

const metadataCache: Map<string, CacheEntry> = new Map()

/**
 * Test/runtime helper to clear the per-issuer metadata cache. Useful in
 * test suites; production code should rely on the TTL.
 */
export function __clearDcrMetadataCache(): void {
  metadataCache.clear()
}

/**
 * Register a client with the AS via RFC 7591 Dynamic Client Registration.
 *
 * Discovers `registration_endpoint` via RFC 8414, POSTs the supplied
 * metadata as JSON, and returns the AS's parsed response. The framework
 * does NOT persist any field of the response — the caller decides
 * whether to write it to disk, a secret manager, or a database.
 */
export async function registerClient(input: RegisterClientInput): Promise<RegisteredClient> {
  validateInput(input)

  const timeoutMs = input.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const doFetch: FetchLike = input.fetch ?? (globalThis.fetch as FetchLike)

  const registrationEndpoint =
    input.registrationEndpoint !== undefined
      ? input.registrationEndpoint
      : await resolveRegistrationEndpoint(input.issuer, doFetch, timeoutMs, input.noCache === true)

  // Sanity-check the endpoint URL whether it came from discovery or the
  // caller. A malformed registrationEndpoint should fail before any I/O.
  assertHttpOrHttpsUrl(registrationEndpoint, "registration_endpoint")

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
  }
  if (input.initialAccessToken !== undefined) {
    headers.Authorization = `Bearer ${input.initialAccessToken}`
  }

  const body = JSON.stringify(input.metadata)

  let response: Awaited<ReturnType<FetchLike>>
  try {
    response = await doFetch(registrationEndpoint, {
      method: "POST",
      headers,
      body,
      signal: AbortSignal.timeout(timeoutMs),
    })
  } catch (err) {
    const message = err instanceof Error ? err.message : "fetch failed"
    throw new DcrError("transport", `registration request failed: ${message}`, { cause: err })
  }

  let parsed: unknown
  try {
    parsed = await response.json()
  } catch (err) {
    throw new DcrError("transport", "registration endpoint returned non-JSON body", {
      status: response.status,
      cause: err,
    })
  }

  if (!isRecord(parsed)) {
    throw new DcrError("malformed-response", "registration endpoint returned non-object body", {
      status: response.status,
    })
  }

  if (!response.ok) {
    throw oauthErrorFrom(response.status, parsed)
  }

  const clientId = parsed.client_id
  if (typeof clientId !== "string" || clientId.length === 0) {
    throw new DcrError("malformed-response", "registration response missing client_id", {
      status: response.status,
    })
  }

  input.logger?.debug(
    {
      issuer: input.issuer,
      registrationEndpoint,
      clientId,
    },
    "client registered",
  )

  // Cast through `unknown` to surface the typed shape without losing the
  // AS-specific extras — the index signature on RegisteredClient picks up
  // whatever the AS chose to return.
  return parsed as unknown as RegisteredClient
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

function validateInput(input: RegisterClientInput): void {
  if (typeof input.issuer !== "string" || input.issuer.length === 0) {
    throw new DcrError("input", "issuer is required")
  }
  assertHttpOrHttpsUrl(input.issuer, "issuer")

  if (input.registrationEndpoint !== undefined) {
    if (typeof input.registrationEndpoint !== "string" || input.registrationEndpoint.length === 0) {
      throw new DcrError("input", "registrationEndpoint, if provided, must be a non-empty string")
    }
  }

  if (input.initialAccessToken !== undefined) {
    if (typeof input.initialAccessToken !== "string" || input.initialAccessToken.length === 0) {
      throw new DcrError("input", "initialAccessToken, if provided, must be a non-empty string")
    }
  }

  if (
    input.metadata === null ||
    typeof input.metadata !== "object" ||
    Array.isArray(input.metadata)
  ) {
    throw new DcrError("input", "metadata is required and must be a plain object")
  }
}

function assertHttpOrHttpsUrl(value: string, label: string): void {
  let url: URL
  try {
    url = new URL(value)
  } catch {
    throw new DcrError("input", `${label} is not a valid URL`)
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new DcrError("input", `${label} must be http(s)`)
  }
}

async function resolveRegistrationEndpoint(
  issuer: string,
  doFetch: FetchLike,
  timeoutMs: number,
  noCache: boolean,
): Promise<string> {
  const cacheKey = normalizeIssuer(issuer)
  if (!noCache) {
    const hit = metadataCache.get(cacheKey)
    if (hit !== undefined && hit.expiresAt > Date.now()) {
      return hit.registrationEndpoint
    }
  }

  const discoveryUrl = metadataUrl(issuer)

  let response: Awaited<ReturnType<FetchLike>>
  try {
    response = await doFetch(discoveryUrl, {
      method: "GET",
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(timeoutMs),
    })
  } catch (err) {
    const message = err instanceof Error ? err.message : "fetch failed"
    throw new DcrError("discovery", `AS metadata discovery failed: ${message}`, { cause: err })
  }

  if (!response.ok) {
    throw new DcrError("discovery", `AS metadata discovery returned HTTP ${response.status}`, {
      status: response.status,
    })
  }

  let body: unknown
  try {
    body = await response.json()
  } catch (err) {
    throw new DcrError("discovery", "AS metadata is not valid JSON", { cause: err })
  }
  if (!isRecord(body)) {
    throw new DcrError("discovery", "AS metadata is not a JSON object")
  }
  const endpoint = body.registration_endpoint
  if (typeof endpoint !== "string" || endpoint.length === 0) {
    throw new DcrError("discovery", "AS metadata missing registration_endpoint")
  }

  metadataCache.set(cacheKey, {
    registrationEndpoint: endpoint,
    expiresAt: Date.now() + METADATA_CACHE_TTL_MS,
  })

  return endpoint
}

function metadataUrl(issuer: string): string {
  // RFC 8414 §3.1: discovery URL is constructed by inserting the
  // well-known path between host and any issuer path component.
  const url = new URL(issuer)
  const path = url.pathname.replace(/\/$/, "")
  const wellKnownPath =
    path.length > 0
      ? `/.well-known/oauth-authorization-server${path}`
      : "/.well-known/oauth-authorization-server"
  return `${url.origin}${wellKnownPath}`
}

function normalizeIssuer(issuer: string): string {
  return issuer.endsWith("/") ? issuer.slice(0, -1) : issuer
}

function oauthErrorFrom(status: number, body: Record<string, unknown>): DcrError {
  const oauthError = typeof body.error === "string" ? body.error : undefined
  const description =
    typeof body.error_description === "string" ? body.error_description : undefined
  const message =
    oauthError !== undefined
      ? description !== undefined
        ? `${oauthError}: ${description}`
        : oauthError
      : `registration endpoint returned HTTP ${status}`

  return new DcrError("as-error", message, {
    ...(oauthError !== undefined ? { oauthError } : {}),
    ...(description !== undefined ? { oauthErrorDescription: description } : {}),
    status,
  })
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}
