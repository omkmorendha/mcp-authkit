/**
 * RFC 7591 Dynamic Client Registration consumer.
 *
 * Spec: docs/spec/v0.2.md#52-dynamic-client-registration-rfc-7591 and
 * docs/spec/v0.2.md#12-security-non-negotiables-additions
 * (DCR initial-access-token handling).
 *
 * Discovers the AS `registration_endpoint` via RFC 8414 metadata, POSTs the
 * caller-supplied `metadata` as JSON, and returns the AS response typed as a
 * {@link RegisteredClient}. The optional `initialAccessToken` is sent as
 * `Authorization: Bearer ...` and MUST NOT appear in any log at any level —
 * this module accepts the token as a function argument only, never stores it,
 * and never embeds it in error messages.
 *
 * @module
 */

/** Minimal `fetch` surface this module depends on. */
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

/** Default request timeout per spec §5.2 (`10s default`). */
const DEFAULT_TIMEOUT_MS = 10_000

/**
 * Caller-supplied RFC 7591 client metadata. The shape is intentionally open:
 * RFC 7591 §2 enumerates well-known fields but allows additional values, and
 * AS-specific extensions are common.
 */
export type ClientMetadata = Record<string, unknown> & {
  redirect_uris?: readonly string[]
  grant_types?: readonly string[]
  response_types?: readonly string[]
  token_endpoint_auth_method?: string
  client_name?: string
  scope?: string
}

/**
 * RFC 7591 §3.2.1 successful registration response. The AS MUST return at
 * least `client_id`; everything else is optional. Additional AS-specific
 * fields are retained on the returned object so consumers can read them.
 */
export type RegisteredClient = Record<string, unknown> & {
  client_id: string
  client_secret?: string
  client_id_issued_at?: number
  client_secret_expires_at?: number
  registration_access_token?: string
  registration_client_uri?: string
}

export interface RegisterClientOptions {
  /** Issuer identifier (no trailing slash); §5.2 example: `https://auth.example.com`. */
  issuer: string
  /** RFC 7591 client metadata payload. */
  metadata: ClientMetadata
  /**
   * Optional initial access token (RFC 7591 §3). When present it is sent as a
   * Bearer credential on the registration request. Spec §12: MUST NOT be
   * persisted by the framework or appear in any log.
   */
  initialAccessToken?: string
  /** Request timeout in ms. Default {@link DEFAULT_TIMEOUT_MS}. */
  timeoutMs?: number
  /**
   * Optional `fetch` override. Useful in tests and for deployments with a
   * custom HTTP client. Defaults to `globalThis.fetch`.
   */
  fetch?: FetchLike
}

/**
 * Typed error surface for failed registration requests.
 *
 * - `kind: "as_error"`  — AS returned a structured RFC 7591 §3.2.2 error
 *   (`error` + optional `error_description`).
 * - `kind: "transport"` — request failed before a response body could be
 *   parsed (network failure, timeout, non-JSON body, unexpected HTTP status
 *   without a structured error payload).
 * - `kind: "discovery"` — RFC 8414 metadata fetch failed or lacked a
 *   `registration_endpoint`.
 * - `kind: "invalid_response"` — registration response was missing required
 *   fields (e.g. `client_id`).
 */
export class OAuthError extends Error {
  readonly kind: "as_error" | "transport" | "discovery" | "invalid_response"
  readonly error?: string
  readonly errorDescription?: string
  readonly status?: number

  constructor(opts: {
    kind: "as_error" | "transport" | "discovery" | "invalid_response"
    message: string
    error?: string
    errorDescription?: string
    status?: number
  }) {
    super(opts.message)
    this.name = "OAuthError"
    this.kind = opts.kind
    if (opts.error !== undefined) this.error = opts.error
    if (opts.errorDescription !== undefined) this.errorDescription = opts.errorDescription
    if (opts.status !== undefined) this.status = opts.status
  }
}

/**
 * Cached RFC 8414 AS metadata, keyed by normalized issuer. Cache is
 * process-lifetime — RFC 8414 metadata changes are rare and consumers can
 * restart the process to refresh.
 */
const metadataCache = new Map<string, Promise<AsMetadata>>()

/** RFC 8414 metadata fields relevant to DCR. Other fields are ignored. */
interface AsMetadata {
  registration_endpoint?: string
  issuer?: string
}

/** Clear the metadata cache. Exposed for tests; not part of the documented surface. */
export function _clearMetadataCache(): void {
  metadataCache.clear()
}

/**
 * Register a new client with the AS via RFC 7591.
 *
 * Throws {@link OAuthError} on any failure. The function does not log: the
 * caller's logger never sees the initial access token because it is consumed
 * only inside this function's request construction.
 */
export async function registerClient(opts: RegisterClientOptions): Promise<RegisteredClient> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const doFetch: FetchLike = opts.fetch ?? (globalThis.fetch as FetchLike)

  const registrationEndpoint = await discoverRegistrationEndpoint(opts.issuer, doFetch, timeoutMs)

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
  }
  if (typeof opts.initialAccessToken === "string" && opts.initialAccessToken.length > 0) {
    headers.Authorization = `Bearer ${opts.initialAccessToken}`
  }

  let response: Awaited<ReturnType<FetchLike>>
  try {
    response = await doFetch(registrationEndpoint, {
      method: "POST",
      headers,
      body: JSON.stringify(opts.metadata),
      signal: AbortSignal.timeout(timeoutMs),
    })
  } catch (err) {
    // Never echo the initial access token in transport error messages.
    const message = err instanceof Error ? err.message : "registration request failed"
    throw new OAuthError({
      kind: "transport",
      message: `registration request failed: ${message}`,
    })
  }

  let body: unknown
  try {
    body = await response.json()
  } catch {
    if (!response.ok) {
      throw new OAuthError({
        kind: "transport",
        message: `registration endpoint returned HTTP ${response.status}`,
        status: response.status,
      })
    }
    throw new OAuthError({
      kind: "invalid_response",
      message: "registration response was not valid JSON",
      status: response.status,
    })
  }

  if (!response.ok) {
    // RFC 7591 §3.2.2: error responses carry `error` / `error_description`.
    if (isRecord(body) && typeof body.error === "string") {
      throw new OAuthError({
        kind: "as_error",
        message: typeof body.error_description === "string" ? body.error_description : body.error,
        error: body.error,
        ...(typeof body.error_description === "string"
          ? { errorDescription: body.error_description }
          : {}),
        status: response.status,
      })
    }
    throw new OAuthError({
      kind: "transport",
      message: `registration endpoint returned HTTP ${response.status}`,
      status: response.status,
    })
  }

  if (!isRecord(body)) {
    throw new OAuthError({
      kind: "invalid_response",
      message: "registration response was not a JSON object",
    })
  }

  if (typeof body.client_id !== "string" || body.client_id.length === 0) {
    throw new OAuthError({
      kind: "invalid_response",
      message: "registration response missing required field: client_id",
    })
  }

  return body as RegisteredClient
}

/**
 * Discover the RFC 8414 `registration_endpoint` for an issuer.
 *
 * RFC 8414 §3: metadata URL is `${issuer}/.well-known/oauth-authorization-server`.
 * We follow the simpler form that the spec example uses — suffix join — which
 * is what every public AS implements in practice for path-less issuers.
 */
async function discoverRegistrationEndpoint(
  issuer: string,
  doFetch: FetchLike,
  timeoutMs: number,
): Promise<string> {
  const key = issuer.replace(/\/+$/, "")
  let pending = metadataCache.get(key)
  if (pending === undefined) {
    pending = fetchMetadata(key, doFetch, timeoutMs)
    metadataCache.set(key, pending)
    // If discovery fails, evict so the next call retries.
    pending.catch(() => {
      metadataCache.delete(key)
    })
  }

  const metadata = await pending
  const endpoint = metadata.registration_endpoint
  if (typeof endpoint !== "string" || endpoint.length === 0) {
    throw new OAuthError({
      kind: "discovery",
      message: "AS metadata is missing registration_endpoint",
    })
  }
  return endpoint
}

async function fetchMetadata(
  issuerNoTrailingSlash: string,
  doFetch: FetchLike,
  timeoutMs: number,
): Promise<AsMetadata> {
  const url = `${issuerNoTrailingSlash}/.well-known/oauth-authorization-server`
  let response: Awaited<ReturnType<FetchLike>>
  try {
    response = await doFetch(url, {
      method: "GET",
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(timeoutMs),
    })
  } catch (err) {
    const message = err instanceof Error ? err.message : "metadata fetch failed"
    throw new OAuthError({
      kind: "discovery",
      message: `failed to fetch AS metadata: ${message}`,
    })
  }

  if (!response.ok) {
    throw new OAuthError({
      kind: "discovery",
      message: `AS metadata endpoint returned HTTP ${response.status}`,
      status: response.status,
    })
  }

  let body: unknown
  try {
    body = await response.json()
  } catch (err) {
    const message = err instanceof Error ? err.message : "invalid json"
    throw new OAuthError({
      kind: "discovery",
      message: `AS metadata was not valid JSON: ${message}`,
    })
  }

  if (!isRecord(body)) {
    throw new OAuthError({
      kind: "discovery",
      message: "AS metadata was not a JSON object",
    })
  }

  return body as AsMetadata
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}
