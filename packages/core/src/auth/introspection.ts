/**
 * RFC 7662 OAuth 2.0 Token Introspection for opaque AS tokens.
 *
 * Spec: docs/spec/v0.1.md#9-token-validation-pipeline (step 5) and
 * docs/spec/v0.1.md#14-security-non-negotiables (audience validation).
 *
 * Builds a standalone validator that POSTs the presented bearer token to
 * the configured `introspectionEndpoint` and maps the response into the
 * same `{ ok, auth | reason }` shape used by `auth/jwt.ts`. The pipeline
 * wiring is Stage 2; v0.1 ships the primitive only.
 *
 * @module
 */
import { createHash } from "node:crypto"
import type { AuthContext } from "../types.js"

/** Discriminator for why an introspection result was rejected. */
export type IntrospectionFailureReason =
  | "malformed"
  | "inactive"
  | "audience"
  | "expired"
  | "not-yet-valid"
  | "claims"
  | "transport"

export type IntrospectionValidationResult =
  | { ok: true; auth: AuthContext }
  | { ok: false; reason: IntrospectionFailureReason; message: string }

/**
 * Minimal `fetch` surface this module depends on. Typed against the global
 * `fetch` signature so consumers can pass a stub without pulling `any`.
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

export interface IntrospectionValidatorOptions {
  /** RFC 7662 introspection endpoint URL on the authorization server. */
  introspectionEndpoint: string
  /**
   * Expected `aud` claim on the introspection response; equal to
   * `AuthKitConfig.resourceIndicator`. Audience mismatch is a spec §14
   * non-negotiable.
   */
  audience: string
  /**
   * Optional override of `globalThis.fetch`. Useful in tests and for
   * deployments that need a custom HTTP client. Must be a typed function;
   * the public surface does not accept `any`.
   */
  fetch?: FetchLike
}

export interface IntrospectionValidator {
  validate(token: string): Promise<IntrospectionValidationResult>
}

/**
 * Build a validator bound to a single introspection endpoint + audience.
 *
 * The validator performs no caching: per the issue (out of scope) and the
 * spec ("treat the introspection response like a JWT validation result"),
 * each call is one HTTP round trip.
 */
export function createIntrospectionValidator(
  opts: IntrospectionValidatorOptions,
): IntrospectionValidator {
  const { introspectionEndpoint, audience } = opts
  const doFetch: FetchLike = opts.fetch ?? (globalThis.fetch as FetchLike)

  async function validate(token: string): Promise<IntrospectionValidationResult> {
    if (typeof token !== "string" || token.length === 0) {
      return { ok: false, reason: "malformed", message: "empty token" }
    }

    let response: Awaited<ReturnType<FetchLike>>
    try {
      response = await doFetch(introspectionEndpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "application/json",
        },
        body: `token=${encodeURIComponent(token)}`,
      })
    } catch (err) {
      const message = err instanceof Error ? err.message : "fetch failed"
      return { ok: false, reason: "transport", message }
    }

    if (!response.ok) {
      return {
        ok: false,
        reason: "transport",
        message: `introspection endpoint returned HTTP ${response.status}`,
      }
    }

    let body: unknown
    try {
      body = await response.json()
    } catch (err) {
      const message = err instanceof Error ? err.message : "invalid json"
      return { ok: false, reason: "transport", message }
    }

    if (!isRecord(body)) {
      return { ok: false, reason: "transport", message: "non-object response" }
    }

    if (body.active !== true) {
      return { ok: false, reason: "inactive", message: "token not active" }
    }

    if (!audienceMatches(body.aud, audience)) {
      return { ok: false, reason: "audience", message: "aud mismatch" }
    }

    const now = Math.floor(Date.now() / 1000)
    if (typeof body.nbf === "number" && body.nbf > now) {
      return { ok: false, reason: "not-yet-valid", message: "nbf in the future" }
    }
    if (typeof body.exp === "number" && body.exp <= now) {
      return { ok: false, reason: "expired", message: "exp in the past" }
    }

    const subject = typeof body.sub === "string" ? body.sub : null
    if (subject === null) {
      return { ok: false, reason: "claims", message: "missing sub" }
    }

    const scopes = extractScopes(body.scope)
    const tokenId =
      typeof body.jti === "string" && body.jti.length > 0 ? body.jti : fallbackTokenId(token)
    const expiresAt = typeof body.exp === "number" ? new Date(body.exp * 1000) : null

    const auth: AuthContext = {
      subject,
      tokenType: "oauth",
      tokenId,
      scopes,
      expiresAt,
      raw: { ...body },
    }
    return { ok: true, auth }
  }

  return { validate }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

function audienceMatches(aud: unknown, expected: string): boolean {
  if (typeof aud === "string") return aud === expected
  if (Array.isArray(aud)) return aud.some((v) => v === expected)
  return false
}

function extractScopes(scope: unknown): readonly string[] {
  if (typeof scope !== "string") return Object.freeze([])
  const parts = scope.split(/\s+/).filter((s) => s.length > 0)
  return Object.freeze(parts)
}

/**
 * Stable, non-reversible fallback `tokenId` when the introspection response
 * lacks `jti`. SHA-256 hex of the presented token — matches `jwt.ts` so the
 * two pipelines produce comparable `AuthContext.tokenId` values.
 */
function fallbackTokenId(token: string): string {
  return createHash("sha256").update(token).digest("hex")
}
