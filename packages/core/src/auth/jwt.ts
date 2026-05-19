/**
 * JWT validation for OAuth access tokens.
 *
 * Spec: docs/spec/v0.1.md#9-token-validation-pipeline (step 4) and
 * docs/spec/v0.1.md#14-security-non-negotiables (audience validation).
 *
 * @module
 */
import { createHash } from "node:crypto"
import { createRemoteJWKSet, type JWTPayload, errors as joseErrors, jwtVerify } from "jose"
import type { AuthContext } from "../types.js"

/** Default JWKS cache TTL (1 hour) per spec §6.1 `jwksCacheTtlMs`. */
const DEFAULT_JWKS_CACHE_TTL_MS = 3_600_000

/** Discriminator for why a JWT was rejected. */
export type JwtValidationFailureReason =
  | "malformed"
  | "signature"
  | "issuer"
  | "audience"
  | "expired"
  | "not-yet-valid"
  | "jwks"
  | "claims"

export type JwtValidationResult =
  | { ok: true; auth: AuthContext }
  | { ok: false; reason: JwtValidationFailureReason; message: string }

export interface JwtValidatorOptions {
  /** Expected `iss` claim; matches `AuthKitConfig.auth.authorizationServer.issuer`. */
  issuer: string
  /**
   * Expected `aud` claim; equal to `AuthKitConfig.resourceIndicator`.
   * Audience mismatch is a spec §14 non-negotiable.
   */
  audience: string
  /** JWKS endpoint URL on the authorization server. */
  jwksUri: string
  /** ms; default {@link DEFAULT_JWKS_CACHE_TTL_MS}. */
  jwksCacheTtlMs?: number
}

/**
 * Validates a JWT bearer token.
 *
 * Uses `jose`'s default clock skew tolerance (0s). v0.1 does not expose
 * a clock skew override; if a deployment needs one, file an issue.
 */
export interface JwtValidator {
  validate(token: string): Promise<JwtValidationResult>
}

/**
 * Build a validator bound to a single AS + audience. The JWKS is fetched
 * lazily on first verification and cached per `cacheMaxAge`.
 */
export function createJwtValidator(opts: JwtValidatorOptions): JwtValidator {
  const { issuer, audience, jwksUri } = opts
  const cacheMaxAge = opts.jwksCacheTtlMs ?? DEFAULT_JWKS_CACHE_TTL_MS

  const jwks = createRemoteJWKSet(new URL(jwksUri), { cacheMaxAge })

  async function validate(token: string): Promise<JwtValidationResult> {
    if (typeof token !== "string" || token.length === 0) {
      return { ok: false, reason: "malformed", message: "empty token" }
    }

    let payload: JWTPayload
    try {
      const result = await jwtVerify(token, jwks, { issuer, audience })
      payload = result.payload
    } catch (err) {
      return mapError(err)
    }

    // Belt-and-suspenders: jose has already enforced audience, but we
    // re-assert it so the audience guarantee is explicit at our boundary
    // and asserted by our own test suite (spec §14).
    if (!audienceMatches(payload.aud, audience)) {
      return { ok: false, reason: "audience", message: "aud mismatch" }
    }
    if (payload.iss !== issuer) {
      return { ok: false, reason: "issuer", message: "iss mismatch" }
    }

    const subject = typeof payload.sub === "string" ? payload.sub : null
    if (subject === null) {
      return { ok: false, reason: "claims", message: "missing sub" }
    }
    const exp = typeof payload.exp === "number" ? payload.exp : null
    if (exp === null) {
      return { ok: false, reason: "claims", message: "missing exp" }
    }

    const scopes = extractScopes(payload.scope)
    const tokenId =
      typeof payload.jti === "string" && payload.jti.length > 0
        ? payload.jti
        : fallbackTokenId(token)

    const auth: AuthContext = {
      subject,
      tokenType: "oauth",
      tokenId,
      scopes,
      expiresAt: new Date(exp * 1000),
      raw: { ...payload },
    }
    return { ok: true, auth }
  }

  return { validate }
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
 * Stable, non-reversible fallback `tokenId` when the JWT lacks `jti`.
 * SHA-256 hex of the compact JWS — deterministic per token, leaks nothing
 * beyond what the token itself does, and fits the opaque-string contract.
 */
function fallbackTokenId(token: string): string {
  return createHash("sha256").update(token).digest("hex")
}

function mapError(err: unknown): JwtValidationResult {
  if (err instanceof joseErrors.JWTExpired) {
    return { ok: false, reason: "expired", message: err.message }
  }
  if (err instanceof joseErrors.JWTClaimValidationFailed) {
    const claim = err.claim
    if (claim === "iss") {
      return { ok: false, reason: "issuer", message: err.message }
    }
    if (claim === "aud") {
      return { ok: false, reason: "audience", message: err.message }
    }
    if (claim === "nbf") {
      return { ok: false, reason: "not-yet-valid", message: err.message }
    }
    if (claim === "exp") {
      return { ok: false, reason: "expired", message: err.message }
    }
    return { ok: false, reason: "claims", message: err.message }
  }
  if (err instanceof joseErrors.JWSSignatureVerificationFailed) {
    return { ok: false, reason: "signature", message: err.message }
  }
  if (
    err instanceof joseErrors.JWKSNoMatchingKey ||
    err instanceof joseErrors.JWKSMultipleMatchingKeys ||
    err instanceof joseErrors.JWKSInvalid ||
    err instanceof joseErrors.JWKSTimeout
  ) {
    return { ok: false, reason: "jwks", message: err.message }
  }
  if (err instanceof joseErrors.JWSInvalid || err instanceof joseErrors.JWTInvalid) {
    return { ok: false, reason: "malformed", message: err.message }
  }
  if (err instanceof joseErrors.JOSEError) {
    return { ok: false, reason: "claims", message: err.message }
  }
  const message = err instanceof Error ? err.message : "unknown error"
  return { ok: false, reason: "malformed", message }
}
