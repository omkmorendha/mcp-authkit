/**
 * RFC 6750 / RFC 9728 Bearer challenge.
 *
 * Spec: docs/spec/v0.1.md#9-token-validation-pipeline (step 6)
 *       docs/spec/v0.1.md#14-security-non-negotiables
 *
 * `WWW-Authenticate: Bearer resource_metadata="<url>"[, error="<code>"][, error_description="<msg>"]`
 *
 * The `resource_metadata` parameter is RFC 9728 §5.1 — discovery hint for the
 * client. The `error` codes are the RFC 6750 §3.1 set.
 *
 * @module
 */
import type { ServerResponse } from "node:http"

export type ChallengeError = "invalid_request" | "invalid_token" | "insufficient_scope"

export interface ChallengeOptions {
  /** RFC 9728 metadata URL — typically `<resource>/.well-known/oauth-protected-resource`. */
  readonly resourceMetadataUrl: string
  /** Optional RFC 6750 §3.1 error code. Omitted when the request had no token. */
  readonly error?: ChallengeError
  /** Optional human-readable description (RFC 6750 §3). */
  readonly errorDescription?: string
}

/**
 * Build the `WWW-Authenticate` header value for a 401 / 403 Bearer challenge.
 *
 * Quotes per RFC 6750 §3 (quoted-string per RFC 7235); embedded `"` and `\`
 * are escaped.
 */
export function buildChallengeHeader(options: ChallengeOptions): string {
  const parts: string[] = [`resource_metadata=${quote(options.resourceMetadataUrl)}`]
  if (options.error) parts.push(`error=${quote(options.error)}`)
  if (options.errorDescription) {
    parts.push(`error_description=${quote(options.errorDescription)}`)
  }
  return `Bearer ${parts.join(", ")}`
}

function quote(value: string): string {
  // RFC 7235: backslash + DQUOTE need escaping inside a quoted-string.
  const escaped = value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')
  return `"${escaped}"`
}

/**
 * Write a 401 (or 403) response with a Bearer challenge header. Sets
 * Cache-Control: no-store so intermediaries don't cache the negative answer.
 */
export function writeChallenge(
  res: ServerResponse,
  options: ChallengeOptions & { readonly status?: 401 | 403 },
): void {
  if (res.headersSent) return
  res.setHeader("WWW-Authenticate", buildChallengeHeader(options))
  res.setHeader("Cache-Control", "no-store")
  res.writeHead(options.status ?? 401)
  res.end()
}

/**
 * Derive the canonical resource metadata URL from a resource indicator. Per
 * RFC 9728 §3 the metadata is hosted at the resource's well-known path.
 */
export function metadataUrlFor(resourceIndicator: string): string {
  // Trim trailing slash to avoid `//`. RFC 9728 §3 is silent on trailing slashes;
  // consumers can override resourceMetadataUrl explicitly via createAuthKit if
  // they mount the metadata handler at a different path.
  const base = resourceIndicator.endsWith("/") ? resourceIndicator.slice(0, -1) : resourceIndicator
  return `${base}/.well-known/oauth-protected-resource`
}
