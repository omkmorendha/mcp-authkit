/**
 * DNS rebinding protection — Host header validation.
 *
 * Spec: docs/spec/v0.1.md#14-security-non-negotiables
 *
 * Rule (spec §14): "Host header validation on by default; configurable
 * allowlist." When no explicit allowlist is configured, the host of
 * `resourceIndicator` is used. To disable (NOT recommended), pass an empty
 * allowlist explicitly.
 *
 * @module
 */
import type { IncomingMessage } from "node:http"

export interface HostValidationOptions {
  /**
   * Lower-cased Host header values that are allowed. May include a port
   * (`api.example.com:3000`) or omit it (`api.example.com`, matches any port).
   */
  readonly allowedHosts: readonly string[]
}

export type HostValidationResult = { ok: true } | { ok: false; reason: "missing" | "disallowed" }

/**
 * Derive a default allowlist entry from a resource indicator URL.
 *
 * Returns `host[:port]` lower-cased. Returns null when the indicator is not
 * a parseable absolute URL (caller should treat that as a config error and
 * fall back to disabled validation rather than crashing at request time).
 */
export function hostFromResourceIndicator(resourceIndicator: string): string | null {
  try {
    const url = new URL(resourceIndicator)
    return url.host.toLowerCase()
  } catch {
    return null
  }
}

/**
 * Validate a request's Host header against the allowlist. The comparison is
 * case-insensitive. Allowlist entries that include a port match only that
 * exact port; entries without a port match any port.
 *
 * Spec §14 mandates this protection; callers must reject requests on a
 * non-`ok` result before doing any auth work.
 */
export function validateHost(
  req: IncomingMessage,
  options: HostValidationOptions,
): HostValidationResult {
  // Explicit empty allowlist = consumer opted out (loudly logged at startup
  // is the consumer's responsibility; we accept).
  if (options.allowedHosts.length === 0) return { ok: true }

  const header = req.headers.host
  if (typeof header !== "string" || header.length === 0) {
    return { ok: false, reason: "missing" }
  }
  const presented = header.toLowerCase()
  const presentedHost = presented.split(":")[0] ?? presented

  for (const entry of options.allowedHosts) {
    const e = entry.toLowerCase()
    if (e === presented) return { ok: true }
    // Entry without a port matches any port on that host.
    if (!e.includes(":") && e === presentedHost) return { ok: true }
  }
  return { ok: false, reason: "disallowed" }
}
