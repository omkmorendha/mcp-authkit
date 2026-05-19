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
  const presentedHost = stripPort(presented)

  for (const entry of options.allowedHosts) {
    const e = entry.toLowerCase()
    if (e === presented) return { ok: true }
    // A host-only allowlist entry (no `:port`) matches any port on that
    // host. Bracketed IPv6 with no trailing port is also host-only.
    if (isHostOnly(e) && e === presentedHost) return { ok: true }
  }
  return { ok: false, reason: "disallowed" }
}

/**
 * Strip the `:port` suffix from a Host header value, preserving bracketed
 * IPv6 literals. `[::1]:3000` → `[::1]`; `[::1]` → `[::1]`;
 * `api.example.com:3000` → `api.example.com`.
 */
function stripPort(host: string): string {
  if (host.startsWith("[")) {
    const close = host.indexOf("]")
    if (close === -1) return host
    return host.slice(0, close + 1)
  }
  const colon = host.indexOf(":")
  return colon === -1 ? host : host.slice(0, colon)
}

/**
 * True if `entry` carries no `:port` component. Bracketed IPv6 with no
 * trailing port (`[::1]`) counts as host-only; with a port (`[::1]:3000`)
 * does not.
 */
function isHostOnly(entry: string): boolean {
  if (entry.startsWith("[")) {
    const close = entry.indexOf("]")
    if (close === -1) return false
    return close === entry.length - 1
  }
  return !entry.includes(":")
}
