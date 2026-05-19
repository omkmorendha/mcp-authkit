/**
 * Produce a safe-to-log summary of an {@link AuthKitConfig}.
 *
 * The CLI and operator tooling print a "loaded config from X" line at
 * startup. Pino is structured-logging by default but operators often pipe
 * to less or grep; we want zero risk of leaking secrets.
 *
 * Returned fields:
 *   - `resourceIndicator`
 *   - `auth.authorizationServer.{issuer, jwksUri}` (no introspection URL —
 *     in many deployments it embeds a credential in basic-auth form).
 *   - `auth.pat.{enabled}` — `prefix` is treated as secret-shaped
 *     (`<redacted>` when set) because revealing it teaches an attacker how
 *     to distinguish PATs from JWTs in logs of tokens-by-mistake.
 *   - `auth.tokenStore` — constructor name only.
 *   - `auth.bypass` — boolean `enabled` only, never `user` or `scopes`.
 *   - `auth.staticToken` — `"<redacted>"` flag; no token, no scopes.
 *   - `scopes.vocabulary` — keys only, descriptions stripped.
 *   - `http.allowedHosts` — kept (already public-ish).
 *
 * Spec: docs/spec/v0.2.md#58-config-file-format
 *       docs/spec/v0.1.md#14-security-non-negotiables
 */
import type { AuthKitConfig } from "./types.js"

const REDACTED = "<redacted>"

/**
 * Look up a class name for an arbitrary instance, falling back to `"object"`.
 * Plain object literals report `"Object"`; we surface `"object"` instead so
 * the redacted output reads naturally.
 */
function classNameOf(value: object): string {
  const ctor = (value as { constructor?: { name?: string } }).constructor
  const name = ctor?.name
  if (name === undefined || name === "Object") return "object"
  return name
}

export function redactConfigForLog(config: AuthKitConfig): Record<string, unknown> {
  const as = config.auth.authorizationServer
  const pat = config.auth.pat
  const bypass = config.auth.bypass
  const staticToken = config.auth.staticToken

  const out: Record<string, unknown> = {
    resourceIndicator: config.resourceIndicator,
    auth: {
      ...(as
        ? {
            authorizationServer: {
              issuer: as.issuer,
              jwksUri: as.jwksUri,
              introspectionEndpoint: as.introspectionEndpoint !== undefined ? REDACTED : undefined,
            },
          }
        : {}),
      tokenStore: classNameOf(config.auth.tokenStore as unknown as object),
      pat: {
        enabled: pat.enabled,
        prefix: pat.prefix !== undefined ? REDACTED : undefined,
      },
      ...(bypass ? { bypass: { enabled: bypass.enabled } } : {}),
      ...(staticToken ? { staticToken: REDACTED } : {}),
    },
    scopes: {
      vocabulary: Object.keys(config.scopes.vocabulary),
      customMatchers:
        config.scopes.customMatchers !== undefined ? config.scopes.customMatchers.length : 0,
    },
    ...(config.http ? { http: { allowedHosts: config.http.allowedHosts } } : {}),
  }
  return out
}
