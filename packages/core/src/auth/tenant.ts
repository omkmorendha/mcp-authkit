/**
 * Multi-tenant authorization server resolution.
 *
 * Spec: docs/spec/v0.2.md#51-multi-tenant-as
 *       docs/spec/v0.2.md#7-multi-tenant-authorization-server
 *       docs/spec/v0.1.md#9-token-validation-pipeline (pipeline ordering)
 *
 * The function-form `AuthKitConfig.auth.authorizationServer` lets a single
 * deployment serve many tenants. Resolution runs BEFORE bypass / static /
 * PAT / JWT / introspection so every downstream step sees the right AS.
 *
 * Hard rules (spec §7):
 *   - Cache JWKS per resolved `issuer`, not per request.
 *   - Memoize the resolver result for a single request lifetime.
 *   - Resolver throw → 503 + `WWW-Authenticate: error="server_error"`, NOT 401.
 *   - Log resolver latency at debug as `authkit.tenant_resolve_ms`.
 *   - Refuse to start if the resolver returns an object missing `issuer` or
 *     `jwksUri`.
 *
 * @module
 */
import type { IncomingMessage } from "node:http"
import type { Logger } from "pino"
import type {
  AuthorizationServerConfig,
  AuthorizationServerResolver,
  AuthorizationServerSelector,
} from "../types.js"

/**
 * Symbol used to memoize a resolver invocation onto an `IncomingMessage` for
 * the duration of a single request. Different `createAuthKit` instances do
 * not share this symbol — a process embedding multiple kits gets isolated
 * caches as a side effect.
 */
const RESOLVER_CACHE = Symbol("mcp-authkit:tenant-resolver-cache")

/**
 * The outcome of tenant resolution. Returned as a tagged union so callers
 * can branch without exception machinery on the hot path.
 */
export type ResolveResult =
  | { readonly ok: true; readonly as: AuthorizationServerConfig; readonly latencyMs: number }
  | { readonly ok: false; readonly error: Error; readonly latencyMs: number }

interface CachedResolution {
  readonly result: Promise<ResolveResult>
}

interface IncomingWithCache extends IncomingMessage {
  [RESOLVER_CACHE]?: CachedResolution
}

/**
 * Parse the leftmost label off the request `Host` header as the tenant id.
 *
 * Examples:
 *   - `acme.example.com:443` → `"acme"`
 *   - `tenant-42.api.example.com` → `"tenant-42"`
 *   - `example.com` (no subdomain) → `null`
 *   - missing / unparseable host → `null`
 *
 * Resolvers that need different routing (path prefix, header, JWT issuer hint)
 * can ignore this and read `incoming.headers` themselves.
 */
export function defaultTenantIdFromHost(host: string | undefined): string | null {
  if (!host) return null
  const trimmed = host.trim()
  if (trimmed.length === 0) return null
  // IPv6 literal: [::1]:port — no tenant routing possible.
  if (trimmed.startsWith("[")) return null
  const withoutPort = trimmed.split(":")[0] ?? ""
  if (withoutPort.length === 0) return null
  const dot = withoutPort.indexOf(".")
  if (dot <= 0) return null
  const label = withoutPort.slice(0, dot)
  if (label.length === 0 || /^\d+$/.test(label)) return null
  return label
}

/**
 * Build the resolver input. Exposed for tests; production callers use
 * `resolveAuthorizationServer` instead.
 */
export function makeSelector(incoming: IncomingMessage): AuthorizationServerSelector {
  const hostHeader = incoming.headers.host
  const host = Array.isArray(hostHeader) ? hostHeader[0] : hostHeader
  return {
    incoming,
    tenantId: defaultTenantIdFromHost(host),
  }
}

/**
 * Validate the shape returned by a function-form resolver. Spec §7 mandates
 * a clear failure when the resolver returns an object missing either
 * `issuer` or `jwksUri`. Thrown errors propagate as the resolver error
 * outcome, which the handler maps to 503.
 */
export function assertResolvedConfig(value: unknown): asserts value is AuthorizationServerConfig {
  if (value === null || typeof value !== "object") {
    throw new Error(
      "authorizationServer resolver returned a non-object value; expected { issuer, jwksUri }",
    )
  }
  const v = value as { issuer?: unknown; jwksUri?: unknown }
  if (typeof v.issuer !== "string" || v.issuer.length === 0) {
    throw new Error("authorizationServer resolver returned a config missing 'issuer'")
  }
  if (typeof v.jwksUri !== "string" || v.jwksUri.length === 0) {
    throw new Error("authorizationServer resolver returned a config missing 'jwksUri'")
  }
}

export interface ResolveOptions {
  /** The resolved request. Required so we can memoize against it. */
  readonly incoming: IncomingMessage
  /** Static config or function. */
  readonly resolverSpec: AuthorizationServerConfig | AuthorizationServerResolver
  /** Logger for the `authkit.tenant_resolve_ms` debug line. */
  readonly logger: Logger
}

/**
 * Resolve the authorization server for a single request.
 *
 * - Static-object spec: returns immediately, latency is 0, no logging.
 * - Function spec: invokes the resolver at most once per request (memoized
 *   on a `Symbol` attached to `incoming`), validates the returned shape, and
 *   logs the call latency at `debug` with `authkit.tenant_resolve_ms`.
 *
 * Errors are returned as `{ ok: false, error }`, never thrown. Callers
 * convert that to HTTP 503 (spec §7) — distinct from the 401 path.
 */
export function resolveAuthorizationServer(opts: ResolveOptions): Promise<ResolveResult> {
  const { incoming, resolverSpec, logger } = opts

  if (typeof resolverSpec !== "function") {
    try {
      assertResolvedConfig(resolverSpec)
    } catch (err) {
      return Promise.resolve({
        ok: false,
        error: err instanceof Error ? err : new Error(String(err)),
        latencyMs: 0,
      })
    }
    return Promise.resolve({ ok: true, as: resolverSpec, latencyMs: 0 })
  }

  const cached = (incoming as IncomingWithCache)[RESOLVER_CACHE]
  if (cached !== undefined) return cached.result

  const start = performance.now()
  const selector = makeSelector(incoming)
  const result = Promise.resolve()
    .then(() => resolverSpec(selector))
    .then(
      (value): ResolveResult => {
        const latencyMs = performance.now() - start
        try {
          assertResolvedConfig(value)
        } catch (err) {
          logger.debug(
            { "authkit.tenant_resolve_ms": latencyMs, ok: false, reason: "invalid-shape" },
            "tenant resolver returned invalid shape",
          )
          return {
            ok: false,
            error: err instanceof Error ? err : new Error(String(err)),
            latencyMs,
          }
        }
        logger.debug(
          { "authkit.tenant_resolve_ms": latencyMs, ok: true, issuer: value.issuer },
          "tenant resolver succeeded",
        )
        return { ok: true, as: value, latencyMs }
      },
      (err): ResolveResult => {
        const latencyMs = performance.now() - start
        const error = err instanceof Error ? err : new Error(String(err))
        logger.debug(
          { "authkit.tenant_resolve_ms": latencyMs, ok: false, err: error.message },
          "tenant resolver threw",
        )
        return { ok: false, error, latencyMs }
      },
    )

  ;(incoming as IncomingWithCache)[RESOLVER_CACHE] = { result }
  return result
}
